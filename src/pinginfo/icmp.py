from __future__ import annotations

import os
import random
import select
import socket
import struct
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMPV6_ECHO_REQUEST = 128
ICMPV6_ECHO_REPLY = 129
IPPROTO_ICMPV6 = getattr(socket, "IPPROTO_ICMPV6", 58)


class IcmpError(OSError):
    pass


@dataclass
class PingReply:
    ok: bool
    rtt_ms: float | None = None
    error: str | None = None
    ttl: int | None = None


def _checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    count = len(data) // 2
    total = sum(struct.unpack(f"!{count}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _parse_ipv4_icmp(packet: bytes) -> tuple[int, int, int, int, int | None] | None:
    ttl = None
    icmp = packet
    if len(packet) >= 20 and (packet[0] >> 4) == 4:
        ihl = (packet[0] & 0x0F) * 4
        if ihl < 20 or len(packet) < ihl + 8:
            return None
        ttl = packet[8]
        icmp = packet[ihl:]
    if len(icmp) < 8:
        return None
    icmp_type, _code, _cksum, ident, seq = struct.unpack("!BBHHH", icmp[:8])
    return icmp_type, _code, ident, seq, ttl


def _parse_ipv6_icmp(packet: bytes) -> tuple[int, int, int, int] | None:
    if len(packet) < 8:
        return None
    icmp_type, _code, _cksum, ident, seq = struct.unpack("!BBHHH", packet[:8])
    return icmp_type, _code, ident, seq


def split_zone(address: str) -> tuple[str, int]:
    if "%" not in address:
        return address, 0
    host, zone = address.rsplit("%", 1)
    if zone.isdigit():
        return host, int(zone)
    try:
        return host, socket.if_nametoindex(zone)
    except OSError:
        return host, 0


def bare_ip(address: str) -> str:
    return address.rsplit("%", 1)[0]


class IcmpEndpoint:
    def __init__(self, family: socket.AddressFamily):
        self.family = family
        self._sock = self._open_socket(family)
        self._lock = threading.Lock()
        self._seq = random.randint(0, 65535)
        self._ident = os.getpid() & 0xFFFF
        try:
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)
        except OSError:
            pass

    @staticmethod
    def _open_socket(family: socket.AddressFamily) -> socket.socket:
        proto = socket.IPPROTO_ICMP if family == socket.AF_INET else IPPROTO_ICMPV6
        errors: list[str] = []
        for kind in (socket.SOCK_DGRAM, socket.SOCK_RAW):
            try:
                sock = socket.socket(family, kind, proto)
                sock.setblocking(False)
                return sock
            except PermissionError as exc:
                errors.append(f"{kind}: 权限不足 ({exc})")
            except OSError as exc:
                errors.append(f"{kind}: {exc}")
        hint = "；".join(errors) if errors else "未知错误"
        raise IcmpError(
            "无法创建 ICMP 套接字（未调用 ping 命令）。"
            f" 需要 CAP_NET_RAW，或将当前用户纳入 net.ipv4.ping_group_range。详情: {hint}"
        )

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass

    def _next_seq(self) -> int:
        with self._lock:
            self._seq = (self._seq + 1) & 0xFFFF
            return self._seq

    def _build(self, seq: int, payload: bytes) -> bytes:
        ident = self._ident
        if self.family == socket.AF_INET:
            header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, ident, seq)
            cksum = _checksum(header + payload)
            return struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, cksum, ident, seq) + payload
        return struct.pack("!BBHHH", ICMPV6_ECHO_REQUEST, 0, 0, ident, seq) + payload

    def _dest(self, address: str) -> tuple:
        if self.family == socket.AF_INET:
            return (bare_ip(address), 0)
        host, ifindex = split_zone(address)
        return (host, 0, 0, ifindex)

    def ping(self, address: str, timeout: float, payload_size: int = 32) -> PingReply:
        results = self.ping_many([address], timeout, payload_size)
        return results.get(address, PingReply(False, error="Request timeout"))

    def ping_many(
        self,
        addresses: Iterable[str],
        timeout: float,
        payload_size: int = 32,
        send_pause: float = 0.0,
    ) -> dict[str, PingReply]:
        targets = list(dict.fromkeys(addresses))
        if not targets:
            return {}

        pending_by_seq: dict[int, tuple[str, float]] = {}
        pending_addrs: dict[str, int] = {}
        replies: dict[str, PingReply] = {}
        expect_type = ICMP_ECHO_REPLY if self.family == socket.AF_INET else ICMPV6_ECHO_REPLY

        def drain(wait: float) -> None:
            deadline = time.perf_counter() + max(0.0, wait)
            while pending_by_seq:
                remaining = deadline - time.perf_counter()
                if remaining < 0 and wait > 0:
                    break
                timeout_s = remaining if wait > 0 else 0.0
                try:
                    ready, _, _ = select.select([self._sock], [], [], timeout_s)
                except (ValueError, OSError):
                    break
                if not ready:
                    if wait <= 0:
                        break
                    if remaining <= 0:
                        break
                    continue
                try:
                    data, src = self._sock.recvfrom(4096)
                except BlockingIOError:
                    continue
                except OSError:
                    break
                src_ip = bare_ip(src[0])
                if self.family == socket.AF_INET:
                    parsed = _parse_ipv4_icmp(data)
                    if parsed is None:
                        continue
                    icmp_type, _code, _rid, rseq, ttl = parsed
                    if icmp_type != expect_type:
                        continue
                    item = pending_by_seq.pop(rseq, None)
                    if item is None:
                        continue
                    address, stamp = item
                    pending_addrs.pop(address, None)
                    rtt = (time.perf_counter() - stamp) * 1000.0
                    replies[address] = PingReply(True, rtt_ms=rtt, ttl=ttl)
                else:
                    parsed6 = _parse_ipv6_icmp(data)
                    if parsed6 is None:
                        continue
                    icmp_type, _code, _rid, rseq = parsed6
                    if icmp_type != expect_type:
                        continue
                    item = pending_by_seq.pop(rseq, None)
                    if item is None:
                        continue
                    address, stamp = item
                    pending_addrs.pop(address, None)
                    rtt = (time.perf_counter() - stamp) * 1000.0
                    replies[address] = PingReply(True, rtt_ms=rtt)
                _ = src_ip

        for address in targets:
            seq = self._next_seq()
            stamp = time.perf_counter()
            payload = struct.pack("!d", stamp) + os.urandom(max(0, payload_size - 8))
            packet = self._build(seq, payload)
            try:
                self._sock.sendto(packet, self._dest(address))
                pending_by_seq[seq] = (address, stamp)
                pending_addrs[address] = seq
            except OSError as exc:
                replies[address] = PingReply(False, error=str(exc) or exc.__class__.__name__)
            drain(0.0)
            if send_pause:
                time.sleep(send_pause)

        if pending_by_seq:
            drain(max(0.05, timeout))
        for address in pending_addrs:
            replies[address] = PingReply(False, error="Request timeout")
        return replies


_local = threading.local()


def _endpoint(family: str) -> IcmpEndpoint:
    af = socket.AF_INET if family == "IPv4" else socket.AF_INET6
    cache: dict = getattr(_local, "endpoints", None)
    if cache is None:
        cache = {}
        _local.endpoints = cache
    endpoint = cache.get(af)
    if endpoint is None:
        endpoint = IcmpEndpoint(af)
        cache[af] = endpoint
    return endpoint


def ping_once(address: str, family: str, timeout: float) -> PingReply:
    return _endpoint(family).ping(address, timeout)


def ping_many(
    targets: list[tuple[str, str]],
    timeout: float,
    send_pause: float = 0.0,
) -> dict[str, PingReply]:
    grouped: dict[str, list[str]] = {"IPv4": [], "IPv6": []}
    for ip, family in targets:
        grouped.setdefault(family, []).append(ip)

    v4 = grouped.get("IPv4") or []
    v6 = grouped.get("IPv6") or []
    if not v4 and not v6:
        return {}

    def _run(family: str, ips: list[str]) -> dict[str, PingReply]:
        try:
            return _endpoint(family).ping_many(ips, timeout, send_pause=send_pause)
        except IcmpError as exc:
            err = PingReply(False, error=str(exc))
            return {ip: err for ip in ips}

    if v4 and v6:
        box: dict[str, dict[str, PingReply]] = {}

        def _v6() -> None:
            box["v6"] = _run("IPv6", v6)

        worker = threading.Thread(target=_v6, name="pinginfo-icmp6", daemon=True)
        worker.start()
        out = _run("IPv4", v4)
        worker.join()
        out.update(box.get("v6") or {})
        return out
    if v4:
        return _run("IPv4", v4)
    return _run("IPv6", v6)
