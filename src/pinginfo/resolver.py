from __future__ import annotations

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from .validator import ipv4_mapped_string, literal_family


@dataclass
class ResolvedHost:
    hostname: str
    family: str | None
    display_ip: str | None
    error: str | None = None

    @property
    def is_resolved(self) -> bool:
        return self.family is not None and self.display_ip is not None


class DNSResolver:
    def __init__(self, ttl: float = 300.0):
        self.ttl = ttl
        self._cache: dict[tuple[str, bool], tuple[float, ResolvedHost]] = {}
        self._lock = threading.Lock()

    def invalidate(self, host: str) -> None:
        with self._lock:
            self._cache = {k: v for k, v in self._cache.items() if k[0] != host}

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()

    def resolve(self, host: str, prefer_ipv6: bool) -> ResolvedHost:
        key = (host, prefer_ipv6)
        now = time.time()
        with self._lock:
            hit = self._cache.get(key)
            if hit and hit[0] > now:
                return hit[1]
        looked = self._lookup(host, prefer_ipv6)
        if looked.is_resolved:
            with self._lock:
                self._cache[key] = (now + self.ttl, looked)
        return looked

    def resolve_all(self, hosts: list[str], prefer_ipv6: bool) -> list[ResolvedHost]:
        literals: list[ResolvedHost] = []
        names: list[str] = []
        order: list[tuple[str, int | None]] = []
        for host in hosts:
            family = literal_family(host)
            if family is not None:
                looked = self._lookup(host, prefer_ipv6)
                order.append(("lit", len(literals)))
                literals.append(looked)
            else:
                order.append(("name", len(names)))
                names.append(host)
        if names:
            if len(names) <= 8:
                resolved_names = [self.resolve(h, prefer_ipv6) for h in names]
            else:
                workers = min(32, len(names))
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    resolved_names = list(pool.map(lambda h: self.resolve(h, prefer_ipv6), names))
        else:
            resolved_names = []
        out: list[ResolvedHost] = []
        for kind, idx in order:
            out.append(literals[idx] if kind == "lit" else resolved_names[idx])
        return out

    def _lookup(self, host: str, prefer_ipv6: bool) -> ResolvedHost:
        family = literal_family(host)
        if family == "IPv4":
            display = ipv4_mapped_string(host) or host
            if display.startswith("::ffff:"):
                display = display.split("::ffff:")[-1]
            return ResolvedHost(host, "IPv4", display)
        if family == "IPv6":
            return ResolvedHost(host, "IPv6", host)

        last_error = None
        if prefer_ipv6:
            got = self._resolve_name(host, socket.AF_INET6)
            if isinstance(got, ResolvedHost):
                return got
            last_error = got
        got = self._resolve_name(host, socket.AF_INET)
        if isinstance(got, ResolvedHost):
            return got
        last_error = got or last_error
        return ResolvedHost(host, None, None, last_error or "DNS: name resolution failed")

    @staticmethod
    def _resolve_name(host: str, af: int) -> ResolvedHost | str:
        try:
            infos = socket.getaddrinfo(host, None, af, socket.SOCK_DGRAM)
        except socket.gaierror as exc:
            return f"DNS: {exc.strerror or exc}"
        except OSError as exc:
            return f"DNS: {exc}"
        for info in infos:
            sockaddr = info[4]
            ip = sockaddr[0]
            if af == socket.AF_INET6 and ip.lower().startswith("::ffff:"):
                continue
            family = "IPv6" if af == socket.AF_INET6 else "IPv4"
            return ResolvedHost(host, family, ip)
        return f"DNS: no {('IPv6' if af == socket.AF_INET6 else 'IPv4')} address"
