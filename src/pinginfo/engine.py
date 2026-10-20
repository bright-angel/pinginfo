from __future__ import annotations

import csv
import io
import threading
import time
from collections.abc import Callable
from datetime import datetime

from .expander import expand_all
from .icmp import PingReply, ping_many
from .models import INVALID_SUFFIX, PingResult, PingStatus
from .resolver import DNSResolver, ResolvedHost
from .validator import literal_family as _literal_family


class PingEngine:
    def __init__(self, on_update: Callable[[], None] | None = None):
        self.on_update = on_update
        self.results: list[PingResult] = []
        self.is_running = False
        self.pin_online_to_top = False
        self.ping_interval = 1.0
        self.timeout = 1.0
        self.resolve_hostnames_via_ipv6 = False
        self.offline_failure_threshold = 2
        self.ipv6_fallback_threshold = 2
        self.send_rate = 800.0

        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._resolver = DNSResolver()
        self._ipv6_by_name: set[str] = set()
        self._downgraded: set[str] = set()
        self._loop_thread: threading.Thread | None = None
        self._row_index: dict[str, int] = {}
        self._generation = 0
        self._sort_key = "status"
        self._sort_reverse = False

    def _notify(self) -> None:
        cb = self.on_update
        if cb:
            cb()

    def start(self, hosts_text: str) -> tuple[list[str], int]:
        self.stop()
        if self._loop_thread and self._loop_thread.is_alive():
            self._loop_thread.join(timeout=3.0)
        with self._lock:
            if self.is_running:
                return [], 0
            hosts, invalid, warnings = expand_all(hosts_text)
            self.results = []
            self._row_index.clear()
            self._ipv6_by_name.clear()
            self._downgraded.clear()

            for host in hosts:
                self._append_result(PingResult(hostname=host, status=PingStatus.WAITING))
            for token in invalid:
                display = token if token.endswith(INVALID_SUFFIX) else token + INVALID_SUFFIX
                self._append_result(
                    PingResult(hostname=display, is_invalid=True, status=PingStatus.INVALID)
                )
            self._reorder_for_pin()
            if not hosts:
                self._notify()
                return warnings, 0

            self._generation += 1
            generation = self._generation
            self.is_running = True
            self._stop_event.clear()
            valid_hosts = list(hosts)

        self._notify()
        self._loop_thread = threading.Thread(
            target=self._run_loop,
            args=(valid_hosts, generation),
            name="pinginfo-loop",
            daemon=True,
        )
        self._loop_thread.start()
        return warnings, len(valid_hosts)

    def start_async(
        self,
        hosts_text: str,
        on_done: Callable[[list[str], int, str | None], None] | None = None,
    ) -> None:
        self.stop()

        def _worker() -> None:
            err: str | None = None
            warnings: list[str] = []
            count = 0
            try:
                warnings, count = self.start(hosts_text)
            except Exception as exc:
                err = str(exc)
            if on_done:
                on_done(warnings, count, err)

        threading.Thread(target=_worker, name="pinginfo-start", daemon=True).start()

    def stop(self) -> None:
        self._stop_event.set()
        with self._lock:
            self.is_running = False
        self._notify()

    def clear(self) -> None:
        self.stop()
        if self._loop_thread and self._loop_thread.is_alive():
            self._loop_thread.join(timeout=2.0)
        with self._lock:
            self.results = []
            self._row_index.clear()
            self._ipv6_by_name.clear()
            self._downgraded.clear()
        self._notify()

    def toggle_pin_online_to_top(self) -> None:
        with self._lock:
            self.pin_online_to_top = not self.pin_online_to_top
            if self.pin_online_to_top:
                self._reorder_for_pin()
        self._notify()

    def set_sort(self, key: str) -> None:
        with self._lock:
            if self._sort_key == key:
                self._sort_reverse = not self._sort_reverse
            else:
                self._sort_key = key
                self._sort_reverse = False
            self._apply_sort()
        self._notify()

    def snapshot(self) -> list[PingResult]:
        with self._lock:
            return list(self.results)

    def running_count(self) -> int:
        with self._lock:
            return sum(1 for r in self.results if not r.is_invalid)

    def csv_content(self) -> str:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(
            [
                "Hostname",
                "Family",
                "ResolvedIP",
                "Status",
                "Sent",
                "Received",
                "Lost",
                "Loss%",
                "LastLatency",
                "AvgLatency",
                "MinLatency",
                "MaxLatency",
                "Jitter",
                "TTL",
                "LastError",
            ]
        )
        with self._lock:
            rows = list(self.results)
        for r in rows:
            loss = f"{r.packet_loss:.1f}%" if r.sent > 0 else "0.0%"
            lat = f"{r.last_latency:.2f}" if r.last_latency is not None else ""
            avg = f"{r.average_latency:.2f}" if r.average_latency is not None else ""
            mn = f"{r.min_latency:.2f}" if r.min_latency is not None else ""
            mx = f"{r.max_latency:.2f}" if r.max_latency is not None else ""
            jit = f"{r.jitter:.2f}" if r.jitter is not None else ""
            ttl = str(r.ttl) if r.ttl is not None else ""
            writer.writerow(
                [
                    r.hostname,
                    r.family or "",
                    r.resolved_ip or "",
                    r.status.value,
                    r.sent,
                    r.received,
                    r.lost,
                    loss,
                    lat,
                    avg,
                    mn,
                    mx,
                    jit,
                    ttl,
                    r.last_error or "",
                ]
            )
        return buf.getvalue()

    def export_csv(self, path: str) -> bool:
        try:
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write(self.csv_content())
            return True
        except OSError:
            return False

    @staticmethod
    def timestamped_name() -> str:
        return f"pinginfo_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    def run_once(self, hosts_text: str, rounds: int = 1) -> tuple[list[str], int]:
        warnings, count = self.start(hosts_text)
        if count <= 0:
            return warnings, count
        deadline = time.perf_counter() + max(8.0, (self.timeout + self.ping_interval) * max(1, rounds) + 15.0)
        while time.perf_counter() < deadline:
            with self._lock:
                done = all(r.sent >= rounds or r.is_invalid for r in self.results)
            if done:
                break
            time.sleep(0.05)
        self.stop()
        if self._loop_thread and self._loop_thread.is_alive():
            self._loop_thread.join(timeout=3.0)
        return warnings, count

    def _append_result(self, result: PingResult) -> None:
        self._row_index[result.hostname] = len(self.results)
        self.results.append(result)

    def _get(self, hostname: str) -> PingResult | None:
        idx = self._row_index.get(hostname)
        if idx is None or idx >= len(self.results):
            return None
        return self.results[idx]

    def _reorder_for_pin(self) -> None:
        if not self.pin_online_to_top:
            self._apply_sort()
            return
        online = [r for r in self.results if r.status == PingStatus.ONLINE]
        if not online or len(online) == len(self.results):
            self._apply_sort()
            return
        rest = [r for r in self.results if r.status != PingStatus.ONLINE]
        self.results = online + rest
        self._row_index = {r.hostname: i for i, r in enumerate(self.results)}

    def _sort_value(self, row: PingResult, key: str):
        mapping = {
            "status": row.status.value,
            "host": row.hostname,
            "family": row.family or "",
            "ip": row.resolved_ip or "",
            "sent": row.sent,
            "recv": row.received,
            "lost": row.lost,
            "loss": row.packet_loss,
            "last": row.last_latency if row.last_latency is not None else float("inf"),
            "avg": row.average_latency if row.average_latency is not None else float("inf"),
            "min": row.min_latency if row.min_latency is not None else float("inf"),
            "max": row.max_latency if row.max_latency is not None else float("inf"),
            "jitter": row.jitter if row.jitter is not None else float("inf"),
            "ttl": row.ttl if row.ttl is not None else -1,
            "error": row.last_error or "",
        }
        return mapping.get(key, row.hostname)

    def _apply_sort(self) -> None:
        if self.pin_online_to_top:
            return
        key = self._sort_key
        reverse = self._sort_reverse
        self.results.sort(key=lambda r: self._sort_value(r, key), reverse=reverse)
        self._row_index = {r.hostname: i for i, r in enumerate(self.results)}

    def _run_loop(self, hosts: list[str], generation: int) -> None:
        resolved = self._resolver.resolve_all(hosts, self.resolve_hostnames_via_ipv6)
        if self._stop_event.is_set():
            return
        with self._lock:
            for item in resolved:
                row = self._get(item.hostname)
                if row is None:
                    continue
                row.family = item.family
                row.resolved_ip = item.display_ip
                if not item.is_resolved:
                    row.record_ping(
                        False,
                        None,
                        item.error or "DNS failed",
                        self.offline_failure_threshold,
                    )
                elif item.family == "IPv6" and _literal_family(item.hostname) is None:
                    self._ipv6_by_name.add(item.hostname)
            self._reorder_for_pin()
        self._notify()

        send_pause = 1.0 / self.send_rate if self.send_rate > 0 else 0.0
        while not self._stop_event.is_set():
            started = time.perf_counter()
            current: list[ResolvedHost] = []
            with self._lock:
                if not self.is_running or self._generation != generation:
                    break
                for host in hosts:
                    row = self._get(host)
                    if row is None or row.is_invalid or not row.family or not row.resolved_ip:
                        continue
                    current.append(
                        ResolvedHost(host, row.family, row.resolved_ip, row.last_error)
                    )
            if current and not self._stop_event.is_set():
                chunk_size = 2048
                for i in range(0, len(current), chunk_size):
                    if self._stop_event.is_set():
                        break
                    self._probe_batch(current[i : i + chunk_size], generation, send_pause)
                    self._notify()
            else:
                self._notify()
            elapsed = time.perf_counter() - started
            remaining = self.ping_interval - elapsed
            if remaining > 0 and self._stop_event.wait(remaining):
                break
        with self._lock:
            if self._generation == generation:
                self.is_running = False
        self._notify()

    def _probe_batch(
        self,
        current: list[ResolvedHost],
        generation: int,
        send_pause: float,
    ) -> None:
        pairs = [(t.display_ip, t.family) for t in current if t.display_ip and t.family]
        replies = ping_many(pairs, self.timeout, send_pause=send_pause)
        by_ip: dict[str, list[ResolvedHost]] = {}
        for target in current:
            if target.display_ip:
                by_ip.setdefault(target.display_ip, []).append(target)
        downgrade_hosts: list[str] = []
        with self._lock:
            if not self.is_running or self._generation != generation:
                return
            for ip, targets in by_ip.items():
                reply = replies.get(ip) or PingReply(False, error="Request timeout")
                for target in targets:
                    row = self._get(target.hostname)
                    if row is None:
                        continue
                    row.record_ping(
                        reply.ok,
                        reply.rtt_ms,
                        reply.error,
                        self.offline_failure_threshold,
                        ttl=reply.ttl,
                    )
                    if not reply.ok and self._should_downgrade(
                        target.hostname, row.consecutive_failures, reply.error
                    ):
                        downgrade_hosts.append(target.hostname)
            self._reorder_for_pin()
        for hostname in downgrade_hosts:
            self._downgrade_to_ipv4(hostname)

    def _should_downgrade(self, hostname: str, failures: int, error: str | None) -> bool:
        if not self.resolve_hostnames_via_ipv6:
            return False
        if hostname not in self._ipv6_by_name or hostname in self._downgraded:
            return False
        if error and self._is_hard_ipv6_failure(error):
            return True
        return failures >= self.ipv6_fallback_threshold

    @staticmethod
    def _is_hard_ipv6_failure(error: str) -> bool:
        lower = error.lower()
        markers = (
            "no route to host",
            "network is unreachable",
            "destination host unreachable",
            "cannot assign requested address",
            "invalid argument",
            "permission denied",
        )
        return any(m in lower for m in markers)

    def _downgrade_to_ipv4(self, hostname: str) -> None:
        with self._lock:
            self._downgraded.add(hostname)
            self._ipv6_by_name.discard(hostname)
        resolved = self._resolver.resolve(hostname, prefer_ipv6=False)
        if resolved.family != "IPv4" or not resolved.display_ip:
            return
        with self._lock:
            row = self._get(hostname)
            if row is None or not self.is_running:
                return
            row.family = resolved.family
            row.resolved_ip = resolved.display_ip
            row.reset()
