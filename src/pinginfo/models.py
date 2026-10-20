from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class PingStatus(str, Enum):
    WAITING = "waiting"
    ONLINE = "online"
    OFFLINE = "offline"
    INVALID = "invalid"
    RESOLVING = "resolving"

    @property
    def label(self) -> str:
        return {
            PingStatus.WAITING: "等待中",
            PingStatus.ONLINE: "在线",
            PingStatus.OFFLINE: "离线",
            PingStatus.INVALID: "非法",
            PingStatus.RESOLVING: "解析中",
        }[self]


INVALID_SUFFIX = " (非法)"


@dataclass
class PingResult:
    hostname: str
    is_invalid: bool = False
    family: str | None = None
    resolved_ip: str | None = None
    status: PingStatus = PingStatus.WAITING
    sent: int = 0
    received: int = 0
    last_latency: float | None = None
    average_latency: float | None = None
    min_latency: float | None = None
    max_latency: float | None = None
    jitter: float | None = None
    ttl: int | None = None
    last_error: str | None = None
    consecutive_failures: int = 0
    _latency_sum: float = 0.0
    _latency_count: int = 0
    _prev_latency: float | None = None

    @property
    def packet_loss(self) -> float:
        if self.sent <= 0:
            return 0.0
        return (self.sent - self.received) / self.sent * 100.0

    @property
    def lost(self) -> int:
        return max(0, self.sent - self.received)

    def record_ping(
        self,
        success: bool,
        latency: float | None,
        error: str | None,
        offline_threshold: int = 2,
        ttl: int | None = None,
    ) -> None:
        self.sent += 1
        if success and latency is not None:
            self.received += 1
            self.last_latency = latency
            self.last_error = None
            self.consecutive_failures = 0
            if ttl is not None:
                self.ttl = ttl
            self._latency_sum += latency
            self._latency_count += 1
            self.average_latency = self._latency_sum / self._latency_count
            if self.min_latency is None or latency < self.min_latency:
                self.min_latency = latency
            if self.max_latency is None or latency > self.max_latency:
                self.max_latency = latency
            if self._prev_latency is not None:
                delta = abs(latency - self._prev_latency)
                if self.jitter is None:
                    self.jitter = delta
                else:
                    self.jitter += (delta - self.jitter) / 16.0
            self._prev_latency = latency
            self.status = PingStatus.ONLINE
        else:
            self.last_latency = None
            self.last_error = error
            self.consecutive_failures += 1
            if self.consecutive_failures >= offline_threshold:
                self.status = PingStatus.OFFLINE

    def reset(self) -> None:
        self.status = PingStatus.WAITING
        self.sent = 0
        self.received = 0
        self.last_latency = None
        self.average_latency = None
        self.min_latency = None
        self.max_latency = None
        self.jitter = None
        self.ttl = None
        self.last_error = None
        self.consecutive_failures = 0
        self._latency_sum = 0.0
        self._latency_count = 0
        self._prev_latency = None

    def as_row(self) -> tuple:
        loss = f"{self.packet_loss:.1f}%"
        last = f"{self.last_latency:.2f}" if self.last_latency is not None else "-"
        avg = f"{self.average_latency:.2f}" if self.average_latency is not None else "-"
        mn = f"{self.min_latency:.2f}" if self.min_latency is not None else "-"
        mx = f"{self.max_latency:.2f}" if self.max_latency is not None else "-"
        jit = f"{self.jitter:.2f}" if self.jitter is not None else "-"
        ttl = str(self.ttl) if self.ttl is not None else "-"
        return (
            self.status.label,
            self.hostname,
            self.family or "-",
            self.resolved_ip or "-",
            str(self.sent),
            str(self.received),
            str(self.lost),
            loss,
            last,
            avg,
            mn,
            mx,
            jit,
            ttl,
            self.last_error or "-",
        )
