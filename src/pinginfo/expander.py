from __future__ import annotations

import ipaddress
import itertools
import re
from collections.abc import Iterator
from dataclasses import dataclass

from .validator import (
    canonical_literal,
    dedupe_key,
    is_hostname,
    is_ipv4,
    is_ipv6,
    is_valid_host,
)

MAX_EXPAND = 65536
IPV4_OCTET_RE = re.compile(r"^(?:\d{1,3}|\*|\d{1,3}-\d{1,3})$")
RANGE_SEP_RE = re.compile(r"\s*(?:-|~|to|TO)\s*")


class ExpandError(ValueError):
    pass


@dataclass(frozen=True)
class TargetSpec:
    original: str
    kind: str
    count: int
    error: str | None = None


def split_input(text: str) -> list[str]:
    tokens: list[str] = []
    for raw_line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "," in line or ";" in line or "|" in line:
            for part in re.split(r"[,;|]", line):
                item = part.strip()
                if item:
                    tokens.append(item)
        else:
            tokens.append(line)
    return tokens


def format_hosts(text: str) -> str:
    seen: set[str] = set()
    result: list[str] = []
    for token in split_input(text):
        key = dedupe_key(token)
        if key in seen:
            continue
        seen.add(key)
        result.append(token)
    return "\n".join(result)


def _ipv4_int(addr: str) -> int:
    return int(ipaddress.IPv4Address(addr))


def _check_count(count: int, original: str) -> None:
    if count <= 0:
        raise ExpandError(f"{original}: 展开结果为空")
    if count > MAX_EXPAND:
        raise ExpandError(
            f"{original}: 展开后共 {count} 个地址，超过上限 {MAX_EXPAND}。"
            "请缩小网段、范围或通配符。"
        )


def _parse_octet_token(token: str) -> list[int]:
    token = token.strip()
    if token == "*":
        return list(range(256))
    if "-" in token:
        left, right = token.split("-", 1)
        if not left.isdigit() or not right.isdigit():
            raise ExpandError(f"非法八位组范围: {token}")
        start, end = int(left), int(right)
        if not (0 <= start <= 255 and 0 <= end <= 255):
            raise ExpandError(f"八位组超出 0-255: {token}")
        if start > end:
            start, end = end, start
        return list(range(start, end + 1))
    if not token.isdigit():
        raise ExpandError(f"非法八位组: {token}")
    if len(token) > 1 and token[0] == "0":
        raise ExpandError(f"禁止前导零: {token}")
    value = int(token)
    if value > 255:
        raise ExpandError(f"八位组超出 0-255: {token}")
    return [value]


def _wildcard_octets(pattern: str) -> list[list[int]]:
    parts = pattern.split(".")
    if len(parts) != 4:
        raise ExpandError(f"IPv4 通配符必须是 4 段: {pattern}")
    return [_parse_octet_token(part) for part in parts]


def count_ipv4_wildcard(pattern: str) -> int:
    octets = _wildcard_octets(pattern)
    count = 1
    for group in octets:
        count *= len(group)
    _check_count(count, pattern)
    return count


def expand_ipv4_wildcard(pattern: str) -> list[str]:
    octets = _wildcard_octets(pattern)
    count = 1
    for group in octets:
        count *= len(group)
    _check_count(count, pattern)
    return [
        f"{a}.{b}.{c}.{d}"
        for a, b, c, d in itertools.product(*octets)
    ]


def _looks_like_ipv4_wildcard(text: str) -> bool:
    parts = text.split(".")
    if len(parts) != 4:
        return False
    has_wild = False
    for part in parts:
        if not IPV4_OCTET_RE.fullmatch(part):
            return False
        if part == "*" or "-" in part:
            has_wild = True
    return has_wild


def _ipv4_range_bounds(text: str) -> tuple[int, int] | tuple[str, int, int]:
    match = re.fullmatch(
        r"(\d{1,3}(?:\.\d{1,3}){3})\s*(?:-|~|to|TO)\s*(\d{1,3}(?:\.\d{1,3}){3})",
        text,
    )
    if match:
        start_s, end_s = match.group(1), match.group(2)
        if not is_ipv4(start_s) or not is_ipv4(end_s):
            raise ExpandError(f"非法 IPv4 范围: {text}")
        start, end = _ipv4_int(start_s), _ipv4_int(end_s)
        if start > end:
            start, end = end, start
        return start, end

    short = re.fullmatch(
        r"(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})\s*(?:-|~|to|TO)\s*(\d{1,3})",
        text,
    )
    if short:
        prefix, a, b = short.group(1), short.group(2), short.group(3)
        start_s, end_s = f"{prefix}.{a}", f"{prefix}.{b}"
        if not is_ipv4(start_s) or not is_ipv4(end_s):
            raise ExpandError(f"非法 IPv4 范围: {text}")
        start, end = int(a), int(b)
        if start > end:
            start, end = end, start
        return prefix, start, end

    raise ExpandError(f"无法解析 IPv4 范围: {text}")


def count_ipv4_range(text: str) -> int:
    bounds = _ipv4_range_bounds(text)
    if len(bounds) == 2:
        start, end = bounds
        count = end - start + 1
    else:
        _prefix, start, end = bounds
        count = end - start + 1
    _check_count(count, text)
    return count


def expand_ipv4_range(text: str) -> list[str]:
    bounds = _ipv4_range_bounds(text)
    if len(bounds) == 2:
        start, end = bounds
        count = end - start + 1
        _check_count(count, text)
        return [str(ipaddress.IPv4Address(i)) for i in range(start, end + 1)]
    prefix, start, end = bounds
    count = end - start + 1
    _check_count(count, text)
    return [f"{prefix}.{i}" for i in range(start, end + 1)]


def _looks_like_ipv4_range(text: str) -> bool:
    if re.fullmatch(
        r"\d{1,3}(?:\.\d{1,3}){3}\s*(?:-|~|to|TO)\s*\d{1,3}(?:\.\d{1,3}){3}",
        text,
    ):
        return True
    if re.fullmatch(
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*(?:-|~|to|TO)\s*\d{1,3}",
        text,
    ):
        return True
    return False


def _ipv6_range_ints(text: str) -> tuple[int, int]:
    parts = RANGE_SEP_RE.split(text)
    if len(parts) != 2:
        raise ExpandError(f"无法解析 IPv6 范围: {text}")
    start_s, end_s = parts[0].strip(), parts[1].strip()
    if not is_ipv6(start_s) or not is_ipv6(end_s):
        raise ExpandError(f"非法 IPv6 范围: {text}")
    start = int(ipaddress.IPv6Address(canonical_literal(start_s) or start_s))
    end = int(ipaddress.IPv6Address(canonical_literal(end_s) or end_s))
    if start > end:
        start, end = end, start
    return start, end


def count_ipv6_range(text: str) -> int:
    start, end = _ipv6_range_ints(text)
    count = end - start + 1
    _check_count(count, text)
    return count


def expand_ipv6_range(text: str) -> list[str]:
    start, end = _ipv6_range_ints(text)
    count = end - start + 1
    _check_count(count, text)
    return [str(ipaddress.IPv6Address(i)) for i in range(start, end + 1)]


def _looks_like_ipv6_range(text: str) -> bool:
    parts = RANGE_SEP_RE.split(text)
    if len(parts) != 2:
        return False
    return is_ipv6(parts[0].strip()) and is_ipv6(parts[1].strip())


def _cidr_usable(text: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, int]:
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise ExpandError(f"非法网段: {text}") from exc

    if isinstance(network, ipaddress.IPv4Network):
        usable = network.num_addresses if network.prefixlen >= 31 else max(0, network.num_addresses - 2)
        _check_count(usable, text)
        return network, usable

    if network.prefixlen < 112:
        raise ExpandError(
            f"{text}: IPv6 网段过长（/{network.prefixlen}），"
            f"仅支持前缀长度 >= 112（最多 {MAX_EXPAND} 个地址）。"
        )
    usable = network.num_addresses if network.prefixlen >= 127 else max(0, network.num_addresses - 2)
    if usable == 0:
        usable = network.num_addresses
    _check_count(usable, text)
    return network, usable


def count_cidr(text: str) -> int:
    _network, usable = _cidr_usable(text)
    return usable


def expand_cidr(text: str) -> list[str]:
    network, _usable = _cidr_usable(text)
    if isinstance(network, ipaddress.IPv4Network):
        hosts = list(network) if network.prefixlen >= 31 else list(network.hosts())
        return [str(h) for h in hosts]
    hosts = list(network.hosts()) if network.prefixlen < 128 else list(network)
    if not hosts:
        hosts = list(network)
    return [str(h) for h in hosts]


def _looks_like_cidr(text: str) -> bool:
    if "/" not in text:
        return False
    try:
        ipaddress.ip_network(text, strict=False)
        return True
    except ValueError:
        return False


def classify_token(token: str) -> str:
    text = token.strip()
    if _looks_like_cidr(text):
        return "cidr"
    if _looks_like_ipv4_wildcard(text):
        return "wildcard"
    if _looks_like_ipv4_range(text):
        return "v4range"
    if _looks_like_ipv6_range(text):
        return "v6range"
    if is_ipv4(text):
        return "ipv4"
    if is_ipv6(text):
        return "ipv6"
    if is_hostname(text):
        return "hostname"
    return "invalid"


def expand_token(token: str) -> list[str]:
    kind = classify_token(token)
    if kind == "cidr":
        return expand_cidr(token)
    if kind == "wildcard":
        return expand_ipv4_wildcard(token)
    if kind == "v4range":
        return expand_ipv4_range(token)
    if kind == "v6range":
        return expand_ipv6_range(token)
    if kind in {"ipv4", "ipv6", "hostname"}:
        return [token.strip()]
    raise ExpandError(f"无法识别的目标: {token}")


def count_token(token: str) -> int:
    kind = classify_token(token)
    if kind == "cidr":
        return count_cidr(token)
    if kind == "wildcard":
        return count_ipv4_wildcard(token)
    if kind == "v4range":
        return count_ipv4_range(token)
    if kind == "v6range":
        return count_ipv6_range(token)
    if kind in {"ipv4", "ipv6", "hostname"}:
        return 1
    raise ExpandError(f"无法识别的目标: {token}")


def preview_token(token: str) -> TargetSpec:
    kind = classify_token(token)
    try:
        return TargetSpec(original=token, kind=kind, count=count_token(token))
    except ExpandError as exc:
        return TargetSpec(original=token, kind=kind, count=0, error=str(exc))


def expand_all(text: str) -> tuple[list[str], list[str], list[str]]:
    """Return (valid_hosts, invalid_display_names, warnings)."""
    tokens = split_input(text)
    seen: set[str] = set()
    hosts: list[str] = []
    invalid: list[str] = []
    warnings: list[str] = []

    for token in tokens:
        kind = classify_token(token)
        if kind == "invalid":
            invalid.append(token)
            continue
        try:
            expanded = expand_token(token)
        except ExpandError as exc:
            warnings.append(str(exc))
            invalid.append(token)
            continue
        for host in expanded:
            if not is_valid_host(host) and classify_token(host) == "invalid":
                invalid.append(host)
                continue
            key = dedupe_key(host)
            if key in seen:
                continue
            seen.add(key)
            hosts.append(host)
    return hosts, invalid, warnings


def iter_expanded(text: str) -> Iterator[str]:
    hosts, _invalid, _warnings = expand_all(text)
    yield from hosts
