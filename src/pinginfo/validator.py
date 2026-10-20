from __future__ import annotations

import ipaddress
import re

_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_ZONE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def is_ipv4(text: str) -> bool:
    parts = text.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part or len(part) > 3 or not part.isdigit():
            return False
        if len(part) > 1 and part[0] == "0":
            return False
        value = int(part)
        if value > 255:
            return False
    return True


def _allows_zone(addr: ipaddress.IPv6Address) -> bool:
    return addr.is_link_local or addr.is_multicast or addr.is_loopback or addr.is_site_local


def parse_ipv6(text: str) -> tuple[ipaddress.IPv6Address, str | None] | None:
    zone: str | None = None
    address = text
    if "%" in text:
        address, zone = text.split("%", 1)
        if not _ZONE_RE.fullmatch(zone):
            return None
    if "." in address:
        colon = address.rfind(":")
        if colon < 0 or not is_ipv4(address[colon + 1 :]):
            return None
    try:
        addr = ipaddress.IPv6Address(address)
    except ValueError:
        return None
    if zone is not None and not _allows_zone(addr):
        return None
    return addr, zone


def is_ipv6(text: str) -> bool:
    return parse_ipv6(text) is not None


def is_hostname(text: str) -> bool:
    name = text[:-1] if text.endswith(".") else text
    if not name or len(text) > 253:
        return False
    labels = name.split(".")
    if not labels:
        return False
    for label in labels:
        if not (1 <= len(label) <= 63) or not _LABEL_RE.fullmatch(label):
            return False
    if labels[-1].isdigit():
        return False
    return True


def is_valid_host(text: str) -> bool:
    trimmed = text.strip()
    if not trimmed or len(trimmed) > 253:
        return False
    if is_ipv4(trimmed) or is_ipv6(trimmed):
        return True
    if all(ch.isdigit() or ch == "." for ch in trimmed):
        return False
    return is_hostname(trimmed)


def literal_family(host: str) -> str | None:
    if is_ipv4(host):
        return "IPv4"
    parsed = parse_ipv6(host)
    if parsed is None:
        return None
    addr, _zone = parsed
    if addr.ipv4_mapped is not None:
        return "IPv4"
    return "IPv6"


def ipv4_mapped_string(host: str) -> str | None:
    parsed = parse_ipv6(host)
    if parsed is None:
        return None
    mapped = parsed[0].ipv4_mapped
    return str(mapped) if mapped is not None else None


def canonical_literal(host: str) -> str | None:
    if is_ipv4(host):
        return host
    parsed = parse_ipv6(host)
    if parsed is None:
        return None
    addr, zone = parsed
    mapped = addr.ipv4_mapped
    if mapped is not None:
        return str(mapped)
    base = str(addr)
    return f"{base}%{zone}" if zone else base


def dedupe_key(host: str) -> str:
    lowered = host.strip().lower()
    return canonical_literal(lowered) or lowered
