from __future__ import annotations

import argparse
import sys

from . import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pinginfo",
        description="图形化批量 Ping 工具（ICMP 直发，不调用 ping 命令）",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"pinginfo {__version__}",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="无界面探测一轮后退出",
    )
    parser.add_argument(
        "--csv",
        metavar="PATH",
        help="将结果写入 CSV（可与 --once 联用）",
    )
    parser.add_argument(
        "-t",
        "--targets",
        metavar="TEXT",
        help="探测目标，多行或逗号分隔；缺省时从 stdin 读取",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="探测间隔秒数（默认 1）",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="单轮超时秒数（默认 1）",
    )
    parser.add_argument(
        "--ipv6",
        action="store_true",
        help="域名优先解析 AAAA",
    )
    parser.add_argument(
        "--rounds",
        type=int,
        default=1,
        help="--once 时探测轮数（默认 1）",
    )
    return parser


def _read_targets(args: argparse.Namespace) -> str:
    if args.targets:
        return args.targets
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return ""


def _run_once(args: argparse.Namespace) -> int:
    from .engine import PingEngine

    text = _read_targets(args)
    if not text.strip():
        print("请通过 --targets 或 stdin 提供主机列表。", file=sys.stderr)
        return 2
    engine = PingEngine()
    engine.ping_interval = max(0.2, float(args.interval))
    engine.timeout = max(0.2, float(args.timeout))
    engine.resolve_hostnames_via_ipv6 = bool(args.ipv6)
    warnings, count = engine.run_once(text, rounds=max(1, int(args.rounds)))
    for warning in warnings:
        print(warning, file=sys.stderr)
    if args.csv:
        if not engine.export_csv(args.csv):
            print(f"无法写入 {args.csv}", file=sys.stderr)
            return 1
        print(args.csv)
    else:
        sys.stdout.write(engine.csv_content())
    if count <= 0:
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    if args.once or args.csv:
        return _run_once(args)
    from .gui import run

    run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
