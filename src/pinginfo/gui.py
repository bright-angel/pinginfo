from __future__ import annotations

import json
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .engine import PingEngine
from .expander import MAX_EXPAND, format_hosts, preview_token, split_input
from .models import PingStatus

SAMPLE = """8.8.8.8
1.1.1.1
223.5.5.5
www.baidu.com
192.168.1.1-20
192.168.0.0/30
10.0.0.1-10.0.0.5
192.168.1.*
2001:4860:4860::8888
::1"""

COLUMNS = (
    ("status", "状态", 72, "w"),
    ("host", "主机名 / IP", 220, "w"),
    ("family", "协议族", 60, "w"),
    ("ip", "解析 IP", 200, "w"),
    ("sent", "已发送", 64, "e"),
    ("recv", "已接收", 64, "e"),
    ("lost", "丢包数", 64, "e"),
    ("loss", "丢包率 %", 80, "e"),
    ("last", "当前 (ms)", 80, "e"),
    ("avg", "平均 (ms)", 80, "e"),
    ("min", "最小 (ms)", 80, "e"),
    ("max", "最大 (ms)", 80, "e"),
    ("jitter", "抖动 (ms)", 80, "e"),
    ("ttl", "TTL", 48, "e"),
    ("error", "错误", 220, "w"),
)

CONFIG_PATH = Path.home() / ".pinginfo.json"
MAX_DISPLAY = 2000
PAGE_SIZE = 400


class PingInfoApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("pinginfo")
        self.root.minsize(980, 560)
        self.root.geometry("1280x720")

        self.engine = PingEngine(on_update=self._schedule_refresh)
        self._dirty = False
        self._last_redraw = 0.0
        self._starting = False
        self._page = 0
        self._filtered: list = []
        self._sort_key = "status"

        self._build_style()
        self._build_input()
        self._build_toolbar()
        self._build_table()
        self._build_statusbar()
        self._load_prefs()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._poll()

    def _build_style(self) -> None:
        style = ttk.Style(self.root)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure(
            "Treeview",
            rowheight=24,
            font=("Menlo", 10) if self._has_font("Menlo") else ("Consolas", 10),
        )
        style.configure(
            "Treeview.Heading",
            font=("PingFang SC", 10) if self._has_font("PingFang SC") else ("sans-serif", 10),
        )
        style.configure("Start.TButton", foreground="white", background="#2e7d32")
        style.map("Start.TButton", background=[("active", "#1b5e20")])
        style.configure("Stop.TButton", foreground="white", background="#c62828")
        style.map("Stop.TButton", background=[("active", "#8e0000")])

    @staticmethod
    def _has_font(name: str) -> bool:
        try:
            import tkinter.font as tkfont

            return name in tkfont.families()
        except tk.TclError:
            return False

    def _build_input(self) -> None:
        frame = ttk.Frame(self.root, padding=(12, 10, 12, 6))
        frame.pack(fill=tk.X)
        top = ttk.Frame(frame)
        top.pack(fill=tk.X)
        ttk.Label(top, text="主机地址（每行一个，或用逗号分隔；支持网段 / IP 范围 / 通配符）").pack(
            side=tk.LEFT
        )
        ttk.Button(top, text="格式化去重", command=self._format_input).pack(side=tk.RIGHT)

        wrap = ttk.Frame(frame)
        wrap.pack(fill=tk.X, pady=(6, 0))
        scroll = ttk.Scrollbar(wrap)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.input = tk.Text(
            wrap,
            height=7,
            font=("Menlo", 11) if self._has_font("Menlo") else ("Consolas", 11),
            undo=True,
            wrap=tk.NONE,
        )
        self.input.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.input.configure(yscrollcommand=scroll.set)
        scroll.configure(command=self.input.yview)
        self.input.insert("1.0", SAMPLE)

    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self.root, padding=(12, 6, 12, 6))
        bar.pack(fill=tk.X)

        self.start_btn = ttk.Button(bar, text="开始", style="Start.TButton", command=self._toggle)
        self.start_btn.pack(side=tk.LEFT)
        ttk.Button(bar, text="清空", command=self._clear).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(bar, text="Export CSV", command=self._export).pack(side=tk.LEFT, padx=(8, 0))

        ttk.Separator(bar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=12, pady=2)

        ttk.Label(bar, text="间隔:").pack(side=tk.LEFT)
        self.interval_var = tk.StringVar(value="1秒")
        interval = ttk.Combobox(
            bar,
            textvariable=self.interval_var,
            values=("1秒", "2秒", "5秒", "10秒"),
            width=8,
            state="readonly",
        )
        interval.pack(side=tk.LEFT, padx=(6, 0))
        interval.bind("<<ComboboxSelected>>", lambda _e: self._apply_interval())

        ttk.Label(bar, text="超时:").pack(side=tk.LEFT, padx=(12, 0))
        self.timeout_var = tk.StringVar(value="1秒")
        timeout = ttk.Combobox(
            bar,
            textvariable=self.timeout_var,
            values=("0.5秒", "1秒", "2秒", "3秒"),
            width=8,
            state="readonly",
        )
        timeout.pack(side=tk.LEFT, padx=(6, 0))

        self.ipv6_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="域名使用 IPv6 解析", variable=self.ipv6_var).pack(
            side=tk.LEFT, padx=(16, 0)
        )

        self.filter_var = tk.StringVar(value="全部")
        ttk.Label(bar, text="筛选:").pack(side=tk.LEFT, padx=(16, 0))
        filt = ttk.Combobox(
            bar,
            textvariable=self.filter_var,
            values=("全部", "仅在线", "仅离线", "仅非法"),
            width=8,
            state="readonly",
        )
        filt.pack(side=tk.LEFT, padx=(6, 0))
        filt.bind("<<ComboboxSelected>>", lambda _e: self._on_filter_change())

        ttk.Button(bar, text="上一页", command=self._prev_page).pack(side=tk.LEFT, padx=(12, 0))
        ttk.Button(bar, text="下一页", command=self._next_page).pack(side=tk.LEFT, padx=(4, 0))

        self.status_var = tk.StringVar(value="")
        ttk.Label(bar, textvariable=self.status_var, foreground="#666").pack(side=tk.RIGHT)

    def _build_table(self) -> None:
        wrap = ttk.Frame(self.root, padding=(12, 0, 12, 0))
        wrap.pack(fill=tk.BOTH, expand=True)
        yscroll = ttk.Scrollbar(wrap)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)
        xscroll = ttk.Scrollbar(wrap, orient=tk.HORIZONTAL)
        xscroll.pack(side=tk.BOTTOM, fill=tk.X)

        self.tree = ttk.Treeview(
            wrap,
            columns=[c[0] for c in COLUMNS],
            show="headings",
            selectmode="extended",
        )
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        yscroll.configure(command=self.tree.yview)
        xscroll.configure(command=self.tree.xview)

        for key, title, width, anchor in COLUMNS:
            self.tree.heading(key, text=title, command=self._on_heading(key))
            self.tree.column(
                key,
                width=width,
                minwidth=48,
                anchor=anchor,
                stretch=(key in {"host", "ip", "error"}),
            )

        self.tree.tag_configure("online", foreground="#1b8f3a")
        self.tree.tag_configure("offline", foreground="#c62828")
        self.tree.tag_configure("waiting", foreground="#757575")
        self.tree.tag_configure("invalid", foreground="#ef6c00")
        self.tree.tag_configure("resolving", foreground="#546e7a")
        self.tree.heading("status", text="↑ 状态")

    def _build_statusbar(self) -> None:
        bar = ttk.Frame(self.root, padding=(12, 4, 12, 8))
        bar.pack(fill=tk.X)
        self.summary_var = tk.StringVar(
            value="ICMP 直发，不调用 ping 命令。支持 IPv4 / IPv6 / 域名 / CIDR / 范围 / 通配符。"
        )
        ttk.Label(bar, textvariable=self.summary_var, foreground="#555").pack(side=tk.LEFT)

    def _on_heading(self, key: str):
        def _handler() -> None:
            if key == "status":
                self.engine.toggle_pin_online_to_top()
                pin = "↑ 状态" if self.engine.pin_online_to_top else "状态"
                self.tree.heading("status", text=pin)
            else:
                self.engine.set_sort(key)
                self._sort_key = key
            self._redraw(force=True)

        return _handler

    def _apply_interval(self) -> None:
        mapping = {"1秒": 1.0, "2秒": 2.0, "5秒": 5.0, "10秒": 10.0}
        self.engine.ping_interval = mapping.get(self.interval_var.get(), 1.0)

    def _apply_timeout(self) -> None:
        mapping = {"0.5秒": 0.5, "1秒": 1.0, "2秒": 2.0, "3秒": 3.0}
        self.engine.timeout = mapping.get(self.timeout_var.get(), 1.0)

    def _format_input(self) -> None:
        text = self.input.get("1.0", tk.END)
        self.input.delete("1.0", tk.END)
        self.input.insert("1.0", format_hosts(text))

    def _toggle(self) -> None:
        if self._starting:
            return
        if self.engine.is_running:
            self.engine.stop()
            self.start_btn.configure(text="开始", style="Start.TButton")
            self.status_var.set("已停止")
            return
        self._start()

    def _start(self) -> None:
        text = self.input.get("1.0", tk.END)
        tokens = split_input(text)
        if not tokens:
            messagebox.showinfo("pinginfo", "请先输入主机、网段、范围或通配符。")
            return

        total = 0
        errors: list[str] = []
        for token in tokens:
            spec = preview_token(token)
            if spec.error:
                errors.append(spec.error)
            else:
                total += spec.count
        if errors and total == 0:
            messagebox.showerror("无法解析", "\n".join(errors[:8]))
            return
        if total > MAX_EXPAND:
            messagebox.showerror(
                "目标过多",
                f"展开后约 {total} 个地址，超过上限 {MAX_EXPAND}。请缩小网段或范围。",
            )
            return
        if total >= 4096:
            ok = messagebox.askokcancel(
                "大网段确认",
                f"将并发探测 {total} 个地址（单套接字批量 ICMP，不调用 ping 命令）。\n"
                "表格分页显示，是否继续？",
            )
            if not ok:
                return

        self._apply_interval()
        self._apply_timeout()
        self.engine.resolve_hostnames_via_ipv6 = bool(self.ipv6_var.get())
        self._starting = True
        self.start_btn.configure(state=tk.DISABLED)
        self.status_var.set("正在展开目标...")

        def _done(warnings: list[str], count: int, err: str | None) -> None:
            self.root.after(0, lambda: self._start_finished(warnings, count, err))

        self.engine.start_async(text, on_done=_done)

    def _start_finished(self, warnings: list[str], count: int, err: str | None) -> None:
        self._starting = False
        self.start_btn.configure(state=tk.NORMAL)
        self._redraw(force=True)
        if err:
            messagebox.showerror("启动失败", err)
            self.start_btn.configure(text="开始", style="Start.TButton")
            self.status_var.set("")
            return
        if count == 0:
            if warnings:
                messagebox.showwarning("无法展开", "\n".join(warnings[:8]))
            elif not self.engine.snapshot():
                messagebox.showinfo("pinginfo", "没有可探测的目标。")
            self.start_btn.configure(text="开始", style="Start.TButton")
            return
        self.start_btn.configure(text="停止", style="Stop.TButton")
        extra = f"；{warnings[0]}" if warnings else ""
        self.status_var.set(f"正在 ping {count} 个主机...{extra}")

    def _clear(self) -> None:
        self.engine.clear()
        self.input.delete("1.0", tk.END)
        self.start_btn.configure(text="开始", style="Start.TButton")
        self.status_var.set("")
        self.summary_var.set("已清空。")
        self._page = 0
        self._redraw(force=True)

    def _export(self) -> None:
        if not self.engine.snapshot():
            messagebox.showinfo("pinginfo", "没有可导出的结果。")
            return
        path = filedialog.asksaveasfilename(
            title="导出 CSV",
            defaultextension=".csv",
            initialfile=self.engine.timestamped_name(),
            filetypes=[("CSV", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        if not self.engine.export_csv(path):
            messagebox.showerror("导出失败", "无法写入所选文件。")
            return
        self.status_var.set(f"已导出 {path}")

    def _schedule_refresh(self) -> None:
        self._dirty = True

    def _poll(self) -> None:
        if self._dirty:
            self._dirty = False
            self._redraw()
        running = self.engine.is_running
        if running and not self._starting:
            self.start_btn.configure(text="停止", style="Stop.TButton")
            self.status_var.set(f"正在 ping {self.engine.running_count()} 个主机...")
        elif self.start_btn["text"] == "停止" and not self._starting:
            self.start_btn.configure(text="开始", style="Start.TButton")
            if self.engine.snapshot():
                self.status_var.set("已停止")
        self.root.after(200, self._poll)

    def _on_filter_change(self) -> None:
        self._page = 0
        self._redraw(force=True)

    def _prev_page(self) -> None:
        if self._page > 0:
            self._page -= 1
            self._redraw(force=True)

    def _next_page(self) -> None:
        total = len(self._filtered)
        page_size = self._page_size(total)
        if (self._page + 1) * page_size < total:
            self._page += 1
            self._redraw(force=True)

    @staticmethod
    def _page_size(total: int) -> int:
        if total <= MAX_DISPLAY:
            return max(total, 1)
        return PAGE_SIZE

    def _redraw(self, force: bool = False) -> None:
        all_rows = self.engine.snapshot()
        now = time.monotonic()
        if not force and len(all_rows) > 1500 and now - self._last_redraw < 1.0:
            self._dirty = True
            return
        self._last_redraw = now
        mode = self.filter_var.get()
        if mode == "仅在线":
            rows = [r for r in all_rows if r.status == PingStatus.ONLINE]
        elif mode == "仅离线":
            rows = [r for r in all_rows if r.status == PingStatus.OFFLINE]
        elif mode == "仅非法":
            rows = [r for r in all_rows if r.status == PingStatus.INVALID]
        else:
            rows = all_rows
        self._filtered = rows
        page_size = self._page_size(len(rows))
        max_page = max(0, (len(rows) - 1) // page_size) if rows else 0
        if self._page > max_page:
            self._page = max_page
        start = self._page * page_size
        view = rows[start : start + page_size]
        online = sum(1 for r in all_rows if r.status == PingStatus.ONLINE)
        offline = sum(1 for r in all_rows if r.status == PingStatus.OFFLINE)
        invalid = sum(1 for r in all_rows if r.status == PingStatus.INVALID)
        page_info = ""
        if len(rows) > MAX_DISPLAY:
            page_info = f"  |  第 {self._page + 1}/{max_page + 1} 页"
        self.summary_var.set(
            f"共 {len(all_rows)} 项，显示 {len(view)}/{len(rows)} 行  |  "
            f"在线 {online}  离线 {offline}  非法 {invalid}{page_info}"
        )

        children = self.tree.get_children()
        if force or len(children) != len(view):
            self.tree.delete(*children)
            for idx, result in enumerate(view):
                values = result.as_row()
                tag = result.status.value
                self.tree.insert("", tk.END, iid=str(idx), values=values, tags=(tag,))
            return
        for idx, result in enumerate(view):
            values = result.as_row()
            iid = str(idx)
            current = self.tree.item(iid, "values")
            if tuple(current) != values:
                self.tree.item(iid, values=values, tags=(result.status.value,))

    def _load_prefs(self) -> None:
        try:
            data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        hosts = data.get("hosts")
        if isinstance(hosts, str) and hosts.strip():
            self.input.delete("1.0", tk.END)
            self.input.insert("1.0", hosts)
        interval = data.get("interval")
        if interval in ("1秒", "2秒", "5秒", "10秒"):
            self.interval_var.set(interval)
            self._apply_interval()
        timeout = data.get("timeout")
        if timeout in ("0.5秒", "1秒", "2秒", "3秒"):
            self.timeout_var.set(timeout)
            self._apply_timeout()
        if isinstance(data.get("ipv6"), bool):
            self.ipv6_var.set(data["ipv6"])
        filt = data.get("filter")
        if filt in ("全部", "仅在线", "仅离线", "仅非法"):
            self.filter_var.set(filt)

    def _save_prefs(self) -> None:
        data = {
            "hosts": self.input.get("1.0", tk.END).rstrip("\n"),
            "interval": self.interval_var.get(),
            "timeout": self.timeout_var.get(),
            "ipv6": bool(self.ipv6_var.get()),
            "filter": self.filter_var.get(),
        }
        try:
            CONFIG_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError:
            pass

    def _on_close(self) -> None:
        self._save_prefs()
        self.engine.stop()
        self.root.destroy()


def run() -> None:
    root = tk.Tk()
    PingInfoApp(root)
    root.mainloop()
