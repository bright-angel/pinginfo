# pinginfo

图形化批量 Ping 工具，。用 Python 标准库（tkinter + socket ICMP）实现，不调用系统 ping 命令。

## 功能

- 多行输入：IPv4、IPv6、域名、CIDR 网段、IP 范围、通配符
- 大网段并发探测：同一地址族共用一个 ICMP 套接字批量收发
- 实时表格：状态、协议族、解析 IP、发送/接收/丢包、最小/最大/平均延迟、抖动、TTL、错误
- 间隔 1s / 2s / 5s / 10s，可调超时；按设定间隔轮询
- 域名优先 AAAA 解析，IPv6 不通时回退 IPv4；链路本地 IPv6 保留 zone
- 格式化去重、列排序、在线置顶、CSV 导出、按状态筛选、大表分页
- 输入与选项写入 `~/.pinginfo.json`
- 无界面：`pinginfo --once --targets ... [--csv out.csv]`

## 输入示例

```
8.8.8.8
www.baidu.com
192.168.1.1-20
10.0.0.1-10.0.0.5
192.168.0.0/30
192.168.1.*
10.0.0.1-10
2001:4860:4860::8888
::1
```

单次展开上限 65536 个地址（例如 `/16` 或 `x.x.*.*`）。`/8`、`10.*.*.*`、过长的 IPv6 前缀会被拒绝。

## 安装（uv tool）

需要 [uv](https://docs.astral.sh/uv/) 和系统 tkinter（Debian/Ubuntu: `apt install python3-tk`）。

从当前仓库安装为独立工具：

```
uv tool install .
```

开发时用可编辑安装：

```
uv tool install --editable .
```

安装后执行：

```
pinginfo
```

无界面探测一轮并打印 CSV：

```
pinginfo --once --targets '8.8.8.8,1.1.1.1'
pinginfo --once --targets '192.168.1.0/30' --csv result.csv
```

从 Git 安装：

```
uv tool install git+https://github.com/<org>/pinginfo
```

临时运行、不写入工具目录：

```
uvx --from . pinginfo
```

升级 / 卸载：

```
uv tool upgrade pinginfo
uv tool uninstall pinginfo
```

## 开发

```
uv sync
uv run pinginfo
uv run python -m pinginfo --version
uv run python -m unittest discover -s tests -v
```

构建发行包：

```
uv build
```

产物在 `dist/`，可用 `uv tool install dist/pinginfo-1.0.0-py3-none-any.whl` 安装。

## ICMP 权限

ICMP 使用 `SOCK_DGRAM`（Linux ping 组）或 `SOCK_RAW`。若提示无法创建套接字，需要 `CAP_NET_RAW`，或把当前用户加入 `net.ipv4.ping_group_range`。
