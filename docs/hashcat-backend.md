# hashcat 引擎接口

GUI 不直接依赖某个固定的 hashcat 可执行文件，而是通过
`core/hashcat_backend.py` 中的 `HashcatBackend` 协议调用引擎。

## 协议

```python
class HashcatBackend(Protocol):
    name: str

    def start(self, config: AttackConfig, outfile: Path) -> None: ...
    def stop(self) -> None: ...
    def join(self, timeout: float | None = None) -> None: ...
```

`start()` 是非阻塞的：实现可以在后台线程或远程服务中运行。

## 事件

后端把事件放入构造时传入的 `queue.Queue`：

| 事件 | payload | 说明 |
| --- | --- | --- |
| `command` | `list[str]` | 本次执行的命令 |
| `log` | `str` | 一行日志 |
| `status` | `StatusSnapshot` | 进度、速度、ETA |
| `found` | `str` | 找到的密码 |
| `done` | `CrackResult` | 任务结束 |

## 本地实现

`LocalHashcatBackend` 使用 `HashcatRunner` 启动 `hashcat.exe`，并自动：

- 设置工作目录；
- 使用绝对路径传入哈希、字典和输出文件；
- 关闭 hashcat potfile / restore / logfile，避免污染运行时目录；
- 在停止时终止子进程。

## 远程实现示例

```python
class RemoteHashcatBackend:
    name = "remote"

    def __init__(self, endpoint, events, token):
        self.endpoint = endpoint
        self.events = events
        self.token = token

    def start(self, config, outfile):
        # 调用你的 HTTP 服务；通过 events.put(...) 回传状态
        ...

    def stop(self):
        ...

    def join(self, timeout=None):
        ...
```

远程实现需要自行处理认证、任务隔离和结果文件下载。

## 配置 hashcat

项目不提交 `runtime/` 和 hashcat 二进制。任选一种：

1. 运行 `scripts/setup_hashcat.ps1 -Source <hashcat 目录>`；
2. 把 hashcat 放到 `runtime/hashcat`；
3. 在 GUI 右上角“设置”里指定 `hashcat.exe` 路径。

`data/`、`runtime/`、`*.hash`、`*.pot` 等均已在 `.gitignore` 中排除。
