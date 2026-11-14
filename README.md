# 压缩包密码破解器

一个用于**恢复自己有权访问的压缩包密码**的 Windows 图形界面，底层调用
[hashcat](https://hashcat.net/hashcat/) 8.0.0。

界面使用 Python + Tkinter，纯本地离线运行，不会上传压缩包、哈希或密码。

## 快速开始

1. 双击 `启动.bat`。
2. 点击“选择压缩包”，选择 `.zip` 或 `.rar`。
3. 选择“字典攻击”并指定密码字典（每行一个密码），或者使用“掩码攻击”。
   没有字典时，可以点“根据姓名 / 生日生成”快速生成专属字典。
4. 点击“开始破解”。

程序会自动完成：

- 识别压缩包格式；
- 提取 hashcat 需要的哈希；
- 自动选择正确的 hashcat 模式；
- 调用本机显卡破解；
- 显示实时进度、速度、预计剩余时间；
- 找到密码后复制到剪贴板并保存到 `data/results`。

## 从 GitHub 运行

hashcat 二进制**不提交到仓库**。克隆后准备一次即可：

```powershell
git clone <你的仓库地址>
cd <仓库目录>

# 方式一：从本地 hashcat 目录复制到 runtime/hashcat
powershell -ExecutionPolicy Bypass -File scripts/setup_hashcat.ps1 `
  -Source "D:\tools\hashcat-8.0.0"

# 方式二：不复制，启动后到“设置”里指定 hashcat.exe
python app.py
```

双击 `启动.bat` 也可以启动。

### 仓库不会包含

- `data/`：哈希、生成的字典、找到的密码；
- `runtime/`：hashcat 二进制和内核缓存；
- `*.hash`、`*.pot`、`*.log` 等运行产物。

这些路径都已写入 `.gitignore`。提交前可以运行：

```powershell
git status --short
```

确认没有 `data/` 或 `runtime/` 下的文件。

## 支持的格式

| 格式 | 加密方式 | hashcat 模式 |
| --- | --- | --- |
| ZIP | ZipCrypto（传统加密） | 17200 / 17210 |
| ZIP | WinZip AES-128 / 192 / 256 | 13600 |
| RAR | RAR3 `-p` / `-hp` | 23700 / 23800 / 12500 |
| RAR | RAR5 `-p` / `-hp` | 13000 |
| 7z | 需要已有 `$7z$` 哈希 | 11600 |

> hashcat 的 PKZIP 模式最多接受约 320 KB 密文，WinZip AES 模式约 8 MB 密文。
> 如果压缩包里单个加密文件超过这个大小，程序会提示选择更小的条目或重新打包。
> 这是 hashcat 解析器的限制，不是压缩包损坏。

### 关于 7z

hashcat 官方压缩包**不包含** 7z2hashcat 提取器，本项目也没有附带 Perl 运行时。
因此 7z 不能直接选择压缩包破解，需要：

1. 用 [7z2hashcat](https://github.com/philsmd/7z2hashcat) 生成 `$7z$...` 哈希文件；
2. 在界面点击“使用哈希文件”，选择该文件；
3. 再选择字典、掩码或暴力破解开始。

如果不需要保留 7z 格式，也可以先用 7-Zip 解压后重新打包成 ZIP 再破解。

## 攻击方式

### 字典攻击

每行一个候选密码。适合：

- 常见弱密码；
- rockyou 等泄漏字典；
- 自己整理的候选列表。

### 字典生成器

没有现成字典时，点击字典输入框下方的“**没有字典？根据姓名 / 生日生成 →**”。

填写（所有字段都可以留空）：

- 中文姓名，例如 `张三`；
- 拼音 / 英文，例如 `zhang san`（用空格分隔可自动生成 `zhang`、`san`、`zs`、`zhangsan` 等变体）；
- 生日：年、月、日；
- **常用字符串**：每行一条，行内不拆分。不同行会按任意顺序组合，并且会尝试
  大小写变体。例如输入三行 `zhang`、`san`、`1990`，会得到 `zhangsan`、
  `ZhangSan`、`san1990`、`1990zhang`、`zhang.san` 等组合。
  不超过 8 个英文字母的片段会尝试所有大小写组合；更长的片段使用全小写、
  全大写、首字母大写等常见形式，避免字典爆炸。

程序会组合出类似下面的候选：

```text
zhangsan1990
zhangsan19900101
zhangsan123
zhangsan!
19900101
zs1990
张三1990
zhang.san.1990
```

### 指定位置插入字符

在“指定位置插入字符（可选）”里可以添加规则：

| 位置 | 含义 |
| --- | --- |
| 开头 | 在候选密码最前面插入 |
| 结尾 | 在候选密码最后面插入 |
| 第 N 位后 | 在第 N 个字符之后插入 |

每条规则可以指定插入内容，以及数量范围，例如：

- 位置“结尾”、内容 `!`、数量 `1 至 3`：生成 `密码!`、`密码!!`、`密码!!!`；
- 位置“开头”、内容 `520`、数量 `1`：生成 `520密码`；
- 位置“第 2 位后”、内容 `@`、数量 `1`：在第二个字符后插入 `@`。

最多添加 4 条规则。多条规则既会单独生效，也会组合生成变体。
插入规则对所有基础候选生效，包括姓名、生日、常用字符串和内置弱密码。

默认还会加入常见弱密码、年份/月日变体、大小写变体、后缀 `123/!/@/520` 等。
生成数量通常几千到几万条，保存到 `data/dicts`，并自动填入字典攻击。

> 中文姓名会直接参与组合；程序本地运行、不联网，也不内置拼音库，
> 所以建议在“拼音 / 英文”里手动填写拼音（用空格分隔，例如 `zhang san`），
> 这样才能生成 `zhangsan1990`、`zs1990` 这类常见拼音组合。

### 掩码攻击

用占位符描述密码结构：

| 占位符 | 含义 |
| --- | --- |
| `?l` | 小写字母 |
| `?u` | 大写字母 |
| `?d` | 数字 |
| `?s` | 符号 |
| `?a` | 全部可打印字符 |
| `??` | 字面问号 |

例如：

- `?d?d?d?d?d?d`：6 位纯数字；
- `?l?l?l?l?l?l`：6 位小写字母；
- `hello?d?d?d`：`hello000` 到 `hello999`；
- `1?d?d?d?d?d?d?d?d?d?d`：11 位手机号。

小掩码（不超过 100 万条）会自动展开成临时字典，以绕开部分 Intel
核显驱动的掩码内核自检问题。大掩码仍使用 hashcat 原生掩码；如果提示
“内核自检失败”，请更新显卡驱动或改用字典攻击。

### 暴力破解

不需要字典，也不需要手写掩码。只需选择：

- 字符集：数字、小写、字母+数字、全部可打印字符；
- 最小长度、最大长度（1–12 位）。

程序会从最短长度开始，逐位遍历到最大长度。候选密码由界面生成后通过
stdin 交给 hashcat，因此不依赖 hashcat 的掩码内核，Intel 核显也能用。

纯暴力的候选数量按指数增长，例如 94 个字符、6 位约有 `6.97e11` 个候选；
ZIP AES / RAR5 本身只有每秒几到几百次，实际可能需要数年。它只适合很短
或字符集很小的密码，通常应优先用字典和掩码。

## hashcat 引擎接口

GUI 通过 `HashcatBackend` 协议调用引擎，不直接绑定某个哈希程序：

```python
class HashcatBackend(Protocol):
    name: str

    def start(self, config: AttackConfig, outfile: Path) -> None: ...
    def stop(self) -> None: ...
    def join(self, timeout: float | None = None) -> None: ...
```

- 本地实现：`LocalHashcatBackend`，调用本机 `hashcat.exe`；
- 事件队列：`command / log / status / found / done`；
- 以后可以新增 HTTP、远程 GPU 队列或其他破解引擎，而不改界面代码。

详见 [docs/hashcat-backend.md](docs/hashcat-backend.md)。

## 运行要求

- Windows 10 / 11 64 位；
- Python 3.10+（当前机器为 3.12）；
- 可用的 OpenCL 显卡驱动（Intel / NVIDIA / AMD 均可）；
- 项目自带精简版 hashcat 8.0.0 运行时，位于 `runtime/hashcat`。

如需使用其他 hashcat：

1. 点击右上角“设置”；
2. 填写 `hashcat.exe` 的完整路径或所在文件夹；
3. 点击“测试路径”，保存。

> 注意：hashcat 需要往自己所在目录写 PID、日志和内核缓存。如果放在
> `C:\Program Files` 等只读目录，可能启动失败；建议使用项目自带的
> `runtime/hashcat`，或把它复制到可写目录。

## 数据目录

```text
data/
  hashes/      提取出来的 hashcat 哈希
  results/     找到的密码记录（明文，请妥善保管）
  sessions/    临时字典和本次运行的输出
  config.json  界面配置
  potfile.txt  旧版本遗留文件，可删除
```

“设置”里可以清空 `data/results` 下的结果记录。

## 常见问题

### 提示“未找到 hashcat”

确认 `runtime/hashcat/hashcat.exe` 存在，或在“设置”中指定路径。
也可以在项目根目录执行：

```powershell
.\runtime\hashcat\hashcat.exe --version
```

应输出 `v8.0.0`。

### 提示“没有找到可用的 OpenCL 设备”

更新显卡驱动；NVIDIA 用户请安装官方驱动，不要只用 Windows 基础显示驱动。
可在项目根目录运行：

```powershell
.\runtime\hashcat\hashcat.exe -I
```

查看设备列表。

### 掩码攻击提示“内核自检失败”

这是显卡驱动与 hashcat 内核不兼容，常见于部分 Intel 核显。
可以：

- 更新 Intel / NVIDIA / AMD 驱动；
- 改用字典攻击；
- 使用不超过 100 万条的小掩码（程序会自动展开成字典）。

### 破解速度很慢

- 确认使用的是独显而不是核显；
- 提高“性能模式”；
- 缩小字典或掩码范围；
- ZIP AES、RAR5 本身使用 PBKDF2，速度远低于 ZipCrypto，属正常现象。

## 免责声明

本工具仅用于**恢复你有权访问的文件**（例如自己的备份、自己设置的密码）。
请勿用于未经授权的访问。使用者需自行承担因使用本工具产生的一切责任。
