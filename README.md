# ssj — 可运行研究工作台

Python 3.10+，仅使用标准库，无需安装依赖。此版本用于本机单用户研究。

## 多 Agent 演示工作台

首页现为专家主导的多 Agent 演示版。输入 `.xpc` 绝对路径即可演示规划、分析、实验、评审退回与补充验证；支持专家随时插话重新规划，以及原话归档、知识编辑确认和下一轮引用。默认模式先自动调查运行时 UID/EUID、entitlements、sandbox 和 IPC，再通过已登录的 Codex 调用 gpt-6-luna 规划分析。macOS 采集器先匹配进程及 launchd 配置，必要时正常激活已注册的目标服务，不修改配置或提升权限。实验和评审仍明确标为模拟。iOS 动态采集需要设备适配器，当前未接入，不能以 macOS 主机状态代替。真实模式要求目标存在；纯模拟模式允许不存在的 `.xpc` 路径。所有真实二进制分析拒绝 x86-only；Universal Binary 先提取 ARM 切片，工具和模型仅使用该切片。

在当前仓库目录运行 `python3 app.py --port 8766`，打开 <http://127.0.0.1:8766>。前置调查还会通过 IDA/Hex-Rays 恢复 IPC 回调、鉴权分支和带逐跳反汇编的调用链；配置说明与边界见 [演示说明](docs/demo-guide.md)。下文原版真实分析功能位于 <http://127.0.0.1:8766/legacy>。

## 启动

```sh
cd /path/to/ai-research
python3 app.py --port 8766
```

打开 http://127.0.0.1:8766/legacy 。点击「填入示例目标」→「启动研究」，查看文件清单、静态证据、待验证假设和执行轨迹。任务详情可打开 Markdown 报告和 JSON 导出，浏览器可另存为本地文件。

也可以填写本地源码目录或二进制文件路径。原版入口默认仅允许仓库上级目录下的目标。扩大范围：

```sh
export NEXUS_ALLOWED_ROOTS="/Users/orochisun/work:/another/research/path"
python3 app.py
```

环境变量不会自动从 `.env` 加载。路径列表在 macOS/Linux 上以冒号分隔。

## 可选模型

支持提供 `/chat/completions` 的兼容接口。BASE_URL 填到 API 前缀，应用追加 `/chat/completions`。模型名称由服务方提供。

```sh
export NEXUS_MODEL_BASE_URL="https://your-model-service.example/v1"
export NEXUS_MODEL="your-model-name"
read -s NEXUS_MODEL_API_KEY
export NEXUS_MODEL_API_KEY
python3 app.py
```

本地无鉴权模型可不设置 API_KEY。仅本机 HTTP 或远程 HTTPS 端点被接受。AI 模式发送研究目标、文件名以及最多 60 条匹配的代码片段；本地模式不进行网络调用。密钥只从进程环境读取，不通过 API 返回，也不存入任务数据库。

无模型配置时仍保留本地分析结果，任务显示「完成 · 有提示」。模型调用失败同样保留基础结果。模型输出必须为 JSON；引用不存在的证据编号的假设会被丢弃。证据编号校验不等于对模型结论完成事实验证。

## 已实现

- 浏览器工作台：创建、选择、轮询和取消研究任务。
- SQLite 持久化任务、事件、证据与结果；单工作线程排队执行。
- 源码入口规则：进程执行、内存操作、反序列化、文件操作、IPC。
- 二进制初步识别、SHA256、有限字符串采样。
- 基于规则生成待验证问题；可选模型证据审查。
- JSON / Markdown 结果导出。
- 文件数、单文件大小、总字节数和线索数预算限制。

## 当前边界

这是静态研究入口原型。源码规则是文本匹配，可能命中注释或安全调用，也可能漏报；未实现数据流、可达性、反编译、真实动态实验、Fuzzing、版本差分或自动漏洞证明。二进制分析仅接受 ARM Mach-O；Universal Binary 选择 ARM 切片。所有研究假设均为 unverified。

真实模式默认调查阶段支持用户配置的静态分析工具，未启用时明确记录 disabled，不自动调用 Dagger。IDA 提供静态调用图；Atuin 尚未接入。规划与分析使用 gpt-6-luna，实验与评审仍明确标为模拟。外部工具的零发现、部分覆盖或失败均不能作为安全结论。

大文件、隐藏文件、符号链接，以及 `.git`、`node_modules`、`.venv`、`data` 等目录会被跳过。当前不是针对恶意并发修改文件系统设计的沙箱；请在自己控制的本地目标上使用。默认只监听回环地址，带 Host / Origin 校验，不适合直接开放到局域网或公网。

## 数据与恢复

默认数据库：`data/nexus.sqlite3`。通过 `NEXUS_DATA` 可修改存储目录。重启后运行中的任务标记 interrupted；排队任务继续执行。可重新提交同一目标创建新任务。取消在文件边界检查；模型请求等待最长 60 秒后再响应取消。请勿用多个进程共享同一数据库。

## 验证

```sh
python3 -m unittest discover -s tests -v
node --check static/app.js
```

详见 [架构与接口](docs/architecture.md)。

## v0.2：Codex 自主研究（推荐）

选择「Codex 自主研究 · GPT-6-Luna」。复用本机 `codex login` 登录，无需额外 API key。默认模型 `gpt-6-luna`，可通过 `NEXUS_CODEX_MODEL` 修改。

本模式将已索引文件复制到 `data/runs/<任务ID>/target/`，检查内容哈希，然后调用真实 `codex exec`：`workspace-write`、禁止交互审批、忽略用户 config 与 execpolicy rules、临时会话、结构化结论。Codex 自主使用其工具读取目标、在 `experiments/` 写测试并执行、检查反例、汇总结果。外层记录命令事件和工具输出，每 0.3 秒检查取消，最长运行 600 秒；取消/超时终止整个执行进程组。

- `events.jsonl`：Codex 原始事件。
- `stderr.log`：CLI 诊断。
- `experiments/`：实际编写的测试与输出日志。
- `conclusion.json`：模型结构化结论。
- 工作台展示工具轨迹、实验产物和 supported / refuted / inconclusive 状态。

这些状态是 Agent 根据实验作出的判断，并非独立审计认证。引用必须指向 experiments 下真实存在的文件，否则降为 inconclusive。应查看日志和测试是否支持结论。目标副本不自动包含被索引限制跳过的依赖，大型项目可能因此无法构建。

上述 v0.1 的“未执行程序”限制仅适用于 local/ai 模式；Codex 模式会执行模型编写的实验。workspace-write 是执行权限控制，不是完整隔离虚拟机；当前适用于可控研究样本。原始目标只复制，研究在副本中进行。

## v0.3 开发中：二进制工具与 Dagger 适配

新增 `research_tools.py`，提供 inventory / binary / dagger 三个命令。binary 实际执行本机 file、nm、strings、otool（或 objdump），保留参数、退出码、耗时和截断信息。Dagger 通过 `NEXUS_DAGGER_BIN` 指定内部引擎，调用 `audit <target>`；没有引擎时明确返回 unavailable。

第三方源码和构建产物不随本仓库提交，固定来源与提交见 `dependencies.json`。按需获取：

```sh
python3 scripts/fetch_dependencies.py cJSON
# 需要内部仓库访问权限：
python3 scripts/fetch_dependencies.py dagger
```

实际 cJSON 研究已使用 GPT-6-Luna 读取原始源码、直接链接 cJSON.c 编译 ASan/UBSan harness，并运行解析长度和 NUL 边界用例，也执行了二进制分析。此阶段生成的 harness 仅打印结果，缺少自动断言，独立验收还需补齐。不能将正常退出视为全部假设验证成功。

2026-11-12 已用本机 `dagger-main/target/release/dagger` 对 FontValidator 的 arm64e 切片完成真实调用：退出码 0，发现 0，覆盖 partial。原 `dagger/target/release/dagger` 构建对该样本发生 canonical OWNER panic；记录保留，不作为零发现处理。任务数据库和原始日志不随 Git 提交。

`dagger_adapter.py` 支持 audit stream v1 与 protocol v4，保存引擎/输入 SHA256、参数、NDJSON、stderr、覆盖限制及报告。可用 `NEXUS_DAGGER_BIN` 显式指定内部 Dagger；否则按仓库 engines/dagger、相邻 dagger-main、相邻 dagger 查找，不使用 PATH 中同名的 CI 产品。引擎预算 90 秒，外层超时 110 秒；暂停或插话取消在途进程，旧轮次结果不会发布。输入只接受已验证的 ARM 切片。D1 与运行环境证据、IDA 调用链一起交给真实规划/分析 Agent，以上为历史 Dagger 专用适配器行为，仍供原版 CLI 显式调用；当前多 Agent 默认流程使用下述通用配置。


## 通用静态分析工具配置

工作台 → **静态分析工具配置**，填写工具名称、可执行文件绝对路径、参数、输出格式及报告来源，勾选启用后保存。配置保存在本地 SQLite；重启保留。新任务与“调整方向”开启的新轮次读取当前配置，执行中的轮次保持配置快照。没有配置时跳过外部工具，继续其他调查。

参数填写 JSON 字符串数组，例如：

```json
["analyze", "{arm_binary}", "--output", "{output_file}"]
```

- `{arm_binary}`：已经校验 SHA256 的 ARM 切片副本；x86-only 在任务入口拒绝。
- `{output_dir}`：本轮独立工具目录。
- `{output_file}`：报告文件绝对路径。报告来源填 `reports/result.json` 等相对路径；若软件向标准输出写报告，填 `stdout` 并省略输出参数。
- 格式可选 `json`、`ndjson`、`text`。不同厂商报告原样保留，由 Agent 分析；通用适配器不猜测私有字段意义或覆盖率。

参数逐项传给程序，不经过 shell；路径含空格不需要额外引号，不支持管道或重定向。超时可设 1–1800 秒。保留命令、退出码、stdout、stderr、报告及配置快照；报告读取上限 4 MiB，提供给模型的 S1 摘录上限 100000 字符，截断明确标记。正常退出标为 executed，仅代表执行完成；覆盖范围默认 unknown，零发现不能证明安全。暂停或插话会取消在途调用，过期结果不进入新轮次。

配置 API：GET/POST `/api/demo/static-tool`。POST 字段：`enabled`、`name`、`executable`、`args`（字符串数组）、`format`、`output`、`timeout_seconds`。当前入口配置一个 CLI 工具，不包含 API/MCP 或厂商特定报告映射。
