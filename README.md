# 星枢 Nexus — 可运行研究工作台

Python 3.10+，仅使用标准库，无需安装依赖。此版本用于本机单用户研究。

## 启动

```sh
cd /Users/orochisun/work/atuin/nexus
python3 app.py --port 8766
```

打开 http://127.0.0.1:8766 。点击「填入示例目标」→「启动研究」，查看文件清单、静态证据、待验证假设和执行轨迹。任务详情可打开 Markdown 报告和 JSON 导出，浏览器可另存为本地文件。

也可以填写本地源码目录或二进制文件路径。默认仅允许工作区目录 `nexus/..` 下的目标。扩大范围：

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

这是静态研究入口原型。源码规则是文本匹配，可能命中注释或安全调用，也可能漏报；未实现数据流、可达性、反编译、真实动态实验、多 Agent、Fuzzing、版本差分或自动漏洞证明。二进制签名识别属于初筛，PE 与通用 Mach-O 等仍需解析器确认。所有研究假设均为 unverified。

Dagger / Atuin 尚未接入，没有使用内部 API 或伪造插件执行结果。模型接口已实现，但实际服务需要你配置。演示目标是明确标注的测试文件。

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

Dagger 源码已获取，但当前构建停在 dagger-datalog 的 `result_option_map_or_default` 不稳定接口错误（本机 rustc 1.97.1）。尚未成功运行 Dagger，适配器不能视为已完成端到端验收。任务数据库和原始运行日志保留于原开发机，不随 Git 提交。
