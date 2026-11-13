# 真实 Luna 工作台使用说明

运行 `python3 app.py --port 8766`，打开 <http://127.0.0.1:8766>。本机需要已登录的 Codex CLI，模型固定为 gpt-6-luna。仅支持真实研究；输入存在的 .xpc 或 ARM Mach-O 文件，universal 选择 ARM，拒绝 x86-only。

流程：真实环境与静态采集 → Luna 规划 → Luna 逐项分析 → 真实探测与 Luna 实验核验 → Luna 评审 → 按缺口补充调查 → Luna 再评审。实验器未支持的请求明确标为 blocked，不生成模拟数据。评审未解决计划项时退回，自动补充一次后仍有缺口显示“证据缺口未解决”，可重试；不把客观调查问题交给专家代查。

每个模型产物展示逐项计划交付：结论、静态/运行时状态、实际核查动作、证据编号与技术阻塞。模型引用按行号与原始工具文本校验；字面匹配不能代替语义正确性。

用户可随时暂停、插话调整方向、记录经验；旧轮次保留，过期调用结果不能覆盖新轮次。专家原话进入知识候选，编辑确认后按任务/全局范围使用。历史模拟任务只保留记录，不能恢复执行。

“静态分析工具配置”支持软件路径、参数、JSON/NDJSON/文本、报告来源和超时。未启用时明确跳过外部软件，IDA 和系统工具仍可工作。配置详情见 README。

XPCKeychainSandboxCheck 使用只读元数据请求取得实际返回路径与服务身份，不记录或使用 extension token，不读取 keychain 内容；当前普通调用进程的观测不等于所有调用者权限矩阵。

## 默认前置运行环境调查

新建真实研究采用七节点流程，旧记录保留原有六节点进度。环境调查完成后，带时间、PID、进程启动时间及路径的证据交给规划与分析模型。专家调整方向会重新采样，旧证据保留所属轮次。

- 启动链：扫描标准 LaunchAgents/LaunchDaemons 目录，按可执行文件完整路径匹配；检查实时 launchd 配置，必要时 `launchctl kickstart` 正常激活现有服务。不使用 `-k`，不替换配置，不强杀已有系统服务。
- 身份：通过 libproc 确认实际进程路径、ARM 架构、UID/EUID/GID/EGID、父进程与启动时间。采样前后身份发生变化则丢弃，避免 PID 复用。
- Entitlements：通过 `csops(CS_OPS_ENTITLEMENTS_BLOB)` 查询运行进程。与静态签名输出分别保留；失败或不支持的格式标未知，不能推断为空。
- Sandbox：通过 `sandbox_check(pid, NULL, 0)` 查询采样时是否存在 sandbox，并复测。它不等于完整有效策略枚举；目标引用的 `.sb` 文件只作为静态策略线索。
- IPC：收集 launchd MachServices/Sockets 配置和实时服务端点、目标进程 fd/socket；从 ARM 符号和完整反汇编中提取 CFMessagePort、XPC、Mach、audit token、SecTask 等调用点。模型继续梳理接收入口和鉴权路径，不能把导入符号当成已验证入口。

未知项必须附采集失败原因和进一步查证方案，不再把基础环境问题转交人类专家。当前运行采集器支持本机 macOS；iOS 设备适配器尚未接入，未取得设备证据时动态状态保持未知。没有已注册启动链且目标未运行时，不猜测任意启动参数。

引用来源：Apple [csops 定义](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)；libproc 结构以本机 SDK 的 `sys/proc_info.h` 为准。sandbox_check 属于私有接口，失败时明确降为未知。


## IPC 鉴权与调用图

真实研究的前置调查现在自动启动独立 IDA/Hex-Rays 采集器。只打开已提取并校验 SHA256 的 ARM 快照，不分析 x86 切片。优先使用 `SSJ_IDA_PYTHON` 指定的 Python；未配置时检测本机 IDA Pro MCP 插件的 Python 环境。缺少依赖时明确报告 unavailable，不生成假调用链。

采集器恢复 CFMessagePort 回调注册（包括 ARM PAC 签名指针的局部传递）、函数调用边、完整鉴权函数伪代码、反汇编和 CFG。模型必须据此自动回答具体 entitlement、布尔类型/值检查、放行条件、拒绝路径和返回值，不能再将这些事实问题交给专家。

调用链导出兼容 `finding_idx/source/sink/tag/chain/source_reason/raw/disasm_file` 字段，同时增加逐跳 `edges`（调用点地址、指令、边类型）、跳数、分析界限和 UNVERIFIED 状态。只遍历真实调用指令、明确的跨函数尾调用及能解析到常量目标的间接调用；不把普通条件分支或 fallthrough 当函数调用。每个 source/sink 输出一条已发现的最短路径，默认深度 12、最多 100 条结果、10000 次遍历；触及上限会标 truncated。

当前版本聚焦单一 Mach-O：导入库函数体是边界；Objective-C selector stub 不能证明 receiver 类，因此不会按同名 selector 拼接方法。未恢复的间接调用单独列出。CFMessagePort 注册是可自动识别的入口；其他 XPC/Objective-C protocol 入口自动恢复尚未完整支持。UNVERIFIED 表示调用链没有证明执行路径可行、数据可控或存在漏洞。

完整图保存在 `callgraph/ida-export.json`，兼容链表在 `callgraph/findings.json`，逐链反汇编在 `callgraph/disasm/`。也可以独立执行：

```sh
python3 call_graph.py --manifest /absolute/path/to/inputs/evidence.json --output /absolute/path/to/callgraph-output
```

macOS ARM 主机另运行两个独立测试进程，对 `sandbox_check_by_audit_token(token, NULL, 0)` 做普通 / sandbox 环境返回值校准。不向研究目标发消息，不签发私有 entitlement，不改变系统安全配置；这一证据不能冒充目标端到端调用验证。

引用机制现支持 `@lines:起始行-结束行`，模型不得拼接不连续汇编作为一段原文；程序校验范围并还原精确证据文本，引用仍不代表语义判断自动正确。


FontValidator 的已知系统路径另带最小 IPC 对照适配器：正常 / sandboxed 两个测试进程各发送一次固定非 plist 文本，不提供字体输入，同时采集最近的拒绝日志（C98）。C99 仍只校准本机 API。两类证据分开保存；空回复不等于鉴权成功，时间相关日志不等于唯一客户端归因。其他目标不会自动套用该协议适配器。
