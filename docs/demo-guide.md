# 多 Agent 演示版使用说明

## 启动

在仓库目录运行 `python3 app.py --port 8766`，打开 <http://127.0.0.1:8766>。Python 无额外依赖。默认真实规划/分析模式要求本机已安装 Codex CLI 并完成登录，使用 `gpt-6-luna`。纯模拟模式无需模型。原版真实分析功能保留在 `/legacy`。

首页输入 `.xpc` 绝对路径或已存在的普通文件绝对路径，也可点击“填入演示目标”。真实模式读取目标或 XPC 的主可执行文件，拒绝 x86-only；Universal Binary 只提取 ARM 切片（优先 arm64e）。原始容器和所选切片分别记录 SHA256，后续工具只读取该 ARM 快照，模型接收工具文本证据；前置调查可通过 launchctl 正常激活路径匹配的已注册目标服务；不会发送漏洞实验输入。纯模拟模式的 XPC 路径不要求存在。

## 演示顺序

1. 点击“启动协作研究”。真实模式先进入环境调查 Agent，自动确认运行身份、权限、sandbox 与 IPC，随后规划、分析、实验和评审角色会自动流转。真实模型阶段耗时取决于服务，面板展示当前调用角色和原始日志路径；模拟节点约三秒一个。
2. 首次模拟评审发现预设实验缺少对照（XPC 身份对照或普通文件的空/截断输入），退回实验 Agent，并显示退回理由、接收角色和补齐标准。
3. 补充对照后再次评审，流程停在“等待专家判断”。纯模拟流程约二十秒，真实模型模式更久。
4. 在专家席位选择“调整方向”，输入新的研究重点并提交。旧计划归档，新计划以专家原话为研究方向；历史证据保留原轮次。
5. 选择“补充经验”时，只记录发言，不改变当前计划。评审完成后可选择“阶段判断”收束研究。
6. 打开专家知识库，查看原话、编辑提炼，选择“仅当前研究”或“同模式全部研究”，确认后保存。
7. 下一轮规划会引用适用范围内已确认的知识，显示知识编号和版本。候选与废弃知识不会被规划引用。

暂停和单步按钮适合逐段讲解；单步执行后保持暂停，直到最后一个节点进入专家判断。研究记录可以导出为 JSON，包含模拟来源、专家原话、评审、计划历史、证据和知识引用快照。

## 实现范围

编排、轮次切换、专家输入、评审状态、知识修订与 SQLite 存储真实工作。真实模式的规划和分析调用 gpt-6-luna；工具采集 file、nm、strings、otool 和签名信息。模型观察通过 evidence-lines.json 的行号定位证据，由程序提取原文，引用匹配不代表语义正确，仍需专家复核。结构或引用校验失败时，系统保留首次输出，并将具体错误交回模型自动纠错一次；纠错仍失败则明确报错，可继续重试，不会降级为模拟成功。纠错记录出现在时间线及模型结果中。默认调查阶段调用工作台中启用的静态分析软件，并保留 S1 原始报告和执行记录；未配置时明确跳过，不自动调用 Dagger；IDA 提供带地址的静态调用链。实验与评审仍使用确定性模拟脚本。FontValidator 调查包含明确记录的最小 IPC 身份探测，不等同于真实漏洞实验。研究方向会成为新计划及产物的上下文，XPC 使用预设身份对照场景，普通文件使用正常、空和截断输入的边界场景，不会根据自然语言自动生成新的真实实验。

知识整理初版采用无损原话作为候选提炼，由专家编辑确认；尚未自动调用模型概括。专家确认表示提炼符合专家意见，实验依据仍独立标为“未经实验验证”。

数据保存在 `data/nexus.sqlite3` 的 `demo_runs` 和 `expert_knowledge` 表中，也遵循 `NEXUS_DATA` 配置。刷新或重启后记录保留，暂停任务保持暂停，执行中的模型调用在重启后标为暂停，由用户继续。暂停或插话会取消当前调用，过期结果不会覆盖新轮次。模拟知识与真实模式知识隔离。`NEXUS_*` 环境变量及数据库文件名为兼容旧数据保留，产品名为 ssj。

## 验证

运行 `python3 -m unittest discover -s tests -v` 及 `node --check static/demo.js`。新增测试覆盖评审退回、插话重规划、历史保留、专家收束、知识范围和版本冲突、暂停恢复、路径检查及 HTTP 来源校验。


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
