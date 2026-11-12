# 架构与接口

## 数据流

浏览器 → HTTP API → SQLite 队列 → 单工作线程 → 文件索引与静态规则 → 可选模型审查 → 持久化结果 → 报告。

前端使用原生 HTML/CSS/JS，无 CDN 和构建步骤。HTTP 使用 Python ThreadingHTTPServer；数据库连接按操作创建。所有目标文本在页面显示前转义。模型输出只作为数据展示，不执行其生成命令。

## 状态

`queued → running → completed / completed_with_warnings / failed / cancelled`。

启动恢复：`running → interrupted`。取消排队任务立即生效；运行中任务在检查点退出。分析阶段结束时保存一份基础结果，以便模型失败或取消后保留已有工作。

## 数据对象

- Task：id、created、updated、status、request、result、events、cancel。
- Request：target（本地绝对路径）、goal、mode（local 或 ai）。
- File：相对路径、大小、SHA256、类型；源码行数或二进制字符串采样。
- Evidence：id、file、line、excerpt、rule、title、question。
- Hypothesis：id、title、evidence_ids、validation、status=unverified、origin。
- Result：files、evidence、hypotheses、skipped、limits、truncated、bytes_read、scope、ai。

AI 的输入最多包含前 60 条证据。输出引用会校验是否属于已有证据集合，但尚未进行独立语义复核。报告中的“证据”仅证明对应代码片段存在，不证明安全缺陷。

## API

| 方法 | 路径 | 内容 |
|---|---|---|
| GET | /api/config | 非敏感运行配置和示例路径 |
| GET | /api/tasks | 最近 100 个任务摘要 |
| POST | /api/tasks | JSON：target、goal、mode |
| GET | /api/tasks/{id} | 完整任务与结果 |
| POST | /api/tasks/{id}/cancel | 请求取消 |
| GET | /api/tasks/{id}/report | Markdown 报告 |
| GET | /api/tasks/{id}/export | JSON 导出 |

示例：

```sh
curl -s http://127.0.0.1:8766/api/tasks \
  -H 'Content-Type: application/json' \
  -d '{"target":"/Users/orochisun/work/atuin/nexus/examples","goal":"梳理研究入口","mode":"local"}'
```

## 扩展边界

后续引擎可沿用 File → Evidence → Hypothesis 的输出形状，增加 engine、engine_version、artifact_refs 等来源字段。Dagger 应通过独立适配器执行并转换真实结构化输出；当前没有对其 CLI/schema 做兼容承诺。

真实实验执行应独立于 HTTP 进程，增加隔离环境、超时、资源回收和原始日志归档。跨平台支持需要各自工具与设备适配，当前只支持跨平台文件的本地初步索引。

## 设计参考

- https://github.com/AzozzALFiras/iOS-Research ：研究地图、证据和负结果组织。
- https://github.com/dawgyg/AppleResearch ：研究材料、实验资产与报告组织。
- https://meet.kanxue.com/kxmeet-19.htm ：自主建模和实验反馈的公开议题摘要。
- https://bbs.kanxue.com/thread-293238.htm ：ZeroMDASH 的领域建模与证据复核设计启发。

本原型独立编写，没有复制上述仓库的研究代码或声称复现其能力。

## v0.2 Codex 执行适配器

`mode=codex` 进入 `codex_runner.run`，使用真实 Codex 原生 Agent 循环，不使用预先写好的假设响应。模型工具由 Codex 执行，外层负责范围快照、哈希核对、进程生命周期、事件归档和结果展示。

新的 result.agent 包含 model、workspace、tool_events、artifacts、duration_seconds。每个产物保留路径、SHA256 和最多 20000 字符展示内容。最终报告包含 Agent 记录。模型认证沿用 CLI 登录，本应用不读取或存储凭证。

Codex 成功退出并返回结构化结论后，假设状态为 supported/refuted/inconclusive；缺少有效实验产物引用时自动降为 inconclusive。此处只校验引用存在性，不将模型自评冒充确定性验证。保留原始实验是为了供人复查和再次执行。
