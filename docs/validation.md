# 验证记录

日期：2026-11-12。

- Python unittest：8 项通过，覆盖持久化、报告、模型缺失降级、目标范围、取消、重启恢复、二进制与预算、模型响应引用过滤、HTTP 接口及来源校验。
- JavaScript：`node --check static/app.js` 通过。
- 真实浏览器：Playwright 驱动本机 Chrome，以独立无头会话打开工作台，填写示例目标、启动研究、等待完成、检查文件操作证据和 Markdown 报告；通过，未发现页面 JS 异常。
- 390px 移动视口：未出现水平溢出。
- 桌面全页截图：[workbench.png](workbench.png)。

模型校验测试使用模拟响应；没有配置或调用真实模型服务。没有连接 Dagger / Atuin，没有执行目标样本或动态漏洞验证。浏览器测试使用的示例任务保留在本机任务列表中。

## v0.2 真实模型验收

使用本机已登录 Codex CLI，模型 **gpt-6-luna**，任务 **433b13284881**，实际完成源码阅读、生成实验脚本、执行测试、结构化返回结论。

实验覆盖：正常路径读取、`../` 拒绝、目录外绝对路径拒绝，以及 subprocess 列表参数捕获。测试在内存中替换基准目录，并对 subprocess 使用替身；未宣称证明竞态不存在或所有路径场景安全。Agent 结束后独立重跑生成的测试，ASSERTIONS=passed。

原始证据位于 `data/runs/433b13284881/`，包括 events.jsonl、conclusion.json、experiments/test_sample.py 和 experiments/test_sample.log。任务在工作台可查看。

新增测试覆盖快照发生变化时拒绝执行、CLI 事件读取、结论引用存在性检查；共 10 项测试通过。CLI 协议单元测试使用显式 fake fixture，以上验收任务使用真实模型。

## v0.3 当前开发状态

- cJSON 固定提交见 dependencies.json；真实任务 f95193fa89dd 已结束。
- 实际执行 clang ASan/UBSan 编译、9 项解析边界输入、file/nm/strings/otool 二进制分析。
- 生成的 harness 缺少自动断言，当前仅保留观察结果；独立断言验收未完成。
- Dagger 固定源码已通过 SSH 获取，构建因稳定 Rust 不支持的库接口失败；没有宣称 Dagger 已运行。
- 推送前重新执行 10 项单元测试和 JS 语法检查，均通过。
