# 系统测试优化方案

## 背景

2026-03-13 全量 `tests/eval` 回归中，前 8 个用例均能成功完成，但日志与运行结构暴露出明显的系统性问题：

- `DeepVulnAgent` 递归创建子 Agent 时没有并发限流，调用图较宽的样本会放大 LLM 与日志写入压力。
- `FunctionSummaryAgent` 对解析后落到同一 callee 的摘要请求没有真正去重，存在重复摘要任务。
- 函数摘要缓存对 Redis 是硬依赖，缓存不可用时会直接把摘要链路打断。
- LLM 日志导出缺少稳定 `role` 字段，`llm_interactions.md` 中大量消息会显示为 `unknown`，不利于排障。

## 优化目标

1. 降低递归分析阶段的资源争抢，减少全量系统测试的长尾耗时。
2. 删除重复摘要任务，避免无效 LLM 调用。
3. 将 Redis 从“硬依赖”降级为“优先使用”，不可用时自动回落到进程内缓存。
4. 改善日志结构，让评测产物更容易直接定位慢点与对话问题。

## 具体改动

### 1. DeepVulnAgent 子 Agent 并发限流

- 在 `DeepVulnAgent` 内引入子 Agent 级别的 semaphore。
- 所有后台子 Agent 任务统一经过 semaphore 执行，避免递归 fan-out 无上限扩散。
- 为子 Agent 与摘要任务补充 `agent_tasks` 级结构化日志，便于在 `agent_logs.db` 中查看真实慢点。

### 2. FunctionSummaryAgent 摘要去重

- 在 callsite 解析完成后，以解析后的 `callee_identifier` 为键做二次去重。
- 一个 callee 在同轮只触发一次摘要分析，多个调用点共享结果。

### 3. FunctionSummary 缓存降级

- 新增进程内本地摘要缓存实现。
- Redis 可用时继续使用原有缓存；Redis 不可用时自动回落到本地缓存，不中断主流程。

### 4. LLM 日志结构修复

- `ToolBasedLLMClient` 在序列化消息时同时保存 `role` 与 `type`。
- `tests/eval` 导出 `llm_interactions.md` 时优先读取 `role`，回退到 `type`，消除 `unknown` 消息。

## 验证方式

1. 完成一次基线全量 `tests/eval` 执行，确认问题表现。
2. 修改后重新运行关键回归用例，重点观察：
   - 子 Agent fan-out 是否受控
   - 摘要任务是否不再重复
   - Redis 不可用时是否仍能继续分析
   - `llm_interactions.md` 是否正确显示消息角色
