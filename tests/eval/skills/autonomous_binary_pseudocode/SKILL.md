---
name: autonomous-binary-pseudocode-eval
description: "系统测试通用 workflow：对 IDA 伪代码视图执行自主漏洞挖掘"
engine: source
target_type: source
taint_sources:
  - "入口函数参数（默认视为外部可控输入）"
  - "协议字段、长度字段、数量字段"
  - "全局状态和外部接口返回值"
dangerous_apis:
  - "memcpy / memmove / strcpy / strncpy"
  - "malloc / calloc / realloc / free"
  - "printf / sprintf / snprintf / fprintf"
tags: [eval, source, system_test, autonomous, pseudocode]
---

## 系统测试 Workflow

### 总体目标

基于目标伪代码视图，自主规划并执行漏洞挖掘。重点是让 Agent 从用户给定入口出发，自行决定要继续读取哪些函数、如何扩展调用链、何时提交漏洞结论。

### 执行原则

1. 将任务文件中的请求视为唯一 testcase 专属用户输入，不假设额外 hidden hint。
2. 先理解入口函数的输入来源、关键状态和危险操作，再决定是否沿调用链继续下钻。
3. 优先识别真实可证据化的问题：越界读写、UAF、整数错误、格式化字符串、类型混淆、状态校验缺失。
4. 尽量依赖 LLM + tool 调用收集证据，避免使用硬编码规则、固定题库答案或 testcase 记忆。
5. 输出必须落到具体代码事实：可控输入、约束缺失、危险操作、影响范围。

### 报告要求

- 每个漏洞都要说明类型、位置、触发路径、根因和风险。
- 如果只能得到中等置信度，也必须给出证据锚点，不能泛化空谈。
- 不要复述整份伪代码，只保留支撑结论所需的关键信息。
