---
name: testcase-ipc-dispatch-type-confusion-01
description: "系统测试 workflow: ipc_dispatch_type_confusion_01"
engine: source
target_type: source
taint_sources:
  - "函数参数（视为攻击者可控输入）"
  - "全局变量"
  - "外部输入函数返回值"
dangerous_apis:
  - "memcpy() - 内存拷贝，可能溢出"
  - "strcpy() - 字符串拷贝，不检查长度"
  - "strncpy() - 字符串拷贝，可能不添加 \\0"
  - "sprintf() - 格式化输出，可能溢出"
  - "snprintf() - 格式化输出，需检查返回值"
  - "printf() - 格式化输出，注意格式化字符串漏洞"
  - "fprintf() - 格式化输出，注意格式化字符串漏洞"
  - "malloc() - 内存分配，注意整数溢出"
  - "free() - 内存释放，注意 UAF 和 Double Free"
  - "realloc() - 内存重分配，注意指针更新"
background_knowledge_files:
  - "../../../vuln_skills/_shared/vulnerability_workflow_knowledge.md"
tags: [eval, source, system_test, ipc, multi_handler, partial_validation]
---

## 系统测试 Workflow

### 通用目标

本 skill 用于评估 IVAgent 在 IPC dispatcher 多分支路径上的漏洞挖掘能力，重点关注内存安全漏洞、整数安全漏洞、格式化字符串漏洞与跨函数数据流追踪。

### 通用分析策略

1. 将所有函数参数默认视为外部输入，重点跟踪长度参数、计数字段和指针参数。
2. 优先检查 `memcpy`、`strcpy`、`printf`、`malloc`、`free` 等危险 API。
3. 当污点数据跨函数传播时，主动创建 sub-agent 深入分析被调函数。
4. 报告漏洞时明确给出漏洞类型、位置、数据流、触发条件和修复建议。

### 测试目标

围绕 `ipc_dispatch_message` 的消息分发路径执行真实漏洞挖掘，重点验证系统是否能区分安全 handler 与危险 handler，并深入到 `handle_data` 的不同 subtype 分支中识别不完整校验。

### 入口与处理链

- 主入口：`ipc_dispatch_message`
- 关键处理链：`ipc_dispatch_message` -> `handle_data`
- 子路径一：TEXT 分支 -> `sanitize_text`
- 子路径二：STRUCT 分支 -> `field_offsets[]` / `field_data[]` 访问
- 对比路径：AUTH handler 为安全参考路径

### 执行要求

1. 先理解 dispatcher 的外层 envelope 校验与 handler 路由逻辑，不要只盯住单个 handler。
2. 必须分别分析 TEXT 与 STRUCT 两个子路径，确认是否存在“部分校验掩盖真实边界约束缺失”的情况。
3. 对安全的 AUTH 路径可做快速对比，用来说明危险分支缺少了什么约束。
4. 报告时要区分外层消息校验与内层结构体/子类型校验的职责边界。

### 输出要求

- 优先保证召回率，但不能脱离代码事实臆测。
- 若存在多个独立问题，需分别落到具体子路径，不要合并成笼统结论。
