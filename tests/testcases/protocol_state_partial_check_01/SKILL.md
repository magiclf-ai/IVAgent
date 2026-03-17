---
name: testcase-protocol-state-partial-check-01
description: "系统测试 workflow: protocol_state_partial_check_01"
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
tags: [eval, source, system_test, protocol, state_machine, partial_validation]
---

## 系统测试 Workflow

### 通用目标

本 skill 用于评估 IVAgent 在协议状态机与数据解析混合场景下的漏洞挖掘能力，重点关注内存安全漏洞、整数安全漏洞、格式化字符串漏洞与跨函数数据流追踪。

### 通用分析策略

1. 将所有函数参数默认视为外部输入，重点跟踪长度参数、计数字段和指针参数。
2. 优先检查 `memcpy`、`strcpy`、`printf`、`malloc`、`free` 等危险 API。
3. 当污点数据跨函数传播时，主动创建 sub-agent 深入分析被调函数。
4. 报告漏洞时明确给出漏洞类型、位置、数据流、触发条件和修复建议。

### 测试目标

围绕 `process_protocol_msg` 的状态迁移和字段解析流程执行真实漏洞挖掘，重点验证系统是否能同时识别逻辑层面的认证绕过与数据层面的累计写入溢出。

### 入口与处理链

- 主入口：`process_protocol_msg`
- 关键处理链：`process_protocol_msg` -> 状态分派 -> `parse_data_fields`
- 重点关注 INIT/AUTH/DATA 状态切换与 `data_buf` 的累计使用

### 执行要求

1. 必须先建立状态机模型，确认不同命令在 INIT、AUTH、DATA 状态下的处理路径。
2. 检查是否存在绕过认证前置条件直接进入数据处理的状态迁移错误。
3. 在 `parse_data_fields` 中分析单字段边界检查与累计缓冲区容量之间是否脱节。
4. 报告时要明确区分逻辑漏洞与内存破坏漏洞，并说明它们是否可链式利用。

### 输出要求

- 优先保证召回率，但不能脱离代码事实臆测。
- 若识别到两个独立问题，需分别说明证据，不要只给出单一结论。
