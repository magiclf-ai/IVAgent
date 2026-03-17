---
name: testcase-integer-overflow-chain-01
description: "系统测试 workflow: integer_overflow_chain_01"
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
tags: [eval, source, system_test, integer_overflow, chain]
---

## 系统测试 Workflow

### 通用目标

本 skill 用于评估 IVAgent 在整数溢出驱动的漏洞链场景下的漏洞挖掘能力，重点关注内存安全漏洞、整数安全漏洞、格式化字符串漏洞与跨函数数据流追踪。

### 通用分析策略

1. 将所有函数参数默认视为外部输入，重点跟踪长度参数、计数字段和指针参数。
2. 优先检查 `memcpy`、`strcpy`、`printf`、`malloc`、`free` 等危险 API。
3. 当污点数据跨函数传播时，主动创建 sub-agent 深入分析被调函数。
4. 报告漏洞时明确给出漏洞类型、位置、数据流、触发条件和修复建议。

### 测试目标

围绕 `allocate_and_copy` 的分配和拷贝流程执行真实漏洞挖掘，重点验证系统是否能同时识别算术根因与后续内存破坏后果，并将两者串联为同一条漏洞链。

### 入口与处理链

- 主入口：`allocate_and_copy`
- 关键处理链：`allocate_and_copy` -> `calculate_size`
- 重点关注乘法溢出如何影响 `malloc` 大小与后续 `memcpy` 长度

### 执行要求

1. 从 `count`、`item_size` 两个输入参数出发，确认其在 `calculate_size` 与 `allocate_and_copy` 中的使用方式。
2. 必须检查分配大小与拷贝大小是否使用了同一安全前提，尤其关注溢出后的截断值与原始乘积的分离。
3. 报告时要明确区分整数溢出根因和后续缓冲区溢出后果，并说明它们的因果链。

### 输出要求

- 优先保证召回率，但不能脱离代码事实臆测。
- 不要只报告单独的整数问题或单独的 `memcpy` 问题，需优先给出链式分析。
