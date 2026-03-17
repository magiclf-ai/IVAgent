---
name: testcase-heap-overflow-01
description: "系统测试 workflow: heap_overflow_01"
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
tags: [eval, source, system_test, heap_overflow, simple]
---

## 系统测试 Workflow

### 通用目标

本 skill 用于评估 IVAgent 在简单堆溢出场景下的漏洞挖掘能力，重点关注内存安全漏洞、整数安全漏洞、格式化字符串漏洞与跨函数数据流追踪。

### 通用分析策略

1. 将所有函数参数默认视为外部输入，重点跟踪长度参数、计数字段和指针参数。
2. 优先检查 `memcpy`、`strcpy`、`printf`、`malloc`、`free` 等危险 API。
3. 当污点数据跨函数传播时，主动创建 sub-agent 深入分析被调函数。
4. 报告漏洞时明确给出漏洞类型、位置、数据流、触发条件和修复建议。

### 测试目标

围绕 `parse_packet` 的直接内存拷贝路径执行真实漏洞挖掘，验证系统是否能在简单单函数场景下给出完整的长度约束缺失分析。

### 入口与处理链

- 主入口：`parse_packet`
- 关键处理链：`parse_packet` -> `memcpy`
- 重点关注固定大小堆对象与攻击者可控长度之间的关系

### 执行要求

1. 从入口参数 `data`、`len` 出发，确认它们如何进入目标对象写入。
2. 必须检查分配大小、目标缓冲区大小与 `memcpy` 长度参数之间是否存在显式上界。
3. 报告时要把可控输入、目标缓冲区大小和危险写入点直接关联起来。

### 输出要求

- 优先保证召回率，但不能脱离代码事实臆测。
- 不要只输出“memcpy 可能溢出”，必须给出具体边界缺失证据。
