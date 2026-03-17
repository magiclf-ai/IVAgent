---
name: testcase-cross-func-overflow-01
description: "系统测试 workflow: cross_func_overflow_01"
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
tags: [eval, source, system_test, cross_function, strcpy]
---

## 系统测试 Workflow

### 通用目标

本 skill 用于评估 IVAgent 在跨函数污点传播场景下的漏洞挖掘能力，重点关注内存安全漏洞、整数安全漏洞、格式化字符串漏洞与跨函数数据流追踪。

### 通用分析策略

1. 将所有函数参数默认视为外部输入，重点跟踪长度参数、计数字段和指针参数。
2. 优先检查 `memcpy`、`strcpy`、`printf`、`malloc`、`free` 等危险 API。
3. 当污点数据跨函数传播时，主动创建 sub-agent 深入分析被调函数。
4. 报告漏洞时明确给出漏洞类型、位置、数据流、触发条件和修复建议。

### 测试目标

围绕 `handle_request` 发起的简单调用链执行真实漏洞挖掘，验证系统是否能从入口函数跟踪外部输入跨函数流入 `copy_data`，并识别最终 `strcpy` 导致的栈溢出。

### 入口与处理链

- 主入口：`handle_request`
- 关键处理链：`handle_request` -> `copy_data`
- 重点关注参数 `input` 到 `src` 再到 `strcpy` 的跨函数传播

### 执行要求

1. 先从 `handle_request` 标定外部输入，再继续分析它如何原样传入下游 helper。
2. 必须在 `copy_data` 中确认固定大小目标缓冲区、危险 API 和缺失的边界校验。
3. 报告时要把入口与内部函数之间的数据流说完整，不接受只有局部 API 告警、没有来源说明的结果。

### 输出要求

- 优先保证召回率，但不能脱离代码事实臆测。
- 报告必须包含跨函数传播链，而非只列出 `strcpy` 调用。
