---
name: testcase-format-string-01
description: "系统测试 workflow: format_string_01"
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
tags: [eval, source, system_test, format_string, simple]
---

## 系统测试 Workflow

### 通用目标

本 skill 用于评估 IVAgent 在简单格式化字符串场景下的漏洞挖掘能力，重点关注内存安全漏洞、整数安全漏洞、格式化字符串漏洞与跨函数数据流追踪。

### 通用分析策略

1. 将所有函数参数默认视为外部输入，重点跟踪长度参数、计数字段和指针参数。
2. 优先检查 `memcpy`、`strcpy`、`printf`、`malloc`、`free` 等危险 API。
3. 当污点数据跨函数传播时，主动创建 sub-agent 深入分析被调函数。
4. 报告漏洞时明确给出漏洞类型、位置、数据流、触发条件和修复建议。

### 测试目标

围绕 `log_message` 的输出路径执行真实漏洞挖掘，验证系统是否能直接识别用户可控字符串进入格式化位置的风险。

### 入口与处理链

- 主入口：`log_message`
- 关键处理链：`log_message` -> `printf`
- 重点关注参数 `msg` 是否直接作为格式化模板使用

### 执行要求

1. 从入口参数出发，确认 `msg` 的可控性与最终使用位置。
2. 必须区分“作为普通字符串参数输出”和“作为格式化模板使用”两种语义。
3. 报告时要解释可利用性，而不是只说存在 `printf` 调用。

### 输出要求

- 优先保证召回率，但不能脱离代码事实臆测。
- 报告必须明确指出格式字符串参数位置与用户输入之间的对应关系。
