---
name: eval-source-scan
description: "源码漏洞检测（评估专用）"
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
tags: [eval, source, generic, memory_safety]
---

## 评估 Skill

通用源码漏洞检测，用于评估框架测试。

### 分析目标

本 skill 用于评估 IVAgent 的漏洞检测能力，重点关注：

1. 内存安全漏洞
2. 整数安全漏洞
3. 格式化字符串漏洞
4. 跨函数数据流追踪

### 分析策略

1. 将所有函数参数默认视为外部输入，重点跟踪长度参数和指针参数。
2. 优先检查 `memcpy`、`strcpy`、`printf`、`malloc`、`free` 等危险 API。
3. 当污点数据跨函数传播时，主动创建 sub-agent 深入分析被调函数。
4. 报告漏洞时明确给出漏洞类型、位置、数据流和修复建议。

### 评估要求

- 用于评估时优先保证召回率。
- 对复杂数据流允许中等置信度，但必须给出证据。
- 跨函数分析时最多追踪 3 层调用深度。
