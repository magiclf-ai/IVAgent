---
name: testcase-uaf-cross-func-01
description: "系统测试 workflow: uaf_cross_func_01"
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
tags: [eval, source, system_test, uaf, cross_function]
---

## 系统测试 Workflow

### 通用目标

本 skill 用于评估 IVAgent 在跨函数 UAF 场景下的漏洞挖掘能力，重点关注内存安全漏洞、整数安全漏洞、格式化字符串漏洞与跨函数数据流追踪。

### 通用分析策略

1. 将所有函数参数默认视为外部输入，重点跟踪长度参数、计数字段和指针参数。
2. 优先检查 `memcpy`、`strcpy`、`printf`、`malloc`、`free` 等危险 API。
3. 当污点数据跨函数传播时，主动创建 sub-agent 深入分析被调函数。
4. 报告漏洞时明确给出漏洞类型、位置、数据流、触发条件和修复建议。

### 测试目标

围绕 `process_data` 的对象生命周期管理流程执行真实漏洞挖掘，验证系统是否能识别“释放后未清空全局引用”导致的跨函数 use-after-free。

### 入口与处理链

- 主入口：`process_data`
- 关键处理链：`process_data` -> `free_buffer` -> `use_buffer`
- 重点关注全局指针 `global_buf` 的生命周期和释放后状态

### 执行要求

1. 从入口建立对象分配、释放、再次访问的时序关系。
2. 必须检查 `free_buffer` 是否只释放内存而未同步清空全局引用。
3. 继续分析 `use_buffer` 是否在看似非空的条件下使用已释放对象。
4. 报告时要同时给出 free 点和 use 点，并解释为何两者在控制流上可连通。

### 输出要求

- 优先保证召回率，但不能脱离代码事实臆测。
- 报告必须说明悬挂指针为何仍可被后续路径访问。
