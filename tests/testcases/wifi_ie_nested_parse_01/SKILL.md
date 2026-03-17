---
name: testcase-wifi-ie-nested-parse-01
description: "系统测试 workflow: wifi_ie_nested_parse_01"
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
tags: [eval, source, system_test, wifi, nested_parsing, partial_validation]
---

## 系统测试 Workflow

### 通用目标

本 skill 用于评估 IVAgent 在 WiFi IE 嵌套解析场景下的漏洞挖掘能力，重点关注内存安全漏洞、整数安全漏洞、格式化字符串漏洞与跨函数数据流追踪。

### 通用分析策略

1. 将所有函数参数默认视为外部输入，重点跟踪长度参数、计数字段和指针参数。
2. 优先检查 `memcpy`、`strcpy`、`printf`、`malloc`、`free` 等危险 API。
3. 当污点数据跨函数传播时，主动创建 sub-agent 深入分析被调函数。
4. 报告漏洞时明确给出漏洞类型、位置、数据流、触发条件和修复建议。

### 测试目标

围绕 `process_mgmt_frame` 的 IE 和 sub-element 解析流程执行真实漏洞挖掘，重点验证系统是否能在多个并列解析器中识别“一个路径安全、另一路径遗漏数组容量校验”的不一致实现。

### 入口与处理链

- 主入口：`process_mgmt_frame`
- 关键处理链：`process_mgmt_frame` -> `parse_vendor_ie` -> `parse_cipher_suites`
- 对比路径：`process_mgmt_frame` -> `parse_vendor_ie` -> `parse_pmkid_list`
- 重点关注 count、byte budget 与固定数组上界的关系

### 执行要求

1. 先从外层 frame/IE 边界校验出发，确认它们只保证子块在输入缓冲区内可读。
2. 必须分别分析 cipher suites 与 PMKID list 两个子解析器，确认它们是否执行了同样完整的数量校验。
3. 报告时要明确指出“byte budget 校验存在，但数组容量校验缺失”的不一致点。

### 输出要求

- 优先保证召回率，但不能脱离代码事实臆测。
- 报告需用安全路径与危险路径对比来支撑结论，而不是只给单点 memcpy 告警。
