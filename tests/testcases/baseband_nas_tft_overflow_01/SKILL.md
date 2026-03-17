---
name: testcase-baseband-nas-tft-overflow-01
description: "系统测试 workflow: baseband_nas_tft_overflow_01"
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
tags: [eval, source, system_test, baseband, tlv, cross_function]
---

## 系统测试 Workflow

### 通用目标

本 skill 用于评估 IVAgent 在复杂基带 TLV 解析链上的漏洞挖掘能力，重点关注内存安全漏洞、整数安全漏洞、格式化字符串漏洞与跨函数数据流追踪。

### 通用分析策略

1. 将所有函数参数默认视为外部输入，重点跟踪长度参数、计数字段和指针参数。
2. 优先检查 `memcpy`、`strcpy`、`printf`、`malloc`、`free` 等危险 API。
3. 当污点数据跨函数传播时，主动创建 sub-agent 深入分析被调函数。
4. 报告漏洞时明确给出漏洞类型、位置、数据流、触发条件和修复建议。

### 测试目标

围绕 `parse_tft_ie` 驱动的基带 NAS TFT 解析流程执行真实漏洞挖掘，重点验证系统是否能沿正常入口下钻到嵌套 packet filter/component 解析逻辑，并识别“字节预算校验存在但数组容量校验缺失”的问题。

### 入口与处理链

- 主入口：`parse_tft_ie`
- 关键处理链：`parse_tft_ie` -> `parse_packet_filter` -> `parse_component`
- 重点关注两阶段解析过程中长度校验与固定容量约束是否脱节

### 执行要求

1. 从 `parse_tft_ie` 进入，先理解外层 IE 长度校验，再继续跟踪内层 packet filter 的长度与组件数量来源。
2. 必须检查 `parse_packet_filter` 的 first pass 和 second pass 是否使用了不同的安全前提，尤其关注组件总字节数校验与 `components[]` 固定容量是否独立。
3. 若发现内层 component 数量由攻击者控制，必须继续确认该数量如何影响数组写入、指针保存或堆对象布局。
4. 报告时要说明漏洞是否需要跨函数分析才能成立，并把入口、内层解析器、最终危险写入点串联起来。

### 输出要求

- 优先保证召回率，但不能脱离代码事实臆测。
- 对复杂跨函数链路允许中等置信度，但必须给出证据锚点。
- 不要只给出“TLV 解析有风险”之类泛化判断，必须落到具体约束缺失点。
