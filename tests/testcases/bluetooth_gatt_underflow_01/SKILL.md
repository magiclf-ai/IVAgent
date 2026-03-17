---
name: testcase-bluetooth-gatt-underflow-01
description: "系统测试 workflow: bluetooth_gatt_underflow_01"
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
tags: [eval, source, system_test, bluetooth, gatt, partial_validation]
---

## 系统测试 Workflow

### 通用目标

本 skill 用于评估 IVAgent 在蓝牙 GATT 响应构造路径上的漏洞挖掘能力，重点关注内存安全漏洞、整数安全漏洞、格式化字符串漏洞与跨函数数据流追踪。

### 通用分析策略

1. 将所有函数参数默认视为外部输入，重点跟踪长度参数、计数字段和指针参数。
2. 优先检查 `memcpy`、`strcpy`、`printf`、`malloc`、`free` 等危险 API。
3. 当污点数据跨函数传播时，主动创建 sub-agent 深入分析被调函数。
4. 报告漏洞时明确给出漏洞类型、位置、数据流、触发条件和修复建议。

### 测试目标

围绕 `build_read_multi_rsp` 的多属性读响应构造流程执行真实漏洞挖掘，重点验证系统是否能发现“前置容量检查遗漏长度前缀开销”导致的剩余空间判断失真。

### 入口与处理链

- 主入口：`build_read_multi_rsp`
- 关键处理链：`build_read_multi_rsp` -> `check_attr_fits`
- 重点关注 variable-length 模式下长度前缀与真实写入模式是否一致

### 执行要求

1. 从入口跟踪 handles、attribute data、remaining buffer space 的计算方式。
2. 必须检查 `check_attr_fits` 是否完整覆盖 variable-length 模式下的全部写入成本，而不是只比较属性数据长度。
3. 分析长度前缀写入后 `total_written`、`remaining`、后续 `memcpy` 的关系，确认是否存在跨步骤的边界失配。
4. 报告时要说明这是“局部校验存在但与真实写入模式不一致”的问题。

### 输出要求

- 优先保证召回率，但不能脱离代码事实臆测。
- 报告必须描述长度前缀、数据写入和缓冲区剩余空间三者之间的约束关系。
- 不要只报告单点 `memcpy`，要解释为什么前置校验没有真正覆盖该写入。
