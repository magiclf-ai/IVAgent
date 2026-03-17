---
name: testcase-bt-l2cap-fragment-uaf-01
description: "系统测试 workflow: bt_l2cap_fragment_uaf_01"
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
tags: [eval, source, system_test, bluetooth, l2cap, use_after_free]
---

## 系统测试 Workflow

### 通用目标

本 skill 用于评估 IVAgent 在蓝牙 L2CAP 分片重组错误处理链上的漏洞挖掘能力，重点关注内存安全漏洞、整数安全漏洞、格式化字符串漏洞与跨函数数据流追踪。

### 通用分析策略

1. 将所有函数参数默认视为外部输入，重点跟踪长度参数、计数字段和指针参数。
2. 优先检查 `memcpy`、`strcpy`、`printf`、`malloc`、`free` 等危险 API。
3. 当污点数据跨函数传播时，主动创建 sub-agent 深入分析被调函数。
4. 报告漏洞时明确给出漏洞类型、位置、数据流、触发条件和修复建议。

### 测试目标

围绕 `l2cap_recv_fragment` 驱动的重组和错误恢复流程执行真实漏洞挖掘，重点验证系统是否能在“校验失败后的清理路径”中识别 dangling pointer 与后续重用。

### 入口与处理链

- 主入口：`l2cap_recv_fragment`
- 关键处理链：`l2cap_recv_fragment` -> `find_or_create_entry` -> `append_fragment` -> `handle_reassembly_error` -> `process_completed_entries`
- 重点关注 oversized continuation 触发的错误路径与队列清理一致性

### 执行要求

1. 从入口梳理重组队列、entry 生命周期和 fragment 异常处理流程。
2. 必须检查 `handle_reassembly_error` 是否只释放对象而未同步更新队列或状态引用。
3. 继续分析 `process_completed_entries` 或后续流程是否会重新读取已释放对象的字段或内部缓冲区。
4. 报告时要给出“释放点”和“悬挂引用再次使用点”两端证据，说明中间状态如何保持可达。

### 输出要求

- 优先保证召回率，但不能脱离代码事实臆测。
- 若问题依赖特定报文序列，需在报告中描述触发顺序。
- 不要把错误处理路径当作不可达分支忽略。
