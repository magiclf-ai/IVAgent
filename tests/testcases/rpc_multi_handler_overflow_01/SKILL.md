---
name: testcase-rpc-multi-handler-overflow-01
description: "系统测试 workflow: rpc_multi_handler_overflow_01"
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
tags: [eval, source, system_test, rpc, nested_tlv, multi_handler]
---

## 系统测试 Workflow

### 通用目标

本 skill 用于评估 IVAgent 在 RPC dispatcher 多 handler 场景下的漏洞挖掘能力，重点关注内存安全漏洞、整数安全漏洞、格式化字符串漏洞与跨函数数据流追踪。

### 通用分析策略

1. 将所有函数参数默认视为外部输入，重点跟踪长度参数、计数字段和指针参数。
2. 优先检查 `memcpy`、`strcpy`、`printf`、`malloc`、`free` 等危险 API。
3. 当污点数据跨函数传播时，主动创建 sub-agent 深入分析被调函数。
4. 报告漏洞时明确给出漏洞类型、位置、数据流、触发条件和修复建议。

### 测试目标

围绕 `rpc_dispatch` 的多 handler 路由和 CONFIG 嵌套 TLV 解析流程执行真实漏洞挖掘，重点验证系统是否能区别安全 handler 与危险 handler，并在 `parse_nested_config` 中识别多类边界缺失。

### 入口与处理链

- 主入口：`rpc_dispatch`
- 关键处理链：`rpc_dispatch` -> `handle_config` -> `parse_nested_config` -> `parse_tlv`
- 对比路径：PING 与 QUERY handler 为安全参考路径
- 重点关注 entry 数量、`val_len`、`MAX_CONFIG_ENTRIES` 与 `MAX_VALUE_LEN`

### 执行要求

1. 先从 dispatcher 角度理解不同 handler 的外层校验行为，再下钻到 CONFIG 分支。
2. 必须检查 `parse_tlv` 的边界校验是否只保证“可读”，而未保证“可安全写入目标结构体”。
3. 在 `parse_nested_config` 中分别分析条目数量约束和单个值长度约束，不要混为一个问题。
4. 报告时可用 QUERY handler 的安全模式作为对照，说明 CONFIG 分支遗漏了哪些关键约束。

### 输出要求

- 优先保证召回率，但不能脱离代码事实臆测。
- 若发现多个独立问题，需分别给出位置和数据流，不要用“CONFIG handler 不安全”替代具体结论。
