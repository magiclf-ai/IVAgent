---
name: testcase-baseband-rlc-reassembly-01
description: "系统测试 workflow: baseband_rlc_reassembly_01"
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
tags: [eval, source, system_test, baseband, fragment_reassembly, multi_stage]
---

## 系统测试 Workflow

### 通用目标

本 skill 用于评估 IVAgent 在复杂基带重组链上的漏洞挖掘能力，重点关注内存安全漏洞、整数安全漏洞、格式化字符串漏洞与跨函数数据流追踪。

### 通用分析策略

1. 将所有函数参数默认视为外部输入，重点跟踪长度参数、计数字段和指针参数。
2. 优先检查 `memcpy`、`strcpy`、`printf`、`malloc`、`free` 等危险 API。
3. 当污点数据跨函数传播时，主动创建 sub-agent 深入分析被调函数。
4. 报告漏洞时明确给出漏洞类型、位置、数据流、触发条件和修复建议。

### 测试目标

围绕 `rlc_process_data_blocks` 驱动的分片重组流程执行真实漏洞挖掘，重点验证系统是否能同时识别根因位于 `add_fragment` 的数组越界，以及后续在 `concatenate_fragments` 中触发的堆溢出后果。

### 入口与处理链

- 主入口：`rlc_process_data_blocks`
- 关键处理链：`rlc_process_data_blocks` -> `add_fragment` -> `validate_fragments` -> `concatenate_fragments`
- 重点关注描述符固定数组、元数据污染与后续分配/拷贝不一致

### 执行要求

1. 先从入口理解 fragment 个数、offset、size 等字段如何流入 `FragmentDescriptor`。
2. 必须验证 `add_fragment` 中固定数组写入是否有容量上界，以及越界后会污染哪些相邻元数据字段。
3. 继续分析被污染的 `total_size`、`allocated_size`、`n_blocks` 如何影响 `validate_fragments` 与 `concatenate_fragments`。
4. 报告时要区分“根因”和“可利用后果”，说明这是否构成多阶段漏洞链。

### 输出要求

- 优先保证召回率，但不能脱离代码事实臆测。
- 若同时发现根因和后果，需明确说明两者之间的数据依赖关系。
- 不要只停留在单点 `memcpy` 报警，必须解释它为何会在前序结构体污染后变得可利用。
