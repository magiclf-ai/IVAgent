---
name: test-and-eval
description: "IVAgent 测试与评估工作流。修改代码后运行回归测试、LLM 语义评测和日志分析。当用户要求测试、验证、评估或回归检查时使用。"
user-invocable: true
allowed-tools: Bash, Read, Glob, Grep
tags: [test, eval, regression, validation]
---

## 测试与评估 Skill

本 skill 用于 IVAgent 开发后的自动化测试和回归验证，基于 LLM 语义理解的端到端评测框架。

### 使用场景

- 修改核心分析逻辑后的回归验证
- 添加新功能后的功能验证
- 性能优化后的效果评估
- CI/CD 流程中的自动化测试

### 前置要求

1. Redis 必须已启动
2. 使用项目虚拟环境 `.venv/bin/python`
3. 配置 LLM API 环境变量：
   ```bash
   OPENAI_API_KEY='your-api-key-1'
   OPENAI_BASE_URL='http://192.168.72.1:8317/v1'
   OPENAI_MODEL='gpt-5.2'
   ```

### 测试框架入口

CLI 入口：`tests/eval/cli.py`

支持的子命令：
- `list` - 列出所有测试用例
- `run` - 运行测试用例
- `evaluate` - LLM 语义评测
- `analyze` - LLM 日志分析
- `monitor` - 运行时监控
- `monitor-batch` - 批量回归运行时监控

## 快速开始

### 1. 列出测试用例

```bash
.venv/bin/python -m tests.eval.cli list
```

当前内置用例：
- `heap_overflow_01` - 简单堆缓冲区溢出
- `format_string_01` - 格式化字符串漏洞
- `cross_func_overflow_01` - 跨函数数据流缓冲区溢出
- `uaf_cross_func_01` - 跨函数 Use-After-Free
- `integer_overflow_chain_01` - 整数溢出链导致缓冲区溢出

### 2. 运行单个测试

```bash
OPENAI_API_KEY='your-api-key-1' \
OPENAI_BASE_URL='http://192.168.72.1:8317/v1' \
OPENAI_MODEL='gpt-5.2' \
.venv/bin/python -m tests.eval.cli run \
  --testcase heap_overflow_01 \
  --output-dir /tmp/ivagent_eval
```

### 3. 运行全部测试

```bash
OPENAI_API_KEY='your-api-key-1' \
OPENAI_BASE_URL='http://192.168.72.1:8317/v1' \
OPENAI_MODEL='gpt-5.2' \
.venv/bin/python -m tests.eval.cli run \
  --all \
  --engine source \
  --parallel 3 \
  --output-dir /tmp/ivagent_eval_all
```

### 4. 监控批量回归

另起一个命令持续观察批量进度：

```bash
OPENAI_API_KEY='your-api-key-1' \
OPENAI_BASE_URL='http://192.168.72.1:8317/v1' \
OPENAI_MODEL='gpt-5.2' \
.venv/bin/python -m tests.eval.cli monitor-batch \
  --results-dir /tmp/ivagent_eval_all \
  --interval 15
```

## 完整测试流程

### Step 1: 运行测试

```bash
OUTPUT_DIR=/tmp/eval_run_$(date +%s)
OPENAI_API_KEY='your-api-key-1' \
OPENAI_BASE_URL='http://192.168.72.1:8317/v1' \
OPENAI_MODEL='gpt-5.2' \
.venv/bin/python -m tests.eval.cli run \
  --all \
  --engine source \
  --parallel 3 \
  --output-dir $OUTPUT_DIR
```

建议同时再起一个命令持续监控：

```bash
OPENAI_API_KEY='your-api-key-1' \
OPENAI_BASE_URL='http://192.168.72.1:8317/v1' \
OPENAI_MODEL='gpt-5.2' \
.venv/bin/python -m tests.eval.cli monitor-batch \
  --results-dir $OUTPUT_DIR \
  --interval 15
```

### Step 2: LLM 语义评测

对已运行完成的结果进行语义评测：

单个测试用例：
```bash
OPENAI_API_KEY='your-api-key-1' \
OPENAI_BASE_URL='http://192.168.72.1:8317/v1' \
OPENAI_MODEL='gpt-5.2' \
.venv/bin/python -m tests.eval.cli evaluate \
  --results-dir $OUTPUT_DIR/heap_overflow_01 \
  --output $OUTPUT_DIR/heap_overflow_01/evaluation_report.md
```

批量评测：
```bash
OPENAI_API_KEY='your-api-key-1' \
OPENAI_BASE_URL='http://192.168.72.1:8317/v1' \
OPENAI_MODEL='gpt-5.2' \
.venv/bin/python -m tests.eval.cli evaluate \
  --results-dir $OUTPUT_DIR \
  --output $OUTPUT_DIR/evaluation_report.md
```

### Step 3: LLM 日志分析

对单次运行目录做 LLM 日志分析：

```bash
OPENAI_API_KEY='your-api-key-1' \
OPENAI_BASE_URL='http://192.168.72.1:8317/v1' \
OPENAI_MODEL='gpt-5.2' \
.venv/bin/python -m tests.eval.cli analyze \
  --run-dir $OUTPUT_DIR/heap_overflow_01 \
  --output $OUTPUT_DIR/heap_overflow_01/analysis_report.md
```

### Step 4: 运行时监控（可选）

适合长时间任务：

```bash
OPENAI_API_KEY='your-api-key-1' \
OPENAI_BASE_URL='http://192.168.72.1:8317/v1' \
OPENAI_MODEL='gpt-5.2' \
.venv/bin/python -m tests.eval.cli monitor \
  --run-dir $OUTPUT_DIR/heap_overflow_01 \
  --interval 10
```

## 运行产物

每个 testcase 运行目录下会生成：

- `run_summary.md` - 本次运行摘要
- `detection_results.md` - 检测出的漏洞 Markdown
- `llm_interactions.md` - 格式化后的 LLM 交互全文
- `agent_execution.md` - 格式化后的 Agent 执行过程
- `llm_logs.db` - LLM 日志数据库
- `agent_logs.db` - Agent 日志数据库
- `vulnerabilities.db` - 漏洞数据库

批量运行时，结果根目录还会生成：
- `RUNS.md` - 批量运行汇总
- `PROGRESS.md` - 批量运行实时进度
- `PROGRESS.json` - 批量运行机读状态

每个 testcase 目录还会生成：
- `console.log` - 该 testcase 的完整运行日志

### 推荐查看顺序

1. `run_summary.md` - 快速了解运行结果
2. `detection_results.md` - 查看检测到的漏洞
3. `evaluation_report.md` - 查看 LLM 评测结果
4. `llm_interactions.md` - 深入了解 LLM 交互过程
5. `agent_execution.md` - 深入了解 Agent 执行过程

## 评测原则

### 核心原则

- testcase ground truth 使用 `TESTCASE.md`
- 检测结果使用 Markdown
- 评测报告由 LLM 语义判断生成
- 日志分析由 LLM 阅读运行摘要生成
- 报告要求输出中文 Markdown

### 评测输入

评测不再依赖 `results.json`，而是直接读取：
- `run_summary.md`
- `detection_results.md`

sqlite 保留给程序内部统计和导出，用户优先查看 Markdown 文件。

## 日常开发验证

改动源码分析逻辑后，推荐最少执行：

```bash
# 1. 列出测试用例
.venv/bin/python -m tests.eval.cli list

# 2. 运行单个测试
OPENAI_API_KEY='your-api-key-1' \
OPENAI_BASE_URL='http://192.168.72.1:8317/v1' \
OPENAI_MODEL='gpt-5.2' \
.venv/bin/python -m tests.eval.cli run \
  --testcase heap_overflow_01 \
  --output-dir /tmp/ivagent_eval_dev

# 3. 评测结果
OPENAI_API_KEY='your-api-key-1' \
OPENAI_BASE_URL='http://192.168.72.1:8317/v1' \
OPENAI_MODEL='gpt-5.2' \
.venv/bin/python -m tests.eval.cli evaluate \
  --results-dir /tmp/ivagent_eval_dev/heap_overflow_01
```

## Codex 执行规范

长时间批量回归时，Codex 应默认执行以下流程：

1. 用 `run --all --parallel N` 启动批量回归，优先使用 `output/` 下的新目录保存产物。
2. 另起一个命令执行 `monitor-batch --results-dir <OUTPUT_DIR>` 持续观察运行状态。
3. 运行期间定时向用户汇报：
   - 已完成 / 总数
   - 当前 running testcase
   - 最近失败或异常 testcase
   - 是否出现长时间无进展
4. 批量运行结束后，再执行 `evaluate` 和必要的 `analyze`。

推荐并发度：

- 本地开发：`--parallel 2`
- 完整 source 回归：`--parallel 3`

除非明确需要复现单 testcase 时序问题，否则不要默认串行跑完整 `--all`。

## 测试用例格式

每个测试用例目录包含：

```text
tests/testcases/<name>/
├── TESTCASE.md
└── source/
    └── vuln.c
```

`TESTCASE.md` 用自然语言描述：
- 元数据（Engine、Skill、Entry Functions、Timeout、Tags）
- 入口函数
- 期望漏洞
- 数据流
- 根因
- 严重性

示例字段：

```markdown
# Test Case: heap_overflow_01

## Metadata
- **Engine**: source
- **Skill**: eval_source_scan
- **Entry Functions**: parse_packet
- **Timeout**: 300 seconds
- **Tags**: buffer_overflow, memcpy, heap
```

## 添加新测试用例

1. 在 `tests/testcases/` 下创建新目录
2. 创建 `TESTCASE.md`
3. 创建 `source/vuln.c`
4. 运行 `.venv/bin/python -m tests.eval.cli list` 验证被发现
5. 运行 `.venv/bin/python -m tests.eval.cli run --testcase your_testcase` 验证可执行

## 注意事项

- 当前项目按新方案开发，不做旧方案兼容层
- 当前测评链路优先使用 Markdown 文档而不是中间 JSON
- 所有测试用例当前都使用 `source` 引擎，无需外部逆向工具
- 评测报告和日志分析报告必须输出中文 Markdown
