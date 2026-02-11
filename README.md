# IVAgent - 智能漏洞分析系统

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

IVAgent (Intelligent Vulnerability Analysis Agent) 是一个基于大语言模型(LLM)的智能漏洞挖掘系统，支持多种分析引擎和二进制/源码分析场景。

## 核心特性

- **多引擎支持**: IDA Pro (二进制)、JEB (Android)、ABC-Decompiler (HarmonyOS)、Source Code (源码)
- **递归深度分析**: 基于调用链的深度漏洞挖掘，支持跨函数分析
- **约束传播**: 支持污点源追踪和参数约束在调用链中的传播
- **智能调度**: LLM 驱动的 Workflow 编排和任务调度
- **可视化**: 完整的 Web 界面支持日志追踪、漏洞管理和 Agent 执行可视化

## 快速开始

### 安装依赖

```bash
pip install -r requirements.txt
```

### 环境配置

```bash
export OPENAI_API_KEY="your-api-key"
export OPENAI_BASE_URL="https://api.openai.com/v1"  # 可选
export OPENAI_MODEL="gpt-4"  # 可选
```

### 启动 IDA RPC 服务器

```bash
# 在 IDA Pro 中加载 IDB 后运行
python start_ida_rpc.py --idb /path/to/binary.i64 --port 9999
```

### 运行漏洞扫描

```bash
# 扫描单个函数
python ivagent_scan.py -e ida -t /path/to/binary.i64 -f "sub_140001000" --preset binary

# 扫描多个函数
python ivagent_scan.py -e ida -t /path/to/binary.i64 -f "func1" -f "func2" -c 5
```

### 运行 Workflow 分析

```bash
python orchestrator_cli.py --workflow workflows/android_sql_injection.md -e ida -t /path/to/target
```

### 启动 Web 可视化界面

```bash
python launch_web.py
# 访问 http://localhost:8080
```

llm 日志交互

![alt text](llm-log-image.png)


漏洞信息
![alt text](vuln-web-image.png)



## 项目架构

```
ivas/
├── ivagent/                    # 核心包
│   ├── agents/                 # Agent 实现
│   │   ├── deep_vuln_agent.py  # 深度漏洞挖掘 Agent (核心)
│   │   ├── callsite_agent.py   # 调用点解析 Agent
│   │   ├── function_summary_agent.py  # 函数摘要 Agent
│   │   └── prompts.py          # 提示词模板
│   ├── backends/               # 后端适配器
│   │   ├── ida/                # IDA Pro 适配器
│   │   ├── jeb/                # JEB 适配器
│   │   └── abc_decompiler/     # ABC 反编译器适配器
│   ├── core/                   # 核心组件
│   │   ├── llm_logger.py       # LLM 调用日志
│   │   ├── agent_logger.py     # Agent 执行日志
│   │   ├── vuln_storage.py     # 漏洞存储
│   │   └── tool_llm_client.py  # Tool Call 客户端
│   ├── engines/                # 分析引擎
│   │   ├── base_static_analysis_engine.py  # 引擎基类
│   │   ├── ida_engine.py       # IDA 引擎
│   │   ├── jeb_engine.py       # JEB 引擎
│   │   ├── abc_engine.py       # ABC 引擎
│   │   ├── source_code_engine.py  # 源码引擎
│   │   └── factory.py          # 引擎工厂
│   ├── models/                 # 数据模型
│   │   ├── constraints.py      # 约束和上下文
│   │   ├── vulnerability.py    # 漏洞模型
│   │   └── workflow.py         # Workflow 模型
│   ├── orchestrator/           # 任务编排
│   │   ├── orchestrator_agent.py  # 编排 Agent
│   │   ├── workflow_parser.py  # Workflow 解析器
│   │   └── tools.py            # 编排工具集
│   ├── scanner.py              # 扫描器主类
│   └── web/                    # Web 界面
│       ├── server.py           # Web 服务器
│       ├── api.py              # REST API
│       └── static/             # 静态资源
├── preconditions/              # 预置条件配置
│   ├── _template.md            # 模板
│   ├── android.md              # Android 入口分析
│   ├── binary.md               # 二进制分析
│   └── harmony.md              # HarmonyOS 分析
├── workflows/                  # Workflow 定义
│   ├── android_sql_injection.md
│   ├── arkts_ability_hijack.md
│   └── rpc_server_analysis.md
├── ivagent_scan.py             # 扫描 CLI
├── orchestrator_cli.py         # Workflow CLI
├── launch_web.py               # Web 启动器
└── start_ida_rpc.py            # IDA RPC 启动器
```

## 核心概念

### 1. DeepVulnAgent - 深度漏洞挖掘

系统的核心 Agent，采用多轮对话和 Tool Call 机制：

- **Tool Call 机制**: LLM 通过调用工具主动获取信息
- **递归分析**: 创建子 Agent 深入分析调用链
- **约束传播**: 父函数向子函数传递参数约束
- **增量保存**: 漏洞发现后立即保存到数据库

主要工具:
- `get_function_summary_tool`: 获取子函数摘要
- `create_sub_agent_tool`: 创建子 Agent 深入分析
- `report_vulnerability_tool`: 报告发现的漏洞
- `finalize_analysis_tool`: 完成分析

### 2. 分析引擎 (Engine)

统一的引擎接口支持多种后端：

```python
# 创建引擎
from ivagent.engines.factory import create_engine

engine = create_engine(
    "ida",
    target_path="/path/to/binary.i64",
    host="127.0.0.1",
    port=9999
)

# 获取函数定义
func_def = await engine.get_function_def(function_identifier="sub_140001000")

# 获取调用点
sites = await engine.get_callee(function_identifier)
```

### 3. 前置条件 (Precondition)

用于描述目标函数的已知约束，帮助 Agent 更精准地分析：

```yaml
---
name: "Android Entry Point"
description: "Android Activity/Service 入口点分析"
target: android_entry
taint_sources:
  - "intent.getStringExtra()"
  - "bundle.getSerializable()"
---

## 参数说明
- `param1`: 参数说明
- `param2`: 污点数据，需要严格检查
```

### 4. Workflow 编排

LLM 驱动的任务规划，通过 Markdown 文档描述分析意图：

```markdown
---
name: "Android SQL 注入漏洞挖掘"
description: "针对 Android 应用的 SQL 注入分析"
---

## 分析范围
重点关注 ContentProvider 和数据库操作代码

## 工作流
1. 搜索可能的 ContentProvider
2. 分析对外暴露的回调函数
3. 对暴露接口开展漏洞挖掘
```

## 配置说明

### Precondition 配置

Precondition 用于描述函数的已知约束和特性：

```python
from ivagent.models.constraints import Precondition

# 从文本创建
precondition = Precondition.from_text(
    name="Entry Point Analysis",
    text_content="""
## 参数约束
- param1: 用户可控输入
- param2: 内核分配对象，可信

## 关注点
1. 污点追踪
2. 危险操作检查
""",
    taint_sources=["param1", "user_input"]
)
```

### 引擎配置

支持的环境变量:

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `OPENAI_API_KEY` | LLM API Key | - |
| `OPENAI_BASE_URL` | API 基础 URL | - |
| `OPENAI_MODEL` | 模型名称 | gpt-4 |
| `LLM_LOG_STORAGE` | 日志存储类型 (sqlite/memory) | sqlite |

## API 参考

### 扫描器 API

```python
from ivagent.scanner import IVAgentScanner, ScanConfig

config = ScanConfig(
    engine_type="ida",
    target_path="/path/to/binary.i64",
    llm_api_key="your-key",
    llm_model="gpt-4",
    max_concurrency=10
)

scanner = IVAgentScanner(config)
results = await scanner.scan_functions(["func1", "func2"], precondition)
```

### 编排器 API

```python
from ivagent.orchestrator import TaskOrchestratorAgent

orchestrator = TaskOrchestratorAgent(
    llm_client=llm,
    engine_type="ida",
    target_path="/path/to/binary"
)

result = await orchestrator.execute_workflow("workflows/analysis.md")
```

## 漏洞输出格式

```json
{
  "vulnerabilities": [
    {
      "type": "BUFFER_OVERFLOW",
      "name": "缓冲区溢出",
      "description": "函数使用 memcpy 时未检查长度",
      "location": "sub_140001000: 第 15 行",
      "severity": 0.9,
      "confidence": 0.8,
      "data_flow": {
        "source": "用户输入",
        "sink": "局部缓冲区",
        "path_description": "污点传播路径"
      },
      "remediation": "添加长度检查",
      "metadata": {
        "call_stack": ["main", "process_input", "sub_140001000"],
        "evidence": ["代码证据行"]
      }
    }
  ]
}
```

## Web 界面功能

- **日志查询**: 查看 LLM 调用日志、支持筛选和搜索
- **Agent 追踪**: 可视化 Agent 执行树和调用链
- **漏洞管理**: 漏洞列表、详情、统计和状态管理
- **Tool Call 分析**: 查看工具调用详情和统计
- **实时推送**: WebSocket 实时更新

## 扩展开发

### 添加新的分析引擎

继承 `BaseStaticAnalysisEngine`:

```python
from ivagent.engines.base_static_analysis_engine import BaseStaticAnalysisEngine

class MyEngine(BaseStaticAnalysisEngine):
    async def get_function_def(self, function_identifier, **kwargs):
        # 实现获取函数定义
        pass
    
    async def get_callee(self, function_identifier):
        # 实现获取子函数调用
        pass
    
    async def _resolve_static_callsite(self, callsite, caller_identifier):
        # 实现调用点解析
        pass
```

### 添加新的 Agent

继承 `BaseAgent`:

```python
from ivagent.agents.base import BaseAgent

class MyAgent(BaseAgent):
    async def run(self, **kwargs) -> Dict[str, Any]:
        # 实现 Agent 逻辑
        pass
```

## 贡献指南

欢迎贡献代码、报告问题或提出改进建议！

## 许可证

MIT License
