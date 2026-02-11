# IVAgent: 基于大语言模型的智能漏洞挖掘系统

## 前言

在软件安全领域，漏洞挖掘一直是一项复杂而耗时的工作。传统的静态分析工具虽然能够发现一些明显的漏洞模式，但面对复杂的业务逻辑和跨函数调用链时往往力不从心。近年来，随着大语言模型(LLM)能力的提升，我们开始探索如何利用 AI 来增强漏洞挖掘的效率和准确性。

本文将介绍 IVAgent (Intelligent Vulnerability Analysis Agent) 的设计与实现，这是一个融合了大语言模型智能分析能力和传统静态分析工具的系统。

## 项目背景

### 传统漏洞挖掘的挑战

1. **复杂调用链分析困难**: 现代软件往往包含多层函数调用，传统工具难以有效追踪跨函数的数据流
2. **业务逻辑理解不足**: 静态规则难以理解复杂的业务逻辑和约束条件
3. **误报率高**: 缺乏上下文的分析容易产生大量误报
4. **分析深度有限**: 传统符号执行等方法在处理大型代码库时面临路径爆炸问题

### LLM 带来的新可能

大语言模型展现出强大的代码理解和推理能力：
- 能够理解复杂的代码逻辑和约束条件
- 可以进行跨函数的语义分析
- 能够学习并应用安全知识
- 支持交互式分析，动态获取信息

## 系统设计方案

### 整体架构

IVAgent 采用**分层设计**，核心组件包括：

```
┌─────────────────────────────────────────────────────┐
│                 用户界面层                           │
│  (CLI / Web UI / API)                               │
├─────────────────────────────────────────────────────┤
│                 编排调度层                           │
│  (Orchestrator / Task Manager / Workflow Parser)    │
├─────────────────────────────────────────────────────┤
│                 智能分析层                           │
│  (DeepVulnAgent / FunctionSummaryAgent / ...)       │
├─────────────────────────────────────────────────────┤
│                 引擎抽象层                           │
│  (IDA Engine / JEB Engine / Source Engine / ...)    │
├─────────────────────────────────────────────────────┤
│                 数据存储层                           │
│  (Vuln Storage / Log Storage / Cache)               │
└─────────────────────────────────────────────────────┘
```

### 核心设计理念

#### 1. 多轮对话 + Tool Call 机制

不同于传统的单次提示(prompt)方式，IVAgent 采用**多轮对话**模式：

```
第 1 轮: 提供完整上下文（函数代码、调用点、约束条件）
    ↓
LLM 分析 → Tool Call 请求（获取子函数摘要 / 创建子 Agent）
    ↓
第 2 轮: 返回 Tool 执行结果
    ↓
LLM 继续分析 → 可能发现漏洞或继续深入
    ↓
...
第 N 轮: finalize_analysis_tool 结束分析
```

这种设计的优势：
- **增量信息获取**: LLM 按需获取信息，避免一次性提供过多上下文
- **可控的递归深度**: 通过 Tool Call 控制递归分析深度
- **灵活的分析策略**: LLM 自主决定分析路径

#### 2. 约束传播机制

在跨函数分析中，**约束传播**是关键：

```python
# 父函数发现约束
父函数: process_input(buf, size)
    ↓ 调用
子函数: memcpy(dst, src, len)
    
# 传播约束到子函数
argument_constraints = [
    "src 指向用户可控数据（污点）",
    "len 最大为 1024 字节",
    "dst 是局部缓冲区，大小 256 字节"
]
```

约束以**纯文本**格式传播，降低了对 LLM 的结构化输出要求。

#### 3. 引擎抽象层

为了支持多种分析后端（IDA、JEB、源码等），设计了统一的引擎接口：

```python
class BaseStaticAnalysisEngine(ABC):
    @abstractmethod
    async def get_function_def(self, function_identifier) -> FunctionDef:
        """获取函数定义（代码、参数等）"""
        
    @abstractmethod
    async def get_callee(self, function_identifier) -> List[CallSite]:
        """获取函数内调用的子函数"""
        
    @abstractmethod
    async def resolve_function_by_callsite(self, callsite) -> str:
        """根据调用点解析函数签名"""
```

这种设计使得上层 Agent 代码与具体引擎解耦。

## 核心实现

### DeepVulnAgent 实现

DeepVulnAgent 是系统的核心分析组件，其实现要点：

#### Tool Call 定义

```python
def get_function_summary_tool(
    line_number: int,
    column_number: int,
    function_identifier: str,
    arguments: List[str],
    call_text: str,
) -> Dict[str, Any]:
    """获取子函数摘要"""
    
def create_sub_agent_tool(
    line_number: int,
    function_identifier: str,
    argument_constraints: List[str],
    reason: str,
) -> Dict[str, Any]:
    """创建子 Agent 深入分析"""
    
def report_vulnerability_tool(
    vuln_type: str,
    name: str,
    description: str,
    confidence: int,
    severity: str,
    data_flow_source: str,
    data_flow_sink: str,
) -> Dict[str, Any]:
    """报告发现的漏洞"""
```

#### 多轮对话流程

```python
async def _deep_analysis(self, function_identifier, context):
    # 初始化消息列表
    messages = [HumanMessage(content=initial_prompt)]
    
    for iteration in range(max_iterations):
        # LLM 分析
        result = await self._llm_analyze_with_messages(messages, context)
        
        # 处理 Tool Calls
        for tc in result.tool_calls:
            if tc['name'] == 'get_function_summary_tool':
                summary = await self._get_sub_function_summary(tc['args'])
                messages.append(ToolMessage(content=summary))
            elif tc['name'] == 'create_sub_agent_tool':
                self._start_sub_agent_background(tc['args'], context)
            elif tc['name'] == 'report_vulnerability_tool':
                self._save_vulnerability(tc['args'])
            elif tc['name'] == 'finalize_analysis_tool':
                return  # 分析完成
```

#### 递归深度控制

```python
async def _create_sub_agent(self, call_args, parent_context):
    # 检查调用深度
    if len(parent_context.call_stack) >= self.max_depth:
        return {"skipped": True, "reason": "max_depth"}
    
    # 检查循环调用
    if func_sig in parent_context.call_stack:
        return {"skipped": True, "reason": "circular_call"}
    
    # 创建子 Agent
    sub_agent = DeepVulnAgent(
        engine=self.engine,
        llm_client=self.llm_client,
        call_stack=parent_context.call_stack + [func_sig],
        max_depth=self.max_depth,
        parent_id=self.agent_id,
    )
```

### 调用点解析 (Callsite Resolution)

准确的调用点解析是跨函数分析的基础：

```python
async def resolve_function_by_callsite(
    self,
    callsite: CallsiteInfo,
    caller_identifier: str,
    caller_code: str,
) -> Optional[str]:
    # 1. 优先尝试静态分析解析
    signature = await self._resolve_static_callsite(callsite, caller_identifier)
    if signature:
        return signature
    
    # 2. 静态分析失败，使用 LLM 辅助解析
    if self._source_root and self._llm_client:
        agent = CallsiteAgent(
            llm_client=self._llm_client,
            source_root=self._source_root
        )
        result = await agent.run(callsite, caller_code)
        return result.function_identifier
```

### 前置条件 (Precondition)

Precondition 用于向 Agent 传递领域知识：

```python
@dataclass
class Precondition:
    name: str
    description: str
    text_content: str  # 纯文本格式，直接追加到 prompt
    taint_sources: List[str]  # 预定义的污点源
```

## Workflow 编排

对于复杂的分析任务，IVAgent 提供 Workflow 编排能力：

```python
class TaskOrchestratorAgent:
    async def execute_workflow(self, workflow_path: str):
        # 1. 解析 Workflow
        context = WorkflowParser().parse(workflow_path)
        
        # 2. LLM 自主规划
        messages = [SystemMessage(content=system_prompt)]
        
        while True:
            result = await llm.atool_call(messages, tools)
            
            # 执行 Tool Calls
            for tc in result.tool_calls:
                await self._execute_tool(tc['name'], tc['args'])
            
            # 检查任务完成
            if task_manager.all_completed():
                break
```

Workflow 使用 Markdown 描述分析意图：

```markdown
---
name: "Android SQL 注入分析"
---

## 分析范围
重点关注 ContentProvider 的 query/update/delete 方法

## 工作流
1. 搜索所有 ContentProvider 实现类
2. 分析对外暴露的 URI
3. 检查 selection 参数的校验

## 漏洞关注点
- rawQuery 的参数拼接
- execSQL 的动态 SQL 构造
```

## 可视化与可观测性

### LLM 调用日志

记录每次 LLM 调用的详细信息：
- 输入消息、系统提示词
- 输出响应、Tool Calls
- 延迟、重试次数
- Token 使用量

### Agent 执行追踪

追踪每个 Agent 的执行状态：
- Agent 类型、目标函数
- 调用深度、调用链
- 发现的漏洞数量
- 创建的子 Agent

### Web 界面

提供完整的 Web UI：
- 日志查询和筛选
- Agent 执行树可视化
- 漏洞管理和统计
- Tool Call 分析

## 使用示例

### 场景 1: 二进制漏洞挖掘

```bash
# 1. 启动 IDA RPC 服务器
python start_ida_rpc.py --idb driver.i64 --port 9999

# 2. 运行扫描
python ivagent_scan.py \
    -e ida -t driver.i64 \
    -f "sub_140001000" \
    --preset binary \
    --output results.json
```

### 场景 2: Android 应用分析

```bash
python ivagent_scan.py \
    -e jeb -t app.apk \
    -f "com.example.MainActivity.onCreate" \
    --preset android \
    -c 5
```

### 场景 3: Workflow 编排

```bash
python orchestrator_cli.py \
    --workflow workflows/android_sql_injection.md \
    -e ida -t app.apk \
    --source-root /path/to/source
```

## 性能优化

### 并发控制

```python
# 使用信号量控制并发
semaphore = asyncio.Semaphore(max_concurrency)

async def _scan_single(idx, sig):
    async with semaphore:
        return await agent.run(sig)
```

### 请求去重

```python
# 避免重复请求相同函数摘要
if func_name in requested_summaries:
    continue
requested_summaries.add(func_name)
```

### 缓存机制

- 函数定义缓存
- 函数摘要缓存
- LLM 响应缓存

## 局限性与改进方向

### 当前局限

1. **LLM 成本**: 大规模分析时 API 调用成本较高
2. **响应延迟**: LLM 调用有几百毫秒到数秒的延迟
3. **上下文限制**: 长函数代码可能超出 LLM 上下文窗口
4. **幻觉问题**: LLM 可能产生不准确的分析结果

### 改进方向

1. **本地模型支持**: 集成开源 LLM 降低使用成本
2. **增量分析**: 只分析修改的函数，利用历史结果
3. **RAG 增强**: 结合向量数据库存储和检索安全知识
4. **多模型集成**: 使用多个模型投票减少幻觉

## 总结

IVAgent 是一个探索性的项目，尝试将大语言模型的智能分析能力与传统的静态分析工具相结合。通过 Tool Call 机制、约束传播、递归分析等设计，系统能够在复杂的调用链中发现深层漏洞。

虽然 LLM 在漏洞挖掘中的应用仍处于早期阶段，但我们相信随着模型能力的提升和工程方法的成熟，AI 驱动的漏洞挖掘将成为安全领域的重要方向。

## 参考

- [LangChain](https://github.com/langchain-ai/langchain) - LLM 应用框架
- [IDA Pro](https://hex-rays.com/ida-pro/) - 交互式反汇编器
- [JEB Decompiler](https://www.pnfsoftware.com/) - Android 反编译器

---

**项目地址**: https://github.com/your-org/ivagent  
**文档**: https://ivagent.readthedocs.io  
**问题反馈**: https://github.com/your-org/ivagent/issues
