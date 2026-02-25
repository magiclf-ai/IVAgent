# IVAgent：基于 LLM Tool Call Loop 的智能漏洞挖掘系统设计与实现

## 摘要

本文深入探讨 IVAgent（Intelligent Vulnerability Analysis Agent）的系统设计与关键技术实现。IVAgent 采用 Multi-Agent 架构，基于 LLM Tool Call Loop 机制，实现了对二进制程序、Android 应用、HarmonyOS 应用的智能化漏洞挖掘。文章重点分析系统的核心技术选型决策，包括为何选择原生 Tool Call Loop 而非 LangChain 等框架、约束传播机制的设计考量、递归子 Agent 的实现策略等。

---

## 一、问题背景与技术挑战

### 1.1 传统漏洞挖掘的局限性

传统静态漏洞挖掘工具（如 IDA Pro 插件、CodeQL、Semgrep）主要依赖预定义的规则模式：

```
规则示例：检测 strcpy 危险函数
if (calls_function("strcpy") && !has_length_check()):
    report("Potential buffer overflow")
```

这种方式存在明显局限：

| 问题 | 具体表现 |
|------|----------|
| **规则僵化** | 只能检测已知模式，难以发现变体或新型漏洞 |
| **语义理解缺失** | 无法理解代码意图，误报率高 |
| **上下文断层** | 难以追踪跨函数、跨模块的数据流 |
| **可扩展性差** | 新漏洞类型需要编写新规则 |

### 1.2 LLM 应用于漏洞挖掘的核心挑战

将 LLM 应用于漏洞挖掘面临几个关键技术挑战：

**挑战一：上下文窗口限制**

单个函数可能包含数千行代码，加上调用链上下游，容易超出 LLM 上下文窗口。

**挑战二：被动分析能力不足**

单次请求模式下，LLM 无法主动获取额外信息（如子函数实现、全局变量定义），导致分析不完整。

**挑战三：幻觉问题**

LLM 可能「编造」不存在的漏洞或遗漏真实漏洞，缺乏验证机制。

**挑战四：调用链深度分析**

漏洞往往隐藏在多层调用链深处，需要递归分析能力。

---

## 二、系统架构设计

### 2.1 分层架构

IVAgent 采用四层架构设计：

```
┌─────────────────────────────────────────────────────┐
│                 接口层                               │
│  (CLI / Web UI / REST API)                          │
├─────────────────────────────────────────────────────┤
│                 编排层                               │
│  (TaskOrchestratorAgent / TaskManager / Workflow)   │
├─────────────────────────────────────────────────────┤
│                 分析层                               │
│  (DeepVulnAgent / FunctionSummaryAgent)             │
├─────────────────────────────────────────────────────┤
│                 引擎层                               │
│  (IDA Engine / JEB Engine / ABC Engine / Source)    │
└─────────────────────────────────────────────────────┘
```

### 2.2 引擎抽象层设计

为屏蔽不同分析工具的 API 差异，设计统一抽象接口：

```python
class BaseStaticAnalysisEngine(ABC):
    """静态分析引擎抽象基类"""
    
    @abstractmethod
    async def get_function_def(self, function_identifier: str) -> FunctionDef:
        """获取函数定义（签名、参数、代码）"""
        pass
    
    @abstractmethod
    async def get_callee(self, function_identifier: str) -> List[CallSite]:
        """获取函数的调用目标"""
        pass
    
    @abstractmethod
    async def get_caller(self, function_identifier: str) -> List[CallSite]:
        """获取函数的调用者"""
        pass
    
    @abstractmethod
    async def search_symbol(self, query: str) -> List[SearchResult]:
        """符号搜索（支持正则）"""
        pass
    
    @abstractmethod
    async def get_xrefs_to(self, address: int) -> List[XRef]:
        """获取交叉引用"""
        pass
```

**设计考量**：

1. **异步优先**：所有 IO 操作设计为异步，支持高并发分析场景
2. **批量接口**：提供 `batch_get_function_defs` 减少网络往返开销
3. **符号抽象**：使用 `function_identifier` 而非地址，兼容不同工具的标识体系

---

## 三、核心技术选型分析

### 3.1 为什么选择原生 Tool Call Loop 而非 LangChain？

这是 IVAgent 设计中最核心的技术决策之一。

#### 3.1.1 LangChain 的架构限制

LangChain 采用 Chain 抽象组织处理流程：

```python
# LangChain 典型模式
chain = SequentialChain(
    chains=[step1, step2, step3],
    input_variables=["input"],
    output_variables=["output"]
)
```

**问题分析**：

| 维度 | LangChain 限制 | 漏洞分析需求 |
|------|---------------|-------------|
| **控制流** | 线性链式执行 | 需要条件分支、循环、递归 |
| **状态管理** | 基于字典的简单状态 | 需要复杂的上下文累积 |
| **决策点** | 预定义在 Chain 中 | 需要运行时动态决策 |
| **递归支持** | 需要额外封装 | 原生支持递归子 Agent |

#### 3.1.2 原生 Tool Call Loop 的优势

IVAgent 采用基于 LLM 原生 Tool Call 的迭代循环：

```python
async def tool_call_loop(self, messages: List[BaseMessage], max_iterations: int = 15):
    """Tool Call 驱动的主循环"""
    
    for iteration in range(max_iterations):
        # LLM 决策下一步行动
        result = await self.tool_llm.atool_call(
            messages=messages,
            tools=self.available_tools,
        )
        
        # 记录 LLM 响应（包含 tool_calls）
        messages.append(AIMessage(
            content=result.content,
            tool_calls=result.tool_calls,
        ))
        
        # 并发执行所有工具调用
        tool_results = await asyncio.gather(*[
            self.execute_tool(tc) for tc in result.tool_calls
        ])
        messages.extend(tool_results)
        
        # 检查终止条件
        if self.should_finalize(result.tool_calls):
            break
    
    return self.extract_vulnerabilities(messages)
```

**核心优势**：

1. **动态决策能力**：LLM 根据中间结果动态选择下一步操作
2. **条件分支**：通过 Tool 选择实现自然的条件分支
3. **递归支持**：`create_sub_agent` 工具触发递归分析
4. **上下文累积**：`messages` 列表自然累积分析上下文
5. **零抽象开销**：直接使用 LLM API，无中间层

#### 3.1.3 对比总结

```
┌────────────────┬─────────────────────┬─────────────────────┐
│     维度        │      LangChain      │   Tool Call Loop    │
├────────────────┼─────────────────────┼─────────────────────┤
│ 控制流         │ 线性 Chain          │ 动态 Tool 选择      │
│ 状态管理       │ 显式定义            │ 消息列表自然累积    │
│ 决策机制       │ 预定义              │ LLM 运行时决策      │
│ 递归支持       │ 需额外实现          │ 原生支持            │
│ 调试复杂度     │ 框架层抽象多        │ 流程清晰可追踪      │
│ 性能开销       │ 中间层开销          │ 接近原生 API        │
│ 学习曲线       │ 需理解框架概念      │ 直接理解 Tool Call  │
└────────────────┴─────────────────────┴─────────────────────┘
```

### 3.2 为什么不用 RAG？

RAG（Retrieval-Augmented Generation）是另一种常见的 LLM 增强方案，但不适用于漏洞分析场景。

#### 3.2.1 RAG 的适用场景

RAG 适合**知识检索**场景：
- 问答系统
- 文档搜索
- 知识库查询

#### 3.2.2 漏洞分析的特殊性

漏洞分析需要的是**结构化查询**而非语义检索：

```python
# 需要的查询类型
get_function_def("memcpy_wrapper")      # 精确获取函数定义
get_callee("process_request")           # 获取调用目标
get_caller("dangerous_func")            # 获取调用者
search_symbol("sql.*query")             # 正则搜索符号
```

**RAG 的问题**：

1. **精度不足**：语义检索可能返回不相关的代码片段
2. **结构信息丢失**：RAG 分块处理，丢失函数边界、调用关系
3. **查询延迟**：向量检索 + 重排序增加延迟
4. **更新成本**：代码变更需要重建向量索引

#### 3.2.3 IVAgent 的方案

采用**精确查询 + 摘要缓存**：

```python
# 函数摘要缓存
summary_cache: Dict[str, FunctionSummary] = {}

async def get_function_summary(self, func_id: str) -> FunctionSummary:
    if func_id in self.summary_cache:
        return self.summary_cache[func_id]
    
    # 获取函数定义
    func_def = await self.engine.get_function_def(func_id)
    
    # LLM 生成摘要
    summary = await self.generate_summary(func_def)
    
    self.summary_cache[func_id] = summary
    return summary
```

### 3.3 约束传播：为什么用纯文本而非结构化格式？

当分析跨多层函数调用时，需要在调用链中传递参数约束信息。

#### 3.3.1 结构化方案的问题

```python
# 结构化约束（需要严格 JSON 格式）
{
    "arguments": [
        {
            "name": "buf",
            "type": "char*",
            "constraints": [
                {"type": "tainted", "source": "user_input"},
                {"type": "max_length", "value": 1024}
            ]
        }
    ]
}
```

**问题**：
1. LLM 输出 JSON 需要严格格式遵循
2. 嵌套结构增加 token 消耗
3. 格式错误导致解析失败

#### 3.3.2 纯文本方案

```python
@dataclass
class CallStackFrame:
    function_identifier: str
    call_line: int
    call_code: str
    argument_constraints: List[str]  # 纯文本约束

# 约束示例
argument_constraints = [
    "参数1 buf: 污点数据，来自用户输入，最大1024字节",
    "参数2 len: 可信，已检查 len > 0 && len <= 1024"
]
```

**优势**：
1. **容错性强**：即使格式不完美，信息仍可理解
2. **Token 高效**：无 JSON 语法开销
3. **LLM 友好**：自然语言格式更符合 LLM 输出习惯
4. **人类可读**：便于调试和审查

### 3.4 异步架构设计考量

IVAgent 全面采用异步架构：

```python
# 引擎层异步
async def get_function_def(self, func_id: str) -> FunctionDef

# Agent 层异步
async def analyze(self, context: FunctionContext) -> AnalysisResult

# 工具执行异步
async def execute_tool(self, tool_call: ToolCall) -> ToolResult
```

**设计考量**：

1. **并发分析**：多个函数可同时分析
2. **IO 等待优化**：网络请求不阻塞其他任务
3. **子 Agent 并行**：多个子 Agent 同时执行

---

## 四、Tool Call 工具集设计

### 4.1 工具定义

IVAgent 定义了四个核心工具：

```python
# 工具 1：获取函数摘要
@tool
def get_function_summary(
    line_number: int,          # 调用行号
    function_identifier: str,  # 目标函数
    arguments: List[str],      # 参数名称列表
    call_text: str,           # 调用代码文本
) -> FunctionSummary:
    """获取子函数的行为摘要和参数约束"""
    pass

# 工具 2：创建递归子 Agent
@tool
def create_sub_agent(
    function_identifier: str,
    argument_constraints: List[str],
    reason: str,
) -> SubAgentHandle:
    """创建子 Agent 进行深度分析"""
    pass

# 工具 3：报告漏洞
@tool
def report_vulnerability(
    vuln_type: str,
    name: str,
    description: str,
    location: str,
    confidence: int,
    severity: str,
) -> None:
    """报告发现的安全漏洞"""
    pass

# 工具 4：结束分析
@tool
def finalize_analysis(
    analysis_summary: str,
) -> None:
    """结束分析流程"""
    pass
```

### 4.2 工具执行流程

```
┌──────────────────────────────────────────────────────────────┐
│                    Tool Call 执行流程                         │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────┐    ┌─────────┐    ┌─────────────────────┐      │
│  │ LLM     │───▶│ 解析    │───▶│ 并发执行工具调用    │      │
│ │ Response │    │ToolCalls│    │ asyncio.gather()   │      │
│  └─────────┘    └─────────┘    └─────────────────────┘      │
│                                        │                     │
│                                        ▼                     │
│                              ┌─────────────────────┐        │
│                              │   工具结果合并       │        │
│                              │   messages.extend() │        │
│                              └─────────────────────┘        │
│                                        │                     │
│                                        ▼                     │
│                              ┌─────────────────────┐        │
│                              │   下一轮 LLM 调用    │        │
│                              └─────────────────────┘        │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### 4.3 去重机制

避免重复请求相同的函数摘要：

```python
class ToolExecutor:
    def __init__(self):
        self.requested_summaries: Set[str] = set()
        self.created_agents: List[str] = []
    
    async def execute_tool(self, tool_call: ToolCall):
        if tool_call.name == "get_function_summary":
            func_id = tool_call.args["function_identifier"]
            
            # 去重检查
            if func_id in self.requested_summaries:
                return ToolResult(
                    tool_call_id=tool_call.id,
                    content=f"已在本次分析中获取过 {func_id} 的摘要"
                )
            
            self.requested_summaries.add(func_id)
            return await self._fetch_summary(func_id)
```

---

## 五、递归子 Agent 机制

### 5.1 调用链追踪

每个 Agent 维护调用栈信息：

```python
@dataclass
class FunctionContext:
    function_identifier: str
    
    # 调用链追踪
    call_stack: List[str]              # 简单链 ["main", "parse", "decode"]
    call_stack_detailed: List[CallStackFrame]  # 详细帧
    
    # 深度控制
    depth: int
    max_depth: int = 3
```

### 5.2 循环检测

防止无限递归：

```python
def check_recursion(self, func_sig: str, call_stack: List[str]) -> bool:
    """检测循环调用"""
    return func_sig in call_stack[:-1]

def check_depth(self, call_stack: List[str], max_depth: int) -> bool:
    """检测深度超限"""
    return len(call_stack) > max_depth
```

### 5.3 后台执行模式

子 Agent 采用「fire-and-forget」异步模式：

```python
def start_sub_agent_background(self, call_args, parent_ctx):
    """后台启动子 Agent，不阻塞主分析流程"""
    
    async def run_sub_agent():
        result = await self.create_and_run_sub_agent(call_args, parent_ctx)
        # 子 Agent 发现的漏洞自动合并到共享存储
        
    task = asyncio.create_task(run_sub_agent())
    self.background_tasks.append(task)
```

**优势**：
1. 主流程继续分析其他分支
2. 多个子 Agent 并发执行
3. 结果自动汇总

---

## 六、Prompt 工程设计

### 6.1 系统提示词结构

```python
DEEP_VULN_SYSTEM_PROMPT = """
你是一台**专家级漏洞挖掘引擎**。核心任务是基于源码片段、污点上下文
和约束条件，精准挖掘内存安全与逻辑漏洞。

必须具备编译器级别的代码理解能力，精通控制流图 (CFG) 和数据流分析 (DFA)。

## 分析协议

1. **上下文审查**：检查已知函数摘要和已运行的子Agent
2. **污点追踪**：识别源 → 追踪流 → 定位汇
3. **约束求解**：判断路径检查是否有效清洗污点
4. **批量工具决策**：扫描全函数，一次性输出所有工具调用
5. **约束准备**：创建子Agent前，必须先获取函数摘要

## 漏洞分类

| 标识符 | 核心判定逻辑 |
|--------|-------------|
| BUFFER_OVERFLOW | 写入长度 > 容量，无边界检查 |
| ARRAY_OOB | 数组索引可控且超出范围 |
| ARBITRARY_RW | 指针地址完全可控 |
| FORMAT_STRING | 格式串由攻击者控制 |
| SQL_INJECTION | 用户输入拼接SQL |
| USE_AFTER_FREE | free后未置NULL仍解引用 |

## 效率规则

1. 优先批量调用：扫描后一次性返回所有独立工具调用
2. 准确传递约束：基于调用点代码和子函数摘要
3. 避免重复：检查 created_agents_list
"""
```

### 6.2 上下文注入

动态注入分析上下文：

```python
def build_analysis_prompt(self, context: FunctionContext) -> str:
    return f"""
## 当前分析目标

函数: {context.function_identifier}
深度: {context.depth}/{context.max_depth}
调用链: {' → '.join(context.call_stack)}

## 函数代码

```
{context.function_code}
```

## 参数约束（来自父函数）

{format_constraints(context.argument_constraints)}

## 已分析的子函数摘要

{format_summaries(context.known_summaries)}

## 已创建的子 Agent

{format_created_agents(context.created_agents)}

请根据以上信息进行分析。
"""
```

---

## 七、Workflow 模式实现

### 7.1 Workflow 定义

使用 Markdown 格式定义分析工作流：

```markdown
---
name: "Android SQL 注入漏洞挖掘"
description: 针对 Android 应用的 SQL 注入分析
---

## 分析范围
重点关注 ContentProvider 和数据库操作代码

## 工作流
1. 搜索可能的 ContentProvider
2. 分析对外暴露的回调函数
3. 对暴露接口开展漏洞挖掘

## 漏洞关注点
- rawQuery 的参数拼接
- execSQL 的动态 SQL 构造
```

### 7.2 Workflow 解析与执行

```python
class WorkflowParser:
    def parse(self, workflow_path: str) -> WorkflowContext:
        """解析 Workflow 文档"""
        with open(workflow_path) as f:
            content = f.parse(f.read())
        
        return WorkflowContext(
            name=frontmatter.get('name'),
            description=frontmatter.get('description'),
            analysis_scope=self.extract_section(content, '分析范围'),
            workflow_steps=self.extract_section(content, '工作流'),
            vulnerability_focus=self.extract_section(content, '漏洞关注点'),
        )
```

### 7.3 Orchestrator Agent

```python
class TaskOrchestratorAgent:
    """任务编排 Agent"""
    
    async def execute_workflow(self, workflow: WorkflowContext):
        # 构建规划提示词
        planning_prompt = self.build_planning_prompt(workflow)
        
        messages = [SystemMessage(ORCHESTRATOR_PROMPT), 
                    HumanMessage(planning_prompt)]
        
        while not self.all_tasks_completed():
            result = await self.llm.atool_call(messages, tools)
            messages.append(AIMessage(result))
            
            tool_results = await self.execute_tools(result.tool_calls)
            messages.extend(tool_results)
```

---

## 八、性能优化策略

### 8.1 并发控制

```python
class ConcurrencyController:
    def __init__(self, max_concurrent: int = 10):
        self.semaphore = asyncio.Semaphore(max_concurrent)
    
    async def run_with_limit(self, coro):
        async with self.semaphore:
            return await coro
```

### 8.2 缓存策略

```python
class AnalysisCache:
    """多层缓存"""
    
    def __init__(self):
        self.summary_cache: Dict[str, FunctionSummary] = {}
        self.def_cache: Dict[str, FunctionDef] = {}
        self.xref_cache: Dict[str, List[XRef]] = {}
```

### 8.3 增量更新

```python
def update_messages_incremental(self, messages: List[BaseMessage], 
                                 new_result: AnalysisResult):
    """增量更新消息，避免重复发送完整上下文"""
    # 只添加增量信息
    messages.append(ToolResult(
        content=json.dumps({
            "new_vulnerabilities": new_result.vulnerabilities,
            "new_summaries": new_result.summaries,
        })
    ))
```

---

## 九、与其他方案的对比

### 9.1 与 LangChain Agent 的对比

| 维度 | LangChain Agent | IVAgent Tool Call Loop |
|------|----------------|------------------------|
| 执行模型 | 预定义 Chain + Agent | 纯 Tool Call 驱动 |
| 递归支持 | 需要自定义 Runnable | 原生支持递归子 Agent |
| 状态管理 | 需要显式管理 | 消息列表自然累积 |
| 调试难度 | 框架层多，追踪困难 | 流程清晰，每步可见 |
| Token 效率 | 中间层增加消耗 | 接近原生 |

### 9.2 与传统静态分析工具的对比

| 维度 | 传统工具 (CodeQL/Semgrep) | IVAgent |
|------|---------------------------|---------|
| 检测机制 | 规则匹配 | 语义理解 |
| 漏洞类型 | 预定义模式 | 可扩展理解 |
| 误报处理 | 需人工过滤 | LLM 可解释判断 |
| 调用链分析 | 固定深度 | 动态递归 |
| 报告质量 | 模板化 | 自然语言 + 证据 |

### 9.3 与单次 LLM 请求的对比

| 维度 | 单次请求 | Tool Call Loop |
|------|---------|----------------|
| 信息获取 | 被动 | 主动 |
| 上下文 | 受限于窗口 | 累积式扩展 |
| 分析深度 | 单函数 | 跨函数递归 |
| 结果验证 | 无 | 多轮确认 |

---

## 十、实战案例分析

### 10.1 分析目标

```java
public void handleRequest(String uri, String body) {
    if (uri == null || body == null) return;
    
    String decoded = URLDecoder.decode(body, "UTF-8");
    processData(decoded);
    
    String query = "SELECT * FROM logs WHERE uri = '" + uri + "'";
    executeQuery(query);
}
```

### 10.2 Tool Call 执行序列

```
=== 迭代 1 ===
LLM: 发现两个可疑调用点，需要获取更多信息
Tool Calls:
  - get_function_summary("URLDecoder.decode", ...)
  - get_function_summary("processData", ...)
  - get_function_summary("executeQuery", ...)

=== 迭代 2 ===
Tool Results:
  - URLDecoder.decode: 安全，标准解码函数
  - processData: 需进一步分析，可能存在缓冲区操作
  - executeQuery: 危险！SQL执行函数

LLM: executeQuery 接收拼接的 SQL，存在注入风险；processData 需深入分析
Tool Calls:
  - create_sub_agent("processData", constraints=["参数来自用户输入，URL解码后"])
  - report_vulnerability(
      type="SQL_INJECTION",
      location="handleRequest:第8行",
      confidence=9,
      severity="HIGH"
    )

=== 迭代 3 ===
Tool Results:
  - 子 Agent 已启动（后台执行）
  - 漏洞已记录

LLM: 主流程分析完成，等待子 Agent 结果
Tool Calls:
  - finalize_analysis(summary="发现 SQL 注入漏洞，子 Agent 正在分析 processData")
```

---

## 十一、总结与展望

### 11.1 技术贡献

IVAgent 的核心技术创新包括：

1. **原生 Tool Call Loop**：摒弃 LangChain 等框架的线性约束，实现真正的动态决策
2. **约束传播机制**：纯文本格式的高容错调用链信息传递
3. **递归子 Agent**：支持动态深度的调用链分析
4. **引擎抽象层**：统一接口屏蔽底层工具差异

### 11.2 局限性

当前系统的局限：

1. **LLM 幻觉**：仍存在误报/漏报风险
2. **Token 成本**：复杂分析消耗大量 Token
3. **深度限制**：递归深度有限制（默认3层）
4. **语言覆盖**：主要支持 C/C++/Java/Kotlin

### 11.3 未来方向

1. **MCP 服务化**：封装为标准 MCP 服务
2. **多引擎支持**：集成 Ghidra、Binary Ninja
3. **漏洞利用生成**：从发现到 POC 的完整链路
4. **知识图谱增强**：构建漏洞模式知识库

---

**项目地址**：[https://github.com/magiclf-ai/IVAgent](https://github.com/magiclf-ai/IVAgent)
