#!/usr/bin/env python3
"""
TaskOrchestratorAgent - LLM 驱动的任务规划 Agent

通过 Tools 暴露能力，由 LLM 自主决策执行流程。
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from pathlib import Path
import json
import asyncio

from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage


from ..models.workflow import WorkflowContext
from ..core import ToolBasedLLMClient
from ..core.context import ArtifactStore, MessageManager, ContextAssembler
from .workflow_parser import WorkflowParser
from .tools import OrchestratorTools




@dataclass
class OrchestratorResult:
    """Orchestrator 执行结果"""
    success: bool
    vulnerabilities_found: int
    report: str
    summary: str
    errors: List[str] = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []


class TaskOrchestratorAgent:
    """
    任务规划 Agent - LLM 驱动架构
    
    核心原则:
    - 不做任何硬编码决策，全部委托给 LLM
    - 通过 Tools 暴露能力，让 LLM 决定何时调用
    - Workflow 是"意图描述"，不是"配置"
    """

    def __init__(
        self,
        llm_client: ChatOpenAI,
        engine_type: Optional[str] = None,
        target_path: Optional[str] = None,
        source_root: Optional[str] = None,
        workflow_context: Optional[WorkflowContext] = None,
        verbose: bool = True,
        enable_logging: bool = True,
        session_id: Optional[str] = None,
        context_window_size: int = 12,
        max_inline_chars: int = 4000,
        artifacts_dir: Optional[str] = None,
    ):

        self.llm = llm_client
        self.workflow_context = workflow_context
        self.verbose = verbose
        self.enable_logging = enable_logging
        self.session_id = session_id or f"session_{id(self)}"
        self.agent_id = f"orchestrator_{id(self)}"
        self.context_window_size = context_window_size
        self.max_inline_chars = max_inline_chars
        self.artifacts_dir = artifacts_dir
        self.source_root = source_root
        
        # 初始化 Tools（如果提供了 engine_type 和 target_path 则立即初始化 engine）
        self.tools_manager = OrchestratorTools(
            llm_client=llm_client,
            workflow_context=workflow_context,
            engine_type=engine_type,
            target_path=target_path,
            source_root=source_root,
            session_id=self.session_id,
        )
        self.tools: List[Any] = []
        
        # 确定目标函数显示内容
        if target_path:
            target_function = target_path
        elif workflow_context and workflow_context.target and workflow_context.target.path:
            target_function = workflow_context.target.path
        elif workflow_context and workflow_context.name:
            target_function = f"workflow: {workflow_context.name}"
        else:
            target_function = "orchestrator"

        # 初始化 LLM Client Wrapper
        self.llm_client_wrapper = ToolBasedLLMClient(
            llm=self.llm,
            max_retries=3,
            retry_delay=1.0,
            verbose=self.verbose,
            enable_logging=self.enable_logging,
            session_id=self.session_id,
            agent_id=self.agent_id,
            log_metadata={
                "agent_type": "orchestrator",
                "target_function": target_function,
            },
        )

        # 初始化上下文管理组件
        artifact_dir = self._resolve_artifact_dir(source_root)
        self.artifact_store = ArtifactStore(artifact_dir)
        self.message_manager = MessageManager(
            artifact_store=self.artifact_store,
            summary_provider=self._summarize_large_content,
            max_inline_chars=self.max_inline_chars,
        )
        self.context_assembler = ContextAssembler(
            message_manager=self.message_manager,
            recent_message_limit=self.context_window_size,
        )
        self.tools_manager.set_artifact_store(self.artifact_store)
        
        # 初始化新的任务编排组件（简化设计）
        self._init_orchestrator_components()
        
        self.tools = self.tools_manager.get_tools()


    def _log(self, message: str, level: str = "info"):
        """打印日志"""
        if self.verbose:
            prefix = "[Orchestrator]"
            if level == "error":
                print(f"  [X] {prefix} {message}")
            elif level == "warning":
                print(f"  [!] {prefix} {message}")
            elif level == "success":
                print(f"  [+] {prefix} {message}")
            else:
                print(f"  [*] {prefix} {message}")

    def _init_orchestrator_components(self):
        """初始化简化的任务编排组件（TaskListManager, FileManager, AgentDelegate）"""
        # 确定 session 目录
        session_dir = self._resolve_session_dir()
        
        # 初始化 OrchestratorTools 的新组件
        self.tools_manager.initialize_orchestrator_components(session_dir)
        
        self._log(f"初始化 session 目录: {session_dir}")

    def _resolve_session_dir(self) -> Path:
        """确定 session 目录路径"""
        if self.artifacts_dir:
            base_dir = Path(self.artifacts_dir)
        else:
            base_root = Path(self.source_root) if self.source_root else Path.cwd()
            base_dir = base_root / ".ivagent" / "sessions"
        
        return base_dir / self.session_id

    def _resolve_artifact_dir(self, source_root: Optional[str]) -> Path:
        """确定 Artifact 落盘目录"""
        if self.artifacts_dir:
            return Path(self.artifacts_dir)
        base_root = Path(source_root) if source_root else Path.cwd()
        session = self.session_id or self.agent_id
        return base_root / ".ivagent_artifacts" / "orchestrator" / session

    async def _summarize_large_content(self, content: str, metadata: Optional[Dict[str, Any]] = None) -> str:
        """使用 LLM 对大文本生成摘要"""
        meta = metadata or {}
        tool_name = meta.get("tool_name", "")
        tool_hint = f"工具: {tool_name}\n" if tool_name else ""
        prompt = (
            f"{tool_hint}请对以下内容生成精简摘要，保留关键结论与指标，字数不超过200字：\n\n"
            f"{content}"
        )
        try:
            return (await self.llm_client_wrapper.atext_call(
                messages=[HumanMessage(content=prompt)],
                system_prompt="你是一个上下文压缩助手，只输出纯文本摘要。",
            )).strip()
        except Exception:
            return ""

    async def execute_workflow(self, workflow_path: str = None, target_path: str = None) -> OrchestratorResult:
        """
        执行 Workflow 文档（简化版）

        新的执行流程：
        1. 解析 Workflow 文档（如果提供了 workflow_path）
        2. 引导 LLM 调用 plan_tasks() 规划任务（如果提供了 workflow_path）
        3. 循环引导 LLM 调用 execute_next_task() 执行任务
        4. 检测所有任务完成后结束

        Args:
            workflow_path: Workflow 文件路径（可选，如果为 None 则跳过解析和规划）
            target_path: 目标程序路径（可选，如果 workflow 中未指定）

        Returns:
            OrchestratorResult 执行结果
        """
        # 如果提供了 workflow_path，则解析 Workflow
        if workflow_path:
            self._log(f"读取 Workflow 文档: {workflow_path}")

            try:
                parser = WorkflowParser()
                self.workflow_context = parser.parse_and_validate(workflow_path)
            except Exception as e:
                return OrchestratorResult(
                    success=False,
                    vulnerabilities_found=0,
                    report="",
                    summary=f"Failed to parse workflow: {e}",
                    errors=[str(e)],
                )

            # 异步初始化引擎（如果有待处理的引擎配置）
            if not self.tools_manager._initialized:
                self._log("正在初始化分析引擎...")
                try:
                    # 从 workflow 或参数获取目标路径
                    workflow_target = None
                    if self.workflow_context and self.workflow_context.target:
                        workflow_target = self.workflow_context.target.path
                    final_target = target_path or workflow_target

                    initialized = await self.tools_manager.initialize(target_path=final_target)
                    if not initialized:
                        return OrchestratorResult(
                            success=False,
                            vulnerabilities_found=0,
                            report="",
                            summary="Failed to initialize engine: no engine configuration provided",
                            errors=["Engine initialization failed: engine_type and target_path are required"],
                        )
                    self._log("分析引擎初始化成功", "success")
                    
                    # 重新初始化 orchestrator 组件（需要 engine）
                    self._init_orchestrator_components()
                    
                except Exception as e:
                    return OrchestratorResult(
                        success=False,
                        vulnerabilities_found=0,
                        report="",
                        summary=f"Engine initialization failed: {e}",
                        errors=[str(e)],
                    )

            # 更新 Tools 的 Workflow 上下文
            self.tools_manager.workflow_context = self.workflow_context

            self._log("Workflow 解析成功")
            self._log(f"名称: {self.workflow_context.name}")

            # 使用运行时传入的 target_path 或 workflow 中的 target
            final_target = target_path or (self.workflow_context.target.path if self.workflow_context.target else None)
            if final_target:
                self._log(f"目标: {final_target}")

            # 构建规划 Prompt（引导 LLM 使用简化的 Tools）
            planning_prompt = self._build_simplified_planning_prompt(target_path=final_target)

            # 让 LLM 自主规划并执行
            await self.message_manager.add_user_message(planning_prompt)
        else:
            # workflow_path=None: 跳过解析和规划，直接进入任务执行循环
            self._log("跳过 Workflow 解析，直接进入任务执行循环")

        max_iterations = 20
        iteration = 0
        errors = []

        try:
            while True:
                iteration += 1
                self._log(f"执行迭代 {iteration}/{max_iterations}")

                # 检查是否超过最大迭代次数
                if iteration > max_iterations:
                    self._log(f"达到最大迭代次数 {max_iterations}，结束执行", "warning")
                    break

                # 组装上下文并调用 LLM
                assembled_messages = self.context_assembler.build_messages(
                    system_prompt=self._get_simplified_system_prompt(),
                )
                
                result = await self.llm_client_wrapper.atool_call(
                    messages=assembled_messages,
                    tools=self.tools,
                    system_prompt=None,
                )

                # 记录 AI 消息
                await self.message_manager.add_ai_message(
                    result.content or "",
                    tool_calls=result.tool_calls,
                )

                # 检查是否有 Tool 调用
                if not result.tool_calls:
                    # 如果没有 tool calls，说明 LLM 认为任务已完成
                    self._log("LLM 完成执行，结束", "success")
                    break

                # 并发执行所有 Tool 调用
                async def execute_single_tool(tool_call: Dict[str, Any]) -> ToolMessage:
                    """执行单个 tool call 并返回 ToolMessage"""
                    tool_name = tool_call.get("name", "")
                    tool_args = tool_call.get("args", {})
                    tool_id = tool_call.get("id", "")

                    self._log(f"Tool 调用: {tool_name}")

                    try:
                        result_data = await self._execute_tool(tool_name, tool_args)

                        if isinstance(result_data, dict) and result_data.get("error"):
                            self._log(f"Tool 错误: {result_data['error']}", "warning")
                            errors.append(f"{tool_name}: {result_data['error']}")

                        # Tool 返回字符串时直接传递，其他类型序列化为 JSON
                        if isinstance(result_data, str):
                            content = result_data
                        else:
                            content = json.dumps(result_data, ensure_ascii=False)

                        await self.message_manager.add_tool_message(
                            content=content,
                            tool_name=tool_name,
                            tool_call_id=tool_id,
                        )

                        return ToolMessage(
                            content=content,
                            tool_call_id=tool_id,
                            name=tool_name,
                        )

                    except Exception as e:
                        error_msg = str(e)
                        self._log(f"Tool 执行失败: {error_msg}", "error")
                        errors.append(f"{tool_name}: {error_msg}")

                        error_content = json.dumps({"error": error_msg}, ensure_ascii=False)
                        await self.message_manager.add_tool_message(
                            content=error_content,
                            tool_name=tool_name,
                            tool_call_id=tool_id,
                        )

                        return ToolMessage(
                            content=error_content,
                            tool_call_id=tool_id,
                            name=tool_name,
                        )

                # 并发执行所有 tool calls
                if result.tool_calls:
                    tool_tasks = [
                        execute_single_tool(tc) for tc in result.tool_calls
                    ]
                    await asyncio.gather(*tool_tasks)

            # 最终结果报告
            self._log("任务执行完成", "success")

            return OrchestratorResult(
                success=True,
                vulnerabilities_found=len(self.tools_manager.vulnerabilities),
                report="分析完成",
                summary="分析完成",
                errors=errors,
            )

        except Exception as e:
            error_msg = str(e)
            self._log(f"执行失败: {error_msg}", "error")
            return OrchestratorResult(
                success=False,
                vulnerabilities_found=0,
                report="",
                summary=f"Execution failed: {error_msg}",
                errors=errors + [error_msg],
            )

    async def _execute_tool(self, tool_name: str, tool_args: Dict[str, Any]) -> Dict[str, Any]:

        """执行指定的 Tool"""
        tool_map = {
            # 简化的任务编排工具（新设计）
            "plan_tasks": self.tools_manager.plan_tasks,
            "execute_next_task": self.tools_manager.execute_next_task,
            "get_task_status": self.tools_manager.get_task_status,
            "read_task_output": self.tools_manager.read_task_output,
            # 统一的 Agent 委托接口
            "delegate_task": self.tools_manager.delegate_task,
            # 数据访问工具
            "read_artifact": self.tools_manager.read_artifact,

        }

        tool_func = tool_map.get(tool_name)
        if not tool_func:
            return {"error": f"Unknown tool: {tool_name}"}

        return await tool_func(**tool_args)

    def _get_simplified_system_prompt(self) -> str:

        """获取简化版的 Orchestrator 系统提示词"""
        return """# 角色定义

你是一个任务编排 Agent，负责规划和执行漏洞挖掘任务。

# 工作流程

你的工作分为两个阶段：

## 阶段 1: 规划阶段

1. 阅读 Workflow 文档，理解分析目标和要求
2. 调用 `plan_tasks(workflows)` 创建任务列表
   - 将 Workflow 拆解为具体的、可执行的子任务
   - 每个任务应该清晰、独立、可验证
   - 为每个任务提供 agent_type（code_explorer / vuln_analysis）
   - **vuln_analysis 任务必须显式提供 function_identifier**
   - **若 vuln_analysis 的 function_identifier 未确定：必须先调用 `delegate_task(agent_type="code_explorer", ...)`，要求使用 `search_symbol` 查找并输出标准标识符；得到结果后再调用 `plan_tasks`**
   - **function_identifier 必须原样复制 `search_symbol` 的输出，不得自行推断或改写**
   - 支持单 workflow 和多 workflow 模式
3. 你会看到完整的任务列表和状态

### 单 Workflow 模式

如果整个分析是一个连贯的流程，使用单 workflow：

```json
{
    "workflows": [
        {
            "tasks": [
                {
                    "description": "任务1描述",
                    "agent_type": "code_explorer"
                },
                {
                    "description": "任务2描述",
                    "agent_type": "vuln_analysis",
                    "function_identifier": "Lcom/example/Target;->method(Ljava/lang/String;)V"
                }
            ]
        }
    ]
}
```

### 多 Workflow 模式

如果发现存在多个独立的分析流程，使用多 workflow：

```json
{
    "workflows": [
        {
            "workflow_id": "wf_component_a",
            "workflow_name": "组件A分析",
            "workflow_description": "分析组件A的安全问题",
            "tasks": [
                {
                    "description": "搜索组件A",
                    "agent_type": "code_explorer"
                },
                {
                    "description": "分析组件A的漏洞",
                    "agent_type": "vuln_analysis",
                    "function_identifier": "Lcom/example/A;->query(Ljava/lang/String;)Ljava/lang/String;"
                }
            ]
        },
        {
            "workflow_id": "wf_component_b",
            "workflow_name": "组件B分析",
            "workflow_description": "分析组件B的安全问题",
            "tasks": [
                {
                    "description": "搜索组件B",
                    "agent_type": "code_explorer"
                },
                {
                    "description": "分析组件B的漏洞",
                    "agent_type": "vuln_analysis",
                    "function_identifier": "Lcom/example/B;->doQuery()V"
                }
            ]
        }
    ]
}
```

### 何时使用多 Workflow

使用多 workflow 的场景：
- 分析多个独立的组件（如 ContentProvider、BroadcastReceiver）
- 分析多个独立的漏洞类型（如 SQL注入、命令注入）
- 分析多个独立的攻击面（如网络接口、文件接口）

关键判断标准：**这些分析流程是否可以完全独立执行，互不依赖**

## 阶段 2: 执行阶段

1. 循环调用 `execute_next_task()` 执行任务
   - 先判断任务类型：
     - 代码探索/信息收集/定位/汇总代码事实 → code_explorer
     - 漏洞挖掘/风险评估/触发条件推导/证据链构建 → vuln_analysis
   - **凡是漏洞挖掘相关任务，必须使用 vuln_analysis**，禁止用 code_explorer 输出漏洞结论
   - 若需先收集信息再分析：先用 code_explorer 获取证据，再创建/继续 vuln_analysis 任务
   - 提供必要的 additional_context
2. 每次执行后，你会看到：
   - 当前任务的执行结果
   - 完整的任务列表和状态
3. 根据任务列表判断是否继续执行
4. 当所有任务完成时，总结结果并结束


## 阶段 3: 完成阶段

当所有任务完成时：
1. 总结整体分析结果
2. 汇总发现的漏洞
3. 提供最终报告

# 可用工具

## 核心工具

- `plan_tasks(workflows)`: 规划任务列表（原则上先调用；若需 function_identifier，先通过 delegate_task(code_explorer) 使用 search_symbol 获取）
  - task 支持字符串或对象；对象字段包括 description / agent_type / function_identifier
  - vuln_analysis 任务必须显式提供 function_identifier
  - function_identifier 必须来自 search_symbol 的验证结果，保持原样
- `execute_next_task(agent_type: str, additional_context: str = "")`: 执行下一个任务
  - agent_type: "code_explorer" 或 "vuln_analysis"
  - additional_context: 补充说明、约束条件等

## 辅助工具

- `get_task_status()`: 获取当前任务列表状态
- `read_task_output(task_id: str)`: 读取指定任务的输出

# 重要原则

1. **漏洞挖掘优先使用 vuln_analysis**：凡是漏洞发现、风险评估、触发条件推导、证据链构建，都必须由 vuln_analysis 执行；code_explorer 仅用于检索/定位/汇总代码事实
2. **任务拆解要合理**：每个任务应该独立、清晰、可执行
3. **选择合适的 Agent**：
   - code_explorer: 代码探索、搜索、定位与事实收集
   - vuln_analysis: 漏洞挖掘、风险评估、证据链与触发条件分析
4. **提供充分的上下文**：在 additional_context 中提供必要的背景信息
5. **关注任务状态**：每次执行后检查任务列表，判断下一步行动
6. **及时总结**：所有任务完成后，提供清晰的总结报告


# 示例流程

```
1. 调用 plan_tasks() 规划任务
   → 看到任务列表：2 个任务待执行

2. 调用 execute_next_task(agent_type="code_explorer")
   → 看到任务 1 完成，1 个任务待执行

3. 调用 execute_next_task(agent_type="vuln_analysis", additional_context="重点关注缓冲区溢出")
   → 看到任务 2 完成，所有任务完成

4. 总结结果，结束执行
```

## 任务间信息传递

### 读取前置任务输出

- 执行任务后，输出可能包含 [ARTIFACT_REF:xxx] 引用
- 使用 `read_task_output(task_id)` 读取前置任务的完整输出
- 从输出中提取关键信息（如函数ID、上下文）传递给下一个任务

### 传递信息的最佳实践

当执行 vuln_analysis 任务时，**function_identifier 必须在 plan_tasks 阶段显式提供**。
additional_context 中重点提供：

1. **函数签名和位置**：帮助 Agent 定位和理解函数

2. **前置条件和约束**：
   - 参数来源（用户输入、外部数据等）
   - 已知的验证逻辑
   - 相关的安全约束

3. **上下文引用**：如果需要详细信息，引用 artifact
   - 格式：`详细上下文: [ARTIFACT_REF:abc123]`

### 示例

```
# 执行代码探索任务
execute_next_task(agent_type="code_explorer")

# 输出示例：
# ## 探索结果
# 找到2个函数：
# 1. 函数ID: `com.example.Parser.parse`
#    签名: public void parse(String input)
#    位置: Parser.java:45
#    说明: 解析用户输入，未做验证
# [ARTIFACT_REF:abc123]

# 执行漏洞分析任务，传递提取的信息
execute_next_task(
    agent_type="vuln_analysis",
    additional_context='''
函数签名: public void parse(String input)
位置: Parser.java:45

前置条件：
- 参数 input 来自用户输入
- 未做长度验证

详细上下文: [ARTIFACT_REF:abc123]
    '''
)
```

**关键原则**：
- function_identifier 必须在 plan_tasks 中显式提供，保持原样，不要修改
- 用自然语言清晰描述前置条件
- 如果信息不完整，先读取 artifact 获取详细内容

现在开始执行你的任务。
"""

    def _build_simplified_planning_prompt(self, target_path: str = None) -> str:
        """构建简化版的规划 Prompt"""
        if not self.workflow_context:
            return "No workflow context available."

        # 确定目标路径
        final_target = target_path or (
            self.workflow_context.target.path 
            if self.workflow_context.target and self.workflow_context.target.path 
            else None
        )

        lines = [
            "# Workflow 分析任务",
            "",
            f"## 名称",
            f"{self.workflow_context.name}",
            "",
            f"## 描述",
            f"{self.workflow_context.description}",
            "",
        ]

        if final_target:
            lines.extend([
                f"## 目标",
                f"{final_target}",
                "",
            ])

        if self.workflow_context.scope:
            lines.extend([
                f"## 分析范围",
                f"{self.workflow_context.scope.description}",
                "",
            ])

        if self.workflow_context.vulnerability_focus:
            lines.extend([
                f"## 漏洞关注点",
            ])
            for vuln in self.workflow_context.vulnerability_focus:
                lines.append(f"- {vuln}")
            lines.append("")

        if self.workflow_context.background_knowledge:
            lines.extend([
                f"## 背景知识",
                f"{self.workflow_context.background_knowledge}",
                "",
            ])

        if self.workflow_context.raw_markdown:
            lines.extend([
                f"## 完整 Workflow 文档",
                f"```markdown",
                f"{self.workflow_context.raw_markdown}",
                f"```",
                "",
            ])

        lines.extend([
            "## 你的任务",
            "",
            "1. 理解上述 Workflow 的目标和要求",
            "2. 若存在 vuln_analysis 但 function_identifier 未确定：先调用 `delegate_task(agent_type=\"code_explorer\")` 使用 `search_symbol` 查找并返回标准标识符",
            "3. 调用 `plan_tasks()` 将 Workflow 拆解为具体的子任务",
            "4. 然后循环调用 `execute_next_task()` 执行每个任务",
            "5. 所有任务完成后，总结分析结果",
            "",
            "若需要 function_identifier，请先完成 search_symbol 验证；然后调用 `plan_tasks()` 规划任务列表。",
        ])

        return "\n".join(lines)

# 便捷函数
async def run_workflow(
    workflow_path: str,
    llm_client: ChatOpenAI,
    engine_type: str,
    target_path: str,
    source_root: Optional[str] = None,
    verbose: bool = True,
    enable_logging: bool = True,
    session_id: Optional[str] = None,
) -> OrchestratorResult:
    """
    便捷函数：执行 Workflow
    
    Args:
        workflow_path: Workflow 文件路径
        llm_client: LLM 客户端
        engine_type: 引擎类型 (ida, jeb, abc, source)
        target_path: 目标程序路径
        source_root: 源代码根目录（可选）
        verbose: 是否打印详细日志
        enable_logging: 是否启用 LLM 交互日志记录
        session_id: 会话 ID（用于日志追踪）
        
    Returns:
        执行结果
    """
    orchestrator = TaskOrchestratorAgent(
        llm_client=llm_client,
        engine_type=engine_type,
        target_path=target_path,
        source_root=source_root,
        verbose=verbose,
        enable_logging=enable_logging,
        session_id=session_id,
    )
    return await orchestrator.execute_workflow(workflow_path, target_path=target_path)
