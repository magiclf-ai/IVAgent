#!/usr/bin/env python3
"""
WorkflowAgent - 自主的 Workflow 执行 Agent

这是一个真正的 Agent 风格实现：
- 接收目标（goal），不是指令
- 自主决策如何达成目标
- 自主运行，不需要外部控制
"""

from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from pathlib import Path
import json
import time

from langchain_openai import ChatOpenAI

from ..engines import BaseStaticAnalysisEngine
from ..core import ToolBasedLLMClient
from ..core.context import MessageManager, ContextAssembler, ArtifactStore
from ..core.agent_logger import get_agent_log_manager, AgentStatus
from .tools import OrchestratorTools
from .task_list_manager import TaskListManager
from .file_manager import FileManager
from .agent_delegate import AgentDelegate


@dataclass
class WorkflowResult:
    """Workflow 执行结果"""
    workflow_id: str
    workflow_name: str
    goal: str
    success: bool
    completed_tasks: int
    total_tasks: int
    vulnerabilities_found: int
    execution_time: float
    summary: str
    errors: List[str]


class WorkflowAgent:
    """
    自主的 Workflow Agent
    
    核心特点：
    1. 目标驱动：接收一个明确的目标，自己决定如何达成
    2. 自主运行：不需要外部告诉它"下一步做什么"
    3. 完全独立：拥有独立的状态、上下文、工具
    
    使用方式：
        agent = WorkflowAgent(
            workflow_id="wf_1",
            workflow_name="ContentProvider SQL注入分析",
            goal="找出所有 ContentProvider 中的 SQL 注入漏洞",
            tasks=["搜索 ContentProvider", "分析漏洞"],
            llm_client=llm_client,
            engine=engine,
            session_dir=Path("./session"),
        )
        
        result = await agent.run()  # 自主运行
    """
    
    def __init__(
        self,
        workflow_id: str,
        workflow_name: str,
        goal: str,
        tasks: List[str],
        llm_client: ChatOpenAI,
        engine: BaseStaticAnalysisEngine,
        session_dir: Path,
        source_root: Optional[str] = None,
        verbose: bool = True,
        enable_logging: bool = True,
    ):
        """
        初始化 WorkflowAgent
        
        Args:
            workflow_id: Workflow ID（如 wf_1）
            workflow_name: Workflow 名称（如 "ContentProvider SQL注入"）
            goal: 目标描述（如 "找出所有 ContentProvider 中的 SQL 注入漏洞"）
            tasks: 任务列表（LLM 规划的任务）
            llm_client: LLM 客户端
            engine: 静态分析引擎（已初始化）
            session_dir: Session 目录
            source_root: 源代码根目录
            verbose: 是否打印日志
            enable_logging: 是否启用日志记录
        """
        self.workflow_id = workflow_id
        self.workflow_name = workflow_name
        self.goal = goal
        self.tasks = tasks
        self.llm_client = llm_client
        self.engine = engine
        self.session_dir = session_dir
        self.source_root = source_root
        self.verbose = verbose
        self.enable_logging = enable_logging
        self.agent_id = f"workflow_agent_{self.workflow_id}"
        self.target_function = (
            f"workflow: {self.workflow_name}"
            if self.workflow_name
            else (self.goal or self.workflow_id)
        )
        
        # 创建独立的 workflow 目录
        self.workflow_dir = session_dir / workflow_id
        self.workflow_dir.mkdir(parents=True, exist_ok=True)
        
        # 独立的 artifact 目录
        self.artifact_dir = self.workflow_dir / "artifacts"
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        
        # 状态
        self.completed = False
        self.result = None
        self.errors = []
        
        # 初始化 agent logger
        if self.enable_logging:
            self.agent_log_manager = get_agent_log_manager()
        else:
            self.agent_log_manager = None
        
        # 初始化组件
        self._init_components()
    
    def _init_components(self):
        """初始化 Agent 组件"""
        
        # 1. Artifact Store（必须先创建，因为其他组件依赖它）
        self.artifact_store = ArtifactStore(
            base_dir=self.artifact_dir,
        )
        
        # 2. LLM 客户端包装器
        self.llm_client_wrapper = ToolBasedLLMClient(
            llm=self.llm_client,
            max_retries=3,
            retry_delay=1.0,
            verbose=self.verbose,
            enable_logging=self.enable_logging,
            session_id=self.workflow_id,
            agent_id=self.agent_id,
            log_metadata={
                "agent_type": "workflow_agent",
                "workflow_id": self.workflow_id,
                "workflow_name": self.workflow_name,
                "target_function": self.target_function,
            },
        )
        
        # 3. 消息管理器
        self.message_manager = MessageManager(
            artifact_store=self.artifact_store,
            max_inline_chars=4000,
        )
        
        # 4. 上下文组装器
        self.context_assembler = ContextAssembler(
            message_manager=self.message_manager,
            recent_message_limit=12,
        )
        
        # 5. 任务列表管理器
        tasks_file = self.workflow_dir / "tasks.md"
        self.task_list_manager = TaskListManager(
            tasks_file=tasks_file,
        )
        
        # 6. 文件管理器
        self.file_manager = FileManager(
            session_dir=self.workflow_dir,
        )
        
        # 7. Agent 委托器
        self.agent_delegate:AgentDelegate = AgentDelegate(
            engine=self.engine,
            llm_client=self.llm_client,
            file_manager=self.file_manager,
        )
        
        # 8. 工具管理器
        self.tools_manager = OrchestratorTools(
            llm_client=self.llm_client,
            workflow_context=None,
            engine_type=None,
            target_path=None,
            source_root=self.source_root,
            artifact_store=self.artifact_store,
            session_id=self.workflow_id,
        )
        
        # 9. 设置已初始化的引擎
        self.tools_manager._engine = self.engine
        self.tools_manager._initialized = True
        
        # 10. 设置组件引用
        self.tools_manager._task_list_manager = self.task_list_manager
        self.tools_manager._file_manager = self.file_manager
        self.tools_manager._agent_delegate = self.agent_delegate
        
        # 11. 创建工具列表
        self.tools = self.tools_manager.get_tools()
    
    def _log(self, message: str, level: str = "info"):
        """打印日志"""
        if self.verbose:
            prefix = f"[WorkflowAgent:{self.workflow_id}]"
            if level == "error":
                print(f"[X] {prefix} {message}")
            elif level == "warning":
                print(f"[!] {prefix} {message}")
            elif level == "success":
                print(f"[+] {prefix} {message}")
            else:
                print(f"[*] {prefix} {message}")
    
    def _get_system_prompt(self) -> str:
        """获取系统提示词（目标驱动）"""
        return f"""# 你是谁

你是一个自主的漏洞挖掘 Agent。你的任务是达成给定的目标。

# 你的目标

{self.goal}

# 你的能力

你可以使用以下工具来达成目标：

## 核心工具

- `plan_tasks(workflows)`: 规划任务列表
  - 将目标拆解为具体的、可执行的子任务
  - 每个任务应该清晰、独立、可验证
  - task 支持字符串或对象；对象字段包括 description / agent_type / function_identifier
  - vuln_analysis 任务必须显式提供 function_identifier
  - function_identifier 必须来自 search_symbol 的验证结果，保持原样

- `execute_next_task(agent_type, additional_context)`: 执行下一个任务
  - agent_type: "code_explorer" 用于代码探索和信息收集
  - agent_type: "vuln_analysis" 用于漏洞挖掘和风险评估
  - additional_context: 补充说明、约束条件等

## 辅助工具

- `get_task_status()`: 获取当前任务列表状态
- `read_task_output(task_id)`: 读取指定任务的输出

# 你的工作方式

你是自主的。你自己决定：
- 需要做哪些事情（通过 plan_tasks 规划）
- 按什么顺序做（通过 execute_next_task 执行）
- 何时完成（所有任务完成后自然结束）

没有人会告诉你"下一步做什么"。你自己思考和决策。

# 典型工作流程

1. **规划阶段**：调用 plan_tasks() 将目标拆解为任务列表
   - 若存在 vuln_analysis 但目标函数标识符未确定：先调用 delegate_task(agent_type="code_explorer")，要求使用 search_symbol 查找并返回标准标识符，然后再调用 plan_tasks
2. **执行阶段**：循环调用 execute_next_task() 执行每个任务
3. **完成阶段**：所有任务完成后，总结结果

# 重要原则

1. **目标导向**：始终关注是否达成目标
2. **自主思考**：每一步都是你自己决定的
3. **灵活应变**：根据结果调整策略
4. **及时结束**：目标达成后就结束

# Agent 类型选择

- **code_explorer**: 用于代码探索、搜索、定位、信息收集
  - 搜索特定的类、函数、模式
  - 分析代码结构和调用关系
  - 收集代码事实和证据

- **vuln_analysis**: 用于漏洞挖掘、风险评估、证据链构建
  - 分析潜在的安全漏洞
  - 评估漏洞的严重程度
  - 构建完整的证据链
  - 推导触发条件

**关键规则**：凡是漏洞挖掘相关任务，必须使用 vuln_analysis。code_explorer 只用于收集信息。

现在开始达成你的目标。
"""
    
    async def run(self) -> WorkflowResult:
        """
        自主运行，直到完成目标
        
        Returns:
            WorkflowResult: 执行结果
        """
        start_time = time.time()
        
        # 记录执行开始
        if self.agent_log_manager:
            self.agent_log_manager.log_execution_start(
                agent_id=self.agent_id,
                agent_type="workflow_agent",
                target_function=self.target_function,
                parent_id=None,
                call_stack=[],
                metadata={
                    "workflow_name": self.workflow_name,
                    "goal": self.goal,
                    "task_count": len(self.tasks),
                }
            )
        
        try:
            self._log(f"开始执行 Workflow: {self.workflow_name}")
            self._log(f"目标: {self.goal}")
            
            # 1. 初始化消息：告诉 Agent 它的目标
            task_lines = []
            for i, task in enumerate(self.tasks, 1):
                if isinstance(task, dict):
                    task_desc = task.get("description", "")
                else:
                    task_desc = str(task)
                task_lines.append(f"{i}. {task_desc}")

            await self.message_manager.add_user_message(
                f"""你的目标是：{self.goal}

建议的任务列表：
{chr(10).join(task_lines)}

若存在 vuln_analysis 但 function_identifier 未明确，请先调用 delegate_task(agent_type="code_explorer") 使用 search_symbol 获取标准标识符，然后调用 plan_tasks() 规划任务列表，再循环调用 execute_next_task() 执行任务，直到完成目标。
"""
            )
            
            # 2. 自主循环
            max_iterations = 30
            iteration = 0
            
            while True:
                iteration += 1
                self._log(f"迭代 {iteration}/{max_iterations}")
                
                # 检查是否超过最大迭代次数
                if iteration > max_iterations:
                    self._log(f"达到最大迭代次数 {max_iterations}，结束执行", "warning")
                    break
                
                # 组装上下文并调用 LLM
                assembled_messages = self.context_assembler.build_messages(
                    system_prompt=self._get_system_prompt(),
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
                    self._log("Agent 完成执行", "success")
                    self.completed = True
                    break
                
                # 执行所有 Tool 调用
                for tool_call in result.tool_calls:
                    tool_name = tool_call.get("name", "")
                    tool_args = tool_call.get("args", {})
                    tool_id = tool_call.get("id", "")
                    
                    self._log(f"Tool 调用: {tool_name}")
                    
                    try:
                        # 执行工具
                        result_data = await self._execute_tool(tool_name, tool_args)
                        
                        if isinstance(result_data, dict) and result_data.get("error"):
                            self._log(f"Tool 错误: {result_data['error']}", "warning")
                            self.errors.append(f"{tool_name}: {result_data['error']}")
                        
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
                        
                    except Exception as e:
                        error_msg = str(e)
                        self._log(f"Tool 执行失败: {error_msg}", "error")
                        self.errors.append(f"{tool_name}: {error_msg}")
                        
                        error_content = json.dumps({"error": error_msg}, ensure_ascii=False)
                        await self.message_manager.add_tool_message(
                            content=error_content,
                            tool_name=tool_name,
                            tool_call_id=tool_id,
                        )
            
            # 3. 汇总结果
            end_time = time.time()
            execution_time = end_time - start_time
            
            # 获取任务统计
            tasks = self.task_list_manager.get_all_tasks()
            total_tasks = len(tasks)
            completed_tasks = sum(1 for task in tasks if task.status.value == "completed")
            
            # 获取漏洞数量
            vulnerabilities_found = len(self.tools_manager.vulnerabilities)
            
            summary = f"""# Workflow 执行摘要

## 基本信息

- **Workflow ID**: {self.workflow_id}
- **Workflow 名称**: {self.workflow_name}
- **目标**: {self.goal}

## 执行统计

- **总任务数**: {total_tasks}
- **完成任务数**: {completed_tasks}
- **发现漏洞数**: {vulnerabilities_found}
- **执行时间**: {execution_time:.2f} 秒
- **迭代次数**: {iteration}

## 任务列表

"""
            for i, task in enumerate(tasks, 1):
                status_icon = "✓" if task.status.value == "completed" else "✗"
                summary += f"{i}. [{status_icon}] {task.description} ({task.status.value})\n"
            
            if self.errors:
                summary += "\n## 错误信息\n\n"
                for error in self.errors:
                    summary += f"- {error}\n"
            
            # 保存摘要
            summary_file = self.workflow_dir / "workflow_summary.md"
            summary_file.write_text(summary, encoding="utf-8")
            
            self._log(f"Workflow 执行完成: {completed_tasks}/{total_tasks} 任务完成", "success")
            
            # 记录执行结束
            if self.agent_log_manager:
                status = AgentStatus.COMPLETED if completed_tasks == total_tasks else AgentStatus.FAILED
                self.agent_log_manager.log_execution_end(
                    agent_id=self.agent_id,
                    status=status,
                    vulnerabilities_found=vulnerabilities_found,
                    summary=f"completed_tasks={completed_tasks}, total_tasks={total_tasks}, vulnerabilities_found={vulnerabilities_found}",
                    error_message="; ".join(self.errors) if self.errors else None,
                )
            
            return WorkflowResult(
                workflow_id=self.workflow_id,
                workflow_name=self.workflow_name,
                goal=self.goal,
                success=completed_tasks == total_tasks,
                completed_tasks=completed_tasks,
                total_tasks=total_tasks,
                vulnerabilities_found=vulnerabilities_found,
                execution_time=execution_time,
                summary=summary,
                errors=self.errors,
            )
            
        except Exception as e:
            end_time = time.time()
            execution_time = end_time - start_time
            
            error_msg = f"Workflow 执行失败: {str(e)}"
            self._log(error_msg, "error")
            self.errors.append(error_msg)
            
            # 记录执行失败
            if self.agent_log_manager:
                self.agent_log_manager.log_execution_end(
                    agent_id=self.agent_id,
                    status=AgentStatus.FAILED,
                    summary=error_msg,
                    error_message=error_msg,
                )
            
            return WorkflowResult(
                workflow_id=self.workflow_id,
                workflow_name=self.workflow_name,
                goal=self.goal,
                success=False,
                completed_tasks=0,
                total_tasks=len(self.tasks),
                vulnerabilities_found=0,
                execution_time=execution_time,
                summary=error_msg,
                errors=self.errors,
            )
    
    async def _execute_tool(self, tool_name: str, tool_args: Dict[str, Any]) -> Any:
        """执行工具调用"""
        # 获取工具方法
        tool_method = getattr(self.tools_manager, tool_name, None)
        
        if tool_method is None:
            return {"error": f"Unknown tool: {tool_name}"}
        
        # 调用工具
        try:
            result = await tool_method(**tool_args)
            return result
        except Exception as e:
            return {"error": str(e)}
