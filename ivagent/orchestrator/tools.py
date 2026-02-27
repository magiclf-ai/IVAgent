#!/usr/bin/env python3
"""
Orchestrator Tools - 简化的 Tool 管理

所有 Tools 整合到一个类中，通过类变量共享状态：
- engine: 当前分析引擎
- workflow_context: Workflow 上下文
- llm_client: LLM 客户端
- agents: 创建的 Agent 缓存
- vulnerabilities: 发现的漏洞列表
"""


from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from pathlib import Path
import uuid
import json
import asyncio

from .agent_delegate import AgentDelegate
from ..models.workflow import WorkflowContext

from ..engines import create_engine, BaseStaticAnalysisEngine
from ..engines.base_static_analysis_engine import SearchOptions
from ..agents.deep_vuln_agent import DeepVulnAgent
from ..agents.prompts import get_vuln_agent_system_prompt
from ..core.context import ArtifactStore
from ..core import SummaryService
from ..core.tool_llm_client import ToolBasedLLMClient
from langchain_core.messages import HumanMessage



@dataclass
class AgentInstance:
    """Agent 实例记录"""
    agent_id: str
    agent_type: str
    engine_name: str
    analysis_focus: str
    instance: Any = None


@dataclass
class VulnerabilityInfo:
    """漏洞信息"""
    name: str
    vuln_type: str
    description: str
    location: str
    severity: float
    confidence: float
    evidence: List[str] = field(default_factory=list)
    remediation: str = ""


class OrchestratorTools:
    """
    Orchestrator 工具集合
    
    所有工具方法共享类变量状态，无需通过参数传递上下文。
    """

    def __init__(
            self,
            llm_client: Any = None,
            workflow_context: Optional[WorkflowContext] = None,
            engine_type: Optional[str] = None,
            target_path: Optional[str] = None,
            source_root: Optional[str] = None,
            artifact_store: Optional[ArtifactStore] = None,
            session_id: Optional[str] = None,
            max_vuln_concurrency: int = 3,
            summary_service: Optional[SummaryService] = None,
            tool_output_summary_threshold: int = 4000,
    ):

        self.llm_client = llm_client
        self.workflow_context = workflow_context

        # 共享状态
        self.engine: Optional[BaseStaticAnalysisEngine] = None
        self.engine_name: Optional[str] = None
        self.agents: Dict[str, AgentInstance] = {}
        self.vulnerabilities: List[VulnerabilityInfo] = []
        self._last_agent_id: Optional[str] = None
        self.artifact_store: Optional[ArtifactStore] = artifact_store
        self.summary_service: Optional[SummaryService] = summary_service
        self._tool_summary_service: Optional[SummaryService] = None
        self.tool_output_summary_threshold = max(0, int(tool_output_summary_threshold))


        # 延迟初始化参数（用于异步初始化）

        self._pending_engine_type = engine_type
        self._pending_target_path = target_path
        self._pending_source_root = source_root
        self._initialized = False
        
        # 工作流规划状态
        self._planned_workflows: Optional[List[Dict[str, Any]]] = None
        self._is_multi_workflow: bool = False
        
        # 新设计的组件（简化的任务编排）
        self._session_id = session_id
        self._task_list_manager: Optional[Any] = None
        self._file_manager: Optional[Any] = None
        self._agent_delegate: Optional[AgentDelegate] = None
        self._verified_function_identifiers: Dict[str, set[str]] = {}
        self.max_vuln_concurrency = max(1, int(max_vuln_concurrency))
        self._recovery_lock_task_id: Optional[str] = None

    def _set_recovery_lock(self, task_id: str) -> None:
        """锁定需要恢复的任务，避免执行阶段跳到其他任务。"""
        self._recovery_lock_task_id = task_id

    def _clear_recovery_lock(self, task_id: Optional[str] = None) -> None:
        """清除恢复锁。若指定 task_id，则仅在匹配时清除。"""
        if not self._recovery_lock_task_id:
            return
        if task_id and self._recovery_lock_task_id != task_id:
            return
        self._recovery_lock_task_id = None

    def _format_recovery_lock_error(
        self,
        task_id: str,
        description: str = "",
        task_group: Optional[str] = None,
    ) -> str:
        """生成恢复锁定态的错误提示。"""
        group_hint = f", task_group=\"{task_group}\"" if task_group else ""
        return (
            self._format_recoverable_error(
                error_code="RECOVERY_LOCK_ACTIVE",
                message=f"存在未恢复的任务锁定：{task_id}，请先完成该任务的 function_identifier 绑定。",
                payload={
                    "task_id": task_id,
                    "task_description": description,
                    "required_next_actions": [
                        "调用 resolve_function_identifier 获取由 search_symbol 验证的候选标识符",
                        "调用 set_task_function_identifier 回填任务参数",
                        "重新调用 execute_next_task(agent_type='vuln_analysis', task_group=...)",
                    ],
                },
            )
            + "\n\n请严格按以下步骤恢复：\n"
            + f"1. resolve_function_identifier(task_id=\"{task_id}\", query_hint=\"{description}\")\n"
            + f"2. set_task_function_identifier(task_id=\"{task_id}\", function_identifier=\"<从上一步候选中选择>\", source=\"search_symbol\")\n"
            + f"3. execute_next_task(agent_type=\"vuln_analysis\"{group_hint})"
        )

    # ==================== 内部方法 ====================

    def _get_next_task_index(self) -> int:
        """获取下一个任务序号（用于 append_tasks 的 task_id 预分配）。"""
        if not self._task_list_manager:
            return 1
        max_num = 0
        for task in self._task_list_manager.get_all_tasks():
            try:
                num = int(str(task.id).split("_", 1)[1])
                max_num = max(max_num, num)
            except Exception:
                continue
        return max_num + 1

    def _externalize_analysis_context(
        self,
        flat_tasks: List[Dict[str, Any]],
        start_index: int = 1,
    ) -> None:
        """
        将任务的 analysis_context 写入 artifacts 文件，并在任务中保存引用文件名。

        说明：
            - 仅当 analysis_context 非空时生效
            - 需要 FileManager 才能落盘
        """
        if not self._file_manager:
            return
        for offset, task in enumerate(flat_tasks):
            raw_context = task.get("analysis_context")
            if raw_context is None:
                continue
            context_text = str(raw_context).strip()
            if not context_text:
                continue
            task_id = f"task_{start_index + offset}"
            file_path = self._file_manager.get_artifact_path(
                task_id=task_id,
                artifact_name="analysis_context",
            )
            self._file_manager.write_artifact(file_path, context_text)
            task["analysis_context"] = file_path.name

    def _resolve_task_analysis_context(self, task: Any) -> str:
        """
        解析任务的 analysis_context 引用为具体内容。

        返回：
            解析后的前置信息文本（可能为空）
        """
        value = getattr(task, "analysis_context", None)
        if not value:
            return ""
        if not self._file_manager:
            return str(value)
        candidate = self._file_manager.artifacts_dir / str(value)
        if candidate.exists():
            return self._file_manager.read_artifact(candidate)
        return str(value)

    def _build_task_context(self, task: Any, additional_context: str) -> str:
        """
        构建任务执行上下文，优先注入 analysis_context。
        """
        analysis_context = self._resolve_task_analysis_context(task).strip()
        extra = (additional_context or "").strip()
        if analysis_context and extra:
            return f"{analysis_context}\n\n{extra}"
        return analysis_context or extra

    def _format_recoverable_error(
        self,
        error_code: str,
        message: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> str:
        """统一生成可恢复错误响应，方便 LLM 按步骤自愈。"""
        body = {"error_code": error_code, "recoverable": True}
        if payload:
            body.update(payload)
        pretty_json = json.dumps(body, ensure_ascii=False, indent=2)
        return (
            f"[错误] {message}\n\n"
            "```json\n"
            f"{pretty_json}\n"
            "```"
        )

    def _get_summary_service(self) -> Optional[SummaryService]:
        """获取用于工具输出摘要的 SummaryService（必要时惰性创建）。"""
        if self.summary_service:
            return self.summary_service
        if not self.llm_client:
            return None
        if not self._tool_summary_service:
            self._tool_summary_service = SummaryService(
                llm_client=self.llm_client,
                max_retries=2,
                retry_delay=1.0,
                enable_logging=True,
                verbose=False,
                session_id=self._session_id,
                agent_id=f"tool_summary_{self._session_id or id(self)}",
                agent_type="tool_summary",
                target_function="orchestrator_tools",
            )
        return self._tool_summary_service

    def _should_summarize_tool_output(self, content: str) -> bool:
        """
        判断是否需要对工具输出生成摘要。

        说明:
            - 仅在输出超长时摘要
            - 对可恢复错误输出保持原文，避免丢失修复步骤
        """
        if not content:
            return False
        if self.tool_output_summary_threshold <= 0:
            return False
        if '"recoverable": true' in content or '"recoverable":true' in content:
            return False
        return len(content) > self.tool_output_summary_threshold

    async def _summarize_tool_output(self, tool_name: str, content: str) -> str:
        """调用 LLM 生成工具输出摘要（Markdown 纯文本）。"""
        service = self._get_summary_service()
        if not service:
            return ""
        return await service.summarize_message_large(
            content=content,
            metadata={"tool_name": tool_name},
        )

    async def _maybe_pack_tool_output(self, tool_name: str, content: str) -> Any:
        """
        仅在输出超长时返回 content/summary 双轨结构，否则返回原文。
        """
        if not self._should_summarize_tool_output(content):
            return content
        summary = await self._summarize_tool_output(tool_name, content)
        if not summary:
            return content
        return {"content": content, "summary": summary}

    async def _validate_and_normalize_workflows(
        self,
        workflows: List[Dict[str, Any]],
        verify_function_identifier: bool = True,
        verified_identifiers: Optional[Set[str]] = None,
    ) -> Tuple[Optional[List[Dict[str, Any]]], Optional[str], Set[str]]:
        """
        校验并标准化 workflows 结构，返回标准化结果与已验证的函数标识符集合。

        Args:
            workflows: 原始 workflow 列表
            verify_function_identifier: 是否调用 search_symbol 进行校验
            verified_identifiers: 已验证的 function_identifier 集合（可选）

        Returns:
            (标准化后的 workflows, 错误信息, 已验证标识符集合)
        """
        if not workflows:
            return None, "[错误] workflows 参数为空", set()
        if not isinstance(workflows, list):
            return None, "[错误] workflows 必须是列表类型", set()

        verified = set(verified_identifiers or [])

        for i, wf in enumerate(workflows):
            if not isinstance(wf, dict):
                return None, f"[错误] workflow[{i}] 不是字典类型", verified
            if "tasks" not in wf:
                return None, f"[错误] workflow[{i}] 缺少必需字段 'tasks'", verified

            tasks = wf["tasks"]
            if isinstance(tasks, dict):
                if "tasks" in tasks:
                    wf["tasks"] = tasks["tasks"]
                elif "task_list" in tasks:
                    wf["tasks"] = tasks["task_list"]
                else:
                    wf["tasks"] = list(tasks.values()) if tasks else []
                tasks = wf["tasks"]

            if not isinstance(tasks, list) or not tasks:
                return None, f"[错误] workflow[{i}] 的 'tasks' 必须是非空列表", verified

            for j, task in enumerate(tasks):
                if isinstance(task, str):
                    description = task.strip()
                    return None, self._format_recoverable_error(
                        error_code="MISSING_AGENT_TYPE_IN_PLAN",
                        message=f"workflow[{i}] 的 tasks[{j}] 缺少 agent_type（任务必须显式指定）。",
                        payload={
                            "workflow_index": i,
                            "task_index": j,
                            "task_description": description,
                            "required_next_actions": [
                                "将该任务改为对象形式，并补充 agent_type",
                                "若为 vuln_analysis 任务，补充 function_identifier",
                                "重新调用 plan_tasks(workflows)",
                            ],
                        },
                    ), verified
                if isinstance(task, dict):
                    if "description" not in task:
                        return None, f"[错误] workflow[{i}] 的 tasks[{j}] 缺少 description 字段", verified
                    description = str(task["description"]).strip()
                    agent_type = task.get("agent_type")
                    function_identifier = (task.get("function_identifier") or "").strip()

                    if not agent_type:
                        return None, self._format_recoverable_error(
                            error_code="MISSING_AGENT_TYPE_IN_PLAN",
                            message=f"workflow[{i}] 的 tasks[{j}] 缺少 agent_type（任务必须显式指定）。",
                            payload={
                                "workflow_index": i,
                                "task_index": j,
                                "task_description": description,
                                "required_next_actions": [
                                    "为该任务补充 agent_type（code_explorer / vuln_analysis）",
                                    "若为 vuln_analysis 任务，补充 function_identifier",
                                    "重新调用 plan_tasks(workflows)",
                                ],
                            },
                        ), verified

                    if agent_type == "vuln_analysis" and not function_identifier:
                        return None, self._format_recoverable_error(
                            error_code="MISSING_FUNCTION_IDENTIFIER_IN_PLAN",
                            message=f"workflow[{i}] 的 tasks[{j}] 缺少 function_identifier（vuln_analysis 必需）。",
                            payload={
                                "workflow_index": i,
                                "task_index": j,
                                "task_description": description,
                                "required_next_actions": [
                                    "先调用 delegate_task(agent_type='code_explorer')，并要求使用 search_symbol 返回标准函数标识符",
                                    "将返回的 function_identifier 原样填写到该 vuln_analysis 任务",
                                    "重新调用 plan_tasks(workflows)",
                                ],
                            },
                        ), verified

                    analysis_context = task.get("analysis_context")
                    if analysis_context is None:
                        analysis_context = ""
                    if not isinstance(analysis_context, str):
                        analysis_context = str(analysis_context)

                    if agent_type == "vuln_analysis":
                        if verify_function_identifier:
                            if not self.engine:
                                return None, self._format_recoverable_error(
                                    error_code="ENGINE_NOT_READY_FOR_FUNCTION_IDENTIFIER_VALIDATION",
                                    message="引擎未初始化，无法使用 search_symbol 校验 function_identifier。",
                                    payload={
                                        "workflow_index": i,
                                        "task_index": j,
                                        "function_identifier": function_identifier,
                                        "required_next_actions": [
                                            "先初始化分析引擎",
                                            "调用 delegate_task(agent_type='code_explorer') 或 search_symbol 进行校验",
                                            "确认后重新调用 plan_tasks(workflows)",
                                        ],
                                    },
                                ), verified

                            is_verified = await self._is_function_identifier_verified_by_search_symbol(
                                function_identifier
                            )
                            if not is_verified:
                                return None, self._format_recoverable_error(
                                    error_code="UNVERIFIED_FUNCTION_IDENTIFIER_IN_PLAN",
                                    message=(
                                        f"workflow[{i}] 的 tasks[{j}] function_identifier 未通过 "
                                        "search_symbol 验证。function_identifier 必须是单个字符串，"
                                        "不可使用列表/拼接字符串；多函数分析需拆分为多个任务。"
                                    ),
                                    payload={
                                        "workflow_index": i,
                                        "task_index": j,
                                        "task_description": description,
                                        "function_identifier": function_identifier,
                                        "required_next_actions": [
                                            "调用 delegate_task(agent_type='code_explorer') 使用 search_symbol 获取标准标识符",
                                            "将 function_identifier 替换为 search_symbol 的单个返回值（保持原样）",
                                            "若需多函数分析，请拆分为多个 vuln_analysis 任务",
                                            "重新调用 plan_tasks(workflows)",
                                        ],
                                    },
                                ), verified
                            verified.add(function_identifier)
                        else:
                            if verified and function_identifier not in verified:
                                return None, (
                                    f"[错误] workflow[{i}] 的 tasks[{j}] function_identifier "
                                    f"未在已验证集合中: {function_identifier}"
                                ), verified
                        if not analysis_context.strip():
                            return None, self._format_recoverable_error(
                                error_code="MISSING_ANALYSIS_CONTEXT_IN_PLAN",
                                message=f"workflow[{i}] 的 tasks[{j}] 缺少 analysis_context（漏洞挖掘上下文摘要）。",
                                payload={
                                    "workflow_index": i,
                                    "task_index": j,
                                    "task_description": description,
                                    "required_next_actions": [
                                        "调用 delegate_task(agent_type='code_explorer') 获取目标函数的入参约束/全局约束/风险点",
                                        "将上述信息写入该 vuln_analysis 任务的 analysis_context（纯文本）",
                                        "重新调用 plan_tasks(workflows)",
                                    ],
                                },
                            ), verified

                    tasks[j] = {
                        "description": description,
                        "agent_type": agent_type,
                        "function_identifier": function_identifier or None,
                        "analysis_context": analysis_context.strip(),
                    }
                    continue
                return None, f"[错误] workflow[{i}] 的 tasks[{j}] 类型不支持（仅支持字典对象）", verified

        return workflows, None, verified

    async def _is_function_identifier_verified_by_search_symbol(self, identifier: str) -> bool:
        """通过 search_symbol 校验 function_identifier 是否可解析。"""
        normalized = (identifier or "").strip()
        if not normalized or not self.engine:
            return False

        try:
            results = await self.engine.search_symbol(
                query=normalized,
                options=SearchOptions(limit=20),
            )
        except Exception:
            return False

        for item in results or []:
            signature = (getattr(item, "signature", "") or "").strip()
            name = (getattr(item, "name", "") or "").strip()
            if signature == normalized or name == normalized:
                return True
        return False

    async def initialize(
            self,
            engine_type: Optional[str] = None,
            target_path: Optional[str] = None,
            source_root: Optional[str] = None,
    ) -> bool:
        """异步初始化分析引擎。"""
        # 使用延迟初始化参数（如果没有提供新参数）
        engine_name = (engine_type or self._pending_engine_type)
        target = (target_path or self._pending_target_path)
        src_root = (source_root or self._pending_source_root)

        if not engine_name or not target:
            return False

        engine_name = engine_name.lower()
        path = Path(target)

        if not path.exists():
            raise ValueError(f"Target path does not exist: {target}")

        try:
            self.engine = create_engine(
                engine_type=engine_name,
                target_path=target,
                source_root=src_root,
                max_concurrency=10,
                llm_client=self.llm_client
            )

            # 异步初始化
            initialized = await self.engine.initialize()
            if not initialized:
                raise ValueError(f"Failed to initialize {engine_name} engine")

            self.engine_name = engine_name
            self._initialized = True
            return True

        except Exception as e:
            raise ValueError(f"Engine initialization failed: {e}")

    def _ensure_initialized(self) -> None:
        """确保引擎已初始化"""
        if not self._initialized or not self.engine:
            raise ValueError("Engine not initialized. Call initialize() first.")

    def set_artifact_store(self, artifact_store: ArtifactStore) -> None:
        """设置 ArtifactStore（用于 read_artifact 工具）"""
        self.artifact_store = artifact_store

    def initialize_orchestrator_components(self, session_dir: Path) -> None:
        """初始化简化的任务编排组件（幂等）
        
        Args:
            session_dir: Session 目录路径（如 .ivagent/sessions/{session_id}）
        """
        from .task_list_manager import TaskListManager
        from .file_manager import FileManager
        from .agent_delegate import AgentDelegate
        
        # 初始化 FileManager（幂等）
        if not self._file_manager:
            self._file_manager = FileManager(session_dir=session_dir)
        
        # 初始化 TaskListManager（幂等）
        if not self._task_list_manager:
            tasks_file = session_dir / "tasks.md"
            self._task_list_manager = TaskListManager(tasks_file=tasks_file)
        
        # 初始化 AgentDelegate（幂等）
        if self.engine and self.llm_client and not self._agent_delegate:
            self._agent_delegate = AgentDelegate(
                engine=self.engine,
                llm_client=self.llm_client,
                file_manager=self._file_manager,
            )

    # ==================== Tool 定义 ====================

    async def read_artifact(
            self,
            artifact_id: str,
            offset: int = 0,
            limit: int = 200,
    ) -> Any:
        """读取已归档的 Artifact 原文内容。

        参数:
            artifact_id: Artifact ID
            offset: 起始行号（从0开始）
            limit: 返回行数上限

        返回:
            正文内容；若输出超长，返回 {"content": "...", "summary": "..."}。
        """
        if not self.artifact_store:
            return "[错误] ArtifactStore 未初始化"

        content = self.artifact_store.read(artifact_id, offset=offset, limit=limit)
        return await self._maybe_pack_tool_output("read_artifact", content)

    async def delegate_task(
            self,
            agent_type: str,
            query: str,
            context: Optional[str] = None,
            function_identifier: Optional[str] = None,
            max_depth: int = 10,
            max_iterations: int = 15,
    ) -> Any:
        """委托任务给专门的 Agent 执行。
        
        这是一个统一的 Agent 调度接口，类似 Claude 的 task 工具。
        根据 agent_type 自动创建并调用相应的 Agent，返回markdown格式的文本结果。
        
        参数:
            agent_type: Agent 类型，可选值：
                - "code_explorer": 代码探索 Agent（搜索、读取、语义分析）
                - "vuln_analysis": 漏洞挖掘 Agent（深度漏洞分析）
            
            query: 任务描述（自然语言）
                - 对于 code_explorer: "找到所有处理用户输入的函数"
                - 对于 vuln_analysis: "分析 parse_request 函数的缓冲区溢出风险"
            
            context: 可选的上下文信息
                - 约束、背景知识等
                - 建议包含“上下文摘要”三部分：入参约束 / 全局约束 / 风险点
                - 必须描述攻击者可控性与约束（输入来源、可控字段/指针、长度/计数约束、状态机/校验约束）
            
            function_identifier: 函数唯一标识符（仅 vuln_analysis 使用）
                - 如果提供，直接使用此标识符，不从 query 中提取
                - 格式示例: "PasswordProvider.query", "parse_request", "com.example.MyClass.method"
                - 推荐：先使用 search_symbol 或 query_code 获取准确的函数标识符，再传入此参数
            
            max_depth: 最大分析深度（仅 vuln_analysis 使用）
            max_iterations: 最大迭代次数
        
        返回: markdown 格式文本；若输出超长，返回 {"content": "...", "summary": "..."}。
        """
        if not self.engine:
            # Best-effort lazy initialization when pending engine config is available.
            if not self._initialized:
                try:
                    initialized = await self.initialize()
                except Exception as e:
                    return f"[错误] 引擎初始化失败: {str(e)}"
                if initialized and self.engine:
                    pass
                else:
                    return "[错误] 引擎未初始化，请先调用 initialize()（并提供 engine_type/target_path）"
            else:
                return "[错误] 引擎未初始化，请先调用 initialize()"

        if not self.llm_client:
            return "[错误] LLM 客户端不可用"

        try:
            if agent_type == "code_explorer":
                # 创建 CodeExplorerAgent
                from ..agents.code_explorer_agent import CodeExplorerAgent

                agent = CodeExplorerAgent(
                    engine=self.engine,
                    llm_client=self.llm_client,
                    max_iterations=max_iterations,
                    enable_logging=True,
                    session_id=getattr(self, 'session_id', None),
                )

                result = await agent.explore(
                    query=query,
                    context=context
                )

                if isinstance(result, dict):
                    error = (result.get("error") or "").strip()
                    if error:
                        return error
                    output = result.get("output", "") or ""
                    return await self._maybe_pack_tool_output("delegate_task", output)

                return await self._maybe_pack_tool_output("delegate_task", result or "")

            elif agent_type == "vuln_analysis":
                # function_identifier 是必需的
                target_function_id = function_identifier
                if not target_function_id:
                    return """[错误] 必须提供 function_identifier 参数

请按以下步骤操作：
1. 使用 search_symbol 或其他工具查找目标函数
2. 从结果中提取标准格式的函数标识符
3. 再次调用 delegate_task 并传递 function_identifier

示例：
  search_symbol(pattern="PasswordProvider")
  # 从结果中获取: com.example.auth.PasswordProvider.query
  delegate_task(
      agent_type="vuln_analysis",
      query="分析SQL注入漏洞",
      function_identifier="com.example.auth.PasswordProvider.query",
      context="参数来自用户输入，未验证"
  )
"""

                # 构建上下文摘要
                analysis_context = context if context else query

                # 创建 DeepVulnAgent
                from ..agents.deep_vuln_agent import DeepVulnAgent
                from ..agents.prompts import get_vuln_agent_system_prompt
                from ..models.constraints import FunctionContext, Precondition

                base_prompt = get_vuln_agent_system_prompt(self.engine_name or "ida")

                agent = DeepVulnAgent(
                    engine=self.engine,
                    llm_client=self.llm_client,
                    max_iterations=max_iterations,
                    max_depth=max_depth,
                    verbose=True,
                    system_prompt=base_prompt,
                )

                agent_id = str(uuid.uuid4())[:8]
                self.agents[agent_id] = AgentInstance(
                    agent_id=agent_id,
                    agent_type="DeepVulnAgent",
                    engine_name=self.engine_name or "unknown",
                    analysis_focus=target_function_id,
                    instance=agent,
                )
                self._last_agent_id = agent_id

                # 执行分析
                precondition_text = (analysis_context or "").strip()
                if self.workflow_context and self.workflow_context.background_knowledge:
                    if precondition_text:
                        precondition_text = f"{precondition_text}\n\n### 背景知识\n{self.workflow_context.background_knowledge}"
                    else:
                        precondition_text = f"### 背景知识\n{self.workflow_context.background_knowledge}"
                precondition = None
                if precondition_text:
                    precondition = Precondition.from_text(
                        name="analysis_context",
                        text_content=precondition_text,
                        description="analysis context",
                        target="vuln_analysis",
                    )
                function_context = FunctionContext(
                    function_identifier=target_function_id,
                    precondition=precondition,
                )

                result = await agent.run(function_identifier=target_function_id, context=function_context)
                
                # 格式化结果为markdown文本
                formatted = self._format_vuln_result(result, target_function_id, agent_id)
                return await self._maybe_pack_tool_output("delegate_task", formatted)

            else:
                return f"[错误] 不支持的 Agent 类型: {agent_type}，支持的类型: code_explorer, vuln_analysis"

        except Exception as e:
            return f"[错误] Agent 执行失败: {str(e)}"
    
    def _log(self, message: str, level: str = "info"):
        """打印日志"""
        prefix = "[OrchestratorTools]"
        if level == "error":
            print(f"  [X] {prefix} {message}")
        elif level == "warning":
            print(f"  [!] {prefix} {message}")
        elif level == "success":
            print(f"  [+] {prefix} {message}")
        else:
            print(f"  [*] {prefix} {message}")

    def _format_vuln_result(
            self,
            result: Dict[str, Any],
            function_identifier: str,
            agent_id: str
    ) -> str:
        """格式化漏洞分析结果为markdown文本"""
        vulns = result.get("vulnerabilities", [])

        all_vulns = []
        for v in vulns:
            vuln_info = VulnerabilityInfo(
                name=getattr(v, 'name', 'Unknown'),
                vuln_type=getattr(v, 'type', 'UNKNOWN'),
                description=getattr(v, 'description', ''),
                location=getattr(v, 'location', ''),
                severity=getattr(v, 'severity', 0.5),
                confidence=getattr(v, 'confidence', 0.5),
            )
            self.vulnerabilities.append(vuln_info)
            all_vulns.append(vuln_info)

        # 格式化为markdown文本
        lines = [
            "# 漏洞分析结果",
            "",
            f"**目标函数**: {function_identifier}",
            f"**Agent ID**: {agent_id}",
            "",
            f"## 分析摘要",
            "",
            f"- 本次发现漏洞: {len(all_vulns)} 个",
            f"- 累计漏洞总数: {len(self.vulnerabilities)} 个",
            "",
        ]

        if all_vulns:
            lines.append("## 漏洞详情")
            lines.append("")
            for i, v in enumerate(all_vulns, 1):
                lines.append(f"### 漏洞 #{i}: {v.name}")
                lines.append("")
                lines.append(f"- **类型**: {v.vuln_type}")
                lines.append(f"- **位置**: {v.location}")
                lines.append(f"- **严重度**: {v.severity:.2f}")
                lines.append(f"- **置信度**: {v.confidence:.2f}")
                lines.append(f"- **描述**: {v.description}")
                lines.append("")
        else:
            lines.append("## 分析结果")
            lines.append("")
            lines.append("本次分析未发现漏洞。")
            lines.append("")

        return "\n".join(lines)

    async def run_vuln_analysis(

            self,
            function_identifier: str,
            analysis_context: str,
            max_depth: int = 10,
    ) -> str:
        """创建漏洞分析 Agent 并执行单一函数的深度漏洞挖掘。

        根据上下文约束，创建 Specialized 漏洞分析 Agent，
        对指定的函数开展深度漏洞挖掘。

        参数:
            function_identifier: 待分析的函数标识符（如 "int parse_request(char* buf, size_t len)"）
            analysis_context: 上下文约束描述，应包含：
                - 函数标识符和参数信息
                - 污点参数说明（哪些参数是受外部输入影响的）
                - 目标漏洞类型（如缓冲区溢出、命令注入等）
                - 相关组件/模块背景
                - 历史分析经验或前期发现的关键信息
            max_depth: 最大调用深度，默认 10
        """
        # 返回: 格式化的漏洞分析结果文本
        if not function_identifier:
            return "[错误] 必须指定 function_identifier（函数标识符）"

        if not self.engine:
            return "[错误] 引擎未初始化"

        if not self.llm_client:
            return "[错误] LLM 客户端不可用"

        try:
            # 创建 Agent
            base_prompt = get_vuln_agent_system_prompt(self.engine_name or "ida")

            agent = DeepVulnAgent(
                engine=self.engine,
                llm_client=self.llm_client,
                max_iterations=10,
                max_depth=max_depth,
                verbose=True,
                system_prompt=base_prompt,
            )

            agent_id = str(uuid.uuid4())[:8]
            self.agents[agent_id] = AgentInstance(
                agent_id=agent_id,
                agent_type="DeepVulnAgent",
                engine_name=self.engine_name or "unknown",
                analysis_focus=function_identifier,
                instance=agent,
            )
            self._last_agent_id = agent_id

            # 执行分析
            from ..models.constraints import FunctionContext, Precondition
            precondition_text = (analysis_context or "").strip()
            if self.workflow_context and self.workflow_context.background_knowledge:
                if precondition_text:
                    precondition_text = f"{precondition_text}\n\n### 背景知识\n{self.workflow_context.background_knowledge}"
                else:
                    precondition_text = f"### 背景知识\n{self.workflow_context.background_knowledge}"
            precondition = None
            if precondition_text:
                precondition = Precondition.from_text(
                    name="analysis_context",
                    text_content=precondition_text,
                    description="analysis context",
                    target="vuln_analysis",
                )
            function_context = FunctionContext(
                function_identifier=function_identifier,
                precondition=precondition,
            )
            result = await agent.run(function_identifier=function_identifier, context=function_context)
            vulns = result.get("vulnerabilities", [])

            all_vulns = []
            for v in vulns:
                vuln_info = VulnerabilityInfo(
                    name=getattr(v, 'name', 'Unknown'),
                    vuln_type=getattr(v, 'type', 'UNKNOWN'),
                    description=getattr(v, 'description', ''),
                    location=getattr(v, 'location', ''),
                    severity=getattr(v, 'severity', 0.5),
                    confidence=getattr(v, 'confidence', 0.5),
                )
                self.vulnerabilities.append(vuln_info)
                all_vulns.append(vuln_info)

            # 格式化为易读的文本
            lines = [
                f"=== 漏洞分析结果 ===",
                f"",
                f"目标函数: {function_identifier}",
                f"Agent ID: {agent_id}",
                f"",
                f"【本次发现漏洞】: {len(all_vulns)} 个",
                f"【累计漏洞总数】: {len(self.vulnerabilities)} 个",
                f"",
            ]

            if all_vulns:
                lines.append("【漏洞详情】")
                for i, v in enumerate(all_vulns, 1):
                    lines.append(f"\n--- 漏洞 #{i} ---")
                    lines.append(f"  名称: {v.name}")
                    lines.append(f"  类型: {v.vuln_type}")
                    lines.append(f"  位置: {v.location}")
                    lines.append(f"  严重度: {v.severity:.2f}")
                    lines.append(f"  置信度: {v.confidence:.2f}")
                    lines.append(f"  描述: {v.description}")
            else:
                lines.append("【结果】本次分析未发现漏洞。")

            return "\n".join(lines)

        except Exception as e:
            return f"[错误] 漏洞分析执行失败: {str(e)}"

    # ==================== 简化的 Tool 接口（新设计）====================


    async def plan_tasks(self, workflows: Optional[List[Dict[str, Any]]] = None) -> str:
        """规划任务列表，支持单/多 workflow 模式。

        每个 workflow 字典应包含: tasks (必需的任务列表), workflow_id (可选标识符),
        workflow_name (可选名称), workflow_description (可选描述),
        execution_mode (可选，sequential 或 parallel)。
        
        tasks 必须为字典对象，字段包括 description / agent_type / function_identifier / analysis_context
          - agent_type 必须显式提供（code_explorer / vuln_analysis）
          - agent_type 为 vuln_analysis 时必须提供 function_identifier
          - function_identifier 必须来自 search_symbol 的验证结果，保持原样
          - function_identifier 必须是单个字符串，不允许列表/拼接；多函数分析需拆分任务
          - analysis_context 为漏洞挖掘前置信息（纯文本）

        Args:
            workflows: Workflow 配置列表，缺失时返回可恢复错误提示

        Returns:
            规划结果摘要（Markdown 格式）
        """
        try:
            if not workflows:
                return (
                    "[错误] 缺少 workflows 参数，请调用 plan_tasks(workflows) 并提供规划内容。\n"
                    "示例：\n"
                    "```\n"
                    "{\n"
                    "  \"workflows\": [\n"
                    "    {\n"
                    "      \"workflow_id\": \"analysis_1\",\n"
                    "      \"workflow_name\": \"SQL 注入分析\",\n"
                    "      \"tasks\": [\n"
                    "        {\n"
                    "          \"description\": \"定位用户输入到数据库查询的路径\",\n"
                    "          \"agent_type\": \"code_explorer\"\n"
                    "        }\n"
                    "      ]\n"
                    "    }\n"
                    "  ]\n"
                    "}\n"
                    "```\n"
                )
            # 1. 校验与标准化（含 function_identifier 校验）
            normalized_workflows, error, verified = await self._validate_and_normalize_workflows(
                workflows,
                verify_function_identifier=True,
            )
            if error:
                return error

            # 2. 标准化 workflow 信息
            normalized = self._normalize_workflows(normalized_workflows)

            # 3. 保存规划状态（关键！）
            self._planned_workflows = normalized
            self._is_multi_workflow = True

            # 4. 创建任务列表（多 workflow 展开为统一任务序列）
            if not hasattr(self, '_task_list_manager') or not hasattr(self, '_file_manager'):
                return "[错误] TaskListManager 或 FileManager 未初始化。请先初始化 Orchestrator。"

            flat_tasks = self._flatten_workflow_tasks(normalized)
            self._externalize_analysis_context(flat_tasks, start_index=1)
            self._clear_recovery_lock()
            self._verified_function_identifiers = {}
            self._task_list_manager.create_tasks(flat_tasks)

            # 5. 返回多 workflow 摘要
            return self._format_multi_workflow_summary(normalized)

        except Exception as e:
            return f"[错误] 规划任务失败: {str(e)}"

    async def append_tasks(self, workflows: Optional[List[Dict[str, Any]]] = None) -> str:
        """追加任务列表到现有任务看板。

        Args:
            workflows: Workflow 配置列表（结构与 plan_tasks 一致）

        Returns:
            追加结果摘要（Markdown 格式）
        """
        try:
            if not workflows:
                return (
                    "[错误] 缺少 workflows 参数，请调用 append_tasks(workflows) 并提供追加内容。\n"
                    "提示：workflows 结构与 plan_tasks 保持一致。"
                )
            if not self._planned_workflows:
                return "[错误] 尚未存在基础任务列表，请先调用 plan_tasks(workflows)。"

            normalized_workflows, error, verified = await self._validate_and_normalize_workflows(
                workflows,
                verify_function_identifier=True,
            )
            if error:
                return error

            normalized = self._normalize_workflows(normalized_workflows)

            # 追加到已规划的 workflows
            merged = list(self._planned_workflows)
            for wf in normalized:
                existing = next((x for x in merged if x.get("workflow_id") == wf.get("workflow_id")), None)
                if existing:
                    existing["tasks"].extend(wf.get("tasks", []))
                else:
                    merged.append(wf)

            self._planned_workflows = merged

            if not hasattr(self, '_task_list_manager') or not hasattr(self, '_file_manager'):
                return "[错误] TaskListManager 或 FileManager 未初始化。请先初始化 Orchestrator。"

            flat_tasks = self._flatten_workflow_tasks(normalized)
            start_index = self._get_next_task_index()
            self._externalize_analysis_context(flat_tasks, start_index=start_index)
            self._task_list_manager.append_tasks(flat_tasks)

            total_added = len(flat_tasks)
            return "\n".join([
                "# 任务追加完成",
                "",
                f"**追加任务数**: {total_added}",
                "",
                "✅ 任务已追加到统一任务看板。",
            ])
        except Exception as e:
            return f"[错误] 追加任务失败: {str(e)}"


    async def resolve_function_identifier(self, task_id: str, query_hint: str = "") -> str:
        """
        通过 search_symbol 为指定任务解析可用的 function_identifier。

        Args:
            task_id: 任务 ID（如 task_2）
            query_hint: 可选的查询提示；为空时回退到任务 description

        Returns:
            Markdown 结果，包含候选列表与推荐标识符
        """
        try:
            if not self._task_list_manager:
                return "[错误] TaskListManager 未初始化。"
            if not self.engine:
                return "[错误] 引擎未初始化，无法调用 search_symbol。"

            if self._recovery_lock_task_id and task_id != self._recovery_lock_task_id:
                locked_task = self._task_list_manager.get_task(self._recovery_lock_task_id)
                description = locked_task.description if locked_task else ""
                task_group = locked_task.task_group if locked_task else None
                return self._format_recovery_lock_error(self._recovery_lock_task_id, description, task_group=task_group)

            task = self._task_list_manager.get_task(task_id)
            if not task:
                return f"[错误] 任务不存在: {task_id}"

            query = (query_hint or task.description or "").strip()
            if not query:
                return f"[错误] 缺少查询条件，无法为任务 {task_id} 解析 function_identifier。"

            options = SearchOptions(limit=20)
            results = await self.engine.search_symbol(query=query, options=options)

            candidate_rows = []
            signatures: List[str] = []
            for item in results or []:
                signature = (getattr(item, "signature", "") or "").strip()
                symbol_type = str(getattr(getattr(item, "symbol_type", None), "value", getattr(item, "symbol_type", "unknown")))
                if symbol_type not in {"function", "method", "unknown"}:
                    continue
                if not signature:
                    continue
                signatures.append(signature)
                candidate_rows.append({
                    "signature": signature,
                    "name": getattr(item, "name", ""),
                    "type": symbol_type,
                    "file_path": getattr(item, "file_path", "") or "",
                    "line": getattr(item, "line", 0),
                    "score": getattr(item, "match_score", 0.0),
                })

            dedup_signatures = list(dict.fromkeys(signatures))
            self._verified_function_identifiers[task_id] = set(dedup_signatures)

            if not dedup_signatures:
                return (
                    f"[错误] 未通过 search_symbol 找到可用函数标识符（task_id={task_id}, query={query}）。\n"
                    "请调整 query_hint 后重试 resolve_function_identifier。"
                )

            recommended = dedup_signatures[0]
            lines = [
                "# function_identifier 解析结果",
                "",
                f"- 任务: `{task_id}`",
                f"- 查询: `{query}`",
                f"- 候选数量: {len(dedup_signatures)}",
                f"- 推荐: `{recommended}`",
                "",
                "## 候选列表（来自 search_symbol）",
                "",
            ]
            for idx, row in enumerate(candidate_rows[:10], 1):
                lines.extend([
                    f"{idx}. `{row['signature']}`",
                    f"   - type: {row['type']}, score: {row['score']}",
                    f"   - location: {row['file_path']}:{row['line']}",
                ])

            lines.extend([
                "",
                "## 下一步",
                "",
                "调用 `set_task_function_identifier` 写回任务参数，然后重试 `execute_next_task`。",
                f"示例: set_task_function_identifier(task_id=\"{task_id}\", function_identifier=\"{recommended}\", source=\"search_symbol\")",
            ])
            content = "\n".join(lines)
            return await self._maybe_pack_tool_output("read_task_output", content)
        except Exception as e:
            return f"[错误] resolve_function_identifier 失败: {str(e)}"

    async def set_task_function_identifier(
        self,
        task_id: str,
        function_identifier: str,
        source: str = "search_symbol",
    ) -> str:
        """
        为任务写入 function_identifier，并要求来源可追溯到 search_symbol。

        Args:
            task_id: 任务 ID
            function_identifier: 函数标识符
            source: 标识符来源，默认必须为 search_symbol

        Returns:
            写回结果（Markdown 文本）
        """
        try:
            if not self._task_list_manager:
                return "[错误] TaskListManager 未初始化。"
            if source != "search_symbol":
                return "[错误] source 必须是 search_symbol。"

            if self._recovery_lock_task_id and task_id != self._recovery_lock_task_id:
                locked_task = self._task_list_manager.get_task(self._recovery_lock_task_id)
                description = locked_task.description if locked_task else ""
                task_group = locked_task.task_group if locked_task else None
                return self._format_recovery_lock_error(self._recovery_lock_task_id, description, task_group=task_group)

            task = self._task_list_manager.get_task(task_id)
            if not task:
                return f"[错误] 任务不存在: {task_id}"

            normalized = (function_identifier or "").strip()
            if not normalized:
                return "[错误] function_identifier 不能为空。"

            verified = normalized in self._verified_function_identifiers.get(task_id, set())
            if not verified:
                verified = await self._is_function_identifier_verified_by_search_symbol(normalized)

            if not verified:
                return (
                    f"[错误] function_identifier 未通过 search_symbol 验证: `{normalized}`。\n"
                    "请先调用 resolve_function_identifier，或使用其返回的候选标识符。"
                )

            self._task_list_manager.set_task_function_identifier(task_id=task_id, function_identifier=normalized)
            self._clear_recovery_lock(task_id)

            return "\n".join([
                "# 任务参数已更新",
                "",
                f"- task_id: `{task_id}`",
                f"- function_identifier: `{normalized}`",
                "- source: `search_symbol`",
                "",
                "请继续调用 `execute_next_task(agent_type=\"vuln_analysis\", task_group=...)`。",
            ])
        except Exception as e:
            return f"[错误] set_task_function_identifier 失败: {str(e)}"

    async def execute_next_task(
        self,
        agent_type: str,
        additional_context: str = "",
        task_group: Optional[str] = None,
    ) -> Any:
        """执行下一个待执行任务（自动处理所有细节）
        
        自动获取下一个待执行任务，读取前置任务的输出文件，生成输出文件路径，
        调用 AgentDelegate 执行任务，更新任务状态，返回执行结果和完整任务列表。
        
        Args:
            agent_type: Agent 类型，支持 code_explorer 用于代码探索和分析，或 vuln_analysis 用于漏洞挖掘分析
            additional_context: 额外的上下文信息，如补充说明或约束条件
            task_group: 任务分组标识（可选，建议显式提供）
        
        重要要求：
            - 如果 agent_type 为 vuln_analysis，当前任务必须在 plan_tasks 阶段显式提供 function_identifier
            - 所有任务必须显式提供 agent_type，否则执行阶段会返回可恢复错误

        自动处理：
            - 自动获取下一个待执行任务
            - 自动读取前置任务的输出文件（如果有）
            - 自动生成输出文件路径
            - 自动更新任务状态
            - 自动传递上下文给子 Agent
        
        Returns:
            执行结果 + 完整任务列表状态；若输出超长，返回 {"content": "...", "summary": "..."}。
            例如：
            '''
            ## 执行结果
            
            任务: task_1 - 分析攻击面
            状态: 已完成
            输出文件: artifacts/task_1_output.md
            
            关键发现:
            - 找到 5 个对外暴露的函数
            - 主要入口点: handle_request, process_input
            
            ---
            
            ## 当前任务列表
            
            - [x] task_1: 分析攻击面，找到所有对外暴露的函数
            - [ ] task_2: 对攻击面函数进行漏洞挖掘
            
            总计: 2 个任务
            已完成: 1 个
            待执行: 1 个
            '''
        """
        try:
            # 检查是否已初始化
            if not self._task_list_manager or not self._file_manager:
                return "[错误] TaskListManager 或 FileManager 未初始化。请先初始化 Orchestrator。"
            
            # 1. 确定 task_group（若存在多个分组则要求显式提供）
            all_tasks = self._task_list_manager.get_all_tasks()
            if task_group is None:
                groups = {t.task_group for t in all_tasks if t.task_group}
                if len(groups) > 1:
                    return self._format_recoverable_error(
                        error_code="MISSING_TASK_GROUP",
                        message="存在多个 task_group，必须显式指定 task_group 才能执行任务。",
                        payload={
                            "task_groups": sorted(groups),
                            "required_next_actions": [
                                "调用 get_task_status(task_group=...) 查看对应任务列表",
                                "在 execute_next_task 中显式传入 task_group",
                            ],
                        },
                    )
                if len(groups) == 1:
                    task_group = next(iter(groups))

            # 2. 获取下一个待执行任务
            current_task = self._task_list_manager.get_current_task(task_group=task_group)
            
            if not current_task:
                # 检查任务列表是否为空
                all_tasks = self._task_list_manager.get_all_tasks(task_group=task_group)
                if not all_tasks:
                    group_info = f"(task_group={task_group})" if task_group else ""
                    return f"[错误] 任务列表为空{group_info}。请先使用 plan_tasks 工具规划任务。"
                
                # 检查是否所有任务已完成
                if self._task_list_manager.is_all_completed(task_group=task_group):
                    stats = self._task_list_manager.get_statistics(task_group=task_group)
                    return self._format_all_completed_message(stats, task_group=task_group)
                else:
                    return "[错误] 没有待执行的任务，但任务列表不为空且未全部完成。这可能是一个异常状态。"

            # 2. 任务类型必须显式指定
            expected_type = getattr(current_task, "agent_type", None)
            if not expected_type:
                return self._format_recoverable_error(
                    error_code="MISSING_AGENT_TYPE",
                    message="当前任务缺少 agent_type，无法执行。",
                    payload={
                        "task_id": current_task.id,
                        "task_description": current_task.description,
                        "required_next_actions": [
                            "在 plan_tasks 中为每个任务显式提供 agent_type",
                            "重新调用 plan_tasks(workflows)",
                            "再调用 execute_next_task(agent_type=..., task_group=...) 执行任务",
                        ],
                    },
                )

            if expected_type != agent_type:
                return (
                    f"[错误] 当前待执行任务要求 agent_type={expected_type}，"
                    f"但收到 agent_type={agent_type}。请使用正确的 agent_type 调用 execute_next_task。"
                )

            # 3. 恢复锁检查（仅允许恢复同一任务）
            if self._recovery_lock_task_id and current_task.id != self._recovery_lock_task_id:
                locked_task = self._task_list_manager.get_task(self._recovery_lock_task_id)
                description = locked_task.description if locked_task else ""
                task_group_locked = locked_task.task_group if locked_task else None
                return self._format_recovery_lock_error(self._recovery_lock_task_id, description, task_group=task_group_locked)

            # 4. vuln_analysis 必须具备 function_identifier
            if agent_type == "vuln_analysis":
                function_identifier = getattr(current_task, "function_identifier", None)
                if not function_identifier:
                    self._set_recovery_lock(current_task.id)
                    group_hint = f", task_group=\"{task_group}\"" if task_group else ""
                    return (
                        self._format_recoverable_error(
                            error_code="MISSING_FUNCTION_IDENTIFIER",
                            message="当前任务缺少 function_identifier（vuln_analysis 必需）。",
                            payload={
                                "task_id": current_task.id,
                                "task_description": current_task.description,
                                "required_next_actions": [
                                    "调用 resolve_function_identifier 获取由 search_symbol 验证的候选标识符",
                                    "调用 set_task_function_identifier 回填任务参数",
                                    "重新调用 execute_next_task(agent_type='vuln_analysis', task_group=...)",
                                ],
                            },
                        )
                        + "\n\n请严格按以下步骤恢复：\n"
                        + f"1. resolve_function_identifier(task_id=\"{current_task.id}\", query_hint=\"{current_task.description}\")\n"
                        + f"2. set_task_function_identifier(task_id=\"{current_task.id}\", function_identifier=\"<从上一步候选中选择>\", source=\"search_symbol\")\n"
                        + f"3. execute_next_task(agent_type=\"vuln_analysis\"{group_hint})"
                    )
                self._clear_recovery_lock(current_task.id)

            # 5. 选择可执行任务批次（并发控制）
            batch_tasks = self._select_batch_tasks(
                agent_type=agent_type,
                require_function_identifier=agent_type == "vuln_analysis",
                task_group=task_group,
            )
            if not batch_tasks:
                return "[错误] 未找到可执行的任务批次，请检查任务状态。"

            # 6. 初始化 AgentDelegate（仅在真正执行任务前）
            if not self._agent_delegate:
                if not self.engine:
                    return "[错误] 引擎未初始化，无法创建 AgentDelegate。请先初始化引擎并重新初始化 Orchestrator。"
                if not self.llm_client:
                    return "[错误] LLM 客户端未初始化，无法创建 AgentDelegate。"
                if not self._file_manager:
                    return "[错误] FileManager 未初始化，无法创建 AgentDelegate。"
                from .agent_delegate import AgentDelegate
                self._agent_delegate = AgentDelegate(
                    engine=self.engine,
                    llm_client=self.llm_client,
                    file_manager=self._file_manager,
                )

            # 5. 执行任务（支持并发）
            if len(batch_tasks) == 1:
                task = batch_tasks[0]
                task_context = self._build_task_context(task, additional_context) if agent_type == "vuln_analysis" else additional_context
                input_override = None
                candidate_files = input_override or self._get_previous_task_outputs(task.id, task_group=task_group)
                selected_files = await self._select_context_files(
                    task_description=task.description,
                    additional_context=additional_context,
                    input_files=candidate_files,
                )
                if selected_files:
                    input_override = selected_files
                task, result, output_file = await self._execute_single_task(
                    task=task,
                    agent_type=agent_type,
                    additional_context=task_context,
                    input_files_override=input_override,
                )
                content = self._format_execution_result(
                    task=task,
                    result=result,
                    output_file=output_file,
                    task_group=task_group,
                )
                return await self._maybe_pack_tool_output("execute_next_task", content)

            semaphore = asyncio.Semaphore(self._max_parallel_tasks(agent_type))

            async def _run_task(t):
                async with semaphore:
                    task_context = self._build_task_context(t, additional_context) if agent_type == "vuln_analysis" else additional_context
                    input_override = None
                    candidate_files = input_override or self._get_previous_task_outputs(t.id, task_group=task_group)
                    selected_files = await self._select_context_files(
                        task_description=t.description,
                        additional_context=additional_context,
                        input_files=candidate_files,
                    )
                    if selected_files:
                        input_override = selected_files
                    return await self._execute_single_task(
                        task=t,
                        agent_type=agent_type,
                        additional_context=task_context,
                        input_files_override=input_override,
                    )

            results = await asyncio.gather(*[_run_task(t) for t in batch_tasks])
            content = self._format_batch_execution_result(results, task_group=task_group)
            return await self._maybe_pack_tool_output("execute_next_task", content)
        
        except Exception as e:
            return f"[错误] 执行任务失败: {str(e)}"

    async def get_task_status(self, task_group: Optional[str] = None) -> str:
        """获取当前任务列表状态

        读取 tasks.md，返回完整任务列表和统计信息。

        Args:
            task_group: 任务分组标识（可选）

        Returns:
            完整任务列表（Markdown 格式）+ 统计信息
        """
        try:
            # 检查是否已初始化
            if not hasattr(self, '_task_list_manager'):
                return "[错误] TaskListManager 未初始化。请先初始化 Orchestrator。"
            
            # 获取所有任务和统计信息
            all_tasks = self._task_list_manager.get_all_tasks(task_group=task_group)
            stats = self._task_list_manager.get_statistics(task_group=task_group)
            
            if not all_tasks:
                group_info = f"(task_group={task_group})" if task_group else ""
                return f"# 任务列表\n\n（无任务{group_info}）"
            
            # 格式化返回结果
            lines = [
                "# 任务列表",
                "",
            ]
            
            for task in all_tasks:
                lines.append(task.to_markdown_line())
            
            lines.extend([
                "",
                "---",
                "",
                f"**总计**: {stats['total']} 个任务",
                f"**待执行**: {stats['pending']} 个",
                f"**执行中**: {stats['in_progress']} 个",
                f"**已完成**: {stats['completed']} 个",
                f"**失败**: {stats['failed']} 个",
                f"**完成率**: {stats['completion_rate']}%",
            ])
            
            # 如果所有任务已完成，添加祝贺信息
            if self._task_list_manager.is_all_completed(task_group=task_group):
                lines.extend([
                    "",
                    "🎉 **所有任务已完成！**",
                ])
            
            return "\n".join(lines)
        
        except Exception as e:
            return f"[错误] 获取任务状态失败: {str(e)}"

    async def list_artifacts(self) -> str:
        """
        列出当前 ArtifactStore 中的摘要列表（Markdown 纯文本）
        """
        if not self.artifact_store:
            return "[错误] ArtifactStore 未初始化。"

        artifact_ids = self.artifact_store.list_artifacts()
        if not artifact_ids:
            return "当前没有可用的 artifacts。"

        lines = [
            "# Artifact 摘要列表",
            "",
            f"- 总数: {len(artifact_ids)}",
            "",
        ]
        for idx, artifact_id in enumerate(artifact_ids, 1):
            meta = self.artifact_store.read_metadata(artifact_id)
            summary = (meta.get("summary") or "").strip()
            size = meta.get("size", 0)
            created_at = meta.get("created_at", 0)
            lines.append(f"{idx}. `{artifact_id}`")
            lines.append(f"   - size: {size}")
            lines.append(f"   - created_at: {created_at}")
            if summary:
                lines.append(f"   - summary: {summary}")
            lines.append("")

        return "\n".join(lines)

    async def read_task_output(self, task_id: str) -> Any:
        """读取指定任务的输出文件
        
        根据 task_id 找到输出文件，返回文件内容。
        
        Args:
            task_id: 任务 ID，例如 "task_1"
        
        Returns:
            任务输出文件的内容；若输出超长，返回 {"content": "...", "summary": "..."}。
        """
        try:
            # 检查是否已初始化
            if not hasattr(self, '_file_manager'):
                return "[错误] FileManager 未初始化。请先初始化 Orchestrator。"
            
            # 生成输出文件路径
            output_file = self._file_manager.get_artifact_path(
                task_id=task_id,
                artifact_name="output"
            )
            
            # 检查文件是否存在
            if not output_file.exists():
                return f"[错误] 任务 {task_id} 的输出文件不存在: {output_file}"
            
            # 读取文件内容
            content = self._file_manager.read_artifact(output_file)
            
            # 格式化返回结果
            lines = [
                f"# 任务输出: {task_id}",
                "",
                f"**文件路径**: {output_file}",
                "",
                "---",
                "",
                content,
            ]
            
            return "\n".join(lines)
        
        except FileNotFoundError:
            return f"[错误] 任务 {task_id} 的输出文件不存在"
        except Exception as e:
            return f"[错误] 读取任务输出失败: {str(e)}"

    # ==================== 辅助方法 ====================

    def _get_previous_task_outputs(self, current_task_id: str, task_group: Optional[str] = None) -> List[Path]:
        """
        获取前置任务的输出文件列表
        
        Args:
            current_task_id: 当前任务 ID (如 task_2)
            task_group: 任务分组标识（可选）
        
        Returns:
            List[Path]: 前置任务的输出文件路径列表
        """
        tasks = self._task_list_manager.get_all_tasks(task_group=task_group)
        if not tasks:
            return []

        task_ids = [task.id for task in tasks]
        if current_task_id not in task_ids:
            return []

        current_index = task_ids.index(current_task_id)
        input_files = []
        for prev_task in tasks[:current_index]:
            output_file = self._file_manager.get_artifact_path(
                task_id=prev_task.id,
                artifact_name="output",
            )
            if output_file.exists():
                input_files.append(output_file)

        return input_files

    async def _build_context_candidates(self, input_files: List[Path]) -> List[Dict[str, Any]]:
        """
        构建上下文候选摘要列表

        Args:
            input_files: 输入文件路径列表

        Returns:
            候选列表（每项包含 file_id, file_path, summary, size）
        """
        if not self._file_manager:
            return []

        candidates = []
        for file_path in input_files:
            summary_path = file_path.with_suffix(".summary.md")
            if not summary_path.exists():
                raise RuntimeError(f"[错误] 缺少摘要文件: {summary_path}")

            try:
                summary = self._file_manager.read_artifact(summary_path)
            except Exception as e:
                raise RuntimeError(f"[错误] 读取摘要文件失败: {summary_path} ({e})") from e

            size = file_path.stat().st_size if file_path.exists() else 0
            candidates.append({
                "file_id": file_path.name,
                "file_path": str(file_path),
                "summary": summary,
                "size": size,
            })

        return candidates

    async def _select_context_files(
        self,
        task_description: str,
        additional_context: str,
        input_files: List[Path],
    ) -> Optional[List[Path]]:
        """
        使用 LLM 选择当前任务所需的上下文文件列表

        Args:
            task_description: 任务描述
            additional_context: 额外上下文
            input_files: 候选输入文件路径

        Returns:
            选中的文件路径列表；失败返回 None（回退原始列表）
        """
        if not self.llm_client or not input_files:
            return None
        if len(input_files) <= 1:
            return input_files

        candidates = await self._build_context_candidates(input_files)
        if not candidates:
            return None

        def finish_context_manifest(selected_file_ids: List[str], manifest_markdown: str = ""):
            """
            Return selected file ids and a Markdown context manifest.

            Args:
                selected_file_ids: 选中的 file_id 列表
                manifest_markdown: Markdown 纯文本 Manifest
            """
            pass

        system_prompt = (
            "你是一个上下文选择器。"
            "请根据任务目标选择最小但充分的上下文文件集合。"
            "不要依赖数量阈值或规则判断。"
        )
        user_prompt = (
            "请从候选上下文中选择与任务直接相关的文件。\n\n"
            "## 任务描述\n"
            f"{task_description}\n\n"
            "## 额外上下文\n"
            f"{additional_context}\n\n"
            "## 候选摘要列表（每项包含 file_id）\n"
            "```json\n"
            f"{json.dumps(candidates, ensure_ascii=False, indent=2)}\n"
            "```\n\n"
            "输出要求：\n"
            "- 返回 selected_file_ids（file_id 列表）\n"
            "- manifest_markdown 为 Markdown 纯文本\n"
            "- 不要输出 JSON 或结构化对象\n"
        )

        try:
            session_tag = self._session_id or "default"
            agent_id = f"context_selector_{session_tag}"
            metadata_target = (task_description or "").strip() or "context_selection"
            tool_client = ToolBasedLLMClient(
                llm=self.llm_client,
                max_retries=2,
                retry_delay=1.0,
                verbose=False,
                enable_logging=True,
                session_id=self._session_id,
                agent_id=agent_id,
                log_metadata={
                    "agent_type": "context_selector",
                    "target_function": metadata_target,
                },
            )
            result = await tool_client.atool_call(
                messages=[HumanMessage(content=user_prompt)],
                tools=[finish_context_manifest],
                system_prompt=system_prompt,
            )
            if result and result.tool_calls:
                args = result.tool_calls[0].get("args", {})
                selected_ids = args.get("selected_file_ids") or []
                if not selected_ids:
                    return None
                selected = [p for p in input_files if p.name in set(selected_ids)]
                return selected or None
            if result and result.content:
                return None
        except Exception:
            return None

        return None

    def _max_parallel_tasks(self, agent_type: str) -> int:
        """根据 agent_type 返回最大并发任务数（由 Agent 控制）"""
        if agent_type == "vuln_analysis":
            return self.max_vuln_concurrency
        return 1

    def _select_batch_tasks(
        self,
        agent_type: str,
        require_function_identifier: bool = False,
        task_group: Optional[str] = None,
    ) -> List[Any]:
        """选择可并发执行的一批任务（从首个 PENDING 开始，连续同类型且条件满足）"""
        from .task_list_manager import TaskStatus
        all_tasks = self._task_list_manager.get_all_tasks(task_group=task_group)
        start_idx = None
        for idx, task in enumerate(all_tasks):
            if task.status == TaskStatus.PENDING:
                start_idx = idx
                break
        if start_idx is None:
            return []

        batch = []
        max_parallel = self._max_parallel_tasks(agent_type)
        for task in all_tasks[start_idx:]:
            if task.status != TaskStatus.PENDING:
                break
            if not task.agent_type:
                break
            if task.agent_type != agent_type:
                break
            if require_function_identifier and not getattr(task, "function_identifier", None):
                break
            batch.append(task)
            if len(batch) >= max_parallel:
                break
        return batch

    async def _execute_single_task(
        self,
        task: Any,
        agent_type: str,
        additional_context: str,
        input_files_override: Optional[List[Path]] = None,
    ) -> Tuple[Any, Any, Path]:
        """执行单个任务并返回结果元组"""
        from .task_list_manager import TaskStatus

        # 更新任务状态为 in_progress
        self._task_list_manager.update_task_status(
            task_id=task.id,
            status=TaskStatus.IN_PROGRESS
        )

        # 读取前置任务的输出文件（如果有）
        input_files = input_files_override if input_files_override is not None else self._get_previous_task_outputs(task.id)

        # 生成输出文件路径
        output_file = self._file_manager.get_artifact_path(
            task_id=task.id,
            artifact_name="output"
        )

        # 调用 AgentDelegate 执行任务
        result = await self._agent_delegate.delegate(
            agent_type=agent_type,
            task_description=task.description,
            input_files=input_files,
            output_file=output_file,
            context=additional_context,
            function_identifier=getattr(task, "function_identifier", None),
        )

        # 更新任务状态
        if result.success:
            self._task_list_manager.update_task_status(
                task_id=task.id,
                status=TaskStatus.COMPLETED
            )
        else:
            self._task_list_manager.update_task_status(
                task_id=task.id,
                status=TaskStatus.FAILED,
                error_message=result.error_message
            )

        return task, result, output_file

    def _format_batch_execution_result(
        self,
        results: List[Tuple[Any, Any, Path]],
        task_group: Optional[str] = None,
    ) -> str:
        """格式化批量任务执行结果"""
        lines = [
            "## 执行结果",
            "",
            f"**批量任务数**: {len(results)}",
            "",
        ]

        for task, result, output_file in results:
            lines.append(f"### {task.id} - {task.description}")
            if result.success:
                lines.extend([
                    f"- 状态: 已完成 ✓",
                    f"- 输出文件: {output_file.relative_to(self._file_manager.session_dir)}",
                ])
            else:
                lines.extend([
                    f"- 状态: 失败 ✗",
                    f"- 错误: {result.error_message}",
                ])
            lines.append("")

        lines.extend([
            "---",
            "",
            "## 当前任务列表",
            "",
        ])

        # 添加任务列表
        all_tasks = self._task_list_manager.get_all_tasks(task_group=task_group)
        for task_item in all_tasks:
            lines.append(task_item.to_markdown_line())

        # 添加统计信息
        stats = self._task_list_manager.get_statistics(task_group=task_group)
        lines.extend([
            "",
            "---",
            "",
            f"**总计**: {stats['total']} 个任务",
            f"**已完成**: {stats['completed']} 个",
            f"**待执行**: {stats['pending']} 个",
            f"**进度**: {stats['completion_rate']}%",
        ])

        if self._task_list_manager.is_all_completed(task_group=task_group):
            lines.extend([
                "",
                "🎉 **所有任务已完成！**",
            ])

        return "\n".join(lines)

    def _format_execution_result(
        self,
        task: Any,
        result: Any,
        output_file: Path,
        task_group: Optional[str] = None,
    ) -> str:
        """
        格式化任务执行结果
        
        Args:
            task: 任务对象
            result: AgentDelegate 返回的结果
            output_file: 输出文件路径
        
        Returns:
            str: 格式化的结果文本
        """
        lines = [
            "## 执行结果",
            "",
            f"**任务**: {task.id} - {task.description}",
        ]
        
        if result.success:
            lines.extend([
                f"**状态**: 已完成 ✓",
                f"**输出文件**: {output_file.relative_to(self._file_manager.session_dir)}",
                "",
            ])
            
            # 提取关键发现（从输出中提取前几行作为摘要）
            if result.output:
                summary_lines = result.output.split('\n')[:10]
                lines.extend([
                    "**关键发现**:",
                    "",
                    '\n'.join(summary_lines),
                    "",
                    "（完整结果已保存到输出文件）",
                ])
        else:
            lines.extend([
                f"**状态**: 失败 ✗",
                f"**错误**: {result.error_message}",
                "",
            ])
        
        lines.extend([
            "",
            "---",
            "",
            "## 当前任务列表",
            "",
        ])
        
        # 添加任务列表
        all_tasks = self._task_list_manager.get_all_tasks(task_group=task_group)
        for task_item in all_tasks:
            lines.append(task_item.to_markdown_line())
        
        # 添加统计信息
        stats = self._task_list_manager.get_statistics(task_group=task_group)
        lines.extend([
            "",
            "---",
            "",
            f"**总计**: {stats['total']} 个任务",
            f"**已完成**: {stats['completed']} 个",
            f"**待执行**: {stats['pending']} 个",
            f"**进度**: {stats['completion_rate']}%",
        ])
        
        # 如果所有任务已完成，添加祝贺信息
        if self._task_list_manager.is_all_completed(task_group=task_group):
            lines.extend([
                "",
                "🎉 **所有任务已完成！**",
            ])
        
        return "\n".join(lines)

    def _format_all_completed_message(self, stats: Dict[str, Any], task_group: Optional[str] = None) -> str:
        """
        格式化所有任务已完成的消息
        
        Args:
            stats: 统计信息
        
        Returns:
            str: 格式化的消息
        """
        lines = [
            "## 执行结果",
            "",
            "**状态**: 所有任务已完成 🎉",
            "",
            "---",
            "",
            "## 任务列表",
            "",
        ]
        
        # 添加任务列表
        all_tasks = self._task_list_manager.get_all_tasks(task_group=task_group)
        for task in all_tasks:
            lines.append(task.to_markdown_line())
        
        # 添加统计信息
        lines.extend([
            "",
            "---",
            "",
            f"**总计**: {stats['total']} 个任务",
            f"**已完成**: {stats['completed']} 个",
            f"**失败**: {stats['failed']} 个",
            f"**完成率**: {stats['completion_rate']}%",
        ])
        
        return "\n".join(lines)

    def _build_query_prompt(self, query: str, context: Optional[str]) -> str:
        """构建代码查询提示词"""
        lines = [
            "你是一个代码分析助手。请根据以下信息回答问题。",
            "",
            f"查询: {query}",
        ]

        if context:
            lines.append(f"\n上下文: {context}")

        if self.workflow_context:
            lines.append(
                f"\n分析目标: {self.workflow_context.target.path if self.workflow_context.target else 'Unknown'}")

        if self.engine:
            lines.append(f"引擎类型: {self.engine.__class__.__name__}")
            if hasattr(self.engine, 'file_path'):
                lines.append(f"目标文件: {self.engine.file_path}")

        lines.append("\n请提供详细的分析结果。")

        return "\n".join(lines)

    def _normalize_workflows(self, workflows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """标准化 workflow 信息，补充默认值"""
        normalized = []
        for i, wf in enumerate(workflows, 1):
            normalized_wf = {
                "workflow_id": wf.get("workflow_id", f"workflow_{i}"),
                "workflow_name": wf.get("workflow_name", f"Workflow {i}"),
                "workflow_description": wf.get("workflow_description", ""),
                "tasks": wf["tasks"],
                "execution_mode": wf.get("execution_mode", "sequential"),
            }
            normalized.append(normalized_wf)
        return normalized

    def _flatten_workflow_tasks(self, workflows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """将多 workflow 任务展开为统一序列，保留 workflow 元信息"""
        flat_tasks: List[Dict[str, Any]] = []
        for wf in workflows:
            workflow_id = wf.get("workflow_id", "")
            workflow_name = wf.get("workflow_name", "")
            execution_mode = wf.get("execution_mode", "sequential")
            for task in wf.get("tasks", []):
                if isinstance(task, dict):
                    merged = dict(task)
                    merged["task_group"] = workflow_id
                    merged["workflow_name"] = workflow_name
                    merged["workflow_execution_mode"] = execution_mode
                    merged["analysis_context"] = task.get("analysis_context")
                    flat_tasks.append(merged)
                else:
                    flat_tasks.append({
                        "description": str(task).strip(),
                        "task_group": workflow_id,
                        "workflow_name": workflow_name,
                        "workflow_execution_mode": execution_mode,
                    })
        return flat_tasks

    def _format_single_workflow_summary(self, workflow: Dict[str, Any]) -> str:
        """格式化单 workflow 摘要"""
        tasks = workflow["tasks"]
        lines = [
            "# 任务规划完成",
            "",
            f"**模式**: 单 Workflow",
            f"**任务数量**: {len(tasks)}",
            "",
            "## 任务列表",
            "",
        ]
        
        for i, task in enumerate(tasks, 1):
            if isinstance(task, dict):
                task_desc = task.get("description", "")
            else:
                task_desc = str(task)
            lines.append(f"{i}. {task_desc}")
        
        lines.extend([
            "",
            "---",
            "",
            "✅ 任务列表已创建，可以开始执行任务。",
        ])
        
        return "\n".join(lines)

    def _format_multi_workflow_summary(self, workflows: List[Dict[str, Any]]) -> str:
        """格式化多 workflow 摘要"""
        total_tasks = sum(len(wf["tasks"]) for wf in workflows)
        
        lines = [
            "# 任务规划完成",
            "",
            f"**模式**: 多 Workflow",
            f"**Workflow 数量**: {len(workflows)}",
            f"**总任务数量**: {total_tasks}",
            "",
            "## Workflow 列表",
            "",
        ]
        
        for i, wf in enumerate(workflows, 1):
            lines.extend([
                f"### {i}. {wf['workflow_name']}",
                "",
                f"**ID**: `{wf['workflow_id']}`",
            ])
            
            if wf.get("workflow_description"):
                lines.append(f"**描述**: {wf['workflow_description']}")
            
            lines.extend([
                f"**执行模式**: {wf['execution_mode']}",
                f"**任务数量**: {len(wf['tasks'])}",
                "",
                "**任务列表**:",
                "",
            ])
            
            for j, task in enumerate(wf["tasks"], 1):
                if isinstance(task, dict):
                    task_desc = task.get("description", "")
                else:
                    task_desc = str(task)
                lines.append(f"{j}. {task_desc}")
            
            lines.append("")
        
        lines.extend([
            "---",
            "",
            "✅ 多 Workflow 规划完成，任务列表已创建，可以开始执行任务。",
        ])
        
        return "\n".join(lines)

    # 新增：供 MasterOrchestrator 查询的方法
    def get_planned_workflows(self) -> Optional[List[Dict[str, Any]]]:
        """获取规划的 workflow 列表"""
        return self._planned_workflows

    def is_multi_workflow(self) -> bool:
        """判断是否为多 workflow 模式"""
        return self._is_multi_workflow

    # ==================== LangChain Tool 导出 ====================

    def get_tools(self) -> List[Any]:
        """
        获取所有 Tool 的函数列表。
        供 OrchestratorAgent 使用。
        """
        return [
            # 简化的任务编排工具（新设计）
            self.plan_tasks,
            self.append_tasks,
            self.execute_next_task,
            self.resolve_function_identifier,
            self.set_task_function_identifier,
            self.get_task_status,
            self.read_task_output,
            self.list_artifacts,
            # 统一的 Agent 委托接口
            self.delegate_task,
            # 数据访问工具
            self.read_artifact,
        ]

    def get_executor_tools(self) -> List[Any]:
        """
        获取执行器可用的 Tool 列表。

        TaskExecutorAgent 只允许执行任务，不允许规划与委托。
        """
        return [
            self.execute_next_task,
            self.resolve_function_identifier,
            self.set_task_function_identifier,
            self.get_task_status,
            self.read_task_output,
            self.read_artifact,
        ]


