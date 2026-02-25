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


from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from pathlib import Path
import uuid
import json

from .agent_delegate import AgentDelegate
from ..models.workflow import WorkflowContext

from ..engines import create_engine, BaseStaticAnalysisEngine
from ..agents.deep_vuln_agent import DeepVulnAgent
from ..agents.prompts import get_vuln_agent_system_prompt
from ..core.context import ArtifactStore



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

    # ==================== 内部方法 ====================

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
    ) -> str:
        """读取已归档的 Artifact 内容。

        参数:
            artifact_id: Artifact ID
            offset: 起始行号（从0开始）
            limit: 返回行数上限
        """
        if not self.artifact_store:
            return "[错误] ArtifactStore 未初始化"

        content = self.artifact_store.read(artifact_id, offset=offset, limit=limit)
        metadata = self.artifact_store.read_metadata(artifact_id)

        lines = [
            "=== Artifact 内容 ===",
            "",
            f"Artifact ID: {artifact_id}",
        ]
        if isinstance(metadata, dict) and not metadata.get("error"):
            summary = metadata.get("summary", "")
            size = metadata.get("size", "")
            lines.append(f"大小: {size}")
            if summary:
                lines.append(f"摘要: {summary}")
        lines.extend([
            "",
            "【内容】",
            content,
        ])
        return "\n".join(lines)

    async def delegate_task(
            self,
            agent_type: str,
            query: str,
            context: Optional[str] = None,
            function_identifier: Optional[str] = None,
            max_depth: int = 10,
            max_iterations: int = 15,
    ) -> str:
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
                - 前置条件、约束、背景知识等
            
            function_identifier: 函数唯一标识符（仅 vuln_analysis 使用）
                - 如果提供，直接使用此标识符，不从 query 中提取
                - 格式示例: "PasswordProvider.query", "parse_request", "com.example.MyClass.method"
                - 推荐：先使用 search_symbol 或 query_code 获取准确的函数标识符，再传入此参数
            
            max_depth: 最大分析深度（仅 vuln_analysis 使用）
            max_iterations: 最大迭代次数
        
        返回: markdown格式的文本结果（包含分析摘要和关键发现）
        """
        if not self.engine:
            return "[错误] 引擎未初始化，请先调用 initialize_engine"

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

                return result

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

                # 构建前置条件
                preconditions = context if context else query

                # 创建 DeepVulnAgent
                from ..agents.deep_vuln_agent import DeepVulnAgent
                from ..agents.prompts import get_vuln_agent_system_prompt

                base_prompt = get_vuln_agent_system_prompt(self.engine_name or "ida")

                specialization = f"""## 当前分析任务特化

### 分析目标
函数: `{target_function_id}`

### 前置条件约束
{preconditions}
"""
                if self.workflow_context and self.workflow_context.background_knowledge:
                    specialization += f"\n### 背景知识\n{self.workflow_context.background_knowledge}\n"

                full_prompt = f"{base_prompt}\n\n{specialization}"

                agent = DeepVulnAgent(
                    engine=self.engine,
                    llm_client=self.llm_client,
                    max_iterations=max_iterations,
                    max_depth=max_depth,
                    verbose=True,
                    system_prompt=full_prompt,
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
                result = await agent.run(function_identifier=target_function_id)
                
                # 格式化结果为markdown文本
                return self._format_vuln_result(result, target_function_id, agent_id)

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
            preconditions: str,
            max_depth: int = 10,
    ) -> str:
        """创建漏洞分析 Agent 并执行单一函数的深度漏洞挖掘。
        
        根据前置条件约束，创建 Specialized 漏洞分析 Agent，
        对指定的函数开展深度漏洞挖掘。
        
        参数:
            function_identifier: 待分析的函数标识符（如 "int parse_request(char* buf, size_t len)"）
            preconditions: 前置条件约束描述，应包含：
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

            specialization = f"""## 当前分析任务特化

### 分析目标
函数: `{function_identifier}`

### 前置条件约束
{preconditions}
"""
            if self.workflow_context and self.workflow_context.background_knowledge:
                specialization += f"\n### 背景知识\n{self.workflow_context.background_knowledge}\n"

            full_prompt = f"{base_prompt}\n\n{specialization}"

            agent = DeepVulnAgent(
                engine=self.engine,
                llm_client=self.llm_client,
                max_iterations=10,
                max_depth=max_depth,
                verbose=True,
                system_prompt=full_prompt,
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
            result = await agent.run(function_identifier=function_identifier)
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


    async def plan_tasks(self, workflows: List[Dict[str, Any]]) -> str:
        """规划任务列表，支持单/多 workflow 模式。

        每个 workflow 字典应包含: tasks (必需的任务列表), workflow_id (可选标识符),
        workflow_name (可选名称), workflow_description (可选描述),
        execution_mode (可选，sequential 或 parallel)。
        
        tasks 支持两种形式：
        - 字符串：任务描述
        - 字典：显式任务对象，字段包括 description / agent_type / function_identifier
          其中 agent_type 为 vuln_analysis 时必须提供 function_identifier
          function_identifier 必须来自 search_symbol 的验证结果，保持原样

        Args:
            workflows: Workflow 配置列表

        Returns:
            规划结果摘要（Markdown 格式）
        """
        try:
            # 1. 验证参数
            if not workflows:
                return "[错误] workflows 参数为空"

            if not isinstance(workflows, list):
                return "[错误] workflows 必须是列表类型"

            for i, wf in enumerate(workflows):
                if not isinstance(wf, dict):
                    return f"[错误] workflow[{i}] 不是字典类型"
                if "tasks" not in wf:
                    return f"[错误] workflow[{i}] 缺少必需字段 'tasks'"
                
                # 修复：确保tasks是列表，如果是dict则转换
                tasks = wf["tasks"]
                if isinstance(tasks, dict):
                    # 如果是dict，尝试提取任务列表
                    if "tasks" in tasks:
                        wf["tasks"] = tasks["tasks"]
                    elif "task_list" in tasks:
                        wf["tasks"] = tasks["task_list"]
                    else:
                        # 尝试从dict的values中提取
                        wf["tasks"] = list(tasks.values()) if tasks else []
                    tasks = wf["tasks"]
                
                if not isinstance(tasks, list) or not tasks:
                    return f"[错误] workflow[{i}] 的 'tasks' 必须是非空列表"
                
                # 校验并标准化 task 结构
                for j, task in enumerate(tasks):
                    if isinstance(task, str):
                        tasks[j] = task.strip()
                        continue
                    if isinstance(task, dict):
                        if "description" not in task:
                            return f"[错误] workflow[{i}] 的 tasks[{j}] 缺少 description 字段"
                        if task.get("agent_type") == "vuln_analysis" and not task.get("function_identifier"):
                            return f"[错误] workflow[{i}] 的 tasks[{j}] 缺少 function_identifier（vuln_analysis 必需）"
                        tasks[j] = {
                            "description": str(task["description"]).strip(),
                            "agent_type": task.get("agent_type"),
                            "function_identifier": task.get("function_identifier"),
                        }
                        continue
                    return f"[错误] workflow[{i}] 的 tasks[{j}] 类型不支持（仅支持字符串或字典）"

            # 2. 判断单/多 workflow（在标准化之前判断）
            is_multi = len(workflows) > 1 or (
                len(workflows) == 1 and workflows[0].get("workflow_id") is not None
            )

            # 3. 标准化 workflow 信息
            normalized = self._normalize_workflows(workflows)

            # 4. 保存规划状态（关键！）
            self._planned_workflows = normalized
            self._is_multi_workflow = is_multi

            # 5. 根据模式返回不同的摘要
            if is_multi:
                return self._format_multi_workflow_summary(normalized)
            else:
                # 单 workflow：直接创建任务列表
                if not hasattr(self, '_task_list_manager') or not hasattr(self, '_file_manager'):
                    return "[错误] TaskListManager 或 FileManager 未初始化。请先初始化 Orchestrator。"

                self._task_list_manager.create_tasks(normalized[0]["tasks"])
                return self._format_single_workflow_summary(normalized[0])

        except Exception as e:
            return f"[错误] 规划任务失败: {str(e)}"


    async def execute_next_task(
        self,
        agent_type: str,
        additional_context: str = ""
    ) -> str:
        """执行下一个待执行任务（自动处理所有细节）
        
        自动获取下一个待执行任务，读取前置任务的输出文件，生成输出文件路径，
        调用 AgentDelegate 执行任务，更新任务状态，返回执行结果和完整任务列表。
        
        Args:
            agent_type: Agent 类型，支持 code_explorer 用于代码探索和分析，或 vuln_analysis 用于漏洞挖掘分析
            additional_context: 额外的上下文信息，如补充说明或约束条件
        
        重要要求：
            - 如果 agent_type 为 vuln_analysis，当前任务必须在 plan_tasks 阶段显式提供 function_identifier

        自动处理：
            - 自动获取下一个待执行任务
            - 自动读取前置任务的输出文件（如果有）
            - 自动生成输出文件路径
            - 自动更新任务状态
            - 自动传递上下文给子 Agent
        
        Returns:
            执行结果 + 完整任务列表状态，例如：
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
            
            # 1. 获取下一个待执行任务
            current_task = self._task_list_manager.get_current_task()
            
            if not current_task:
                # 检查任务列表是否为空
                all_tasks = self._task_list_manager.get_all_tasks()
                if not all_tasks:
                    return "[错误] 任务列表为空。请先使用 plan_tasks 工具规划任务。"
                
                # 检查是否所有任务已完成
                if self._task_list_manager.is_all_completed():
                    stats = self._task_list_manager.get_statistics()
                    return self._format_all_completed_message(stats)
                else:
                    return "[错误] 没有待执行的任务，但任务列表不为空且未全部完成。这可能是一个异常状态。"
            
            # 2. 获取函数标识符（仅 vuln_analysis 使用）
            function_identifier = getattr(current_task, "function_identifier", None)
            if agent_type == "vuln_analysis" and not function_identifier:
                return "[错误] 当前任务缺少 function_identifier（vuln_analysis 必需）。请在 plan_tasks 阶段显式提供。"

            # 3. 更新任务状态为 in_progress
            from .task_list_manager import TaskStatus
            self._task_list_manager.update_task_status(
                task_id=current_task.id,
                status=TaskStatus.IN_PROGRESS
            )
            
            # 4. 读取前置任务的输出文件（如果有）
            input_files = self._get_previous_task_outputs(current_task.id)
            
            # 5. 生成输出文件路径
            output_file = self._file_manager.get_artifact_path(
                task_id=current_task.id,
                artifact_name="output"
            )
            
            # 6. 调用 AgentDelegate 执行任务
            result = await self._agent_delegate.delegate(
                agent_type=agent_type,
                task_description=current_task.description,
                input_files=input_files,
                output_file=output_file,
                context=additional_context,
                function_identifier=function_identifier,
            )
            
            # 7. 更新任务状态
            if result.success:
                self._task_list_manager.update_task_status(
                    task_id=current_task.id,
                    status=TaskStatus.COMPLETED
                )
            else:
                self._task_list_manager.update_task_status(
                    task_id=current_task.id,
                    status=TaskStatus.FAILED,
                    error_message=result.error_message
                )
            
            # 8. 格式化返回结果
            return self._format_execution_result(
                task=current_task,
                result=result,
                output_file=output_file
            )
        
        except Exception as e:
            return f"[错误] 执行任务失败: {str(e)}"

    async def get_task_status(self) -> str:
        """获取当前任务列表状态
        
        读取 tasks.md，返回完整任务列表和统计信息。
        
        Returns:
            完整任务列表（Markdown 格式）+ 统计信息
        """
        try:
            # 检查是否已初始化
            if not hasattr(self, '_task_list_manager'):
                return "[错误] TaskListManager 未初始化。请先初始化 Orchestrator。"
            
            # 获取所有任务和统计信息
            all_tasks = self._task_list_manager.get_all_tasks()
            stats = self._task_list_manager.get_statistics()
            
            if not all_tasks:
                return "# 任务列表\n\n（无任务）"
            
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
            if self._task_list_manager.is_all_completed():
                lines.extend([
                    "",
                    "🎉 **所有任务已完成！**",
                ])
            
            return "\n".join(lines)
        
        except Exception as e:
            return f"[错误] 获取任务状态失败: {str(e)}"

    async def read_task_output(self, task_id: str) -> str:
        """读取指定任务的输出文件
        
        根据 task_id 找到输出文件，返回文件内容。
        
        Args:
            task_id: 任务 ID，例如 "task_1"
        
        Returns:
            任务输出文件的内容
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

    def _get_previous_task_outputs(self, current_task_id: str) -> List[Path]:
        """
        获取前置任务的输出文件列表
        
        Args:
            current_task_id: 当前任务 ID (如 task_2)
        
        Returns:
            List[Path]: 前置任务的输出文件路径列表
        """
        # 提取当前任务编号
        import re
        match = re.match(r"task_(\d+)", current_task_id)
        if not match:
            return []
        
        current_num = int(match.group(1))
        
        # 获取所有前置任务的输出文件
        input_files = []
        for i in range(1, current_num):
            prev_task_id = f"task_{i}"
            output_file = self._file_manager.get_artifact_path(
                task_id=prev_task_id,
                artifact_name="output"
            )
            
            # 只添加存在的文件
            if output_file.exists():
                input_files.append(output_file)
        
        return input_files

    def _format_execution_result(
        self,
        task: Any,
        result: Any,
        output_file: Path
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
        all_tasks = self._task_list_manager.get_all_tasks()
        for task_item in all_tasks:
            lines.append(task_item.to_markdown_line())
        
        # 添加统计信息
        stats = self._task_list_manager.get_statistics()
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
        if self._task_list_manager.is_all_completed():
            lines.extend([
                "",
                "🎉 **所有任务已完成！**",
            ])
        
        return "\n".join(lines)

    def _format_all_completed_message(self, stats: Dict[str, Any]) -> str:
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
        all_tasks = self._task_list_manager.get_all_tasks()
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
            "✅ 多 Workflow 规划完成，MasterOrchestrator 将协调执行。",
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
            self.execute_next_task,
            self.get_task_status,
            self.read_task_output,
            # 统一的 Agent 委托接口
            self.delegate_task,
            # 数据访问工具
            self.read_artifact,
        ]


