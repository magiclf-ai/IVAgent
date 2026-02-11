#!/usr/bin/env python3
"""
Orchestrator Tools - 简化的 Tool 管理

所有 Tools 整合到一个类中，通过类变量共享状态：
- engine: 当前分析引擎
- workflow_context: Workflow 上下文
- llm_client: LLM 客户端
- agents: 创建的 Agent 缓存
- vulnerabilities: 发现的漏洞列表
- task_manager: 任务管理器
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from pathlib import Path
import uuid
import json

from ..models.workflow import WorkflowContext
from ..models.task import TaskStatus
from .task_manager import TaskManager
from ..engines import create_engine, BaseStaticAnalysisEngine
from ..agents.deep_vuln_agent import DeepVulnAgent
from ..agents.prompts import get_vuln_agent_system_prompt


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
    ):
        self.llm_client = llm_client
        self.workflow_context = workflow_context

        # 共享状态
        self.engine: Optional[BaseStaticAnalysisEngine] = None
        self.engine_name: Optional[str] = None
        self.agents: Dict[str, AgentInstance] = {}
        self.vulnerabilities: List[VulnerabilityInfo] = []
        self._last_agent_id: Optional[str] = None
        self.task_manager: TaskManager = TaskManager()

        # 延迟初始化参数（用于异步初始化）
        self._pending_engine_type = engine_type
        self._pending_target_path = target_path
        self._pending_source_root = source_root
        self._initialized = False

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

    # ==================== Tool 定义 ====================

    async def query_code(
            self,
            query: str,
            context: Optional[str] = None,
    ) -> str:
        """语义级代码查询。使用自然语言描述查询需求，返回分析结果。
        
        内部调用 SemanticAnalysisAgent 通过 Tool Call 循环自主探索代码，
        结合基础代码探索（grep/read_file）和高级静态分析能力完成深度分析。
        
        参数:
            query: 自然语言查询描述
            context: 可选上下文信息
        """
        # 返回: 格式化的分析结果文本，包含分析摘要、发现的代码项、证据片段等
        if not self.engine:
            return "[错误] 引擎未初始化，请先调用 initialize_engine"

        if not self.llm_client:
            return "[错误] LLM 客户端不可用"

        try:
            from ..agents.semantic_analysis_agent import SemanticAnalysisAgent

            agent = SemanticAnalysisAgent(
                engine=self.engine,
                llm_client=self.llm_client,
                max_iterations=10,
                enable_logging=True,
                session_id=getattr(self, 'session_id', None),
            )

            result = await agent.analyze(
                query=query,
                context=context
            )

            return result

        except Exception as e:
            return f"[错误] 查询执行失败: {str(e)}"

    async def search_symbol(
            self,
            pattern: str,
            limit: int = 30,
            offset: int = 0,
            case_sensitive: bool = False,
    ) -> str:
        """搜索程序中的符号（函数、字符串、变量）。

        参数:
            pattern: 搜索字符串（Python 正则表达式）
            limit: 返回结果数量上限
            offset: 结果起始偏移量，返回 [offset, offset + limit) 范围内的结果
            case_sensitive: 是否区分大小写，默认为 False（忽略大小写）
        """
        # 返回: 格式化的搜索结果文本
        if not self.engine:
            return "[错误] 引擎未初始化，请先调用 initialize_engine"

        try:
            import re
            from ..engines.base_static_analysis_engine import SearchOptions

            # 验证正则表达式有效性
            flags = 0 if case_sensitive else re.IGNORECASE
            try:
                re.compile(pattern, flags)
            except re.error as e:
                return f"[错误] 正则表达式无效: {str(e)}"

            # 调用引擎搜索，由引擎处理 offset/limit/case_sensitive/regex
            search_results = await self.engine.search_symbol(
                query=pattern,
                options=SearchOptions(
                    limit=limit,
                    offset=offset,
                    case_sensitive=case_sensitive,
                    use_regex=True,
                )
            )

            if not search_results:
                return f"搜索 '{pattern}' 未找到匹配的符号。"

            # 格式化为易读的文本
            lines = [
                f"=== 符号搜索结果 ===",
                f"",
                f"搜索模式: {pattern}",
                f"正则标志: {'区分大小写' if case_sensitive else '忽略大小写'}",
                f"找到结果: {len(search_results)} 个",
                f"",
                f"【匹配结果列表】",
            ]

            for i, sr in enumerate(search_results, offset + 1):
                lines.append(f"\n--- 结果 #{i} ---")
                lines.append(f"  名称: {sr.name}")
                if sr.signature and sr.signature != sr.name:
                    lines.append(f"  签名: {sr.signature}")
                lines.append(f"  类型: {sr.symbol_type.value}")
                if sr.file_path:
                    lines.append(f"  文件: {sr.file_path}")
                if sr.line:
                    lines.append(f"  行号: {sr.line}")

            return "\n".join(lines)

        except Exception as e:
            return f"[错误] 搜索失败: {str(e)}"

    async def get_function_code(
            self,
            function_identifier: str,
    ) -> str:
        """根据函数标识符获取函数的代码。

        参数:
            function_identifier: 函数标识符, 可以使用 search_symbol 获取完整的函数标识符
        """
        # 返回: 格式化的函数代码文本
        if not self.engine:
            return "[错误] 引擎未初始化，请先调用 initialize_engine"

        try:
            func_def = await self.engine.get_function_def(function_identifier=function_identifier)

            if func_def is None:
                return f"[错误] 未找到函数: {function_identifier}"

            # 格式化为易读的文本
            lines = [
                f"=== 函数代码 ===",
                f"",
                f"函数名: {func_def.name}",
                f"签名: {func_def.signature}",
            ]

            if func_def.location:
                lines.append(f"地址: {func_def.location}")
            if func_def.file_path:
                lines.append(f"文件: {func_def.file_path}")
            if func_def.start_line and func_def.end_line:
                lines.append(f"行号: {func_def.start_line} - {func_def.end_line}")

            lines.extend([
                f"",
                f"【代码】",
                f"```",
                func_def.code if func_def.code else "(无代码内容)",
                f"```",
            ])

            return "\n".join(lines)

        except Exception as e:
            return f"[错误] 获取函数代码失败: {str(e)}"

    async def get_xref(
            self,
            target: str,
            xref_type: str = "both",
            limit: int = 20,
    ) -> str:
        """获取函数或地址的交叉引用。
        
        参数:
            target: 目标函数签名或地址
            xref_type: 交叉引用类型 (to: 被谁调用, from: 调用了谁, both: 两者都返回)
            limit: 返回结果数量上限
        """
        # 返回: 格式化的交叉引用结果文本
        if not self.engine:
            return "[错误] 引擎未初始化，请先调用 initialize_engine"

        try:
            lines = [
                f"=== 交叉引用分析 ===",
                f"",
                f"目标: {target}",
                f"",
            ]

            # 获取被谁调用（入边）
            if xref_type in ["to", "both"]:
                callers = await self.engine.get_caller(target)
                lines.append(f"【被以下函数调用】(共 {len(callers)} 个)")
                if callers:
                    for i, c in enumerate(callers[:limit], 1):
                        lines.append(f"  {i}. {c.caller_name}")
                        if c.caller_identifier and c.caller_identifier != c.caller_name:
                            lines.append(f"     标识符: {c.caller_identifier}")
                        if c.line_number:
                            lines.append(f"     行号: {c.line_number}")
                else:
                    lines.append("  (无)")
                lines.append("")

            # 获取调用了谁（出边）
            if xref_type in ["from", "both"]:
                callees = await self.engine.get_callee(target)
                lines.append(f"【调用了以下函数】(共 {len(callees)} 个)")
                if callees:
                    for i, c in enumerate(callees[:limit], 1):
                        lines.append(f"  {i}. {c.callee_name}")
                        if c.callee_identifier and c.callee_identifier != c.callee_name:
                            lines.append(f"     标识符: {c.callee_identifier}")
                        if c.line_number:
                            lines.append(f"     行号: {c.line_number}")
                else:
                    lines.append("  (无)")
                lines.append("")

            return "\n".join(lines)

        except Exception as e:
            return f"[错误] 获取交叉引用失败: {str(e)}"

    async def read_file(
            self,
            file_path: str,
            offset: int = 0,
            limit: int = 200,
    ) -> str:
        """读取指定文件的内容。
        
        参数:
            file_path: 文件路径（绝对路径或相对于源代码根目录的路径）
            offset: 起始行号（从0开始）
            limit: 读取的最大行数
        """
        try:
            import os
            from pathlib import Path

            # 解析文件路径
            path = Path(file_path)

            # 如果路径不存在，尝试相对于 source_root 解析
            if not path.is_absolute() and self._pending_source_root:
                path = Path(self._pending_source_root) / path

            # 检查文件是否存在
            if not path.exists():
                return f"[错误] 文件不存在: {file_path}"

            # 检查是否为文件
            if not path.is_file():
                return f"[错误] 路径不是文件: {file_path}"

            # 读取文件内容
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    all_lines = f.readlines()
            except Exception as e:
                return f"[错误] 读取文件失败: {str(e)}"

            total_lines = len(all_lines)

            # 计算实际的起始和结束行
            start_line = max(0, offset)
            end_line = min(total_lines, offset + limit)

            if start_line >= total_lines:
                return f"[错误] 起始行 {offset} 超出文件范围（文件共 {total_lines} 行）"

            # 获取指定范围的行
            selected_lines = all_lines[start_line:end_line]

            # 格式化为易读的文本
            lines = [
                f"=== 文件内容 ===",
                f"",
                f"文件路径: {path.absolute()}",
                f"总行数: {total_lines}",
                f"显示行号: {start_line + 1} - {end_line}",
                f"",
                f"【内容】",
                f"```",
            ]

            # 添加行号前缀
            for i, line in enumerate(selected_lines, start=start_line + 1):
                lines.append(f"{i:6}|{line.rstrip()}")

            lines.append("```")

            if end_line < total_lines:
                lines.append(f"\n... 还有 {total_lines - end_line} 行未显示")

            return "\n".join(lines)

        except Exception as e:
            return f"[错误] 读取文件失败: {str(e)}"

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

    async def create_task(
            self,
            description: str,
            parent_id: Optional[str] = None,
    ) -> str:
        """创建新任务。

        LLM 可以在执行开始前创建任务列表，将复杂任务分解为多个子任务。
        同一时刻只能有一个任务处于 in_progress 状态。

        参数:
            description: 任务描述，简洁明确说明任务目标（如"分析入口函数"、"识别污点参数"）
            parent_id: 父任务 ID（可选，用于构建任务树）

        返回: 创建成功的任务信息，包含任务 ID 和当前任务状态摘要
        """
        try:
            task = self.task_manager.create_task(description, parent_id)
            current_task = self.task_manager.get_current_task()
            summary = self.task_manager.get_progress_summary()

            lines = [
                f"=== 任务创建成功 ===",
                f"",
                f"任务 ID: {task.id}",
                f"描述: {task.description}",
                f"状态: {task.status.value}",
                f"父任务: {parent_id if parent_id else '（无）'}",
                f"",
                f"【当前执行进度】",
                f"总任务数: {summary['total']}",
                f"已完成: {summary['completed']}",
                f"进行中: {summary['in_progress']}",
                f"待执行: {summary['pending']}",
                f"完成率: {summary['completion_rate']}%",
                f"",
                f"【当前任务】",
                f"{'任务: ' + current_task.description + ' (' + current_task.id + ')' if current_task else '无进行中的任务'}",
            ]

            return "\n".join(lines)

        except Exception as e:
            return f"[错误] 创建任务失败: {str(e)}"

    async def update_task_status(
            self,
            task_id: str,
            status: str,
            result: Optional[str] = None,
            error_message: Optional[str] = None,
    ) -> str:
        """更新任务状态。

        LLM 在开始执行任务时调用，将任务状态设为 in_progress。
        任务完成后调用，将状态设为 completed 并提供执行结果。
        任务失败时调用，将状态设为 failed 并提供错误信息。

        参数:
            task_id: 要更新的任务 ID
            status: 新状态，可选值: "pending", "in_progress", "completed", "failed"
            result: 任务执行结果（可选，仅在 completed 状态时使用）
            error_message: 错误信息（可选，仅在 failed 状态时使用）

        返回: 更新后的任务信息和当前进度摘要
        """
        try:
            # 验证状态值
            valid_statuses = ["pending", "in_progress", "completed", "failed"]
            if status not in valid_statuses:
                return f"[错误] 无效的状态值: {status}，有效值为: {', '.join(valid_statuses)}"

            task_status = TaskStatus(status)
            updated_task = self.task_manager.update_task_status(
                task_id, task_status, result, error_message
            )
            current_task = self.task_manager.get_current_task()
            summary = self.task_manager.get_progress_summary()

            lines = [
                f"=== 任务状态更新 ===",
                f"",
                f"任务 ID: {updated_task.id}",
                f"描述: {updated_task.description}",
                f"新状态: {updated_task.status.value}",
                f"",
                f"【当前执行进度】",
                f"总任务数: {summary['total']}",
                f"已完成: {summary['completed']}",
                f"进行中: {summary['in_progress']}",
                f"待执行: {summary['pending']}",
                f"完成率: {summary['completion_rate']}%",
                f"",
                f"【当前任务】",
                f"{'任务: ' + current_task.description + ' (' + current_task.id + ')' if current_task else '无进行中的任务'}",
            ]

            if updated_task.result:
                lines.extend([
                    "",
                    f"【执行结果】",
                    f"{updated_task.result}"
                ])

            if updated_task.error_message:
                lines.extend([
                    "",
                    f"【错误信息】",
                    f"{updated_task.error_message}"
                ])

            return "\n".join(lines)

        except ValueError as e:
            return f"[错误] 任务不存在: {str(e)}"
        except Exception as e:
            return f"[错误] 更新任务状态失败: {str(e)}"

    async def get_task(self, task_id: str) -> str:
        """获取指定任务的详细信息。

        参数:
            task_id: 任务 ID

        返回: 任务详细信息，包括描述、状态、创建时间等
        """
        try:
            task = self.task_manager.get_task(task_id)
            if not task:
                return f"[错误] 任务不存在: {task_id}"

            lines = [
                f"=== 任务详情 ===",
                f"",
                f"任务 ID: {task.id}",
                f"描述: {task.description}",
                f"状态: {task.status.value}",
                f"父任务: {task.parent_id if task.parent_id else '（无）'}",
                f"创建时间: {task.created_at.strftime('%Y-%m-%d %H:%M:%S')}",
            ]

            if task.completed_at:
                lines.append(f"完成时间: {task.completed_at.strftime('%Y-%m-%d %H:%M:%S')}")

            if task.result:
                lines.extend([
                    f"",
                    f"【执行结果】",
                    f"{task.result}",
                ])

            if task.error_message:
                lines.extend([
                    f"",
                    f"【错误信息】",
                    f"{task.error_message}",
                ])

            return "\n".join(lines)

        except Exception as e:
            return f"[错误] 获取任务失败: {str(e)}"

    async def list_tasks(self, status: Optional[str] = None) -> str:
        """获取任务列表。

        参数:
            status: 按状态过滤，可选值: "pending", "in_progress", "completed", "failed"
                    不提供则返回所有任务

        返回: 任务列表，包含任务 ID、描述和状态
        """
        try:
            # 解析状态过滤
            task_status = None
            if status:
                valid_statuses = ["pending", "in_progress", "completed", "failed"]
                if status not in valid_statuses:
                    return f"[错误] 无效的状态值: {status}，有效值为: {', '.join(valid_statuses)}"
                task_status = TaskStatus(status)

            tasks = self.task_manager.list_tasks(status=task_status)

            if not tasks:
                status_desc = f"（状态: {status}）" if status else ""
                return f"无任务{status_desc}"

            lines = [
                f"=== 任务列表 ===",
                f"",
                f"共 {len(tasks)} 个任务",
                f"",
            ]

            if status:
                lines.append(f"过滤条件: 状态 = {status}")
                lines.append("")

            for i, task in enumerate(tasks, 1):
                lines.append(f"--- 任务 #{i} ---")
                lines.append(f"  ID: {task.id}")
                lines.append(f"  描述: {task.description}")
                lines.append(f"  状态: {task.status.value}")
                if task.parent_id:
                    lines.append(f"  父任务: {task.parent_id}")
                lines.append("")

            return "\n".join(lines)

        except Exception as e:
            return f"[错误] 获取任务列表失败: {str(e)}"

    async def get_current_task(self) -> str:
        """获取当前正在执行的任务。

        LLM 可以使用此工具确认当前应该执行哪个任务。
        同一时刻只能有一个 in_progress 的任务。

        返回: 当前 in_progress 任务的详细信息，无则提示选择下一个待执行任务
        """
        try:
            current_task = self.task_manager.get_current_task()

            if current_task:
                lines = [
                    f"=== 当前执行任务 ===",
                    f"",
                    f"任务 ID: {current_task.id}",
                    f"描述: {current_task.description}",
                    f"状态: {current_task.status.value}",
                ]

                if current_task.parent_id:
                    lines.append(f"父任务: {current_task.parent_id}")

                return "\n".join(lines)
            else:
                # 获取待执行任务
                pending_tasks = self.task_manager.list_tasks(status=TaskStatus.PENDING)

                if pending_tasks:
                    lines = [
                        f"=== 无当前任务 ===",
                        f"",
                        f"当前没有正在执行的任务。",
                        f"",
                        f"【待执行任务】 ({len(pending_tasks)} 个):",
                        f"",
                    ]

                    for i, task in enumerate(pending_tasks, 1):
                        lines.append(f"{i}. {task.description} (ID: {task.id})")

                    lines.append("")
                    lines.append("请使用 update_task_status 开始执行某个任务。")

                    return "\n".join(lines)
                else:
                    # 所有任务已完成
                    lines = [
                        f"=== 任务执行完毕 ===",
                        f"",
                        f"所有任务已完成或失败。",
                        f"",
                        f"可以使用 list_tasks 查看完整任务列表和结果。",
                    ]

                    return "\n".join(lines)

        except Exception as e:
            return f"[错误] 获取当前任务失败: {str(e)}"

    # ==================== 辅助方法 ====================

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

    # ==================== LangChain Tool 导出 ====================

    def get_tools(self) -> List[Any]:
        """
        获取所有 Tool 的函数列表。
        供 OrchestratorAgent 使用。
        """
        return [
            # 任务管理工具
            self.create_task,
            self.update_task_status,
            self.get_task,
            self.list_tasks,
            self.get_current_task,
            # 分析工具
            self.query_code,
            self.search_symbol,
            self.get_function_code,
            self.get_xref,
            self.read_file,
            self.run_vuln_analysis,
        ]
