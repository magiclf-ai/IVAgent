#!/usr/bin/env python3
"""
AgentDelegate - Agent 委托器

负责将任务委托给专门的子 Agent 执行，处理输入 Artifact 读取、输出 Artifact 写入和错误处理。
"""

import asyncio
from typing import Any, List, Optional
from dataclasses import dataclass
from enum import Enum

from ..engines.base_static_analysis_engine import BaseStaticAnalysisEngine
from ..models.constraints import FunctionContext, Precondition
from ..core.context import ArtifactStore

class AgentType(str, Enum):
    """支持的 Agent 类型"""
    CODE_EXPLORER = "code_explorer"
    VULN_ANALYSIS = "vuln_analysis"


@dataclass
class DelegateResult:
    """
    委托执行结果
    
    Attributes:
        success: 是否执行成功
        output: Agent 输出内容（markdown 格式）
        summary: 输出摘要（markdown 纯文本）
        error_message: 错误信息（如果失败）
        agent_type: 使用的 Agent 类型
    """
    success: bool
    output: str
    summary: str = ""
    output_ref: str = ""
    error_message: Optional[str] = None
    agent_type: Optional[str] = None


class AgentDelegate:
    """
    Agent 委托器
    
    职责：
    - 根据 agent_type 创建相应的子 Agent
    - 读取输入 Artifact 内容
    - 构造任务 Prompt
    - 调用子 Agent 执行
    - 将输出写入 ArtifactStore
    - 处理错误和重试
    """
    
    # 重试配置
    MAX_RETRIES = 2
    RETRY_DELAY = 1.0  # seconds
    
    def __init__(
        self,
        engine: BaseStaticAnalysisEngine,
        llm_client: Any,
        artifact_store: Optional[ArtifactStore] = None,
        verbose: bool = True,
    ):
        """
        初始化 Agent 委托器
        
        Args:
            engine: 静态分析引擎
            llm_client: LLM 客户端
            artifact_store: ArtifactStore（统一 Artifact 落盘）
        """
        self.engine = engine
        self.llm_client = llm_client
        self.artifact_store = artifact_store
        self.verbose = verbose
    
    async def delegate(
        self,
        agent_type: str,
        task_description: str,
        input_artifact_refs: Optional[List[str]] = None,
        context: Optional[str] = None,
        function_identifier: Optional[str] = None,
        task_id: str = "",
        task_group: str = "",
        max_iterations: int = 15,
    ) -> DelegateResult:
        """
        委托任务给子 Agent
        
        Args:
            agent_type: Agent 类型 (code_explorer, vuln_analysis)
            task_description: 任务描述
            input_artifact_refs: 输入 artifact_ref 列表（前置任务输出）
            context: 额外上下文信息
            function_identifier: 目标函数标识符（vuln_analysis 必需）
            task_id: 任务 ID（用于输出归档）
            task_group: 任务分组（workflow_id）
            max_iterations: 最大迭代次数
        
        Returns:
            DelegateResult: 执行结果
        """
        # 验证 agent_type
        try:
            agent_type_enum = AgentType(agent_type)
        except ValueError:
            return DelegateResult(
                success=False,
                output="",
                error_message=f"不支持的 Agent 类型: {agent_type}，支持的类型: {', '.join([t.value for t in AgentType])}",
                agent_type=agent_type,
            )
        
        input_content = ""
        if agent_type_enum == AgentType.CODE_EXPLORER and input_artifact_refs:
            input_content = await self._read_input_artifacts(input_artifact_refs)

        task_prompt = ""
        if agent_type_enum == AgentType.CODE_EXPLORER:
            task_prompt = self._build_task_prompt(
                task_description=task_description,
                input_content=input_content,
                context=context,
            )
        
        # 执行任务（带重试）
        result = await self._execute_with_retry(
            agent_type=agent_type_enum,
            task_prompt=task_prompt,
            function_identifier=function_identifier,
            max_iterations=max_iterations,
            analysis_context=context,
            task_description=task_description,
        )
        
        # 写入输出 Artifact
        if result.success and result.output:
            try:
                output_ref = await self._write_output_artifact(
                    content=result.output,
                    summary=result.summary,
                    task_id=task_id,
                    task_group=task_group,
                    agent_type=agent_type,
                )
                result.output_ref = output_ref
            except Exception as e:
                return DelegateResult(
                    success=False,
                    output=result.output,
                    summary=result.summary,
                    error_message=f"写入输出 Artifact 失败: {str(e)}",
                    agent_type=agent_type,
                )
        
        return result
    
    async def _read_input_artifacts(self, input_artifact_refs: List[str]) -> str:
        """
        读取输入文件内容
        
        Args:
            input_artifact_refs: 输入 artifact_ref 列表
        
        Returns:
            str: 合并的文件内容
        """
        contents = []
        
        if not self.artifact_store:
            return "[错误] ArtifactStore 未初始化，无法读取输入 artifacts。"

        for artifact_ref in input_artifact_refs:
            try:
                normalized_ref = str(artifact_ref or "").strip()
                if not normalized_ref:
                    continue
                content = self.artifact_store.read(normalized_ref)
                meta = self.artifact_store.read_metadata(normalized_ref)
                kind = str(meta.get("kind") or "unknown")
                task_id = str(meta.get("task_id") or "")
                contents.append(
                    "\n".join(
                        [
                            f"## 输入 Artifact: {normalized_ref}",
                            f"- kind: {kind}",
                            f"- source_task: {task_id or 'N/A'}",
                            "",
                            content,
                        ]
                    )
                )
            except Exception as e:
                contents.append(
                    f"## 输入 Artifact: {artifact_ref}\n\n[错误] 读取失败: {str(e)}"
                )
        
        return "\n\n---\n\n".join(contents) if contents else ""
    
    def _build_task_prompt(
        self,
        task_description: str,
        input_content: str,
        context: Optional[str],
    ) -> str:
        """
        构造任务 Prompt
        
        Args:
            task_description: 任务描述
            input_content: 输入文件内容
            context: 额外上下文
        
        Returns:
            str: 完整的任务 Prompt
        """
        prompt_parts = [
            "# 任务描述",
            "",
            task_description,
            "",
        ]
        
        if input_content:
            prompt_parts.extend([
                "# 输入数据",
                "",
                input_content,
                "",
            ])
        
        if context:
            prompt_parts.extend([
                "# 额外上下文",
                "",
                context,
                "",
            ])
        
        prompt_parts.extend([
            "# 要求",
            "",
            "- 完成任务描述中的目标",
            "- 将结果以 Markdown 格式输出",
            "- 输出应包含：分析摘要、关键发现、相关代码位置等",
        ])
        
        return "\n".join(prompt_parts)

    async def _execute_with_retry(
        self,
        agent_type: AgentType,
        task_prompt: str,
        function_identifier: Optional[str],
        max_iterations: int,
        analysis_context: Optional[str],
        task_description: Optional[str],
    ) -> DelegateResult:
        """
        执行任务（带重试机制）
        
        Args:
            agent_type: Agent 类型
            task_prompt: 任务 Prompt
            function_identifier: 目标函数标识符（vuln_analysis 使用）
            max_iterations: 最大迭代次数
        
        Returns:
            DelegateResult: 执行结果
        """
        last_error = None
        
        for attempt in range(self.MAX_RETRIES):
            try:
                # 创建并执行 Agent
                result = await self._execute_agent(
                    agent_type=agent_type,
                    task_prompt=task_prompt,
                    function_identifier=function_identifier,
                    max_iterations=max_iterations,
                    analysis_context=analysis_context,
                    task_description=task_description,
                )
                
                # 如果成功，直接返回
                if result.success:
                    return result
                
                # 如果失败，记录错误并重试
                last_error = result.error_message
                
                # 如果不是最后一次尝试，等待后重试
                if attempt < self.MAX_RETRIES - 1:
                    await asyncio.sleep(self.RETRY_DELAY)
            
            except Exception as e:
                last_error = str(e)
                
                # 如果不是最后一次尝试，等待后重试
                if attempt < self.MAX_RETRIES - 1:
                    await asyncio.sleep(self.RETRY_DELAY)
        
        # 所有重试都失败
        return DelegateResult(
            success=False,
            output="",
            summary="",
            error_message=f"执行失败（已重试 {self.MAX_RETRIES} 次）: {last_error}",
            agent_type=agent_type.value,
        )
    
    async def _execute_agent(
        self,
        agent_type: AgentType,
        task_prompt: str,
        function_identifier: Optional[str],
        max_iterations: int,
        analysis_context: Optional[str],
        task_description: Optional[str],
    ) -> DelegateResult:
        """
        执行 Agent
        
        Args:
            agent_type: Agent 类型
            task_prompt: 任务 Prompt
            function_identifier: 目标函数标识符（vuln_analysis 使用）
            max_iterations: 最大迭代次数
        
        Returns:
            DelegateResult: 执行结果
        """
        try:
            if agent_type == AgentType.CODE_EXPLORER:
                return await self._execute_code_explorer(task_prompt, max_iterations)
            
            elif agent_type == AgentType.VULN_ANALYSIS:
                return await self._execute_vuln_analysis(
                    task_prompt=task_prompt,
                    function_identifier=function_identifier,
                    max_iterations=max_iterations,
                    analysis_context=analysis_context,
                    task_description=task_description,
                )
            
            else:
                return DelegateResult(
                    success=False,
                    output="",
                    summary="",
                    error_message=f"未实现的 Agent 类型: {agent_type.value}",
                    agent_type=agent_type.value,
                )
        
        except Exception as e:
            return DelegateResult(
                success=False,
                output="",
                summary="",
                error_message=f"Agent 执行异常: {str(e)}",
                agent_type=agent_type.value,
            )
    
    async def _execute_code_explorer(
        self,
        task_prompt: str,
        max_iterations: int,
    ) -> DelegateResult:
        """
        执行 CodeExplorerAgent
        
        Args:
            task_prompt: 任务 Prompt
            max_iterations: 最大迭代次数
        
        Returns:
            DelegateResult: 执行结果
        """
        try:
            from ..agents.code_explorer_agent import CodeExplorerAgent
            
            # 创建 Agent
            agent = CodeExplorerAgent(
                engine=self.engine,
                llm_client=self.llm_client,
                max_iterations=max_iterations,
                enable_logging=True,
            )
            
            # 执行探索
            result = await agent.explore(query=task_prompt)

            output = ""
            summary = ""
            error = ""
            if isinstance(result, dict):
                output = (result.get("output") or "").strip()
                summary = (result.get("summary") or "").strip()
                error = (result.get("error") or "").strip()
            else:
                output = (result or "").strip()
                if output.startswith("[探索失败]"):
                    error = "代码探索失败"

            if error:
                return DelegateResult(
                    success=False,
                    output=output,
                    summary=summary,
                    error_message=error,
                    agent_type=AgentType.CODE_EXPLORER.value,
                )

            if not output:
                return DelegateResult(
                    success=False,
                    output="",
                    summary=summary,
                    error_message="代码探索失败",
                    agent_type=AgentType.CODE_EXPLORER.value,
                )

            if not summary:
                return DelegateResult(
                    success=False,
                    output=output,
                    summary="",
                    error_message="代码探索缺少摘要，无法继续",
                    agent_type=AgentType.CODE_EXPLORER.value,
                )
            
            # 检查结果
            return DelegateResult(
                success=True,
                output=output,
                summary=summary,
                agent_type=AgentType.CODE_EXPLORER.value,
            )
        
        except ImportError as e:
            return DelegateResult(
                success=False,
                output="",
                summary="",
                error_message=f"无法导入 CodeExplorerAgent: {str(e)}",
                agent_type=AgentType.CODE_EXPLORER.value,
            )
        except Exception as e:
            return DelegateResult(
                success=False,
                output="",
                summary="",
                error_message=f"CodeExplorerAgent 执行失败: {str(e)}",
                agent_type=AgentType.CODE_EXPLORER.value,
            )
    
    async def _execute_vuln_analysis(
        self,
        task_prompt: str,
        function_identifier: Optional[str],
        max_iterations: int,
        analysis_context: Optional[str],
        task_description: Optional[str],
    ) -> DelegateResult:
        """
        执行 VulnAnalysisAgent
        
        Args:
            task_prompt: 任务 Prompt
            function_identifier: 目标函数标识符（必需）
            max_iterations: 最大迭代次数
        
        Returns:
            DelegateResult: 执行结果
        """
        try:
            if not function_identifier:
                return DelegateResult(
                    success=False,
                    output="",
                    summary="",
                    error_message="缺少 function_identifier（vuln_analysis 必需）",
                    agent_type=AgentType.VULN_ANALYSIS.value,
                )

            from ..agents.deep_vuln_agent import DeepVulnAgent
            from ..agents.prompts import get_vuln_agent_system_prompt
            
            # 获取引擎名称
            engine_name = getattr(self.engine, '__class__', type(self.engine)).__name__.lower()
            if 'ida' in engine_name:
                engine_name = 'ida'
            elif 'ghidra' in engine_name:
                engine_name = 'ghidra'
            else:
                engine_name = 'ida'  # 默认
            
            # 构建 System Prompt（仅基础提示词）
            base_prompt = get_vuln_agent_system_prompt(engine_name)
            
            # 创建 Agent
            agent = DeepVulnAgent(
                engine=self.engine,
                llm_client=self.llm_client,
                max_iterations=max_iterations,
                max_depth=10,
                verbose=self.verbose,
                system_prompt=base_prompt,
            )
            
            # 执行分析（目标函数标识符显式传入）
            precondition_text = (analysis_context or "").strip()
            if not precondition_text:
                precondition_text = (task_description or "").strip()
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
            
            # 格式化结果
            formatted_result = self._format_vuln_result(result, function_identifier)
            analysis_summary = (result.get("summary") or "").strip()
            if not analysis_summary:
                return DelegateResult(
                    success=False,
                    output=formatted_result,
                    summary="",
                    error_message="漏洞分析缺少摘要，无法继续",
                    agent_type=AgentType.VULN_ANALYSIS.value,
                )
            
            return DelegateResult(
                success=True,
                output=formatted_result,
                summary=analysis_summary,
                agent_type=AgentType.VULN_ANALYSIS.value,
            )
        
        except ImportError as e:
            return DelegateResult(
                success=False,
                output="",
                summary="",
                error_message=f"无法导入 DeepVulnAgent: {str(e)}",
                agent_type=AgentType.VULN_ANALYSIS.value,
            )
        except Exception as e:
            return DelegateResult(
                success=False,
                output="",
                summary="",
                error_message=f"VulnAnalysisAgent 执行失败: {str(e)}",
                agent_type=AgentType.VULN_ANALYSIS.value,
            )
    
    def _format_vuln_result(
        self,
        result: dict,
        function_identifier: str,
    ) -> str:
        """
        格式化漏洞分析结果
        
        Args:
            result: Agent 返回的结果字典
            function_identifier: 函数标识符
        
        Returns:
            str: 格式化的 Markdown 文本
        """
        vulns = result.get("vulnerabilities", [])
        
        lines = [
            "# 漏洞分析结果",
            "",
            f"**目标函数**: {function_identifier}",
            "",
            "## 分析摘要",
            "",
            f"- 发现漏洞: {len(vulns)} 个",
            "",
        ]
        
        if vulns:
            lines.append("## 漏洞详情")
            lines.append("")
            
            for i, vuln in enumerate(vulns, 1):
                vuln_name = getattr(vuln, 'name', f'漏洞 #{i}')
                vuln_type = getattr(vuln, 'type', 'UNKNOWN')
                description = getattr(vuln, 'description', '无描述')
                location = getattr(vuln, 'location', '未知位置')
                severity = getattr(vuln, 'severity', 0.5)
                confidence = getattr(vuln, 'confidence', 0.5)
                
                lines.extend([
                    f"### {vuln_name}",
                    "",
                    f"- **类型**: {vuln_type}",
                    f"- **位置**: {location}",
                    f"- **严重度**: {severity:.2f}",
                    f"- **置信度**: {confidence:.2f}",
                    f"- **描述**: {description}",
                    "",
                ])
        else:
            lines.extend([
                "## 分析结果",
                "",
                "本次分析未发现漏洞。",
                "",
            ])
        
        return "\n".join(lines)
    
    async def _write_output_artifact(
        self,
        content: str,
        summary: str,
        task_id: str,
        task_group: str,
        agent_type: str,
    ) -> str:
        """
        写入任务输出 Artifact 并返回 artifact_ref。

        Args:
            content: 任务输出正文
            summary: 输出摘要（Markdown 纯文本）
            task_id: 任务 ID
            task_group: workflow/task_group
            agent_type: agent 类型
        """
        if not self.artifact_store:
            raise Exception("ArtifactStore 未初始化")
        if not summary or not summary.strip():
            raise Exception("摘要为空，无法写入输出 Artifact")
        ref = self.artifact_store.put_text(
            content=content,
            kind="task_output",
            summary=summary,
            workflow_id=(task_group or "").strip(),
            task_id=(task_id or "").strip(),
            producer="agent_delegate",
            metadata={
                "agent_type": agent_type,
                "task_id": task_id,
                "task_group": task_group,
                "kind": "task_output",
            },
        )
        return ref.artifact_id


__all__ = [
    "AgentType",
    "DelegateResult",
    "AgentDelegate",
]
