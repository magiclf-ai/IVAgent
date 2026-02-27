#!/usr/bin/env python3
"""
AgentDelegate - Agent 委托器

负责将任务委托给专门的子 Agent 执行，处理输入文件读取、输出文件写入和错误处理。
"""

import asyncio
from typing import Any, List, Optional
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

from ..engines.base_static_analysis_engine import BaseStaticAnalysisEngine
from ..models.constraints import FunctionContext, Precondition

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
    error_message: Optional[str] = None
    agent_type: Optional[str] = None


class AgentDelegate:
    """
    Agent 委托器
    
    职责：
    - 根据 agent_type 创建相应的子 Agent
    - 读取输入文件内容
    - 构造任务 Prompt
    - 调用子 Agent 执行
    - 将输出写入文件
    - 处理错误和重试
    """
    
    # 重试配置
    MAX_RETRIES = 2
    RETRY_DELAY = 1.0  # seconds
    
    def __init__(
        self,
        engine: BaseStaticAnalysisEngine,
        llm_client: Any,
        file_manager: Optional[Any] = None,
    ):
        """
        初始化 Agent 委托器
        
        Args:
            engine: 静态分析引擎
            llm_client: LLM 客户端
            file_manager: 文件管理器（可选，用于读写文件）
        """
        self.engine = engine
        self.llm_client = llm_client
        self.file_manager = file_manager
    
    async def delegate(
        self,
        agent_type: str,
        task_description: str,
        input_files: Optional[List[Path]] = None,
        output_file: Optional[Path] = None,
        context: Optional[str] = None,
        function_identifier: Optional[str] = None,
        max_iterations: int = 15,
    ) -> DelegateResult:
        """
        委托任务给子 Agent
        
        Args:
            agent_type: Agent 类型 (code_explorer, vuln_analysis)
            task_description: 任务描述
            input_files: 输入文件路径列表（前置任务的输出）
            output_file: 输出文件路径
            context: 额外上下文信息
            function_identifier: 目标函数标识符（vuln_analysis 必需）
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
        if agent_type_enum == AgentType.CODE_EXPLORER and input_files:
            input_content = await self._read_input_files(input_files)

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
        
        # 写入输出文件
        if result.success and output_file and result.output:
            try:
                await self._write_output_file(
                    output_file=output_file,
                    content=result.output,
                    summary=result.summary,
                )
            except Exception as e:
                return DelegateResult(
                    success=False,
                    output=result.output,
                    summary=result.summary,
                    error_message=f"写入输出文件失败: {str(e)}",
                    agent_type=agent_type,
                )
        
        return result
    
    async def _read_input_files(self, input_files: List[Path]) -> str:
        """
        读取输入文件内容
        
        Args:
            input_files: 输入文件路径列表
        
        Returns:
            str: 合并的文件内容
        """
        contents = []
        
        for file_path in input_files:
            try:
                if self.file_manager:
                    # 使用 FileManager 读取（带安全检查）
                    content = self.file_manager.read_artifact(file_path)
                else:
                    # 直接读取文件
                    content = file_path.read_text(encoding="utf-8")
                
                contents.append(f"## 输入文件: {file_path.name}\n\n{content}")
            
            except FileNotFoundError:
                contents.append(f"## 输入文件: {file_path.name}\n\n[错误] 文件不存在")
            except Exception as e:
                contents.append(f"## 输入文件: {file_path.name}\n\n[错误] 读取失败: {str(e)}")
        
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
                verbose=True,
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
    
    async def _write_output_file(
        self,
        output_file: Path,
        content: str,
        summary: str,
    ) -> None:
        """
        写入输出文件并写入摘要文件
        
        Args:
            output_file: 输出文件路径
            content: 文件内容
            summary: 摘要内容（Markdown 纯文本）
        
        Raises:
            Exception: 写入失败
        """
        try:
            if self.file_manager:
                # 使用 FileManager 写入（带安全检查）
                self.file_manager.write_artifact(output_file, content)
            else:
                # 确保目录存在
                output_file.parent.mkdir(parents=True, exist_ok=True)
                # 直接写入文件
                output_file.write_text(content, encoding="utf-8")

            if not summary or not summary.strip():
                raise Exception("摘要为空，无法写入 summary 文件")
            summary_path = output_file.with_suffix(".summary.md")
            if self.file_manager:
                self.file_manager.write_artifact(summary_path, summary)
            else:
                summary_path.write_text(summary, encoding="utf-8")

        except Exception as e:
            raise Exception(f"写入输出文件失败: {str(e)}")


__all__ = [
    "AgentType",
    "DelegateResult",
    "AgentDelegate",
]
