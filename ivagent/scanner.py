import asyncio
import time
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field

from langchain_openai import ChatOpenAI

from ivagent.core.cli_logger import CLILogger, format_duration
from ivagent.engines.base_static_analysis_engine import BaseStaticAnalysisEngine
from ivagent.engines.factory import create_engine
from ivagent.agents.deep_vuln_agent import DeepVulnAgent
from ivagent.models.skill import SkillContext


@dataclass
class ScanConfig:
    """Configuration for IVAgent Scanner"""
    engine_type: str
    target_path: Optional[str]
    llm_api_key: str
    llm_base_url: str
    llm_model: str
    engine_host: str = "127.0.0.1"
    engine_port: int = 0  # 0 means use default for engine type
    max_concurrency: int = 10
    temperature: float = 0.1
    verbose: bool = False
    source_root: Optional[str] = None  # 源代码根目录（用于 CallsiteAgent）


class IVAgentScanner:
    """
    Unified scanner interface for IVAgent.
    Supports IDA (binary), JEB (Android), and ABC (HarmonyOS).
    """

    def __init__(self, config: ScanConfig, logger: Optional[CLILogger] = None):
        self.config = config
        self.engine: Optional[BaseStaticAnalysisEngine] = None
        self.llm: Optional[ChatOpenAI] = None
        self.logger = logger or CLILogger(component="IVAgentScanner", verbose=config.verbose)

    def _build_progress_logger(self, function_identifier: str):
        """构建 DeepVulnAgent 进度日志回调。"""
        def _progress_logger(message: str, level: str = "info", kind: str = "trace", **extra_fields: Any):
            self.logger.log(
                level=level,
                event="agent.progress",
                message=message,
                kind=kind,
                function=function_identifier,
                **extra_fields,
            )

        return _progress_logger

    def _create_llm(self) -> ChatOpenAI:
        return ChatOpenAI(
            api_key=self.config.llm_api_key,
            base_url=self.config.llm_base_url,
            model=self.config.llm_model,
            temperature=self.config.temperature,
        )

    def _create_engine(self) -> BaseStaticAnalysisEngine:
        kwargs = {}
        if self.config.engine_host:
            kwargs["host"] = self.config.engine_host
        if self.config.engine_port and self.config.engine_port > 0:
            kwargs["port"] = self.config.engine_port

        return create_engine(
            self.config.engine_type,
            target_path=self.config.target_path,
            max_concurrency=self.config.max_concurrency,
            source_root=self.config.source_root,
            llm_client=self.llm,
            logger=self.logger,
            **kwargs
        )

    async def scan_function(
            self,
            function_identifier: str,
            skill: Optional[SkillContext] = None,
            deadline: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Scan a single function for vulnerabilities.
        
        Args:
            function_identifier: Function address (IDA) or identifier (JEB/ABC)
            skill: Optional skill context and analysis constraints
            
        Returns:
            Scan result dictionary containing vulnerabilities
        """
        # Ensure resources are initialized
        scan_t0 = time.perf_counter()
        self.logger.info(
            "scan_function.start",
            "开始扫描函数",
            function=function_identifier,
            engine=self.config.engine_type,
        )
        if not self.llm:
            self.llm = self._create_llm()

        local_engine = False
        if not self.engine:
            self.engine = self._create_engine()
            local_engine = True

        try:
            # If we created the engine locally, we need to initialize it
            # But BaseStaticAnalysisEngine usually requires async context manager
            # So if we are managing it here, we should probably wrap it

            if local_engine:
                self.logger.debug("engine.init", "初始化分析引擎", engine=self.config.engine_type)
                await self.engine.initialize()

            agent = DeepVulnAgent(
                engine=self.engine,
                llm_client=self.llm,
                skill=skill,
                verbose=self.config.verbose,
                progress_logger=self._build_progress_logger(function_identifier),
                deadline=deadline,
            )

            result = await agent.run(function_identifier)
            vuln_count = len(result.get("vulnerabilities", []))
            self.logger.success(
                "scan_function.completed",
                "函数扫描完成",
                function=function_identifier,
                vulnerabilities=vuln_count,
                duration=format_duration(time.perf_counter() - scan_t0),
            )
            return result
        except Exception as e:
            self.logger.exception(
                "scan_function.failed",
                e,
                function=function_identifier,
            )
            raise

        finally:
            if local_engine and self.engine:
                await self.engine.close()
                self.engine = None

    async def scan_functions(
            self,
            function_identifiers: List[str],
            skill: Optional[SkillContext] = None,
            deadline: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """
        Scan multiple functions concurrently.
        
        Args:
            function_identifiers: List of function addresses/identifiers
            skill: Optional skill context and analysis constraints
            
        Returns:
            List of scan results
        """

        batch_t0 = time.perf_counter()
        if not self.llm:
            self.llm = self._create_llm()

        if not self.engine:
            self.engine = self._create_engine()

        async with self.engine:
            semaphore = asyncio.Semaphore(self.config.max_concurrency)
            total = len(function_identifiers)
            self.logger.info(
                "scan_batch.start",
                "开始批量扫描",
                total=total,
                concurrency=self.config.max_concurrency,
                engine=self.config.engine_type,
            )

            async def _scan_single(idx, sig):
                async with semaphore:
                    single_t0 = time.perf_counter()
                    # Compute per-function deadline from batch deadline
                    func_deadline = deadline
                    if func_deadline is None and deadline is not None:
                        func_deadline = deadline
                    try:
                        self.logger.info(
                            "scan_batch.item_start",
                            "开始扫描目标函数",
                            index=f"{idx + 1}/{total}",
                            function=sig,
                        )
                        agent = DeepVulnAgent(
                            engine=self.engine,
                            llm_client=self.llm,
                            skill=skill,
                            verbose=self.config.verbose,
                            progress_logger=self._build_progress_logger(sig),
                            deadline=func_deadline,
                        )
                        result = await agent.run(sig)
                        vuln_count = len(result.get("vulnerabilities", []))
                        self.logger.success(
                            "scan_batch.item_done",
                            "函数扫描完成",
                            index=f"{idx + 1}/{total}",
                            function=sig,
                            vulnerabilities=vuln_count,
                            duration=format_duration(time.perf_counter() - single_t0),
                        )
                        return result
                    except Exception as e:
                        self.logger.exception(
                            "scan_batch.item_failed",
                            e,
                            index=f"{idx + 1}/{total}",
                            function=sig,
                        )
                        return {"error": str(e), "address": sig, "vulnerabilities": []}

            tasks = [_scan_single(i, sig) for i, sig in enumerate(function_identifiers)]
            results = await asyncio.gather(*tasks)
            failed = sum(1 for r in results if isinstance(r, dict) and r.get("error"))
            self.logger.success(
                "scan_batch.completed",
                "批量扫描完成",
                total=total,
                failed=failed,
                duration=format_duration(time.perf_counter() - batch_t0),
            )
            return results
