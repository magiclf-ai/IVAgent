import asyncio
import argparse
import os
from typing import Optional, List, Dict, Any, Union
from dataclasses import dataclass

from langchain_openai import ChatOpenAI

from ivagent.engines.base_static_analysis_engine import BaseStaticAnalysisEngine
from ivagent.engines.factory import create_engine
from ivagent.agents.deep_vuln_agent import DeepVulnAgent
from ivagent.models.constraints import Precondition


@dataclass
class ScanConfig:
    """Configuration for IVAgent Scanner"""
    engine_type: str
    target_path: str
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

    def __init__(self, config: ScanConfig):
        self.config = config
        self.engine: Optional[BaseStaticAnalysisEngine] = None
        self.llm: Optional[ChatOpenAI] = None

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
            **kwargs
        )

    async def scan_function(
            self,
            function_identifier: str,
            precondition: Optional[Precondition] = None
    ) -> Dict[str, Any]:
        """
        Scan a single function for vulnerabilities.
        
        Args:
            function_identifier: Function address (IDA) or identifier (JEB/ABC)
            precondition: Optional analysis constraints/preconditions
            
        Returns:
            Scan result dictionary containing vulnerabilities
        """
        # Ensure resources are initialized
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
                await self.engine.initialize()

            agent = DeepVulnAgent(
                engine=self.engine,
                llm_client=self.llm,
                precondition=precondition,
                verbose=self.config.verbose
            )

            print(f"[*] Scanning function: {function_identifier}")
            result = await agent.run(function_identifier)
            return result

        finally:
            if local_engine and self.engine:
                await self.engine.close()
                self.engine = None

    async def scan_functions(
            self,
            function_identifiers: List[str],
            precondition: Optional[Precondition] = None
    ) -> List[Dict[str, Any]]:
        """
        Scan multiple functions concurrently.
        
        Args:
            function_identifiers: List of function addresses/identifiers
            precondition: Optional analysis constraints/preconditions
            
        Returns:
            List of scan results
        """

        if not self.llm:
            self.llm = self._create_llm()

        if not self.engine:
            self.engine = self._create_engine()

        async with self.engine:
            semaphore = asyncio.Semaphore(self.config.max_concurrency)
            total = len(function_identifiers)

            async def _scan_single(idx, sig):
                async with semaphore:
                    try:
                        print(f"[{idx + 1}/{total}] Scanning: {sig}")
                        agent = DeepVulnAgent(
                            engine=self.engine,
                            llm_client=self.llm,
                            precondition=precondition,
                            verbose=self.config.verbose
                        )
                        return await agent.run(sig)
                    except Exception as e:
                        print(f"[X] Error scanning {sig}: {e}")
                        return {"error": str(e), "address": sig, "vulnerabilities": []}

            tasks = [_scan_single(i, sig) for i, sig in enumerate(function_identifiers)]
            results = await asyncio.gather(*tasks)
            return results


def main():
    """命令行入口"""
    parser = argparse.ArgumentParser(description='IVAgent Scanner - 漏洞扫描工具')
    parser.add_argument('target', help='目标文件路径 (IDB/APK/ABC)')
    parser.add_argument('functions', nargs='+', help='要扫描的函数签名/地址')
    parser.add_argument('--engine', default='ida', choices=['ida', 'jeb', 'abc'],
                        help='分析引擎类型 (默认: ida)')
    parser.add_argument('--source-root', dest='source_root',
                        help='源代码根目录 (用于 CallsiteAgent 源码分析)')
    parser.add_argument('--host', default='127.0.0.1',
                        help='RPC Server 地址 (默认: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=0,
                        help='RPC Server 端口 (0=使用引擎默认端口)')
    parser.add_argument('--llm-api-key', default=os.getenv('LLM_API_KEY', ''),
                        help='LLM API Key (默认从环境变量 LLM_API_KEY 读取)')
    parser.add_argument('--llm-base-url', default=os.getenv('LLM_BASE_URL', 'http://localhost:8000/v1'),
                        help='LLM Base URL (默认从环境变量 LLM_BASE_URL 读取)')
    parser.add_argument('--llm-model', default=os.getenv('LLM_MODEL', 'gpt-4'),
                        help='LLM 模型名称 (默认从环境变量 LLM_MODEL 读取)')
    parser.add_argument('--max-concurrency', type=int, default=10,
                        help='最大并发数 (默认: 10)')
    parser.add_argument('--temperature', type=float, default=0.1,
                        help='LLM 温度参数 (默认: 0.1)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='显示详细日志')

    args = parser.parse_args()

    # 验证必要参数
    if not args.llm_api_key:
        parser.error('缺少 LLM API Key，请通过 --llm-api-key 提供或设置 LLM_API_KEY 环境变量')

    # 创建配置
    config = ScanConfig(
        engine_type=args.engine,
        target_path=args.target,
        llm_api_key=args.llm_api_key,
        llm_base_url=args.llm_base_url,
        llm_model=args.llm_model,
        engine_host=args.host,
        engine_port=args.port,
        max_concurrency=args.max_concurrency,
        temperature=args.temperature,
        verbose=args.verbose,
        source_root=args.source_root
    )

    # 运行扫描
    scanner = IVAgentScanner(config)

    async def run_scan():
        if len(args.functions) == 1:
            # 单个函数扫描
            result = await scanner.scan_function(args.functions[0])
            print("\n" + "=" * 60)
            print("扫描结果:")
            print("=" * 60)
            import json
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            # 多个函数扫描
            results = await scanner.scan_functions(args.functions)
            print("\n" + "=" * 60)
            print(f"扫描完成，共 {len(results)} 个结果")
            print("=" * 60)
            for i, (sig, result) in enumerate(zip(args.functions, results)):
                print(f"\n[{i + 1}] {sig}:")
                import json
                print(json.dumps(result, indent=2, ensure_ascii=False))

    asyncio.run(run_scan())


if __name__ == '__main__':
    main()
