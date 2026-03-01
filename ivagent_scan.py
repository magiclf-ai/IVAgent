#!/usr/bin/env python3
"""
IVAgent - Intelligent Vulnerability Analysis System
Unified CLI for IDA (Binary), JEB (Android), and ABC (HarmonyOS) analysis.
"""
import asyncio
import argparse
import os
import sys
import json
import re
import time
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple

# Add package root to path
sys.path.insert(0, str(Path(__file__).parent))

from ivagent.core.cli_logger import CLILogger, format_duration
from ivagent.scanner import IVAgentScanner, ScanConfig
from ivagent.models.constraints import Precondition

# Default configurations
DEFAULT_API_KEY = os.environ.get("OPENAI_API_KEY")
DEFAULT_BASE_URL = os.environ.get("OPENAI_BASE_URL")
DEFAULT_MODEL = os.environ.get("OPENAI_MODEL")


def get_preconditions_dir() -> Path:
    """获取预置配置文件目录"""
    script_dir = Path(__file__).parent
    return script_dir / "preconditions"


def parse_markdown_precondition(content: str, file_path: Optional[str] = None) -> Tuple[Dict[str, Any], str]:
    """
    解析 Markdown 格式的 Precondition 文件
    
    格式规范:
    - YAML frontmatter (可选) 用于元数据
    - ## 章节标题 用于分段
    - 正文内容作为 text_content
        
    返回:
        (metadata_dict, text_content) 元组
    """
    metadata = {
        "name": "Unnamed Precondition",
        "description": "",
        "target": "unknown",
        "version": "1.0",
        "author": "user",
        "taint_sources": [],
    }
    
    # 尝试解析 YAML frontmatter
    frontmatter_match = re.match(r'^---\s*\n(.*?)\n---\s*\n', content, re.DOTALL)
    if frontmatter_match:
        yaml_content = frontmatter_match.group(1)
        text_content = content[frontmatter_match.end():]
        
        # 简单解析 YAML (只支持 key: value 格式)
        for line in yaml_content.strip().split('\n'):
            line = line.strip()
            if ':' in line and not line.startswith('#'):
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip().strip('"\'')
                if key in metadata:
                    if key == "taint_sources":
                        # 解析列表格式: [item1, item2] 或 - item1
                        if value.startswith('[') and value.endswith(']'):
                            value = [v.strip().strip('"\'') for v in value[1:-1].split(',') if v.strip()]
                        else:
                            value = [value] if value else []
                    metadata[key] = value
    else:
        text_content = content
    
    # 从文件路径推断名称（如果没有指定）
    if file_path and metadata["name"] == "Unnamed Precondition":
        metadata["name"] = Path(file_path).stem.replace('_', ' ').title()
    
    return metadata, text_content.strip()


def load_precondition_from_file(file_path: str) -> Precondition:
    """
    从文件加载 Precondition 配置
    
    支持格式:
    - Markdown (.md) - 推荐，易读易写
    - JSON (.json) - 兼容旧格式
    
    参数:
        file_path: 配置文件路径
    
    返回:
        Precondition 对象
    """
    p = Path(file_path)
    if not p.exists():
        raise FileNotFoundError(f"Precondition file not found: {file_path}")
    
    content = p.read_text(encoding='utf-8')
    metadata, text_content = parse_markdown_precondition(content, file_path)
    return Precondition.from_text(
        name=metadata["name"],
        text_content=text_content,
        description=metadata["description"],
        target=metadata["target"],
        taint_sources=metadata.get("taint_sources", []),
        version=metadata["version"],
        author=metadata["author"]
    )


def load_preset_precondition(preset_name: str) -> Precondition:
    """
    加载预置的 Precondition 配置
    
    参数:
        preset_name: 预置名称（preconditions 目录下的文件名，不含扩展名）
    
    返回:
        Precondition 对象
    """
    preconditions_dir = get_preconditions_dir()
    
    md_file = preconditions_dir / f"{preset_name}.md"
    return load_precondition_from_file(str(md_file))
   

async def main():
    startup_t0 = time.perf_counter()

    parser = argparse.ArgumentParser(
        description="IVAgent Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Engine configuration
    parser.add_argument("--engine", "-e", required=True, choices=["ida", "jeb", "abc", "source"],
                        help="Analysis engine type")
    parser.add_argument("--target", "-t",
                        help="Target file path (APK, ABC file, or IDB). Optional for IDA if connecting to existing session.")
    parser.add_argument("--host", default="127.0.0.1", help="Engine RPC host")
    parser.add_argument("--port", type=int, default=0, help="Engine RPC port (default depends on engine)")

    # Scan targets
    parser.add_argument("--function", "-f", help="Single function signature/address to scan")

    # LLM configuration
    parser.add_argument("--api-key", default=DEFAULT_API_KEY, help="LLM API Key")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="LLM Base URL")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="LLM Model name")
    parser.add_argument("--temperature", type=float, default=0.1, help="LLM Temperature")

    # Execution control
    parser.add_argument("--concurrency", "-c", type=int, default=10, help="Max concurrency for scanning")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")

    # Source code analysis
    parser.add_argument("--source-root", dest="source_root", help="Source code root directory (for CallsiteAgent)")

    # Precondition
    parser.add_argument("--config", "-C", dest="config_file",
                        help="Path to precondition configuration file (.md or .json)")
    parser.add_argument("--preset", "-P", dest="preset_name",
                        help="Use built-in preset (filename without extension from preconditions/)")

    # Output
    parser.add_argument("--output", "-o", help="Output file for results (JSON)")

    args = parser.parse_args()
    logger = CLILogger(component="ivagent_scan", verbose=args.verbose)

    # Validate arguments
    if not args.function:
        parser.error("Either --function must be provided")

    # Prepare targets
    targets = []
    if args.function:
        targets.append(args.function)

    if not targets:
        logger.warning("scan.no_targets", "没有可扫描的函数")
        return

    # Prepare configuration
    config = ScanConfig(
        engine_type=args.engine,
        target_path=args.target,
        llm_api_key=args.api_key,
        llm_base_url=args.base_url,
        llm_model=args.model,
        engine_host=args.host,
        engine_port=args.port,
        max_concurrency=args.concurrency,
        temperature=args.temperature,
        verbose=args.verbose,
        source_root=args.source_root
    )

    scanner = IVAgentScanner(config, logger=CLILogger(component="ivagent.scanner", verbose=args.verbose))

    # Prepare precondition
    precondition = None
    if args.config_file and args.preset_name:
        parser.error("Cannot use both --config and --preset. Please choose one.")
    elif args.config_file:
        # Load from custom config file
        try:
            precondition = load_precondition_from_file(args.config_file)
            logger.info("precondition.loaded", "已加载前置条件文件", path=args.config_file, name=precondition.name)
            if precondition.description:
                logger.info("precondition.description", precondition.description)
            logger.info("precondition.target", "前置条件目标", target=precondition.target)
        except Exception as e:
            logger.exception("precondition.load_failed", e, path=args.config_file)
            return
    elif args.preset_name:
        # Load from preset
        try:
            precondition = load_preset_precondition(args.preset_name)
            logger.info("precondition.preset", "使用预置前置条件", preset=args.preset_name, name=precondition.name)
            if precondition.description:
                logger.info("precondition.description", precondition.description)
        except Exception as e:
            logger.exception("precondition.preset_failed", e, preset=args.preset_name)
            return
    else:
        logger.warning(
            "precondition.none",
            "未指定前置条件，将按通用约束执行分析",
        )

    startup_elapsed = time.perf_counter() - startup_t0
    logger.success(
        "startup.ready",
        "CLI 启动完成，开始扫描",
        startup_time=format_duration(startup_elapsed),
        engine=args.engine,
        target=args.target or "(未指定)",
        source_root=args.source_root or "(未指定)",
        functions=len(targets),
        concurrency=args.concurrency,
    )

    try:
        scan_t0 = time.perf_counter()
        results = await scanner.scan_functions(targets, precondition)

        # Calculate stats
        vuln_count = 0
        success_count = 0
        failed_count = 0

        for r in results:
            if "error" in r and r.get("error"):
                failed_count += 1
            else:
                success_count += 1
                vuln_count += len(r.get("vulnerabilities", []))

        scan_elapsed = time.perf_counter() - scan_t0
        total_elapsed = time.perf_counter() - startup_t0
        logger.success(
            "scan.completed",
            "扫描完成",
            successful=success_count,
            failed=failed_count,
            vulnerabilities=vuln_count,
            scan_time=format_duration(scan_elapsed),
            total_time=format_duration(total_elapsed),
        )

        # Save results
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                # Convert results to list if not already (results is a list)
                json.dump(results, f, indent=2, ensure_ascii=False, default=str)
            logger.info("scan.output_saved", "结果已保存", output=args.output)

    except KeyboardInterrupt:
        logger.warning("scan.interrupted", "用户中断扫描")
    except Exception as e:
        logger.exception(
            "scan.failed",
            e,
            engine=args.engine,
            target=args.target or "(未指定)",
            function=args.function,
        )


if __name__ == "__main__":
    asyncio.run(main())
