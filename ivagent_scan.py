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
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple

# Add package root to path
sys.path.insert(0, str(Path(__file__).parent))

from ivagent.scanner import IVAgentScanner, ScanConfig
from ivagent.models.constraints import Precondition

# Default configurations
DEFAULT_API_KEY = os.environ.get("OPENAI_API_KEY", "4d6beb96-4e00-4f7e-8751-2244ad7da982")
DEFAULT_BASE_URL = os.environ.get("OPENAI_BASE_URL", "https://ark.cn-beijing.volces.com/api/v3")
DEFAULT_MODEL = os.environ.get("OPENAI_MODEL", "ep-20260108170122-9jn65")
DEFAULT_MODEL = "deepseek-v3-2-251201"


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

    # Validate arguments
    if not args.function:
        parser.error("Either --function must be provided")

    # Prepare targets
    targets = []
    if args.function:
        targets.append(args.function)

    if not targets:
        print("[!] No functions to scan.")
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

    scanner = IVAgentScanner(config)

    # Prepare precondition
    precondition = None
    if args.config_file and args.preset_name:
        parser.error("Cannot use both --config and --preset. Please choose one.")
    elif args.config_file:
        # Load from custom config file
        try:
            precondition = load_precondition_from_file(args.config_file)
            print(f"[*] Loaded precondition from {args.config_file}")
            print(f"    Name: {precondition.name}")
            if precondition.description:
                print(f"    Description: {precondition.description}")
            print(f"    Target: {precondition.target}")
        except Exception as e:
            print(f"[X] Failed to load precondition file: {e}")
            return
    elif args.preset_name:
        # Load from preset
        try:
            precondition = load_preset_precondition(args.preset_name)
            print(f"[*] Using preset: {precondition.name}")
            if precondition.description:
                print(f"    Description: {precondition.description}")
        except Exception as e:
            print(f"[X] Failed to load preset: {e}")
            return
    else:
        print("[!] No precondition specified. Analysis will proceed without target-specific constraints.")
        print("    Use --list-presets to see available presets, or --config to specify a custom file.")

    print(f"\n{'=' * 50}")
    print(f"IVAgent Scan Session")
    print(f"{'=' * 50}")
    print(f"[+] Engine: {args.engine}")
    if args.target:
        print(f"[+] Target: {args.target}")
    if args.source_root:
        print(f"[+] Source Root: {args.source_root}")
    print(f"[+] Functions to scan: {len(targets)}")
    print(f"[+] Concurrency: {args.concurrency}")
    print(f"{'=' * 50}\n")

    try:
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

        print(f"\n{'=' * 50}")
        print(f"Scan Completed")
        print(f"{'=' * 50}")
        print(f"[+] Successful: {success_count}")
        print(f"[+] Failed: {failed_count}")
        print(f"[+] Total Vulnerabilities: {vuln_count}")

        # Save results
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                # Convert results to list if not already (results is a list)
                json.dump(results, f, indent=2, ensure_ascii=False, default=str)
            print(f"[+] Results saved to {args.output}")

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
    except Exception as e:
        print(f"\n[X] Unexpected error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
