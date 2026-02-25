#!/usr/bin/env python3
"""
IVAgent Orchestrator CLI

Workflow 模式的命令行入口。
使用示例:
    python -m ivagent.orchestrator_cli --workflow workflows/android_sql_injection.md --verbose
"""

import argparse
import asyncio
import os
import sys
from pathlib import Path
from typing import Optional

# 添加项目根目录到路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from langchain_openai import ChatOpenAI

from ivagent.orchestrator import MasterOrchestrator, MasterOrchestratorResult


def create_llm_client() -> ChatOpenAI:
    """
    创建 LLM 客户端
    
    Args:
        model: 模型名称
        temperature: 温度参数
        api_key: API 密钥（可选，默认从环境变量读取）
        base_url: API 基础 URL（可选）
        
    Returns:
        ChatOpenAI 实例
    """

    api_key = os.environ.get("OPENAI_API_KEY")
    base_url = os.environ.get("OPENAI_BASE_URL")
    model = os.environ.get("OPENAI_MODEL")

    kwargs = {
        "model": model,
        "temperature": 0.3,
    }

    if api_key:
        kwargs["api_key"] = api_key
    if base_url:
        kwargs["base_url"] = base_url

    return ChatOpenAI(**kwargs)


async def run_workflow(
        workflow_path: str,
        engine_type: Optional[str] = None,
        target_path: Optional[str] = None,
        source_root: Optional[str] = None,
        execution_mode: str = "parallel",
        verbose: bool = True,
) -> MasterOrchestratorResult:
    """
    执行 Workflow

    Args:
        workflow_path: Workflow 文件路径
        engine_type: 分析引擎类型 (ida, source)
        target_path: 目标程序路径（可选，如果 workflow 中未指定）
        source_root: 源代码根目录（可选，用于源码分析）
        execution_mode: 执行模式 (sequential, parallel)
        verbose: 是否打印详细日志

    Returns:
        执行结果
    """
    # 创建 LLM 客户端
    llm_client = create_llm_client()

    # 创建 MasterOrchestrator（支持多 workflow 并发执行）
    orchestrator = MasterOrchestrator(
        llm_client=llm_client,
        engine_type=engine_type,
        target_path=target_path,
        source_root=source_root,
        execution_mode=execution_mode,
        verbose=verbose,
    )

    # 执行 Workflow
    result = await orchestrator.execute_workflow(workflow_path, target_path=target_path)

    return result


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description="IVAgent Orchestrator - Workflow 驱动的漏洞挖掘",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  
  # 源码分析模式
  python -m ivagent.orchestrator_cli --workflow workflows/android_sql_injection.md \\
      --engine source --target /path/to/source --source-root /path/to/source
  
  # 并行执行模式（默认）
  python -m ivagent.orchestrator_cli --workflow workflows/android_sql_injection.md \\
      --engine ida --target app.apk --mode parallel
  
  # 串行执行模式
  python -m ivagent.orchestrator_cli --workflow workflows/android_sql_injection.md \\
      --engine ida --target app.apk --mode sequential
        """
    )

    parser.add_argument(
        "--workflow", "-w",
        required=True,
        help="Workflow 文档路径（Markdown 格式）",
    )

    parser.add_argument(
        "--engine", "-e",
        choices=["ida", "source", "jeb", "abc"],
        help="分析引擎类型 (ida, jeb, abc, source)",
    )

    parser.add_argument(
        "--target", "-t",
        help="目标程序路径（IDB/二进制文件或源码目录）",
    )

    parser.add_argument(
        "--source-root", "-s",
        help="源代码根目录（用于源码分析和 CallsiteAgent）",
    )

    parser.add_argument(
        "--mode", "-m",
        choices=["sequential", "parallel"],
        default="parallel",
        help="执行模式：sequential（串行）或 parallel（并行，默认）",
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=True,
        help="打印详细日志（默认: True）",
    )

    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="静默模式，减少日志输出",
    )

    args = parser.parse_args()

    # 检查 Workflow 文件是否存在
    workflow_path = Path(args.workflow)
    if not workflow_path.exists():
        print(f"[X] Error: Workflow file not found: {args.workflow}")
        sys.exit(1)

    # 确定是否详细输出
    verbose = args.verbose and not args.quiet

    # 执行 Workflow
    print(f"[*] IVAgent Orchestrator")
    print(f"[*] Workflow: {args.workflow}")
    print(f"[*] 执行模式: {args.mode}")
    print()

    try:
        result = asyncio.run(run_workflow(
            workflow_path=str(workflow_path.absolute()),
            engine_type=args.engine,
            target_path=args.target,
            source_root=args.source_root,
            execution_mode=args.mode,
            verbose=verbose,
        ))

        print()
        print("=" * 60)
        print("执行结果")
        print("=" * 60)
        print(f"状态: {'成功' if result.success else '失败'}")
        print(f"总 Workflow 数: {result.total_workflows}")
        print(f"完成 Workflow 数: {result.completed_workflows}")
        print(f"发现漏洞总数: {result.total_vulnerabilities}")
        print(f"执行时间: {result.execution_time:.2f} 秒")
        print()
        print("摘要:")
        print(result.summary)

        if result.errors:
            print()
            print("警告/错误:")
            for error in result.errors:
                print(f"  - {error}")

        sys.exit(0 if result.success else 1)

    except KeyboardInterrupt:
        print("\n[!] 用户中断")
        sys.exit(130)
    except Exception as e:
        print(f"\n[X] 执行失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
