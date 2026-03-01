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
import time
import warnings
from pathlib import Path
from typing import Optional

from ivagent.core.cli_logger import CLILogger, format_duration


# 禁用本地地址的代理，避免请求被转发到代理服务器
os.environ['no_proxy'] = '127.0.0.1,localhost'
os.environ['NO_PROXY'] = '127.0.0.1,localhost'

def disable_system_proxy(logger: Optional[CLILogger] = None) -> list[str]:
    """
    彻底禁用系统代理（清除所有相关环境变量）
    覆盖大小写形式，适配不同操作系统的命名习惯
    """
    logger = logger or CLILogger(component="orchestrator_cli")

    # 所有可能的代理环境变量（包含大小写，覆盖Windows/Linux/macOS）
    proxy_env_vars = [
        'HTTP_PROXY', 'HTTPS_PROXY', 'FTP_PROXY', 'SOCKS_PROXY',
        'http_proxy', 'https_proxy', 'ftp_proxy', 'socks_proxy',
        'ALL_PROXY', 'all_proxy', 'NO_PROXY', 'no_proxy'
    ]

    cleared_vars: list[str] = []

    # 逐个删除环境变量
    for var in proxy_env_vars:
        if var in os.environ:
            del os.environ[var]
            cleared_vars.append(var)
            logger.debug("proxy.cleared", "已清除系统代理环境变量", env_var=var)

    # 验证是否清理干净
    remaining_proxy_vars = [var for var in proxy_env_vars if var in os.environ]
    if not remaining_proxy_vars:
        logger.info("proxy.disabled", "系统代理已禁用", cleared=len(cleared_vars))
    else:
        logger.warning("proxy.remaining", "仍有未清除代理变量", variables=",".join(remaining_proxy_vars))
    return cleared_vars

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

    kwargs['default_headers'] = {"User-Agent": "Zed/0.211.6 (macos; x86_64)"}

    return ChatOpenAI(**kwargs)


async def run_workflow(
        workflow_path: str,
        engine_type: Optional[str] = None,
        target_path: Optional[str] = None,
        source_root: Optional[str] = None,
        execution_mode: str = "parallel",
        verbose: bool = True,
        logger: Optional[CLILogger] = None,
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
        logger: CLI 日志器（用于清理阶段告警）

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
    try:
        result = await orchestrator.execute_workflow(workflow_path, target_path=target_path)
    finally:
        # 显式关闭引擎，避免 aiohttp ClientSession 泄漏警告
        engine = getattr(orchestrator, "engine", None)
        if engine and hasattr(engine, "close"):
            try:
                await engine.close()
            except Exception as e:
                if logger:
                    logger.warning("workflow.cleanup_failed", "引擎关闭失败", error=str(e))

    return result


def main():
    """主函数"""
    # Python 3.14 下第三方已知兼容 warning，避免污染 CLI 输出
    warnings.filterwarnings(
        "ignore",
        message="Core Pydantic V1 functionality isn't compatible with Python 3.14 or greater.",
        category=UserWarning,
    )

    startup_t0 = time.perf_counter()

    parser = argparse.ArgumentParser(
        description="IVAgent Orchestrator - Workflow 驱动的漏洞挖掘",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 使用 Workflow 文档执行扫描（目标路径在 workflow 中指定）
  python -m ivagent.orchestrator_cli --workflow workflows/nvidia_gsp_analysis.md
  
  # 通过参数指定引擎和目标路径
  python -m ivagent.orchestrator_cli --workflow workflows/nvidia_gsp_analysis.md \\
      --engine ida --target /path/to/target.sys
  
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
        default=False,
        help="详细日志模式（显示更多阶段信息）",
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="调试日志模式（显示全量追踪日志）",
    )

    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="静默模式，减少日志输出",
    )

    args = parser.parse_args()

    # 确定日志模式与显示开关
    if args.debug:
        log_mode = "debug"
    elif args.verbose:
        log_mode = "verbose"
    else:
        log_mode = "normal"
    os.environ["IVAGENT_LOG_MODE"] = log_mode

    verbose = not args.quiet
    logger = CLILogger(component="orchestrator_cli", verbose=verbose, mode=log_mode)

    # cleared_vars = disable_system_proxy(logger)

    # 检查 Workflow 文件是否存在
    workflow_path = Path(args.workflow)
    if not workflow_path.exists():
        logger.error(
            "startup.invalid_workflow",
            "Workflow 文件不存在",
            workflow=args.workflow,
        )
        sys.exit(1)

    startup_elapsed = time.perf_counter() - startup_t0
    logger.success(
        "startup.ready",
        "CLI 启动完成，开始执行 Workflow",
        startup_time=format_duration(startup_elapsed),
        workflow=str(workflow_path.absolute()),
        mode=args.mode,
        engine=args.engine or "auto",
        log_mode=log_mode,
        proxy_cleared=len([]),
    )

    try:
        run_t0 = time.perf_counter()
        result = asyncio.run(run_workflow(
            workflow_path=str(workflow_path.absolute()),
            engine_type=args.engine,
            target_path=args.target,
            source_root=args.source_root,
            execution_mode=args.mode,
            verbose=verbose,
            logger=logger,
        ))

        wall_time = time.perf_counter() - run_t0
        logger.success(
            "workflow.completed",
            "Workflow 执行完成",
            status="成功" if result.success else "失败",
            completed=f"{result.completed_workflows}/{result.total_workflows}",
            vulnerabilities=result.total_vulnerabilities,
            execution_time=format_duration(result.execution_time),
            wall_time=format_duration(wall_time),
        )
        logger.info("workflow.summary", result.summary or "(无摘要)")

        if result.errors:
            for idx, error in enumerate(result.errors, 1):
                logger.warning("workflow.issue", error, index=idx)

        sys.exit(0 if result.success else 1)

    except KeyboardInterrupt:
        logger.warning("workflow.interrupted", "用户中断")
        sys.exit(130)
    except Exception as e:
        logger.exception(
            "workflow.failed",
            e,
            workflow=str(workflow_path.absolute()),
            mode=args.mode,
            engine=args.engine or "auto",
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
