#!/usr/bin/env python3
"""
CodeExplorerAgent - 统一的代码探索与语义分析 Agent

本Agent合并了原 SemanticAnalysisAgent 的所有功能，提供统一的代码探索和语义分析能力。

核心职责：
- 代码搜索与导航（search_code, list_directory）
- 文件内容读取（read_file）
- 符号查找与定位（search_symbol）
- 函数定义与调用关系分析（get_function_def, get_caller, get_callee）
- 交叉引用追踪（get_xref）
- 深度语义理解与安全审计

关键特性：
- 支持多种反编译引擎（IDA, JEB, ABC, Ghidra）
- 自动识别并使用正确的函数标识符格式
- 批量工具调用优化，提升分析效率
- 结构化markdown输出，便于后续处理
"""

import os
import subprocess
import uuid
import time
import json
from typing import Dict, List, Optional, Any, Tuple, Set
from pathlib import Path

from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage, AIMessage

from .base import BaseAgent
from ..engines.base_static_analysis_engine import BaseStaticAnalysisEngine, SearchOptions
from ..core.context import AgentMessage, ContextCompressor, ReadArtifactPruner
from ..core import SummaryService

# 导入 ToolBasedLLMClient
try:
    from ..core.tool_llm_client import ToolBasedLLMClient
except ImportError:
    ToolBasedLLMClient = None

# 导入日志系统
try:
    from ..core.agent_logger import get_agent_log_manager, AgentStatus
except ImportError:
    get_agent_log_manager = None
    AgentStatus = None


# 系统提示词
CODE_EXPLORER_SYSTEM_PROMPT = """
## 角色定义

你是一位**专家级代码探索与语义分析引擎**。你的任务是接收自然语言描述的代码分析需求，
通过自主探索代码库，完成深度分析并输出**markdown格式的文本结果**。

## 核心能力
- **代码探索**: 使用搜索和文件读取工具在代码库中自主导航
- **静态分析**: 利用引擎提供的函数定义、调用关系、交叉引用等高级分析接口
- **语义理解**: 基于收集的代码片段进行深度语义分析和安全审计
- **推理规划**: 自主决定分析策略，合理分解复杂查询

## 输出要求（重要）
- 最终输出必须是**markdown格式的纯文本**，不是JSON
- 输出应包含：分析摘要、发现的代码项、关键证据、代码位置等
- 输出必须基于代码事实，禁止使用“应当/需要/建议”等规范性表达
- `summary` 必须是可直接复用的高保真压缩摘要，且包含以下章节（无内容写“无”）：
  - `## 核心结论`
  - `## 函数标识符`
  - `## 关键约束（入参/边界/全局/状态）`
  - `## 证据锚点`
  - `## 关键调用链`
- 当任务涉及函数枚举/函数标识符时，`result` 与 `summary` 都必须优先保留 `search_symbol` 返回的标准 `function_identifier`（原样），不要仅保留 `typeN @0x...` 这类弱标识
- 当用户要求“入参约束/全局变量约束”时，必须新增章节：
  - `## 目标函数约束清单`
  - 每个函数必须包含：function_identifier（search_symbol 标准格式）、signature、参数级入参约束、全局变量约束、证据锚点
- 当输出将用于 `vuln_analysis` 规划时，额外提供 `## 可直接写入 analysis_context` 章节，按固定标题组织：
  - `## 目标函数`
  - `## 入参约束`
  - `## 全局变量约束`
  - `## 证据锚点`
- `## 入参约束` 必须按函数签名顺序逐参数输出，每个参数都要包含：
  - 来源
  - 可控性（直接可控/间接受控/不可控）
  - 污点状态（tainted/untainted/unknown）
  - 大小/边界关系（与长度、计数、索引、分配大小等关系）
  - 显式校验（有/无 + 条件）
  - 证据锚点（关键语句/调用点）
- `## 关键约束（入参/边界/全局/状态）` 中的入参约束仅允许目标函数签名参数；禁止把 `local/tmp/index/n` 等局部变量当作入参约束条目
- 局部变量或中间数据流只能作为证据锚点引用，不能替代参数级约束
- 不得用 malloc/memcpy/printf 等风险操作描述替代参数级约束
- 当任务目标为“函数枚举/分发映射/analysis_context 前置取证”时，禁止输出具体漏洞类型结论（如“栈溢出/命令注入/UAF/格式字符串/CWE-xxx”）
- 若需要给出行为摘要，仅可输出宏观事实特征（如“外部数据参与长度/索引/格式化/资源分配”），不要输出漏洞定性结论
- 若使用“核心行为摘要”表格，推荐列为：`Handler | 关键操作 | 外部输入交互特征`，第三列不得写具体漏洞类型
- **函数标识符规范**：当返回函数信息时，必须使用 `search_symbol` 工具返回的标准函数标识符
  - 标准格式示例：
    * IDA/Ghidra: `function_name` 或 `namespace::function_name`
    * JEB (Java/Android): `Lcom/example/ClassName;->methodName(Ljava/lang/String;)V` (完整Smali格式)
    * ABC (HarmonyOS): `com.example.ClassName.methodName` 或 `ClassName.methodName`
  - ❌ 错误：使用简化名称如 `ClassName.method` (JEB场景)
  - ✅ 正确：使用 `search_symbol` 返回的完整标识符
- 若上下文包含 `## 已执行 Tool Call 与返回摘要（防重复）`：
  - 必须优先复用其中已有结果
  - 禁止重复执行同 `tool_name + args` 的调用
  - 若确需重复调用，必须在输出中明确“目标变化”或“新增证据不足导致需复查”
- 若上下文包含 `## 任务级判定进度（可直接输出/待补证据）` 与 `## 仍需 Tool Call 的最小取证集`：
  - 对“可直接输出”子任务先给出结论，不等待额外工具
  - 同一轮仅对“最小取证集”中的缺口发起工具调用
  - 禁止对已可判定部分回退为全量重复取证
- 当历史 tool call 明显增多且存在冗余时，可主动调用：
  - `mark_compression_projection(remove_message_ids=[...], fold_message_ids=[...], reason=...)` 提交压缩前裁切清单
  - `remove_message_ids` / `fold_message_ids` 必须引用消息首行的 `消息ID: Message_xxx`
  - `remove_message_ids`: 精确删除消息
  - `fold_message_ids`: 折叠消息正文为占位文本（保留 tool_call 链路）
  - 提交后，系统会先按消息ID应用删除/折叠，再进入压缩 Agent 蒸馏
- 若本轮因迭代上限收敛，`result` 必须新增并完整填写以下章节（无内容写“无”）：
  - `## 探索状态`（必须明确：完成 / 部分完成-迭代上限）
  - `## 当前可推断信息`
  - `## 未推断信息`
  - `## 需 Orchestrator 继续规划的 CodeExplorer 子任务`
    - 子任务必须是可直接执行的探索任务描述（用于下一轮 `code_explorer`）
- 只输出和用户需求相关的内容

## 上下文摘要定义（关键）
当用户要求“入参约束/全局变量约束”时，你需要输出**上下文摘要**，用于后续漏洞分析任务。

### 源头抽取流程（必须遵守）
1. 先调用 `search_symbol` 获取标准 `function_identifier`（原样保留）。
2. 调用 `get_function_def(function_identifier=...)` 获取函数签名与参数列表。
   - 若需获取多个函数定义，**单轮最多同时调用 3 个 `get_function_def`**。
   - 每批结果返回后，必须先完成本批源码分析并输出阶段结论，再请求下一批。
   - 候选函数超过 3 个时，先选择与当前任务最相关的 3 个，禁止单轮全量拉取源码。
3. 按参数顺序提取约束，必要时使用 `get_caller/get_xref/read_file` 补充来源与校验证据。
4. 入参约束仅针对目标函数签名参数；局部变量约束仅可写入证据锚点。
5. 若信息不足，明确写“未见明确证据”，不得跳过该参数。
6. 规划阶段仅抽取事实约束，不做漏洞判定与可利用性推断；若需提及风险，仅可使用宏观描述，不得给出具体漏洞类型标签。

### 可直接写入 analysis_context 的标准模板
```markdown
## 目标函数
- function_identifier: <search_symbol 标准标识符>
- signature: <函数签名>

## 入参约束
- 参数1 `<name>`:
  - 来源: <网络/文件/IPC/上层函数传递/未见明确证据>
  - 可控性: <直接可控/间接受控/不可控/unknown>
  - 污点状态: <tainted/untainted/unknown>
  - 大小/边界关系: <与 len/count/index/alloc_size 的关系>
  - 显式校验: <有/无 + 条件>
  - 证据锚点: <关键语句/调用点>
- 参数2 `<name>`:
  - 来源: <...>
  - 可控性: <...>
  - 污点状态: <...>
  - 大小/边界关系: <...>
  - 显式校验: <...>
  - 证据锚点: <...>
- 仅允许列出函数签名中的参数；禁止新增局部变量条目

## 全局变量约束
- <全局变量/对象状态/认证状态/配置约束；无则写“未见明确证据”>

## 证据锚点
- <调用链/关键语句/地址/文件位置>
```

### 反例（禁止）
- 仅写“malloc + memcpy + printf”这类风险操作，不按参数逐条给出来源/可控性/污点/边界/校验。
- 把 `local_buf`、`idx`、`tmp_len` 等局部变量约束写成“入参约束”条目。

## 工作流程

### 1. 理解查询需求
- 仔细阅读用户的自然语言查询
- 识别关键分析目标和约束条件
- 规划分析步骤和策略

### 2. 自主代码探索
根据查询需求，自主选择合适的工具：

**基础探索工具**:
- `search_code`: 在代码库中搜索文本
- `read_file`: 读取文件指定范围
- `list_directory`: 浏览目录结构

**高级分析工具**:
- `get_function_def`: 获取函数完整定义
- `get_callee`: 获取函数内调用的所有子函数
- `get_caller`: 获取调用该函数的所有父函数
- `get_xref`: 获取函数或变量的交叉引用
- `search_symbol`: 根据模式搜索符号

**压缩投影工具**:
- `mark_compression_projection`: 提交待删除/待折叠 `message_id` 清单（压缩前生效）

### 3. 迭代分析
- 收集代码信息后，进行分析和推理
- 若需要批量获取函数源码，`get_function_def` 每轮最多 3 个，必须按“获取一批 -> 分析一批 -> 再获取下一批”执行
- 如果需要更多信息，决定下一步调用哪些工具
- 重复探索和分析过程，直到获得足够信息

### 4. 输出结果
当分析完成时，调用 `finish_exploration` 工具同时提交：
- `result`: markdown格式的正文结果
- `summary`: 对正文结果的精简摘要（Markdown 纯文本）

## 函数标识符提取规范（关键）

当任务要求返回函数标识符时，必须遵循以下流程：

### 标准流程
1. **使用 search_symbol 查找目标**
   ```
   # 对于 JEB (Java/Android)，使用类名或方法名搜索
   search_symbol(pattern="PasswordProvider")
   
   # 也可以使用正则表达式精确匹配
   search_symbol(pattern=".*PasswordProvider.*query.*")
   ```

2. **从结果中提取标准标识符**

3. **可选：使用 get_function_def 验证**
   ```
   # 使用从 search_symbol 获取的完整标识符
   get_function_def(function_identifier="Lcom/zin/dvac/PasswordProvider;->query(Ljava/lang/String;)Ljava/lang/String;")
   ```

4. **在输出中使用标准标识符**
   ```markdown
   ## 目标函数
   
   **函数标识符**: `Lcom/zin/dvac/PasswordProvider;->query(Ljava/lang/String;)Ljava/lang/String;`
   **签名**: `public String query(String username)`
   **位置**: com/zin/dvac/PasswordProvider.java:25
   ```

### 重要提醒
- ❌ 不要使用简化格式或自己拼接标识符
  - 错误示例（JEB）: `PasswordProvider.query` 或 `com.zin.dvac.PasswordProvider.query`
  - 正确示例（JEB）: `Lcom/zin/dvac/PasswordProvider;->query(Ljava/lang/String;)Ljava/lang/String;`
- ✅ 必须使用 search_symbol 返回的完整标识符
- ❌ 不要猜测标识符格式（特别是JEB的Smali格式，包含参数类型和返回类型）
- ✅ 直接复制 search_symbol 结果中 `[type]` 后的完整名称
- 📌 JEB 特别注意：必须包含完整的 Smali 签名，包括 `L...;->methodName(参数类型)返回类型`

### 特殊场景处理
- **多个匹配结果**：如果 search_symbol 返回多个结果，使用 get_function_def 或 read_file 确认哪个是目标；当需要读取多个函数定义时，`get_function_def` 必须按每轮最多 3 个分批执行，并在每批后先完成分析再继续
- **命名空间/包名**：保留完整的命名空间或包名，不要省略
- **重载函数**：如果有多个重载，根据签名选择正确的那个（JEB中签名包含参数类型，可精确区分）

## 分析原则
1. **自主决策**: 你自行决定调用哪些工具、如何组合使用
2. **高效探索**: 优先使用高级分析工具
3. **深度分析**: 不仅定位代码位置，还要理解其语义和上下文
4. **证据驱动**: 所有结论都要有代码证据支持
5. **迭代优化**: 根据新获取的信息不断调整分析策略
6. **标识符规范**: 返回函数时必须使用 search_symbol 提供的标准标识符
"""


class CodeExplorerAgent(BaseAgent):
    """
    代码探索 Agent（合并了原 SemanticAnalysisAgent 的功能）
    
    职责：
    - 代码搜索、文件读取、符号查找
    - 函数定义获取、交叉引用分析
    - 语义理解分析
    
    输出：
        markdown格式的文本结果，包含：
        - 分析摘要
        - 发现的代码项
        - 关键证据和代码位置
    """
    
    def __init__(
        self,
        engine: BaseStaticAnalysisEngine,
        llm_client: Any,
        source_root: Optional[Path] = None,
        max_iterations: int = 15,
        verbose: bool = False,
        enable_logging: bool = True,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        enable_context_compression: bool = True,
        compression_token_threshold: int = 8000,
        compression_max_rounds: int = 2,
    ):
        super().__init__(
            engine=engine,
            llm_client=llm_client,
            max_iterations=max_iterations,
            verbose=verbose,
        )
        
        # 确定源码根目录
        self.source_root = source_root
        if self.source_root is None:
            self.source_root = getattr(engine, 'source_root', None)
        if self.source_root is None:
            self.source_root = getattr(engine, '_source_root', None)
        if self.source_root is None:
            self.source_root = Path(".")
        
        # 日志配置
        self.enable_logging = enable_logging
        self.session_id = session_id
        self.agent_id = agent_id or f"code_explorer_{uuid.uuid4().hex[:8]}"
        self._agent_log_manager = get_agent_log_manager() if (enable_logging and get_agent_log_manager) else None
        self.enable_context_compression = enable_context_compression
        self.compression_token_threshold = compression_token_threshold
        self.compression_max_rounds = compression_max_rounds
        
        # 初始化 ToolBasedLLMClient
        if ToolBasedLLMClient:
            if not isinstance(llm_client, ToolBasedLLMClient):
                self._base_llm = llm_client
                self._tool_client = ToolBasedLLMClient(
                    llm=llm_client,
                    max_retries=3,
                    retry_delay=1.0,
                    verbose=verbose,
                    enable_logging=enable_logging,
                    session_id=session_id,
                    agent_id=self.agent_id,
                    log_metadata={
                        "agent_type": "CodeExplorerAgent",
                    },
                )
            else:
                self._tool_client = llm_client
                self._base_llm = llm_client.llm
        else:
            raise RuntimeError("ToolBasedLLMClient is required")

        self._context_compressor = None
        self._read_artifact_pruner = None
        if self.enable_context_compression:
            summary_service = SummaryService(
                llm_client=self._base_llm,
                max_retries=2,
                retry_delay=1.0,
                enable_logging=self.enable_logging,
                verbose=self.verbose,
                session_id=self.session_id,
                agent_id=self.agent_id,
                agent_type="code_explorer",
                target_function="code_explorer",
            )
            self._context_compressor = ContextCompressor(
                summary_service=summary_service,
                compression_profile="code_explorer",
                consumer_agent="code_explorer",
                compression_purpose="code exploration continuity",
            )
            self._read_artifact_pruner = ReadArtifactPruner()
        
        self.log(f"CodeExplorerAgent initialized (agent_id={self.agent_id})")
        self._tool_result_cache: Dict[str, str] = {}
        self._tool_execution_trace: List[Dict[str, Any]] = []
        self._tool_cache_max_entries = 400
        self._pending_projection_remove_message_ids: Set[str] = set()
        self._pending_projection_fold_message_ids: Set[str] = set()
        self._pending_projection_reason: str = ""
        self._runtime_message_ids: Dict[int, str] = {}
        self._runtime_message_seq: int = 0
        self._projection_last_validation_error: str = ""
    
    # ==========================================================================
    # 基础代码探索工具
    # ==========================================================================
    
    def search_code(self, query: str, path_filter: Optional[str] = None) -> str:
        """Search for text in source files using ripgrep.
        
        Parameters:
            query: The text string to search for (treated as literal string).
            path_filter: Optional glob pattern to filter files (e.g., "*.c", "src/*.java").
        
        Returns:
            Formatted search results with file paths, line numbers, and matching content.
        """
        try:
            cmd = [
                "rg", "-n", "--no-heading", "--fixed-strings",
                "-C", "3",
                str(query), str(self.source_root)
            ]
            
            if path_filter:
                cmd.extend(["-g", path_filter])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=30
            )
            
            if result.returncode not in [0, 1]:
                return f"Search error: {result.stderr}"
            
            lines = result.stdout.strip().split('\n') if result.stdout else []
            if not lines or not lines[0]:
                return f"No matches found for: '{query}'"
            
            formatted = [f"Search results for: '{query}'", "=" * 60]
            
            for line in lines[:50]:
                if not line:
                    continue
                parts = line.split(':', 2)
                if len(parts) >= 3:
                    file_path, line_num, content = parts[0], parts[1], parts[2]
                    formatted.append(f"{file_path}:{line_num} | {content}")
            
            if len(lines) > 50:
                formatted.append(f"\n... and {len(lines) - 50} more matches")
            
            return "\n".join(formatted)
        
        except subprocess.TimeoutExpired:
            return f"Error: Search timed out for: '{query}'"
        except FileNotFoundError:
            return "Error: ripgrep (rg) not found. Please install ripgrep."
        except Exception as e:
            return f"Error searching code: {str(e)}"
    
    def read_file(self, file_path: str, start_line: int, end_line: int) -> str:
        """Read a specific range of lines from a file.
        
        Parameters:
            file_path: Path to the file (relative to source_root or absolute).
            start_line: Start line number (1-based, inclusive).
            end_line: End line number (1-based, inclusive).
        
        Returns:
            File content with line numbers and context header.
        """
        try:
            if os.path.isabs(file_path):
                full_path = Path(file_path)
            else:
                full_path = self.source_root / file_path
            
            full_path = full_path.resolve()
            
            try:
                full_path.relative_to(self.source_root)
            except ValueError:
                return "Error: Access denied. Path outside source root."
            
            if not full_path.exists():
                return f"Error: File not found: {file_path}"
            
            with open(full_path, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
            
            total_lines = len(lines)
            start_idx = max(0, start_line - 1)
            end_idx = min(total_lines, end_line)
            
            if start_idx >= end_idx:
                return f"File: {file_path}\nInvalid range [{start_line}:{end_line}], total lines: {total_lines}"
            
            output = [
                f"File: {file_path}",
                f"Lines: {start_idx + 1} - {end_idx} (of {total_lines})",
                "=" * 60
            ]
            
            for i in range(start_idx, end_idx):
                output.append(f"{i + 1:4d} | {lines[i].rstrip()}")
            
            return "\n".join(output)
        
        except Exception as e:
            return f"Error reading file: {str(e)}"
    
    def list_directory(self, dir_path: str = ".") -> str:
        """List contents of a directory.
        
        Parameters:
            dir_path: Directory path (relative to source_root or absolute).
        
        Returns:
            List of subdirectories and files with sizes.
        """
        try:
            if os.path.isabs(dir_path):
                full_path = Path(dir_path)
            else:
                full_path = self.source_root / dir_path
            
            full_path = full_path.resolve()
            
            try:
                full_path.relative_to(self.source_root)
            except ValueError:
                return "Error: Access denied. Path outside source root."
            
            if not full_path.exists():
                return f"Error: Directory not found: {dir_path}"
            
            if not full_path.is_dir():
                return f"Error: Not a directory: {dir_path}"
            
            entries = list(full_path.iterdir())
            dirs = sorted([e for e in entries if e.is_dir()], key=lambda x: x.name)
            files = sorted([e for e in entries if e.is_file()], key=lambda x: x.name)
            
            output = [f"Directory: {dir_path}", "=" * 60]
            
            if dirs:
                output.append(f"\nSubdirectories ({len(dirs)}):")
                for d in dirs:
                    output.append(f"  [DIR]  {d.name}")
            
            if files:
                output.append(f"\nFiles ({len(files)}):")
                for f in files:
                    size = f.stat().st_size
                    size_str = f"{size:,} bytes" if size < 1024 * 1024 else f"{size / 1024 / 1024:.2f} MB"
                    output.append(f"  [FILE] {f.name:<50} ({size_str})")
            
            return "\n".join(output)
        
        except Exception as e:
            return f"Error listing directory: {str(e)}"
    
    # ==========================================================================
    # 高级静态分析工具
    # ==========================================================================
    
    async def get_function_def(self, function_identifier: str) -> str:
        """获取函数的完整定义。
        
        Parameters:
            function_identifier: 函数标识符或函数名
        
        Returns:
            函数定义信息（markdown格式）
        """
        try:
            func_def = await self.engine.get_function_def(function_identifier=function_identifier)
            if func_def is None:
                return f"Function not found: {function_identifier}"
            
            result = [
                f"Function: {func_def.name}",
                f"identifier: {func_def.function_identifier}",
                f"Location: {func_def.location or 'N/A'}",
                f"Parameters: {func_def.parameters}",
                f"Return Type: {func_def.return_type or 'N/A'}",
                "=" * 60,
                func_def.code if func_def.code else "(No code available)",
            ]
            return "\n".join(result)
        except Exception as e:
            return f"Error getting function definition: {str(e)}"
    
    async def get_callee(self, function_identifier: str) -> str:
        """获取函数内调用的所有子函数。
        
        Parameters:
            function_identifier: 函数标识符
        
        Returns:
            子函数调用列表（markdown格式）
        """
        try:
            call_sites = await self.engine.get_callee(function_identifier)
            if not call_sites:
                return f"No callees found for: {function_identifier}"
            
            result = [f"Callees of {function_identifier}:", "=" * 60]
            for cs in call_sites:
                result.append(f"  Line {cs.line_number}: {cs.callee_name}")
                result.append(f"    Context: {cs.call_context or 'N/A'}")
            return "\n".join(result)
        except Exception as e:
            return f"Error getting callees: {str(e)}"
    
    async def get_caller(self, function_identifier: str) -> str:
        """获取调用该函数的所有父函数。
        
        Parameters:
            function_identifier: 函数标识符
        
        Returns:
            父函数调用列表（markdown格式）
        """
        try:
            call_sites = await self.engine.get_caller(function_identifier)
            if not call_sites:
                return f"No callers found for: {function_identifier}"
            
            result = [f"Callers of {function_identifier}:", "=" * 60]
            for cs in call_sites:
                result.append(f"  From {cs.caller_name} at line {cs.line_number}")
                result.append(f"    Context: {cs.call_context or 'N/A'}")
            return "\n".join(result)
        except Exception as e:
            return f"Error getting callers: {str(e)}"
    
    async def get_xref(self, target: str, target_type: str = "function") -> str:
        """获取目标的交叉引用。
        
        Parameters:
            target: 目标名称或签名
            target_type: 目标类型 (function, variable)
        
        Returns:
            交叉引用列表（markdown格式）
        """
        try:
            xref = await self.engine.get_cross_reference(target_type, target)
            if xref is None or not xref.references:
                return f"No cross-references found for: {target}"
            
            result = [f"Cross-references for {target}:", "=" * 60]
            for ref in xref.references[:20]:
                if isinstance(ref, dict):
                    result.append(f"  [{ref.get('type', 'ref')}] {ref.get('file', 'N/A')}:{ref.get('line', 0)}")
                    result.append(f"    {ref.get('content', 'N/A')}")
                else:
                    result.append("  [ref] N/A:0")
                    result.append(f"    {str(ref)}")
            return "\n".join(result)
        except Exception as e:
            return f"Error getting cross-references: {str(e)}"
    
    async def search_symbol(
        self,
        pattern: str,
        limit: int = 10,
        offset: int = 0,
        case_sensitive: bool = False,
    ) -> str:
        """根据模式搜索符号（函数、类、方法等）。
        
        此工具返回的符号名称是标准格式的函数标识符，可以直接用于：
        - 传递给其他工具（get_function_def, get_callee, get_caller等）
        - 作为漏洞分析的 function_identifier 参数
        - 在最终输出中引用函数
        
        Parameters:
            pattern: 搜索模式（Python 正则表达式）
            limit: 返回结果数量限制
            offset: 结果起始偏移量
            case_sensitive: 是否区分大小写
        
        Returns:
            匹配的符号列表（markdown格式），每个符号包含：
            - 符号类型 [class/method/function]
            - 标准标识符（格式因引擎而异）
              * JEB: Smali格式 Lpackage/Class;->method(Args)Ret
              * IDA/Ghidra: function_name 或 namespace::function_name
              * ABC: package.Class.method
            - 函数签名
            - 文件位置

            注意：[method] 后的完整Smali标识符就是标准格式，必须完整使用。
        """
        try:
            import re
            flags = 0 if case_sensitive else re.IGNORECASE
            try:
                re.compile(pattern, flags)
            except re.error as e:
                return f"Invalid regex pattern: {str(e)}"
            
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
                return f"No symbols found matching: {pattern}"
            
            result = [f"Symbols matching '{pattern}':", "=" * 60]
            for i, sr in enumerate(search_results, offset + 1):
                result.append(f"  #{i} [{sr.symbol_type.value}] {sr.name}")
                result.append(f"    Identifier: {sr.identifier}")
                result.append(f"    File: {sr.file_path or 'N/A'}:{sr.line or 0}")
            return "\n".join(result)
        except Exception as e:
            return f"Error searching symbols: {str(e)}"
    
    # ==========================================================================
    # 完成工具
    # ==========================================================================
    
    def finish_exploration(self, result: str, summary: str) -> str:
        """完成探索并返回markdown格式的文本结果，同时要求提供摘要。
        
        当任务要求返回函数标识符时，必须使用以下结构化格式：
        
        ## 标准输出格式（当查找函数时）
        
        ```markdown
        ## 探索结果
        
        ### 找到的函数
        
        1. **函数标识符**: `com.example.auth.PasswordProvider.query`
           - **签名**: `public String query(String username)`
           - **位置**: src/auth/PasswordProvider.java:25
           - **上下文**: 接收用户输入的用户名，执行数据库查询
           - **外部输入交互特征**: 用户输入参与查询字符串拼接，未见参数化调用证据
        
        2. **函数标识符**: `com.example.http.RequestParser.parse`
           - **签名**: `public Request parse(String rawRequest)`
           - **位置**: src/http/RequestParser.java:45
           - **上下文**: 解析HTTP请求字符串
           - **外部输入交互特征**: 输入长度直接影响解析流程，未见统一长度上限证据
        
        ### 分析摘要
        
        已识别 2 个处理用户输入的函数，已整理参数约束与证据锚点，具体漏洞类型留待 vuln_analysis 阶段判定。
        ```
        
        重要提醒：
        - 函数标识符必须使用 search_symbol 返回的完整标准格式
        - 每个函数必须包含：标识符、签名、位置、上下文
        - code_explorer 结果以事实取证为主，不要在此阶段输出具体漏洞类型结论
        - 使用清晰的 Markdown 结构，便于后续解析
        
        Parameters:
            result: 探索结果描述（markdown格式），包含核心发现、关键证据和相关代码位置
            summary: 精简摘要（markdown纯文本），用于后续上下文选择
        
        Returns:
            格式化后的探索结果文本
        """
        return f"=== 代码探索结果 ===\n\n{result}"

    def mark_compression_projection(
        self,
        remove_message_ids: Optional[List[str]] = None,
        fold_message_ids: Optional[List[str]] = None,
        reason: str = "",
    ) -> str:
        """提交压缩前的消息级裁切清单（按 Message_ID 生效，支持删除与折叠）。"""

        def _normalize_ids(values: Any) -> List[str]:
            if isinstance(values, list):
                raw = values
            elif values is None:
                raw = []
            else:
                raw = [values]
            accepted_ids: List[str] = []
            for item in raw:
                value = str(item or "").strip()
                if value:
                    accepted_ids.append(value)
            return list(dict.fromkeys(accepted_ids))

        accepted_remove = _normalize_ids(remove_message_ids)
        accepted_fold = _normalize_ids(fold_message_ids)
        if accepted_remove and accepted_fold:
            remove_set = set(accepted_remove)
            accepted_fold = [mid for mid in accepted_fold if mid not in remove_set]

        self._pending_projection_remove_message_ids = set(accepted_remove)
        self._pending_projection_fold_message_ids = set(accepted_fold)
        self._pending_projection_reason = str(reason or "").strip()

        lines = [
            "## Compression Projection Marked",
            f"- remove_message_ids_count: {len(accepted_remove)}",
            f"- fold_message_ids_count: {len(accepted_fold)}",
            f"- reason: {self._pending_projection_reason or '无'}",
        ]
        if accepted_remove:
            lines.append("- remove_message_ids:")
            lines.extend([f"  - `{mid}`" for mid in accepted_remove])
        else:
            lines.append("- remove_message_ids: 无")
        if accepted_fold:
            lines.append("- fold_message_ids:")
            lines.extend([f"  - `{mid}`" for mid in accepted_fold])
        else:
            lines.append("- fold_message_ids: 无")
        lines.append("- 说明: 将在触发上下文压缩前应用该清单（删除为精确删除；折叠会保留消息链路并替换为占位文本）。")
        return "\n".join(lines)

    def _canonicalize_tool_args(self, args: Any) -> str:
        payload = {} if args is None else args
        try:
            return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        except TypeError:
            return json.dumps(str(payload), ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    def _tool_cache_key(self, tool_name: str, args: Any) -> str:
        return f"{tool_name}::{self._canonicalize_tool_args(args)}"

    def _should_skip_tool_cache(self, tool_name: str) -> bool:
        return tool_name in {
            "finish_exploration",
            "mark_compression_projection",
        }

    def _lookup_cached_tool_result(self, tool_name: str, args: Any) -> Optional[str]:
        if self._should_skip_tool_cache(tool_name):
            return None
        return self._tool_result_cache.get(self._tool_cache_key(tool_name, args))

    def _remember_tool_result(self, tool_name: str, args: Any, output: str) -> None:
        if self._should_skip_tool_cache(tool_name):
            return
        key = self._tool_cache_key(tool_name, args)
        self._tool_result_cache[key] = output
        if len(self._tool_result_cache) > self._tool_cache_max_entries:
            oldest_key = next(iter(self._tool_result_cache), None)
            if oldest_key is not None:
                self._tool_result_cache.pop(oldest_key, None)

    def _record_tool_trace(
        self,
        tool_name: str,
        args: Any,
        output: str,
        cache_hit: bool,
        tool_call_id: str = "",
    ) -> None:
        text = str(output or "").strip()
        is_error = text.startswith("Error") or text.startswith("[错误]") or "错误" in text[:40]
        dedup_key = self._tool_cache_key(tool_name, args)
        self._tool_execution_trace.append(
            {
                "tool_name": tool_name,
                "tool_call_id": str(tool_call_id or ""),
                "dedup_key": dedup_key,
                "args": self._canonicalize_tool_args(args),
                "cache_hit": cache_hit,
                "is_error": is_error,
                "output_excerpt": text[:2000],
            }
        )
        if len(self._tool_execution_trace) > 600:
            self._tool_execution_trace = self._tool_execution_trace[-600:]

    def _extract_function_identifiers_from_trace(self) -> List[str]:
        identifiers: List[str] = []
        for item in self._tool_execution_trace:
            if item.get("tool_name") != "search_symbol":
                continue
            excerpt = str(item.get("output_excerpt") or "")
            if "Identifier:" not in excerpt:
                continue
            for line in excerpt.splitlines():
                line = line.strip()
                if not line.startswith("Identifier:"):
                    continue
                value = line.split("Identifier:", 1)[1].strip()
                if value:
                    identifiers.append(value)
        return list(dict.fromkeys(identifiers))

    def _extract_unresolved_items(self) -> List[str]:
        unresolved: List[str] = []
        for item in self._tool_execution_trace:
            if item.get("is_error"):
                unresolved.append(
                    f"- 工具调用失败: `{item.get('tool_name')}` args=`{item.get('args')}`，返回=`{item.get('output_excerpt')}`"
                )
        if not unresolved:
            unresolved.append("- 未见明确失败记录，但存在信息覆盖不足，需补充分支与约束取证。")
        return unresolved

    def _build_iteration_limit_handoff_result(self, query: str) -> Dict[str, str]:
        function_ids = self._extract_function_identifiers_from_trace()
        unresolved_items = self._extract_unresolved_items()
        unique_tools = list(
            dict.fromkeys(
                str(item.get("tool_name") or "")
                for item in self._tool_execution_trace
                if item.get("tool_name")
            )
        )
        inferred_lines = [
            "- 已执行工具链: " + (", ".join(unique_tools) if unique_tools else "无"),
            f"- 标准 function_identifier 数量: {len(function_ids)}",
        ]
        for fid in function_ids[:30]:
            inferred_lines.append(f"- `{fid}`")

        pending_tasks = [
            f"- 子任务A（补齐未推断信息）: 基于当前查询 `{query}`，仅针对“未推断信息”逐项取证并输出证据锚点。",
            "- 子任务B（分批探索）: 将目标拆分为更小批次（例如按函数编号区间/调用链阶段）执行新的 CodeExplorer 任务，避免单轮超长探索。",
            "- 子任务C（约束收敛）: 对已枚举函数补齐参数级入参约束与全局变量约束，缺失项必须显式写“未见明确证据”。",
        ]

        result_text = "\n".join(
            [
                "## 分析摘要",
                "本轮探索因达到最大迭代次数限制终止，当前结果为部分完成交接输出。",
                "",
                "## 探索状态",
                "- 部分完成-迭代上限",
                "",
                "## 当前可推断信息",
                *inferred_lines,
                "",
                "## 未推断信息",
                *unresolved_items,
                "",
                "## 需 Orchestrator 继续规划的 CodeExplorer 子任务",
                *pending_tasks,
                "",
                "## 终止说明",
                "- 本轮达到最大迭代次数限制，需 Orchestrator 继续规划新的 CodeExplorer 任务补齐剩余信息。",
            ]
        )

        summary_lines = [
            "## 核心结论",
            "- 本轮探索为部分完成，已输出可复用信息并交接未完成项。",
            "",
            "## 函数标识符",
        ]
        if function_ids:
            summary_lines.extend(f"- `{fid}`" for fid in function_ids[:30])
        else:
            summary_lines.append("- 无")
        summary_lines.extend(
            [
                "",
                "## 关键约束（入参/边界/全局/状态）",
                "- 当前仅保留已执行工具可见约束；其余约束待下一轮 CodeExplorer 补齐。",
                "",
                "## 证据锚点",
                "- 证据来自本轮已执行工具调用与返回片段。",
                "",
                "## 关键调用链",
                "- 待下一轮补齐。",
            ]
        )
        summary_text = "\n".join(summary_lines)
        return {"result": result_text, "summary": summary_text}

    def _ensure_iteration_limit_handoff(
        self,
        result_text: str,
        summary_text: str,
        query: str,
    ) -> Tuple[str, str]:
        fallback = self._build_iteration_limit_handoff_result(query=query)
        merged_result = (result_text or "").strip()
        merged_summary = (summary_text or "").strip()

        required_sections = [
            "## 探索状态",
            "## 当前可推断信息",
            "## 未推断信息",
            "## 需 Orchestrator 继续规划的 CodeExplorer 子任务",
        ]
        if not merged_result:
            merged_result = fallback["result"]
        else:
            missing = [section for section in required_sections if section not in merged_result]
            if missing:
                merged_result = (
                    f"{merged_result}\n\n"
                    "## 探索状态\n"
                    "- 部分完成-迭代上限\n\n"
                    "## 当前可推断信息\n"
                    "- 见上文已收集证据。\n\n"
                    "## 未推断信息\n"
                    "- 仍有信息缺口，需继续取证。\n\n"
                    "## 需 Orchestrator 继续规划的 CodeExplorer 子任务\n"
                    f"- 基于原查询 `{query}` 继续补齐缺口，并输出新增证据锚点。\n"
                )
            if "迭代限制" not in merged_result and "最大迭代次数" not in merged_result:
                merged_result = (
                    f"{merged_result}\n\n"
                    "## 终止说明\n"
                    "- 本轮探索因最大迭代次数限制终止。"
                )

        if not merged_summary:
            merged_summary = fallback["summary"]

        return merged_result, merged_summary
    
    # ==========================================================================
    # 核心探索方法
    # ==========================================================================
    
    async def explore(
        self,
        query: str,
        context: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        执行代码探索
        
        Args:
            query: 自然语言探索需求
            context: 可选上下文
        
        Returns:
            dict: {"output": markdown结果, "summary": 摘要, "error": 可选错误信息}
        """
        self.log(f"Starting exploration for query: {query[:100]}...")
        self._tool_result_cache = {}
        self._tool_execution_trace = []
        self._pending_projection_remove_message_ids = set()
        self._pending_projection_fold_message_ids = set()
        self._pending_projection_reason = ""
        self._runtime_message_ids = {}
        self._runtime_message_seq = 0
        self._projection_last_validation_error = ""
        
        # 更新元数据
        target_function = query[:50] if len(query) <= 50 else query[:50] + "..."
        if isinstance(self._tool_client, ToolBasedLLMClient):
            self._tool_client.log_metadata["target_function"] = target_function
        
        # 记录 Agent 执行日志开始
        agent_log = None
        if self._agent_log_manager:
            agent_log = self._agent_log_manager.log_execution_start(
                agent_id=self.agent_id,
                agent_type="CodeExplorerAgent",
                target_function=target_function,
                metadata={
                    "query": query[:200],
                    "has_context": bool(context),
                    "max_iterations": self.max_iterations,
                }
            )
        
        # 构建消息
        system_prompt = CODE_EXPLORER_SYSTEM_PROMPT
        
        user_prompt = f"""
## 探索需求

{query}

"""
        if context:
            user_prompt += f"""## 上下文信息

{context}

"""
        
        messages = [HumanMessage(content=user_prompt)]
        
        # 准备工具列表
        tools = [
            self.search_code,
            self.read_file,
            self.list_directory,
            self.get_function_def,
            self.get_callee,
            self.get_caller,
            self.get_xref,
            self.search_symbol,
            self.mark_compression_projection,
            self.finish_exploration,
        ]
        
        # 执行 Tool Call 循环
        final_result = None
        
        try:
            for iteration in range(self.max_iterations):
                self.log(f"Iteration {iteration + 1}/{self.max_iterations}")
                
                # 如果是最后一次迭代，注入提示词要求总结
                is_last_iteration = (iteration == self.max_iterations - 1)
                if is_last_iteration:
                    finalize_prompt = """\n\n[系统通知] 已达到最大迭代次数限制。请基于已收集的所有信息，立即调用 finish_exploration 工具提交结果。

要求：
1. 根据已有信息给出最佳探索结果
2. 必须调用 finish_exploration 工具提交结果（包含 result 与 summary）
3. result 必须是 markdown 格式纯文本
4. summary 必须是 markdown 纯文本高保真摘要，并包含章节：
   - ## 核心结论
   - ## 函数标识符
   - ## 关键约束（入参/边界/全局/状态）
   - ## 证据锚点
   - ## 关键调用链
5. 若任务目标是“前置约束/analysis_context”，`result` 中必须给出参数级 `## 入参约束`（逐参数来源/可控性/污点/边界/校验/证据）
6. `## 入参约束` 仅允许函数签名参数；局部变量约束只能写入 `## 证据锚点`
7. 若涉及函数，summary 中必须保留标准 `function_identifier`（search_symbol 原样）
8. 在 result 中说明探索因迭代限制而终止
9. result 必须包含并完整填写以下章节：
   - ## 探索状态（完成 / 部分完成-迭代上限）
   - ## 当前可推断信息
   - ## 未推断信息
   - ## 需 Orchestrator 继续规划的 CodeExplorer 子任务"""
                    messages.append(HumanMessage(content=finalize_prompt))
                
                # 调用 LLM
                result = await self._call_llm_with_tools(
                    messages=messages,
                    tools=tools,
                    system_prompt=system_prompt,
                )
                
                if result is None:
                    final_result = {
                        "output": "",
                        "summary": "",
                        "error": "[探索失败] LLM call failed",
                    }
                    break
                
                # 处理 tool calls
                tool_calls = result.get("tool_calls", [])
                if not tool_calls:
                    content = result.get("content", "")
                    if content:
                        messages.append(AIMessage(content=content))
                        continue
                    else:
                        final_result = {
                            "output": "",
                            "summary": "",
                            "error": "[探索失败] No exploration result generated",
                        }
                        break
                
                # 添加 AI message with tool calls
                tool_calls_data = [{
                    "name": tc["name"],
                    "args": tc["args"],
                    "id": tc.get("id", f"call_{i}")
                } for i, tc in enumerate(tool_calls)]
                messages.append(AIMessage(content=result.get("content", ""), tool_calls=tool_calls_data))
                
                # 执行工具
                for tc in tool_calls:
                    tool_name = tc["name"]
                    args = tc["args"]
                    tool_id = tc.get("id", "unknown")
                    
                    self.log(f"Executing tool: {tool_name}")
                    
                    try:
                        cache_hit = False
                        cached_output = self._lookup_cached_tool_result(tool_name, args)
                        if cached_output is not None:
                            cache_hit = True
                            output = (
                                f"[cache-hit] Reused previous result for {tool_name} with same args.\n\n"
                                f"{cached_output}"
                            )
                        elif tool_name == "search_code":
                            raw_output = self.search_code(**args)
                            self._remember_tool_result(tool_name, args, raw_output)
                            output = raw_output
                        elif tool_name == "read_file":
                            raw_output = self.read_file(**args)
                            self._remember_tool_result(tool_name, args, raw_output)
                            output = raw_output
                        elif tool_name == "list_directory":
                            raw_output = self.list_directory(**args)
                            self._remember_tool_result(tool_name, args, raw_output)
                            output = raw_output
                        elif tool_name == "get_function_def":
                            raw_output = await self.get_function_def(**args)
                            self._remember_tool_result(tool_name, args, raw_output)
                            output = raw_output
                        elif tool_name == "get_callee":
                            raw_output = await self.get_callee(**args)
                            self._remember_tool_result(tool_name, args, raw_output)
                            output = raw_output
                        elif tool_name == "get_caller":
                            raw_output = await self.get_caller(**args)
                            self._remember_tool_result(tool_name, args, raw_output)
                            output = raw_output
                        elif tool_name == "get_xref":
                            raw_output = await self.get_xref(**args)
                            self._remember_tool_result(tool_name, args, raw_output)
                            output = raw_output
                        elif tool_name == "search_symbol":
                            raw_output = await self.search_symbol(**args)
                            self._remember_tool_result(tool_name, args, raw_output)
                            output = raw_output
                        elif tool_name == "mark_compression_projection":
                            output = self.mark_compression_projection(**args)
                        elif tool_name == "finish_exploration":
                            summary = (args.get("summary") or "").strip()
                            result_text = (args.get("result") or "").strip()
                            if is_last_iteration:
                                result_text, summary = self._ensure_iteration_limit_handoff(
                                    result_text=result_text,
                                    summary_text=summary,
                                    query=query,
                                )
                            output = self.finish_exploration(
                                result_text,
                                summary,
                            )
                            if not summary:
                                final_result = {
                                    "output": output,
                                    "summary": "",
                                    "error": "[探索失败] 缺少摘要，无法完成探索",
                                }
                            else:
                                final_result = {
                                    "output": output,
                                    "summary": summary,
                                }
                            self._record_tool_trace(
                                tool_name=tool_name,
                                args=args,
                                output=output,
                                cache_hit=cache_hit,
                                tool_call_id=tool_id,
                            )
                            break
                        else:
                            output = f"Unknown tool: {tool_name}"
                        self._record_tool_trace(
                            tool_name=tool_name,
                            args=args,
                            output=output,
                            cache_hit=cache_hit,
                            tool_call_id=tool_id,
                        )
                    except Exception as e:
                        output = f"Error executing {tool_name}: {str(e)}"
                        self._record_tool_trace(
                            tool_name=tool_name,
                            args=args,
                            output=output,
                            cache_hit=False,
                            tool_call_id=tool_id,
                        )
                    
                    messages.append(
                        ToolMessage(
                            content=str(output),
                            tool_call_id=tool_id,
                            name=tool_name,
                        )
                    )
                
                if final_result:
                    break

                if self.enable_context_compression:
                    messages = await self._maybe_compress_messages(messages)
            
            if final_result is None:
                handoff = self._build_iteration_limit_handoff_result(query=query)
                final_result = {
                    "output": self.finish_exploration(handoff["result"], handoff["summary"]),
                    "summary": handoff["summary"],
                }
        
        except Exception as e:
            final_result = {
                "output": "",
                "summary": "",
                "error": f"[探索失败] Exploration failed: {str(e)}",
            }
        
        # 记录 Agent 执行日志结束
        if self._agent_log_manager and agent_log:
            is_failed = bool(final_result.get("error")) if isinstance(final_result, dict) else True
            status = AgentStatus.FAILED if is_failed else AgentStatus.COMPLETED
            self._agent_log_manager.log_execution_end(
                agent_id=self.agent_id,
                status=status,
                llm_calls=iteration + 1,
                summary=(final_result.get("output") or "")[:200] if isinstance(final_result, dict) else "",
                error_message=final_result.get("error") if isinstance(final_result, dict) and is_failed else None,
            )
        
        return final_result

    async def _maybe_compress_messages(self, messages: List[Any]) -> List[Any]:
        """在需要时压缩上下文消息列表"""
        if (
            not self._context_compressor
            or self.compression_token_threshold <= 0
            or self.compression_max_rounds <= 0
        ):
            return messages

        precompression_reasoning_injected = False
        for _ in range(self.compression_max_rounds):
            agent_messages, _ = self._wrap_messages_for_compression(messages)
            if not agent_messages:
                return messages
            compression_anchors = self._build_compression_anchors(messages)

            estimated_tokens = self._estimate_messages_tokens(agent_messages)
            if estimated_tokens <= self.compression_token_threshold:
                return messages

            if not precompression_reasoning_injected:
                messages = await self._append_precompression_reasoning_turn(messages)
                precompression_reasoning_injected = True
                agent_messages, _ = self._wrap_messages_for_compression(messages)
                if not agent_messages:
                    return messages
                compression_anchors = self._build_compression_anchors(messages)
                estimated_tokens = self._estimate_messages_tokens(agent_messages)
                if estimated_tokens <= self.compression_token_threshold:
                    return messages

            first_system_idx = next((i for i, m in enumerate(messages) if isinstance(m, SystemMessage)), None)
            first_user_idx = next((i for i, m in enumerate(messages) if isinstance(m, HumanMessage)), None)
            preserve_indices: List[int] = []
            if first_system_idx is not None and (
                first_user_idx is None or first_system_idx < first_user_idx
            ):
                preserve_indices.append(first_system_idx)
            if first_user_idx is not None:
                preserve_indices.append(first_user_idx)
            preserve_indices = sorted(set(preserve_indices))
            preserve_set = set(preserve_indices)
            preserve_messages = [messages[i] for i in preserve_indices]
            candidate_messages = [m for i, m in enumerate(messages) if i not in preserve_set]
            if not candidate_messages:
                return messages

            projection_removed = 0
            projection_folded = 0
            if self._pending_projection_remove_message_ids or self._pending_projection_fold_message_ids:
                projection_remove_ids = set(self._pending_projection_remove_message_ids)
                projection_fold_ids = set(self._pending_projection_fold_message_ids)
                if projection_remove_ids and projection_fold_ids:
                    projection_fold_ids = projection_fold_ids - projection_remove_ids
                projection_reason = self._pending_projection_reason
                present_ids = self._collect_message_ids(candidate_messages)
                matched_remove_ids = sorted(projection_remove_ids & present_ids)
                unmatched_remove_ids = sorted(projection_remove_ids - present_ids)
                matched_fold_ids = sorted(projection_fold_ids & present_ids)
                unmatched_fold_ids = sorted(projection_fold_ids - present_ids)
                projection_reject_reason = ""

                if projection_remove_ids:
                    candidate_messages, projection_removed = self._apply_projection_deletions(
                        candidate_messages=candidate_messages,
                        remove_message_ids=projection_remove_ids,
                    )
                    if self._projection_last_validation_error:
                        projection_reject_reason = self._projection_last_validation_error
                        self.log(
                            "Reject LLM compression projection due to invalid tool-call linkage: "
                            f"{projection_reject_reason}",
                            "warning",
                        )
                        self._projection_last_validation_error = ""

                if projection_reject_reason:
                    self._pending_projection_remove_message_ids = set()
                    self._pending_projection_fold_message_ids = set()
                    self._pending_projection_reason = ""
                    messages.append(
                        HumanMessage(
                            content=(
                                "[系统通知] 上一轮 `mark_compression_projection` 裁切清单已被拒绝。\n"
                                f"原因: {projection_reject_reason}\n\n"
                                "请重新提交裁切方案，并确保不会造成 tool call 链断裂：\n"
                                "- 不要删除某个 assistant 的 tool_call 声明但保留其 ToolMessage；\n"
                                "- 不要删除某个 ToolMessage 而保留其对应 assistant tool_call；\n"
                                "- 必须保证每个 assistant tool_call 仍有后续 ToolMessage 返回；\n"
                                "- 对于需要保留链路的长消息，优先使用 `fold_message_ids` 折叠而不是删除。"
                            )
                        )
                    )
                    precompression_reasoning_injected = False
                    continue

                if projection_fold_ids:
                    candidate_messages, projection_folded = self._apply_projection_folding(
                        candidate_messages=candidate_messages,
                        fold_message_ids=projection_fold_ids,
                    )

                self._pending_projection_remove_message_ids = set()
                self._pending_projection_fold_message_ids = set()
                self._pending_projection_reason = ""
                if projection_removed > 0 or projection_folded > 0:
                    self.log(
                        "Applied LLM compression projection: "
                        f"remove={projection_removed}; fold={projection_folded}; "
                        f"matched_remove={len(matched_remove_ids)}; matched_fold={len(matched_fold_ids)}; "
                        f"reason={projection_reason or 'N/A'}"
                    )
                if unmatched_remove_ids or unmatched_fold_ids:
                    preview = unmatched_remove_ids[:8] + unmatched_fold_ids[:8]
                    preview_text = ", ".join(preview)
                    if len(unmatched_remove_ids) + len(unmatched_fold_ids) > 16:
                        preview_text += ", ..."
                    self.log(
                        "LLM compression projection contains unmatched message_ids: "
                        f"{preview_text}",
                        "warning",
                    )
                if not candidate_messages:
                    return preserve_messages

            candidate_agent_messages, id_to_index = self._wrap_messages_for_compression(candidate_messages)
            if not candidate_agent_messages:
                return messages

            head = candidate_agent_messages

            if self._read_artifact_pruner and head:
                prune_result = await self._read_artifact_pruner.prune(head)
                if prune_result.remove_message_ids:
                    head_ids = {m.message_id for m in head}
                    remove_ids = [mid for mid in prune_result.remove_message_ids if mid in head_ids]
                    if remove_ids:
                        remove_indices = {
                            id_to_index[mid] for mid in remove_ids if mid in id_to_index
                        }
                        if remove_indices:
                            pruned_candidate_messages = [
                                msg for idx, msg in enumerate(candidate_messages) if idx not in remove_indices
                            ]
                            valid, reason = self._validate_tool_call_linkage(pruned_candidate_messages)
                            if not valid:
                                self.log(
                                    "Reject read_artifact_pruner removals due to invalid tool-call linkage: "
                                    f"{reason}",
                                    "warning",
                                )
                            else:
                                candidate_messages = pruned_candidate_messages
                                candidate_agent_messages, id_to_index = self._wrap_messages_for_compression(candidate_messages)
                                if not candidate_agent_messages:
                                    return preserve_messages
                                head = candidate_agent_messages

            # 优先采用“LLM 裁切即生效”策略：若裁切后已回到阈值内，直接返回，不再进入 context_compressor。
            projected_messages = preserve_messages + candidate_messages
            projected_agent_messages, _ = self._wrap_messages_for_compression(projected_messages)
            projected_tokens = self._estimate_messages_tokens(projected_agent_messages) if projected_agent_messages else 0
            if projected_tokens <= self.compression_token_threshold:
                self.log(
                    "Projection-only context trimming succeeded; "
                    f"tokens={projected_tokens}, threshold={self.compression_token_threshold}. "
                    "Skip context compressor."
                )
                return projected_messages

            result = await self._context_compressor.compress(
                head,
                anchors=compression_anchors,
                compression_profile="code_explorer",
                consumer_agent="code_explorer",
                purpose="code exploration continuity",
            )
            if not result.summary:
                return messages

            compressed_parts = [f"【上下文压缩摘要】\n{result.summary}"]
            if projection_removed > 0 or projection_folded > 0:
                compressed_parts.append(
                    "\n".join(
                        [
                            "【压缩执行统计】",
                            f"- projection 删除消息数: {projection_removed}",
                            f"- projection 折叠消息数: {projection_folded}",
                        ]
                    )
                )
            tool_memory_block = (result.tool_memory_block or "").strip()
            if tool_memory_block:
                compressed_parts.append(tool_memory_block)
            compressed_message = AIMessage(content="\n\n".join(compressed_parts))
            messages = preserve_messages + [compressed_message]

        return messages

    async def _append_precompression_reasoning_turn(self, messages: List[Any]) -> List[Any]:
        """
        在原始 Agent 对话中追加“压缩前推理”消息并执行相关 tool call。
        """
        message_index = self._build_projection_message_index(messages)
        prompt = """[系统通知] 即将触发上下文压缩。
请基于当前会话中已收集的信息进行压缩前推理，输出 markdown 纯文本，必须包含以下章节：
- `## 与当前分析目标匹配的语义理解蒸馏`
- `### 中间结论`
- `### 是否需要继续获取信息`（填写：是/否）
- `### 最小补充信息集`
- `## LLM 驱动裁切上下文`

你现在可直接按消息ID提交裁切清单（每条消息首行都有 `消息ID: Message_xxx`）：
1. 必须调用 `mark_compression_projection(remove_message_ids=[...], fold_message_ids=[...], reason=...)` 提交结果；
2. 若当前不删任何条目，也必须调用 `mark_compression_projection(remove_message_ids=[], fold_message_ids=[], reason=\"无可安全删除条目\")`。

约束：
- 仅基于现有证据推理，不得编造；
- 优先最小补证集，禁止回退到全量重复取证。
- 系统只会精确删除 `remove_message_ids` 中列出的消息，不会隐式级联删除未列出的消息。
- `fold_message_ids` 会将消息内容替换为“内容已经折叠，信息如需要请重新获取。”，并保留链路结构。
- 提交删除清单时必须规避 tool call 链断裂：
  - 不能删除 assistant 的 tool_call 声明却保留对应 ToolMessage；
  - 不能删除 ToolMessage 却保留对应 assistant tool_call；
  - 每个 assistant tool_call 在删除后仍必须有后续 ToolMessage 返回。
- 优先删除“可单独删除=是”的消息；“可单独删除=否”的消息必须按依赖提示成对处理。
- 对于“可单独删除=否”的长消息，优先使用 `fold_message_ids` 折叠。

## 当前消息索引（可直接引用 message_id）
""" + message_index

        updated = list(messages)
        updated.append(HumanMessage(content=prompt))
        has_mark_projection = False
        max_rounds = 3
        for _ in range(max_rounds):
            llm_messages = self._build_messages_with_message_ids(updated)
            result = await self._call_llm_with_tools(
                messages=llm_messages,
                tools=[self.mark_compression_projection],
                system_prompt=CODE_EXPLORER_SYSTEM_PROMPT,
            )
            if result is None:
                break

            tool_calls = result.get("tool_calls", []) or []
            content = result.get("content", "") or ""
            if tool_calls:
                tool_calls_data = [{
                    "name": tc["name"],
                    "args": tc["args"],
                    "id": tc.get("id", f"compress_reasoning_{i}"),
                } for i, tc in enumerate(tool_calls)]
                updated.append(AIMessage(content=content, tool_calls=tool_calls_data))
            elif content.strip():
                updated.append(AIMessage(content=content))
                break
            else:
                break

            for tc in tool_calls:
                tool_name = tc.get("name", "")
                args = tc.get("args", {})
                tool_id = tc.get("id", "unknown")
                try:
                    if tool_name == "mark_compression_projection":
                        has_mark_projection = True
                        output = self.mark_compression_projection(**args)
                    else:
                        output = f"Unknown tool in precompression reasoning: {tool_name}"
                    self._record_tool_trace(
                        tool_name=tool_name,
                        args=args,
                        output=output,
                        cache_hit=False,
                        tool_call_id=tool_id,
                    )
                except Exception as e:
                    output = f"Error executing {tool_name}: {str(e)}"
                    self._record_tool_trace(
                        tool_name=tool_name,
                        args=args,
                        output=output,
                        cache_hit=False,
                        tool_call_id=tool_id,
                    )

                updated.append(
                    ToolMessage(
                        content=str(output),
                        tool_call_id=tool_id,
                        name=tool_name,
                    )
                )

            if has_mark_projection:
                # 已完成裁切清单提交，结束压缩前推理回合
                break

        if not has_mark_projection:
            # 不再使用空清单兜底提交；改为强制 LLM 结束压缩前推理并输出最终文本。
            force_finalize_prompt = (
                "[系统通知] 你尚未完成压缩前推理的最终回复。"
                "现在必须停止所有 tool call，仅输出 markdown 纯文本最终回复。"
                "禁止再调用任何工具。"
                "输出需包含：\n"
                "- `## 与当前分析目标匹配的语义理解蒸馏`\n"
                "- `### 中间结论`\n"
                "- `### 是否需要继续获取信息`\n"
                "- `### 最小补充信息集`\n"
                "- `## LLM 驱动裁切上下文`\n"
                "若未形成可执行裁切清单，在“LLM 驱动裁切上下文”中明确写“无可安全删除条目（未提交裁切清单）”。"
            )
            updated.append(HumanMessage(content=force_finalize_prompt))
            llm_messages = self._build_messages_with_message_ids(updated)
            force_result = await self._call_llm_with_tools(
                messages=llm_messages,
                tools=[],
                system_prompt=CODE_EXPLORER_SYSTEM_PROMPT,
            )
            if force_result:
                force_content = str(force_result.get("content", "") or "").strip()
                if force_content:
                    updated.append(AIMessage(content=force_content))

        return updated

    def _allocate_runtime_message_id(self) -> str:
        self._runtime_message_seq += 1
        return f"Message_{self._runtime_message_seq:06d}"

    def _ensure_runtime_message_id(self, msg: Any) -> str:
        key = id(msg)
        current = self._runtime_message_ids.get(key)
        if current:
            return current
        message_id = self._allocate_runtime_message_id()
        self._runtime_message_ids[key] = message_id
        return message_id

    def _with_message_id_prefix(self, content: Any, message_id: str) -> str:
        prefix = f"消息ID: {message_id}"
        text = str(content or "")
        if text.startswith(prefix):
            return text
        if text.startswith("消息ID: Message_"):
            lines = text.splitlines()
            if lines:
                lines[0] = prefix
                return "\n".join(lines)
        if not text:
            return prefix
        return f"{prefix}\n{text}"

    def _clone_message_with_id_prefix(self, msg: Any) -> Any:
        message_id = self._ensure_runtime_message_id(msg)
        content = self._with_message_id_prefix(getattr(msg, "content", ""), message_id)
        if isinstance(msg, SystemMessage):
            return SystemMessage(content=content)
        if isinstance(msg, HumanMessage):
            return HumanMessage(content=content)
        if isinstance(msg, ToolMessage):
            return ToolMessage(
                content=content,
                tool_call_id=getattr(msg, "tool_call_id", ""),
                name=getattr(msg, "name", ""),
            )
        if isinstance(msg, AIMessage):
            tool_calls = getattr(msg, "tool_calls", None)
            copied_tool_calls: Optional[List[Any]] = None
            if isinstance(tool_calls, list):
                copied_tool_calls = []
                for tc in tool_calls:
                    copied_tool_calls.append(dict(tc) if isinstance(tc, dict) else tc)
            if copied_tool_calls is not None:
                return AIMessage(content=content, tool_calls=copied_tool_calls)
            return AIMessage(content=content)
        return HumanMessage(content=content)

    def _build_messages_with_message_ids(self, messages: List[Any]) -> List[Any]:
        return [self._clone_message_with_id_prefix(msg) for msg in messages]

    def _message_role_name(self, msg: Any) -> str:
        if isinstance(msg, SystemMessage):
            return "system"
        if isinstance(msg, HumanMessage):
            return "user"
        if isinstance(msg, ToolMessage):
            return "tool"
        return "assistant"

    def _message_index_excerpt(self, msg: Any, limit: int = 80) -> str:
        text = str(getattr(msg, "content", "") or "").strip().replace("\n", " ")
        if text.startswith("消息ID: Message_"):
            lines = text.splitlines()
            text = " ".join(lines[1:]).strip()
        if not text:
            if isinstance(msg, AIMessage) and getattr(msg, "tool_calls", None):
                return "assistant tool_calls"
            if isinstance(msg, ToolMessage):
                return f"tool `{getattr(msg, 'name', '') or 'unknown'}` output"
            return "empty"
        if len(text) <= limit:
            return text
        return text[: limit - 3] + "..."

    def _build_projection_message_index(self, messages: List[Any]) -> str:
        if not messages:
            return "无"
        dependency_notes = self._build_projection_dependency_notes(messages)
        lines = [
            "| message_id | role | 可单独删除 | 依赖提示 | 摘要 |",
            "|------------|------|------------|----------|------|",
        ]
        for msg in messages:
            message_id = self._ensure_runtime_message_id(msg)
            role = self._message_role_name(msg)
            deletable, dependency_hint = dependency_notes.get(message_id, ("是", "-"))
            excerpt = self._message_index_excerpt(msg)
            escaped_dependency = str(dependency_hint).replace("|", "\\|")
            escaped_excerpt = excerpt.replace("|", "\\|")
            lines.append(
                f"| `{message_id}` | `{role}` | {deletable} | {escaped_dependency} | {escaped_excerpt} |"
            )
        return "\n".join(lines)

    def _build_projection_dependency_notes(self, messages: List[Any]) -> Dict[str, Tuple[str, str]]:
        notes: Dict[str, Tuple[str, str]] = {}
        call_to_assistant: Dict[str, str] = {}
        call_to_tools: Dict[str, List[str]] = {}

        for msg in messages:
            message_id = self._ensure_runtime_message_id(msg)
            if isinstance(msg, AIMessage):
                tool_calls = getattr(msg, "tool_calls", None)
                if isinstance(tool_calls, list) and tool_calls:
                    for tc in tool_calls:
                        if not isinstance(tc, dict):
                            continue
                        call_id = str(tc.get("id") or "").strip()
                        if call_id:
                            call_to_assistant[call_id] = message_id
            elif isinstance(msg, ToolMessage):
                call_id = str(getattr(msg, "tool_call_id", "") or "").strip()
                if call_id:
                    call_to_tools.setdefault(call_id, []).append(message_id)

        for call_id, assistant_mid in call_to_assistant.items():
            tool_mids = call_to_tools.get(call_id) or []
            if tool_mids:
                tool_list = ", ".join(f"`{mid}`" for mid in tool_mids[:6])
                if len(tool_mids) > 6:
                    tool_list += ", ..."
                notes[assistant_mid] = ("否", f"含 tool_call；推荐折叠，若删除需同时删除 {tool_list}")
                for tool_mid in tool_mids:
                    notes[tool_mid] = ("否", f"Tool 返回；推荐折叠，删除需与 `{assistant_mid}` 成对处理")
            else:
                notes[assistant_mid] = ("否", "含 tool_call；当前无对应 Tool 返回，禁止单删")

        for call_id, tool_mids in call_to_tools.items():
            if call_id not in call_to_assistant:
                for tool_mid in tool_mids:
                    notes[tool_mid] = ("否", "孤立 Tool 返回，禁止单删")

        return notes

    def _build_compression_anchors(self, messages: List[Any]) -> Dict[str, str]:
        """
        从当前会话消息中提取压缩目标锚点。
        """
        anchors: Dict[str, str] = {}
        first_system = next(
            (
                str(msg.content or "").strip()
                for msg in messages
                if isinstance(msg, SystemMessage) and str(msg.content or "").strip()
            ),
            "",
        )
        first_user_goal = next(
            (
                str(msg.content or "").strip()
                for msg in messages
                if isinstance(msg, HumanMessage) and str(msg.content or "").strip()
            ),
            "",
        )

        if first_system:
            anchors["system_prompt"] = first_system
        if first_user_goal:
            anchors["first_user_goal"] = first_user_goal
        return anchors

    def _apply_projection_deletions(
        self,
        candidate_messages: List[Any],
        remove_message_ids: Set[str],
    ) -> Tuple[List[Any], int]:
        """
        对压缩候选消息应用 LLM 提交的预删除清单。

        删除规则：
        - 按 message_id 精确删除（不会隐式级联删除其他消息）。
        """
        if not candidate_messages or not remove_message_ids:
            return candidate_messages, 0

        explicit_remove_ids = set(remove_message_ids)
        pruned: List[Any] = []
        effects = 0
        for msg in candidate_messages:
            message_id = self._ensure_runtime_message_id(msg)
            if message_id in explicit_remove_ids:
                effects += 1
                continue
            pruned.append(msg)
        valid, reason = self._validate_tool_call_linkage(pruned)
        if not valid:
            self._projection_last_validation_error = reason
            return candidate_messages, 0
        return pruned, effects

    def _apply_projection_folding(
        self,
        candidate_messages: List[Any],
        fold_message_ids: Set[str],
    ) -> Tuple[List[Any], int]:
        """
        对压缩候选消息应用折叠清单：保留消息链路，仅替换正文内容。
        """
        if not candidate_messages or not fold_message_ids:
            return candidate_messages, 0

        folded_messages: List[Any] = []
        effects = 0
        for msg in candidate_messages:
            message_id = self._ensure_runtime_message_id(msg)
            if message_id not in fold_message_ids:
                folded_messages.append(msg)
                continue
            folded = self._clone_with_folded_content(msg, message_id)
            folded_messages.append(folded)
            effects += 1
        return folded_messages, effects

    def _clone_with_folded_content(self, msg: Any, message_id: str) -> Any:
        folded_content = "内容已经折叠，信息如需要请重新获取。"
        if isinstance(msg, ToolMessage):
            cloned = ToolMessage(
                content=folded_content,
                tool_call_id=str(getattr(msg, "tool_call_id", "") or "unknown"),
                name=getattr(msg, "name", None),
            )
        elif isinstance(msg, AIMessage):
            tool_calls = getattr(msg, "tool_calls", None)
            if isinstance(tool_calls, list):
                cloned = AIMessage(content=folded_content, tool_calls=tool_calls)
            else:
                cloned = AIMessage(content=folded_content)
        elif isinstance(msg, HumanMessage):
            cloned = HumanMessage(content=folded_content)
        elif isinstance(msg, SystemMessage):
            cloned = SystemMessage(content=folded_content)
        else:
            cloned = msg
        self._runtime_message_ids[id(cloned)] = message_id
        return cloned

    def _validate_tool_call_linkage(self, messages: List[Any]) -> Tuple[bool, str]:
        """
        校验消息序列中的 tool_call 关联完整性，避免发送给 API 的历史上下文断链。
        """
        call_to_assistant: Dict[str, Tuple[int, str]] = {}
        call_to_tool_items: Dict[str, List[Tuple[int, str]]] = {}

        for idx, msg in enumerate(messages):
            message_id = self._ensure_runtime_message_id(msg)
            if isinstance(msg, AIMessage):
                tool_calls = getattr(msg, "tool_calls", None)
                if not isinstance(tool_calls, list):
                    continue
                for tc in tool_calls:
                    if not isinstance(tc, dict):
                        continue
                    call_id = str(tc.get("id") or "").strip()
                    if call_id:
                        call_to_assistant[call_id] = (idx, message_id)
            elif isinstance(msg, ToolMessage):
                call_id = str(getattr(msg, "tool_call_id", "") or "").strip()
                if not call_id:
                    continue
                call_to_tool_items.setdefault(call_id, []).append((idx, message_id))

        # 1) ToolMessage 必须能关联到先前 assistant tool_call
        for call_id, tool_items in call_to_tool_items.items():
            assistant_item = call_to_assistant.get(call_id)
            tool_message_ids = [mid for _, mid in tool_items]
            if assistant_item is None:
                return False, (
                    f"orphan tool_message call_id={call_id}; "
                    f"tool_message_ids={','.join(tool_message_ids)}"
                )
            assistant_idx, assistant_message_id = assistant_item
            if any(tidx <= assistant_idx for tidx, _ in tool_items):
                return False, (
                    f"tool_message before assistant tool_call call_id={call_id}; "
                    f"assistant_message_id={assistant_message_id}; "
                    f"tool_message_ids={','.join(tool_message_ids)}"
                )

        # 2) assistant tool_call 必须存在至少一个后续 ToolMessage 返回
        for call_id, assistant_item in call_to_assistant.items():
            assistant_idx, assistant_message_id = assistant_item
            tool_items = call_to_tool_items.get(call_id) or []
            if not any(tidx > assistant_idx for tidx, _ in tool_items):
                return False, (
                    f"missing tool_message for assistant tool_call call_id={call_id}; "
                    f"assistant_message_id={assistant_message_id}"
                )

        return True, ""

    def _collect_message_ids(self, messages: List[Any]) -> Set[str]:
        return {self._ensure_runtime_message_id(msg) for msg in messages}

    def _wrap_messages_for_compression(
        self,
        messages: List[Any],
    ) -> Tuple[List[AgentMessage], Dict[str, int]]:
        agent_messages: List[AgentMessage] = []
        id_to_index: Dict[str, int] = {}
        for idx, msg in enumerate(messages):
            role = "assistant"
            if isinstance(msg, SystemMessage):
                role = "system"
            elif isinstance(msg, HumanMessage):
                role = "user"
            elif isinstance(msg, ToolMessage):
                role = "tool"

            metadata: Dict[str, Any] = {}
            if role == "assistant" and getattr(msg, "tool_calls", None):
                metadata["tool_calls"] = msg.tool_calls
            if role == "tool":
                if getattr(msg, "name", None):
                    metadata["tool_name"] = msg.name
                if getattr(msg, "tool_call_id", None):
                    metadata["tool_call_id"] = msg.tool_call_id

            message_id = self._ensure_runtime_message_id(msg)
            id_to_index[message_id] = idx
            agent_messages.append(
                AgentMessage(
                    message_id=message_id,
                    role=role,
                    content_display=msg.content or "",
                    content_full=msg.content or "",
                    created_at=time.time(),
                    artifacts=[],
                    metadata=metadata,
                )
            )
        return agent_messages, id_to_index

    def _split_for_compression(
        self,
        messages: List[AgentMessage],
    ) -> Tuple[List[AgentMessage], List[AgentMessage]]:
        last_tool_call_idx = None
        last_user_idx = None

        for idx, msg in enumerate(messages):
            if msg.role == "user":
                last_user_idx = idx
            if msg.role == "assistant" and msg.metadata.get("tool_calls"):
                last_tool_call_idx = idx

        if last_tool_call_idx is not None:
            prev_user_idx = None
            for idx in range(last_tool_call_idx - 1, -1, -1):
                if messages[idx].role == "user":
                    prev_user_idx = idx
                    break
            tail_start = prev_user_idx if prev_user_idx is not None else last_tool_call_idx
        elif last_user_idx is not None:
            tail_start = last_user_idx
        else:
            tail_start = max(0, len(messages) - 1)

        head = messages[:tail_start]
        tail = messages[tail_start:]
        return head, tail

    def _estimate_messages_tokens(self, messages: List[AgentMessage]) -> int:
        total = 0
        for msg in messages:
            total += self._estimate_message_tokens(msg)
        return total

    def _estimate_message_tokens(self, msg: AgentMessage) -> int:
        content = msg.content_display or ""
        if msg.metadata.get("tool_calls"):
            content += "\n" + json.dumps(msg.metadata.get("tool_calls"), ensure_ascii=False)
        return self._estimate_tokens(content)

    def _estimate_tokens(self, text: str) -> int:
        # 粗略估算：1 token ≈ 4 字符
        return max(1, len(text) // 4) if text else 0
    
    async def _call_llm_with_tools(
        self,
        messages: List[Any],
        tools: List[Any],
        system_prompt: str,
    ) -> Optional[Dict[str, Any]]:
        """调用 LLM 并处理 Tool Call"""
        try:
            result = await self._tool_client.atool_call(
                messages=messages,
                tools=tools,
                system_prompt=system_prompt,
            )
            
            if not result.success:
                return None
            
            if result.tool_calls:
                for tc in result.tool_calls:
                    if tc["name"] == "finish_exploration":
                        return {
                            "is_finished": True,
                            "data": tc["args"],
                            "tool_calls": result.tool_calls,
                        }
                return {
                    "is_finished": False,
                    "tool_calls": result.tool_calls,
                    "content": result.content,
                }
            else:
                return {
                    "is_finished": False,
                    "tool_calls": [],
                    "content": result.content,
                }
        
        except Exception as e:
            self.log(f"LLM call failed: {e}", "ERROR")
            return None
    
    async def run(self, **kwargs) -> dict:
        """实现 BaseAgent 的抽象方法"""
        query = kwargs.get("query", "")
        context = kwargs.get("context")
        
        return await self.explore(query=query, context=context)
