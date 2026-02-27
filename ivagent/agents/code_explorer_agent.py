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
from typing import Dict, List, Optional, Any, Tuple
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
  - `## 风险操作与证据锚点`
  - `## 关键调用链`
  - `## 未知项与待验证`
- 当任务涉及函数枚举/函数标识符时，`result` 与 `summary` 都必须优先保留 `search_symbol` 返回的标准 `function_identifier`（原样），不要仅保留 `typeN @0x...` 这类弱标识
- 当用户要求“入参约束/全局约束/风险点”时，必须新增章节：
  - `## 目标函数约束清单`
  - 每个函数包含：function_identifier（search_symbol 标准格式）、入参约束、全局约束、风险点（纯文本）
- 当输出将用于 `vuln_analysis` 规划时，额外提供 `## 可直接写入 analysis_context` 章节，按固定标题组织：
  - `## 目标函数`
  - `## 攻击者可控性`
  - `## 输入与边界约束`
  - `## 全局/状态/认证约束`
  - `## 风险操作与漏洞假设`
  - `## 可利用性前提`
  - `## 证据锚点`
  - `## 未知项与待验证`
- **函数标识符规范**：当返回函数信息时，必须使用 `search_symbol` 工具返回的标准函数标识符
  - 标准格式示例：
    * IDA/Ghidra: `function_name` 或 `namespace::function_name`
    * JEB (Java/Android): `Lcom/example/ClassName;->methodName(Ljava/lang/String;)V` (完整Smali格式)
    * ABC (HarmonyOS): `com.example.ClassName.methodName` 或 `ClassName.methodName`
  - ❌ 错误：使用简化名称如 `ClassName.method` (JEB场景)
  - ✅ 正确：使用 `search_symbol` 返回的完整标识符
- 只输出和用户需求相关的内容

## 上下文摘要定义（关键）
当用户要求“入参约束/全局约束/风险点”时，你需要输出**上下文摘要**，用于后续漏洞分析任务。
上下文摘要的核心是**攻击者可控性与约束建模**，必须覆盖：
- 输入来源与可控性：参数/字段是否来自外部输入（网络/文件/IPC/用户交互），哪些参数/字段/指针/对象成员可直接或间接受控
- 入参约束：长度/计数/索引等由谁决定，是否有校验或状态机约束，是否与上层 header/上下文绑定
- 全局约束：全局变量/对象状态/缓冲区大小/配置限制等
- 风险点：基于代码证据的潜在问题与可触发路径

### 通用示例（不要照搬真实测试用例）
示例 1（长度字段影响拷贝）：
```c
void handle(const uint8_t *payload, size_t payload_len) {
    uint32_t n = *(uint32_t*)payload;
    memcpy(dst, payload + 4, n);
}
```
对应摘要示例：
- 入参约束：`payload` 来自外部消息体，`payload_len` 由上层解包提供；`n` 来自 payload，可控；`payload_len` 可能受 header 限制
- 全局约束：`dst` 为固定大小缓冲
- 风险点：使用可控 `n` 进行拷贝，可能越界

示例 2（结构体指针与计数循环）：
```c
typedef struct { uint32_t count; Item *items; } Req;
for (i = 0; i < req->count; i++) { use(req->items[i]); }
```
对应摘要示例：
- 入参约束：`req` 来自外部输入解析；`count` 可控；`items` 可能指向 payload 内部偏移
- 全局约束：未见全局变量约束或固定容量限制的证据
- 风险点：未校验 `count/items` 会导致越界访问

示例 3（字符串指针使用）：
```c
char *path = (char*)payload + offset;
fopen(path, "r");
```
对应摘要示例：
- 入参约束：`payload` 来自外部输入；`offset` 可控或半可控，`path` 内容可控
- 全局约束：未见路径长度/终止符约束的证据
- 风险点：路径注入、越界读取、NUL 终止缺失

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

### 3. 迭代分析
- 收集代码信息后，进行分析和推理
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
   search_symbol 返回的格式因引擎而异：
   
   **JEB (Java/Android) - Smali 格式**:
   ```
   #1 [method] Lcom/zin/dvac/PasswordProvider;->query(Ljava/lang/String;)Ljava/lang/String;
     Signature: public String query(String username)
     File: com/zin/dvac/PasswordProvider.java:25
   ```
   标准标识符（完整Smali格式）: 
   `Lcom/zin/dvac/PasswordProvider;->query(Ljava/lang/String;)Ljava/lang/String;`
   
   **IDA/Ghidra (C/C++)**:
   ```
   #1 [function] sub_401000
     Signature: int sub_401000(char* buffer, int size)
     File: main.c:150
   ```
   标准标识符: `sub_401000`
   
   **ABC (HarmonyOS/ArkTS)**:
   ```
   #1 [method] com.example.auth.PasswordProvider.query
     Signature: query(username: string): string
     File: PasswordProvider.ets:25
   ```
   标识符: `com.example.auth.PasswordProvider.query`

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
- **多个匹配结果**：如果 search_symbol 返回多个结果，使用 get_function_def 或 read_file 确认哪个是目标
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
            )
            self._read_artifact_pruner = ReadArtifactPruner()
        
        self.log(f"CodeExplorerAgent initialized (agent_id={self.agent_id})")
    
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
                f"identifier: {func_def.signature}",
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
                result.append(f"  [{ref.get('type', 'ref')}] {ref.get('file', 'N/A')}:{ref.get('line', 0)}")
                result.append(f"    {ref.get('content', 'N/A')}")
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
            
        示例输出 (JEB):
            Symbols matching 'PasswordProvider':
            ============================================================
              #1 [class] Lcom/example/auth/PasswordProvider;
                Signature: public class PasswordProvider
                File: com/example/auth/PasswordProvider.java:10
              #2 [method] Lcom/example/auth/PasswordProvider;->query(Ljava/lang/String;)Ljava/lang/String;
                Signature: public String query(String username)
                File: com/example/auth/PasswordProvider.java:25
            
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
                result.append(f"    Signature: {sr.signature}")
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
           - **关键发现**: 使用字符串拼接构造SQL，存在注入风险
        
        2. **函数标识符**: `com.example.http.RequestParser.parse`
           - **签名**: `public Request parse(String rawRequest)`
           - **位置**: src/http/RequestParser.java:45
           - **上下文**: 解析HTTP请求字符串
           - **关键发现**: 未对请求长度做限制
        
        ### 分析摘要
        
        发现2个处理用户输入的函数，都存在潜在的安全风险...
        ```
        
        重要提醒：
        - 函数标识符必须使用 search_symbol 返回的完整标准格式
        - 每个函数必须包含：标识符、签名、位置、上下文
        - 使用清晰的 Markdown 结构，便于后续解析
        
        Parameters:
            result: 探索结果描述（markdown格式），包含核心发现、关键证据和相关代码位置
            summary: 精简摘要（markdown纯文本），用于后续上下文选择
        
        Returns:
            格式化后的探索结果文本
        """
        return f"=== 代码探索结果 ===\n\n{result}"
    
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
   - ## 风险操作与证据锚点
   - ## 关键调用链
   - ## 未知项与待验证
5. 若涉及函数，summary 中必须保留标准 `function_identifier`（search_symbol 原样）
6. 在 result 中说明探索因迭代限制而终止"""
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
                        if tool_name == "search_code":
                            output = self.search_code(**args)
                        elif tool_name == "read_file":
                            output = self.read_file(**args)
                        elif tool_name == "list_directory":
                            output = self.list_directory(**args)
                        elif tool_name == "get_function_def":
                            output = await self.get_function_def(**args)
                        elif tool_name == "get_callee":
                            output = await self.get_callee(**args)
                        elif tool_name == "get_caller":
                            output = await self.get_caller(**args)
                        elif tool_name == "get_xref":
                            output = await self.get_xref(**args)
                        elif tool_name == "search_symbol":
                            output = await self.search_symbol(**args)
                        elif tool_name == "finish_exploration":
                            summary = (args.get("summary") or "").strip()
                            output = self.finish_exploration(
                                args.get("result", ""),
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
                            break
                        else:
                            output = f"Unknown tool: {tool_name}"
                    except Exception as e:
                        output = f"Error executing {tool_name}: {str(e)}"
                    
                    messages.append(ToolMessage(content=str(output), tool_call_id=tool_id))
                
                if final_result:
                    break

                if self.enable_context_compression:
                    messages = await self._maybe_compress_messages(messages)
            
            if final_result is None:
                final_result = {
                    "output": "",
                    "summary": "",
                    "error": f"[探索失败] 达到最大迭代次数({self.max_iterations})但未获得有效结果",
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

        for _ in range(self.compression_max_rounds):
            agent_messages, _ = self._wrap_messages_for_compression(messages)
            if not agent_messages:
                return messages

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
                            candidate_messages = [
                                msg for idx, msg in enumerate(candidate_messages) if idx not in remove_indices
                            ]
                            candidate_agent_messages, id_to_index = self._wrap_messages_for_compression(candidate_messages)
                            if not candidate_agent_messages:
                                return preserve_messages
                            head = candidate_agent_messages

            result = await self._context_compressor.compress(head)
            if not result.summary:
                return messages

            compressed_message = AIMessage(content=f"【上下文压缩摘要】\n{result.summary}")
            messages = preserve_messages + [compressed_message]

        return messages

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

            message_id = f"msg_{idx}"
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
