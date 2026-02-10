# IVAgent 用户使用手册

## 目录

1. [快速开始](#1-快速开始)
2. [命令行使用](#2-命令行使用)
3. [前置条件配置](#3-前置条件配置)
4. [引擎使用指南](#4-引擎使用指南)
5. [日志可视化](#5-日志可视化)
6. [Python API 使用](#6-python-api-使用)
7. [常见问题](#7-常见问题)

---

## 1. 快速开始

### 1.1 环境准备

**系统要求：**
- Python 3.10 或更高版本
- 4GB+ 可用内存
- 稳定的网络连接（用于 LLM API）

**安装依赖：**

```bash
# 创建虚拟环境（推荐）
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 或 venv\Scripts\activate  # Windows

# 安装依赖
pip install -r requirements.txt
```

**配置环境变量：**

```bash
# 设置 LLM API 配置
export OPENAI_API_KEY="your-api-key"
export OPENAI_BASE_URL="https://api.openai.com/v1"  # 或其他兼容服务
export OPENAI_MODEL="gpt-4"
```

### 1.2 第一个扫描

以 IDA 引擎为例：

```bash
# 1. 启动 IDA RPC 服务
python start_ida_rpc.py --ida-path "/path/to/ida" --idb "/path/to/target.idb"

# 2. 运行扫描
python ivagent_scan.py \
    --engine ida \
    --target /path/to/target.idb \
    --function "0x140001000" \
    --preset binary \
    --api-key $OPENAI_API_KEY
```

---

## 2. 命令行使用

### 2.1 命令行参数

```bash
python ivagent_scan.py --help
```

**主要参数：**

| 参数 | 简写 | 说明 | 示例 |
|------|------|------|------|
| `--engine` | `-e` | 分析引擎类型 | `ida`, `jeb`, `abc`, `source` |
| `--target` | `-t` | 目标文件路径 | `/path/to/binary.idb` |
| `--function` | `-f` | 要分析的函数 | `0x140001000` 或函数签名 |
| `--preset` | `-P` | 使用预置配置 | `binary`, `android`, `harmony` |
| `--config` | `-C` | 自定义配置文件 | `/path/to/config.md` |
| `--concurrency` | `-c` | 最大并发数 | 默认 10 |
| `--output` | `-o` | 输出结果文件 | `/path/to/results.json` |
| `--api-key` | - | LLM API Key | 或从环境变量读取 |
| `--base-url` | - | LLM Base URL | - |
| `--model` | - | LLM 模型名称 | `gpt-4`, `gpt-3.5-turbo` |

### 2.2 使用示例

#### 分析单个函数

```bash
python ivagent_scan.py \
    --engine ida \
    --target /path/to/program.idb \
    --function "sub_140001000" \
    --preset binary \
    --output result.json
```

#### 批量分析多个函数

```bash
python ivagent_scan.py \
    --engine ida \
    --target /path/to/program.idb \
    --function "0x140001000" "0x140002000" "0x140003000" \
    --concurrency 5 \
    --preset binary \
    --output results.json
```

#### 使用 JEB 分析 Android APK

```bash
python ivagent_scan.py \
    --engine jeb \
    --target /path/to/app.apk \
    --function "Lcom/example/MainActivity;->onCreate(Landroid/os/Bundle;)V" \
    --preset android \
    --host 127.0.0.1 \
    --port 16161
```

#### 使用自定义配置

```bash
python ivagent_scan.py \
    --engine ida \
    --target /path/to/program.idb \
    --function "parser_function" \
    --config /path/to/my_precondition.md \
    --output result.json
```

#### 分析源代码

```bash
python ivagent_scan.py \
    --engine source \
    --source-root /path/to/source_code \
    --function "my_function" \
    --preset binary
```

---

## 3. 前置条件配置

前置条件 (Precondition) 帮助 Agent 理解目标函数的上下文，提高分析准确性。

### 3.1 配置文件格式

前置条件使用 Markdown 格式，包含 YAML frontmatter 和正文内容：

```markdown
---
name: 配置名称
description: 配置的简短描述
target: 目标类型标识
version: "1.0"
author: 配置作者
taint_sources: ["param1", "param2"]
---

## 参数说明

### 参数1
- 参数说明
- 是否可信
- 约束条件

### 参数2
- 参数说明
- 是否可信
- 约束条件

## 安全检查清单

- [ ] 检查项1
- [ ] 检查项2

## 常见漏洞模式

- 漏洞类型1
- 漏洞类型2
```

### 3.2 内置预设

| 预设名称 | 适用场景 | 文件 |
|----------|----------|------|
| `binary` | 二进制解析函数 | `preconditions/binary.md` |
| `android` | Android Activity/Service | `preconditions/android.md` |
| `harmony` | HarmonyOS Ability | `preconditions/harmony.md` |

### 3.3 创建自定义配置

复制模板文件：

```bash
cp preconditions/_template.md preconditions/my_config.md
```

编辑配置：

```markdown
---
name: My Custom Parser
description: 自定义解析函数分析配置
target: my_parser
version: "1.0"
author: my_team
taint_sources: ["data_ptr", "data_len"]
---

## 参数说明

### data_ptr (参数1)
- 指向输入数据的指针
- **不可信**: 数据来自用户输入
- 需要验证是否为 NULL
- 需要验证数据范围

### data_len (参数2)
- 数据长度
- **不可信**: 由用户指定
- 需要验证是否大于 0
- 需要验证是否小于最大值

## 数据流关注点

1. **污点追踪**: data_ptr 和 data_len 都是污点源
2. **传播路径**: 检查数据如何被使用
3. **危险操作**: 内存拷贝、数组访问

## 安全检查清单

- [ ] 是否验证 data_ptr != NULL？
- [ ] 是否验证 data_len > 0？
- [ ] 是否验证 data_len <= MAX_SIZE？
- [ ] 内存拷贝是否检查溢出？

## 常见漏洞模式

- 缓冲区溢出（未验证长度）
- 空指针解引用（未验证指针）
- 整数溢出（长度计算）
```

### 3.4 配置使用

```bash
# 使用自定义配置
python ivagent_scan.py \
    --engine ida \
    --target /path/to/program.idb \
    --function "my_parser" \
    --config preconditions/my_config.md
```

---

## 4. 引擎使用指南

### 4.1 IDA 引擎

**前置条件：**
- IDA Pro 7.0+
- IDA MCP 插件已安装

**启动 RPC 服务：**

```bash
python start_ida_rpc.py \
    --ida-path "/Applications/IDA Pro 8.0/ida64.app/Contents/MacOS/ida64" \
    --idb "/path/to/target.idb" \
    --port 9999
```

**常用参数：**

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--host` | 127.0.0.1 | IDA RPC 服务器地址 |
| `--port` | 9999 | IDA RPC 服务器端口 |

**函数签名格式：**
- 地址格式: `0x140001000`
- 名称格式: `sub_140001000`
- 导出函数: `FunctionName`

### 4.2 JEB 引擎

**前置条件：**
- JEB 4.0+
- JEB Auto Analysis 完成

**启动 RPC 服务：**

在 JEB 中执行脚本启动 RPC Server（参考 JEB 文档）

**常用参数：**

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--host` | 127.0.0.1 | JEB RPC 服务器地址 |
| `--port` | 16161 | JEB RPC 服务器端口 |

**函数签名格式：**
```
Lpackage/ClassName;->methodName(Parameters)ReturnType

# 示例
Lcom/example/MainActivity;->onCreate(Landroid/os/Bundle;)V
```

### 4.3 ABC 引擎

**前置条件：**
- ABC Decompiler MCP Server 已启动

**启动 MCP Server：**

```bash
# 参考 ABC Decompiler 文档启动 MCP Server
abc-decompiler-mcp --port 8651
```

**常用参数：**

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--host` | 127.0.0.1 | MCP Server 地址 |
| `--port` | 8651 | MCP Server 端口 |

### 4.4 Source 引擎

用于直接分析源代码，无需反编译工具。

**常用参数：**

| 参数 | 说明 | 示例 |
|------|------|------|
| `--source-root` | 源代码根目录 | `/path/to/source` |
| `--language` | 编程语言（可选） | `c`, `cpp`, `java` |

**示例：**

```bash
python ivagent_scan.py \
    --engine source \
    --source-root /path/to/source_code \
    --function "parse_data" \
    --preset binary
```

---

## 5. 日志可视化

### 5.1 启动日志服务

```bash
# 方式1: 使用快速启动脚本
python launch_logger.py

# 方式2: 指定端口
python launch_logger.py --port 8080

# 方式3: 使用 server.py
python -m ivagent.web.server --port 8080
```

### 5.2 访问日志界面

打开浏览器访问：`http://localhost:8080`

### 5.3 功能介绍

| 页面 | 功能 |
|------|------|
| 仪表盘 | 统计概览、成功率、延迟分布 |
| 日志列表 | 查看所有 LLM 交互记录 |
| 日志详情 | 查看单次调用的完整信息 |
| Agent 追踪 | 查看 Agent 执行流程 |
| 漏洞管理 | 查看、验证、导出漏洞 |

### 5.4 WebSocket 实时推送

日志界面支持 WebSocket 实时推送，无需刷新即可看到最新日志。

---

## 6. Python API 使用

### 6.1 基础用法

```python
import asyncio
from ivagent import IVAgentScanner, ScanConfig
from ivagent.models import Precondition

async def main():
    # 创建配置
    config = ScanConfig(
        engine_type="ida",
        target_path="/path/to/program.idb",
        llm_api_key="your-api-key",
        llm_base_url="https://api.openai.com/v1",
        llm_model="gpt-4",
        max_concurrency=5
    )
    
    # 创建扫描器
    scanner = IVAgentScanner(config)
    
    # 加载前置条件
    precondition = Precondition.from_text(
        name="My Parser",
        text_content="参数1是污点数据，需要严格检查",
        taint_sources=["param1"]
    )
    
    # 扫描单个函数
    result = await scanner.scan_function(
        "0x140001000",
        precondition=precondition
    )
    
    print(result)

if __name__ == "__main__":
    asyncio.run(main())
```

### 6.2 批量扫描

```python
async def batch_scan():
    config = ScanConfig(...)
    scanner = IVAgentScanner(config)
    
    functions = ["0x140001000", "0x140002000", "0x140003000"]
    
    results = await scanner.scan_functions(
        functions,
        precondition=precondition
    )
    
    for func, result in zip(functions, results):
        vuln_count = len(result.get("vulnerabilities", []))
        print(f"{func}: {vuln_count} vulnerabilities found")
```

### 6.3 自定义 Agent

```python
from ivagent.agents.base import BaseAgent

class MyAgent(BaseAgent):
    async def run(self, function_signature: str, **kwargs):
        # 获取函数定义
        func_def = await self.engine.get_function_def(
            function_signature=function_signature
        )
        
        # 调用 LLM
        prompt = f"分析以下函数的安全问题:\n{func_def.code}"
        response = await self.call_llm(prompt)
        
        return response

# 使用自定义 Agent
agent = MyAgent(engine=engine, llm_client=llm)
result = await agent.run("0x140001000")
```

### 6.4 引擎直接使用

```python
from ivagent import create_engine

async def analyze():
    # 创建引擎
    engine = create_engine(
        "ida",
        target_path="/path/to/program.idb",
        host="127.0.0.1",
        port=9999
    )
    
    # 使用上下文管理器
    async with engine:
        # 获取函数定义
        func = await engine.get_function_def(
            function_signature="0x140001000"
        )
        print(func.code)
        
        # 获取被调用者
        callees = await engine.get_callee("0x140001000")
        for call in callees:
            print(f"调用 {call.callee_name} 在行 {call.line_number}")
```

---

## 7. 常见问题

### 7.1 连接问题

**Q: 无法连接到 IDA RPC 服务**

```
Error: Connection refused to 127.0.0.1:9999
```

**A:**
1. 确认 IDA 已启动并加载了 IDB 文件
2. 确认 IDA MCP 插件已正确安装
3. 检查端口是否被占用：`lsof -i :9999`
4. 尝试重启 IDA RPC 服务

**Q: JEB 引擎连接失败**

**A:**
1. 确认 JEB 已启动并完成了自动分析
2. 确认 JEB RPC Server 已启动
3. 检查防火墙设置

### 7.2 LLM 问题

**Q: API Key 无效**

```
Error: Invalid API key
```

**A:**
1. 检查环境变量是否正确设置：`echo $OPENAI_API_KEY`
2. 通过命令行参数显式指定：`--api-key your-key`
3. 确认 API Key 有有效的额度

**Q: LLM 响应解析失败**

**A:**
1. 尝试使用更强大的模型（如 gpt-4）
2. 降低 temperature 参数：`--temperature 0.1`
3. 检查网络连接是否稳定

### 7.3 性能问题

**Q: 分析速度太慢**

**A:**
1. 增加并发数：`--concurrency 20`
2. 使用更快的 LLM 模型
3. 检查网络延迟到 LLM 服务
4. 考虑使用本地部署的模型

**Q: 内存不足**

**A:**
1. 降低并发数：`--concurrency 5`
2. 分批处理函数列表
3. 关闭日志存储或改用 JSON 格式

### 7.4 结果问题

**Q: 误报太多**

**A:**
1. 使用更详细的前置条件配置
2. 调整置信度阈值（在代码中修改）
3. 使用更精确的函数签名

**Q: 漏报严重**

**A:**
1. 检查前置条件是否正确描述了污点源
2. 增加递归深度（在代码中修改 `max_depth`）
3. 使用更强大的 LLM 模型

### 7.5 日志问题

**Q: 日志服务启动失败**

```
Error: Port 8080 already in use
```

**A:**
1. 更换端口：`--port 8081`
2. 查找并停止占用进程：`lsof -i :8080`

**Q: 日志没有显示**

**A:**
1. 确认日志服务已启动
2. 检查日志存储路径权限
3. 查看日志文件是否生成

---

## 8. 最佳实践

### 8.1 分析流程建议

1. **准备工作**
   - 确保反编译工具已完成分析
   - 准备清晰的前置条件配置
   - 测试 LLM 连接

2. **小规模测试**
   - 先分析 1-3 个函数验证配置
   - 检查日志确认分析质量
   - 调整前置条件和参数

3. **批量分析**
   - 设置合适的并发数（建议 5-10）
   - 分批处理大量函数
   - 定期保存结果

4. **结果验证**
   - 人工审查高危漏洞
   - 使用逆向工具验证
   - 记录误报/漏报案例

### 8.2 配置优化

- 为不同类型的函数创建专用配置
- 详细描述参数约束和污点源
- 定期更新配置以改进准确性

### 8.3 安全建议

- 不要在共享环境中使用生产 API Key
- 定期轮换 API Key
- 妥善保存分析结果（可能包含敏感信息）
