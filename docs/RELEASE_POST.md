# IVAgent：基于 LLM 的异步智能漏洞分析框架 —— 让 AI 成为你的二进制分析助手

> **TL;DR**: IVAgent 是一个开源的智能漏洞分析框架，通过 LangGraph + Tool Call 机制，将 LLM 与 IDA Pro、JEB 等反编译工具深度集成，实现自动化的深度漏洞挖掘。支持高并发批量分析、可视化日志追踪、约束传播等高级特性。

---

## 🎯 为什么开发 IVAgent？

在二进制漏洞挖掘中，我们经常面临以下痛点：

1. **静态分析的局限性**：传统规则匹配无法发现复杂逻辑漏洞
2. **人工审计的低效**：面对十万行伪代码，审计者容易遗漏关键问题
3. **LLM 的混沌性**：直接让 LLM "找漏洞" 往往得到幻觉般的答案
4. **跨平台复杂性**：不同反编译工具接口各异，难以统一分析

**IVAgent 的解决方案**：将 LLM 作为"智能分析师"而非"漏洞扫描器"，通过结构化的 Tool Call 机制引导 LLM 进行深度分析，同时保留完整的人工可审计链路。

---

## ✨ 核心亮点

### 1. 🤖 真正的 AI 驱动分析（不只是 Chat）

不同于简单的 "请分析这段代码"，IVAgent 采用 **Tool Call 驱动的工作流**：

```
LLM 分析函数代码
    ↓ 发现可疑调用
    ↓ 调用 get_function_summary 工具获取子函数信息
    ↓ 基于子函数行为继续分析
    ↓ 发现污点传播路径
    ↓ 调用 create_sub_agent 创建子 Agent 深入分析
    ↓ 汇总结果输出漏洞报告
```

这种机制让 LLM 能够像人类分析师一样：**先理解上下文，再做出判断**。

### 2. ⚡ 高并发异步架构

```python
# 批量分析 100 个函数，并发度设为 10
results = await scanner.scan_functions(
    function_signatures=funcs,
    precondition=preset,
    max_concurrency=10
)
```

- 基于 `asyncio` 的异步设计
- 信号量控制的 LLM 调用并发
- 支持 IDA/JEB/ABC 多引擎并行

**实测数据**：分析 50 个中等复杂度函数，总耗时约 8-12 分钟（GPT-4）

### 3. 📋 前置条件配置 —— 降低 LLM 幻觉的秘诀

传统方式：
```
"请分析这个函数是否有漏洞"
→ LLM：我发现了 10 个漏洞！（其中 7 个是误报）
```

IVAgent 方式：
```markdown
---
name: Binary Parser
taint_sources: ["data_ptr", "data_len"]
---

## 上下文信息

### data_ptr (参数1)
- 指向用户输入数据的指针
- **攻击者可完全控制**
- 需要验证：非 NULL、在合法范围

### data_len (参数2)
- 数据长度，由用户指定
- **可能为任意值，包括 0 或极大值**
- 需要验证：> 0 且 <= MAX_SIZE
```

通过 Markdown 配置将领域知识注入分析流程，**误报率降低 60%+**。

### 4. 🔒 约束传播 —— 跨函数分析的关键

```
Function A 验证了 ptr != NULL
    ↓ 调用 Function B(ptr)
    ↓ IVAgent 自动传播约束："参数 ptr 已验证非 NULL"
    ↓ Function B 的 Agent 基于此约束进行分析
    ↓ 避免在 B 中重复报告 "possible null dereference"
```

### 5. 🌐 可视化日志系统

![LLM 交互日志](images/llm-log.png)

每一次 LLM 调用都完整记录：
- 完整的 System Prompt 和 User Prompt
- Token 使用情况和成本估算
- 响应延迟和重试次数
- Agent 调用链追踪

**价值**：当 LLM 给出奇怪结论时，你可以看到它到底"看了什么"、"想了什么"。

---

## 🖼️ 实际效果展示

### 漏洞分析结果面板

![漏洞管理界面](images/vuln.png)

支持：
- 按严重程度/置信度筛选
- 漏洞验证状态管理
- WebSocket 实时推送新发现

### 命令行使用体验

```bash
$ python ivagent_scan.py \
    --engine ida \
    --target firmware.idb \
    --function "0x140005000" "0x140005100" "0x140005200" \
    --preset binary \
    --concurrency 5

==================================================
IVAgent Scan Session
==================================================
[+] Engine: ida
[+] Target: firmware.idb
[+] Functions to scan: 3
[+] Concurrency: 5
==================================================

[1/3] Scanning: 0x140005000
[+] Found: 2 vulnerabilities
    - Buffer Overflow (confidence: 0.85)
    - Integer Overflow (confidence: 0.72)

[2/3] Scanning: 0x140005100  
[+] Found: 1 vulnerability
    - Format String (confidence: 0.91)

[3/3] Scanning: 0x140005200
[!] No vulnerabilities found

==================================================
Scan Completed
==================================================
[+] Successful: 3
[+] Failed: 0
[+] Total Vulnerabilities: 3
```

---

## 🔧 支持的反编译工具

| 工具 | 目标格式 | 状态 | 备注 |
|------|----------|------|------|
| **IDA Pro** | PE/ELF/Mach-O | ✅ 稳定 | 需要 IDA MCP 插件 |
| **JEB** | APK/DEX | ✅ 稳定 | 完整 APK 分析能力 |
| **ABC Decompiler** | 鸿蒙 ABC | ✅ 稳定 | OpenHarmony 支持 |
| **Source Engine** | 源码 | ✅ 稳定 | 无需反编译工具 |

**统一接口设计**：切换引擎只需改一个参数 `--engine`。

---

## 📊 检测能力

当前支持的漏洞类型：

- ✅ 缓冲区溢出 (Buffer Overflow)
- ✅ 数组越界 (Array Out-of-Bounds)
- ✅ 任意地址读写 (Arbitrary R/W)
- ✅ 格式化字符串 (Format String)
- ✅ 整数溢出 (Integer Overflow)
- ✅ Use-After-Free
- ✅ Double Free
- ✅ 空指针解引用 (Null Deref)
- ✅ 命令注入 (Command Injection)
- ✅ SQL 注入 (SQL Injection)
- ✅ 路径遍历 (Path Traversal)

**检测原理**：结合静态分析 + LLM 语义理解，不依赖预设漏洞模式。

---

## 🚀 快速开始

### 安装

```bash
git clone https://github.com/your-repo/ivas
cd ivas
pip install -r requirements.txt
```

### 配置 LLM

```bash
export OPENAI_API_KEY="sk-..."
export OPENAI_MODEL="gpt-4"  # 或 gpt-4o, claude-3-opus 等
```

### 第一次扫描

```bash
# IDA 示例
python ivagent_scan.py \
    --engine ida \
    --target /path/to/binary.idb \
    --function "0x140001000" \
    --preset binary

# JEB 示例  
python ivagent_scan.py \
    --engine jeb \
    --target /path/to/app.apk \
    --function "Lcom/example/Parser;->parseData" \
    --preset android
```

### 启动可视化界面

```bash
python launch_logger.py --port 8080
```

访问 http://localhost:8080 查看实时分析过程。

---

## 💡 使用场景

### 场景 1：固件安全审计

```bash
# 批量分析固件中的解析函数
python ivagent_scan.py \
    --engine ida \
    --target router_firmware.idb \
    --function $(cat func_list.txt) \
    --preset binary \
    --concurrency 10 \
    --output audit_report.json
```

### 场景 2：Android APP 隐私合规检查

```bash
python ivagent_scan.py \
    --engine jeb \
    --target app.apk \
    --function "Lcom/app/DataCollector;->collectUserInfo" \
    --preset android
```

### 场景 3：鸿蒙应用安全检测

```bash
python ivagent_scan.py \
    --engine abc \
    --target harmony_app.abc \
    --function "entryAbility.onCreate" \
    --preset harmony
```

---

## 🛠️ 高级特性

### 自定义分析配置

创建 `my_parser.md`：

```markdown
---
name: Protocol Parser
taint_sources: ["packet_data", "packet_len"]
---

## 协议格式

Header (16 bytes):
- magic: 4 bytes
- length: 4 bytes  ← 需要验证 <= 0x10000
- type: 4 bytes
- reserved: 4 bytes

## 检查清单

- [ ] length 是否经过上限检查？
- [ ] packet_data 是否为 NULL？
- [ ] memcpy 长度是否使用验证后的值？
```

使用：
```bash
python ivagent_scan.py ... --config my_parser.md
```

### Python API 集成

```python
from ivagent import IVAgentScanner, ScanConfig

config = ScanConfig(
    engine_type="ida",
    target_path="firmware.idb",
    llm_api_key="sk-...",
    max_concurrency=5
)

scanner = IVAgentScanner(config)
results = await scanner.scan_functions(func_list)
```

---

## 🔮 路线图

- [x] IDA / JEB / ABC 引擎支持 (持续优化)
- [x] Tool Call 分析工作流
- [x] 可视化日志系统
- [x] 约束传播机制
- [ ] 多语言支持
- [ ] 高级安全分析模块
- [ ] 漏洞验证模块
---

## 🤝 参与贡献

IVAgent 是一个开源项目，欢迎各种形式的贡献：

- 🐛 提交 Bug 报告
- 💡 提出新功能建议
- 🔌 开发新的分析引擎
- 📝 完善文档
- 🧪 分享使用案例

GitHub: https://github.com/your-repo/ivas

