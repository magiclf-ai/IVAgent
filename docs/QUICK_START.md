# IVAgent 快速入门指南

本指南帮助您在 5 分钟内开始使用 IVAgent 进行漏洞分析。

## 环境准备

### 1. 安装 Python 依赖

```bash
cd ivas
pip install -r requirements.txt
```

### 2. 配置 LLM API

```bash
export OPENAI_API_KEY="your-api-key"
export OPENAI_BASE_URL="https://api.openai.com/v1"
export OPENAI_MODEL="gpt-4"
```

## 第一个分析任务

### 使用 IDA 分析二进制文件

**步骤 1: 启动 IDA RPC 服务**

```bash
python start_ida_rpc.py \
    --ida-path "/Applications/IDA Pro 8.0/ida64.app/Contents/MacOS/ida64" \
    --idb "/path/to/your/program.idb"
```

**步骤 2: 运行分析**

```bash
python ivagent_scan.py \
    --engine ida \
    --target /path/to/your/program.idb \
    --function "0x140001000" \
    --preset binary
```

### 使用 JEB 分析 Android APK

```bash
python ivagent_scan.py \
    --engine jeb \
    --target /path/to/app.apk \
    --function "Lcom/example/MainActivity;->onCreate(Landroid/os/Bundle;)V" \
    --preset android
```

### 使用 ABC 分析鸿蒙应用

```bash
python ivagent_scan.py \
    --engine abc \
    --target /path/to/app.abc \
    --function "entry_func" \
    --preset harmony
```

## 查看分析日志

**启动日志服务：**

```bash
python launch_logger.py
```

**访问界面：**

打开浏览器访问 `http://localhost:8080`

## 批量分析示例

```bash
python ivagent_scan.py \
    --engine ida \
    --target /path/to/program.idb \
    --function "0x140001000" "0x140002000" "0x140003000" \
    --concurrency 5 \
    --preset binary \
    --output results.json
```

## 使用自定义配置

创建 `my_config.md`：

```markdown
---
name: My Parser
target: parser
taint_sources: ["data_ptr", "data_len"]
---

## 参数说明

### data_ptr
- 指向输入数据的指针
- **不可信**: 需要验证

### data_len
- 数据长度
- **不可信**: 需要验证范围
```

运行分析：

```bash
python ivagent_scan.py \
    --engine ida \
    --target /path/to/program.idb \
    --function "parser_func" \
    --config my_config.md
```

## 下一步

- 阅读 [用户使用手册](USER_GUIDE.md) 了解更多功能
- 查看 [架构设计文档](ARCHITECTURE.md) 了解系统原理
- 参考 `preconditions/` 目录创建自定义配置
