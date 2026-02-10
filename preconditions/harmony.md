---
name: HarmonyOS Entry Point
description: HarmonyOS (OpenHarmony) ABC 入口点的安全分析配置
target: harmonyos_entry
version: "1.0"
author: security_team
taint_sources: []
---

## 概述

代码中可能通过 want 获取外部输入，里面的数据是污点数据，需要校验，避免出现漏洞。

## 常见风险点

- want 参数解析（getStringParam, getIntParam 等）
- Ability 启动参数处理
- IPC 通信数据接收

## 安全检查清单

- [ ] 是否验证 want 数据来源？
- [ ] 是否检查参数类型和范围？
- [ ] 是否正确处理跨 Ability 调用？

## 危险函数

需重点检查的 API：
- `want.getStringParam()` - 获取字符串参数
- `want.getIntParam()` - 获取整数参数
- `featureAbility.getContext()` - 获取上下文
