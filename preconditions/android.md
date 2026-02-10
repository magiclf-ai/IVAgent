---
name: Android Entry Point
description: Android Activity/Service 入口点的安全分析配置
target: android_entry
version: "1.0"
author: security_team
taint_sources: []
---

## 概述

代码中可能通过 getIntent()/getExtras() 获取外部输入，里面的数据是污点数据，需要校验，避免出现漏洞。重点关注 Intent 解析、序列化对象反序列化等风险。

## 常见风险点

- Intent 数据解析（getStringExtra, getIntExtra 等）
- Bundle 数据读取
- 序列化对象反序列化（getSerializable）
- Parcelable 对象解析

## 安全检查清单

- [ ] 是否验证 Intent 数据来源？
- [ ] 是否检查序列化对象类型？
- [ ] 是否存在隐式 Intent 劫持风险？
- [ ] 是否正确处理 exported 组件的外部输入？

## 危险函数

需重点检查的 API：
- `getIntent()` - 获取外部 Intent
- `getStringExtra()` - 获取字符串参数
- `getSerializable()` - 反序列化对象
- `startActivity()` - 启动新 Activity
