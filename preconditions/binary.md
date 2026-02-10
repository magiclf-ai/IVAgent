---
name: Binary Parser Function
description: 二进制解析函数的安全分析配置（通用）
target: binary_parser
version: "1.0"
author: security_team
taint_sources: []
---

## 参数说明

### 第一个参数
- 指向攻击者控制的数据缓冲区

### 第二个参数
- 数据长度（可能由攻击者指定或需要验证）

## 常见风险点

- 长度验证缺失或不当
- 整数溢出（长度计算）
- 缓冲区溢出
- 格式字符串漏洞

## 安全检查清单

- [ ] 是否验证长度参数的合理性？
- [ ] 是否存在整数溢出风险？
- [ ] 内存拷贝操作是否安全？
- [ ] 是否正确处理边界情况？

## 危险函数

需重点检查的函数：
- `memcpy()` / `strcpy()` / `strncpy()`
- `sprintf()` / `snprintf()`
- `malloc()` / `alloca()` - 检查分配大小
- 数组索引访问
