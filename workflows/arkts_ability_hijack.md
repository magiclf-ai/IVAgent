---
name: "HarmonyOS Ability 劫持漏洞挖掘"
description: 针对 HarmonyOS 应用的 Ability 劫持和权限绕过漏洞分析，重点关注 Want 参数处理、Ability 启动和隐式调用
version: "1.0"
scope:
  description: 处理 Want 参数和启动 Ability 的代码路径
strategy_hints:
  max_depth: "建议调用链深度为 3-5 层"
  concurrency: "可根据函数数量动态决定并发度"
---

## 分析范围

分析范围应覆盖所有处理 Want 参数和启动 Ability 的代码路径。

重点关注以下类型的组件:
- UIAbility 的 onCreate/onNewWant 方法
- 处理 router 参数的处理函数
- startAbility 调用的位置
- Want 参数解析逻辑

### 排除建议
可以排除系统框架类和测试代码。

## 工作流
1. 搜索 UIAbility 实现类及其生命周期方法
2. 分析 Want 参数处理流程
3. 识别 startAbility 调用点并追踪 Want 来源
4. 对可疑路径开展漏洞挖掘

## 漏洞关注点

重点关注以下安全问题:

1. **Ability 劫持**: 隐式 Want 启动未指定 bundleName/abilityName
2. **权限绕过**: 通过伪造 Want 参数绕过权限检查
3. **敏感信息泄露**: Want 参数中的敏感数据处理
4. **嵌套 Want 攻击**: 处理嵌套 Want 时未校验来源

## 背景知识

### HarmonyOS Want 安全机制

#### Want 结构

```typescript
interface Want {
  bundleName?: string;    // 目标包名
  abilityName?: string;   // 目标 Ability 名
  action?: string;        // 动作
  parameters?: {          // 参数 (污点源)
    [key: string]: any;
  };
}
```

#### 危险模式

1. **隐式启动**
```typescript
// 危险：未指定 bundleName/abilityName
router.pushUrl({ url: 'pages/Index', params: userData });
```

2. **未校验嵌套 Want**
```typescript
// 危险：直接使用传入的 Want 参数
onCreate(want: Want) {
  let nestedWant = want.parameters?.nested;
  this.context.startAbility(nestedWant);
}
```

#### 安全做法

- 始终明确指定 bundleName 和 abilityName
- 验证 Want 参数的来源
- 不要直接使用传入的 Want 启动新 Ability

#### 污点源

- router.getParams() 返回的参数
- want.parameters 中的数据
- AppStorage/PersistentStorage 中用户可控的数据

## 入口函数示例

### UIAbility.onCreate
```typescript
export default class EntryAbility extends UIAbility {
  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    // want.parameters 是主要污点源
    let userData = want.parameters?.userData;
  }
}
```

### router 参数处理
```typescript
import router from '@ohos.router';

// 获取路由参数
let params = router.getParams();
// params 来自用户输入，需要验证
```
