---
name: "Android SQL 注入漏洞挖掘"
description: 针对 Android 应用的 SQL 注入漏洞分析，重点关注 ContentProvider、数据库操作中的用户输入拼接问题
version: "1.0"
scope:
  description: Android ContentProvider 和数据库操作代码
strategy_hints:
  max_depth: "建议调用链深度为 4-6 层"
  concurrency: "可根据方法数量动态决定并发度"
---

## 分析范围

分析范围应覆盖所有可能处理用户输入并进行数据库操作的代码路径。

重点关注以下类型的组件:
- ContentProvider 实现类
- SQLiteDatabase 操作函数
- 执行 SQL 语句的方法 (execSQL, rawQuery 等)
- 用户输入处理入口 (Activity, BroadcastReceiver)

### 排除建议
可以排除测试类和框架类。

## 工作流
1. 先搜索可能的 ContentProvider
2. 分析 ContentProvider 有哪些对外暴露的回调函数
3. 对暴露接口开展漏洞挖掘

## 漏洞关注点

重点关注 SQL 注入漏洞，包括:

1. ContentProvider query/update/delete 方法中的注入
2. SQLiteDatabase.rawQuery 的 selection 参数拼接
3. execSQL 执行的动态构造 SQL 语句
4. WebView JavaScript 接口中的数据库操作

## 背景知识

### Android SQL 注入常见模式

#### 危险 API

- `SQLiteDatabase.rawQuery(String sql, String[] selectionArgs)`
- `SQLiteDatabase.execSQL(String sql)`
- `SQLiteDatabase.query(...)` 的不当使用

#### 污点源

- Intent Extra 参数
- ContentProvider URI 参数
- WebView URL 参数
- 用户输入文本

#### 安全做法

- 使用参数化查询 (selectionArgs)
- 使用 ContentValues
- 避免字符串拼接构造 SQL

## 入口类示例

### ContentProvider
```java
// 重点关注 query/insert/update/delete 方法
public class UserProvider extends ContentProvider {
    public Cursor query(Uri uri, String[] projection, String selection, 
                        String[] selectionArgs, String sortOrder) {
        // 检查 selection 参数是否可信
    }
}
```

### Activity 入口
```java
// 处理用户输入并执行数据库操作
public class SearchActivity extends Activity {
    // onCreate 中获取用户输入并查询数据库
}
```
