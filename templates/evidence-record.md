---
name: evidence-record
category: evidence
source: 渗透/sqli-labs-closeout/patterns/sqli-labs-methodology.md
verified_in: [sqli-labs-evidence-standard]
src_value: medium
severity_ceiling: medium
requires_auth: false
payload_count: 0
---

# 证据记录模板（统一字段）

> 来源：SQLi-Labs 证据标准 + web-vuln-mining triage 门槛合并。所有漏洞验证的证据按此模板记录，保证可复现、可追溯、可提交。

## 1. 识别

- 每个漏洞验证必须产出独立证据记录
- 提交门槛（triage.yaml）：`status: reproduced` + `human_reviewed: true` + `scope_confirmed: true` 三条件全满足才可进入平台提交草稿
- 证据文件放运行目录 `evidence/` 下，与扫描产物同目录

## 2. Payload 与记录字段（必填）

```yaml
target: https://example.com/api/login      # URL + 参数 + 方法
context:                                   # 注入点上下文 / 认证状态
  injection_type: string
  auth_required: false
request:                                   # 请求原文（含 payload）
  method: POST
  path: /api/login
  body: '{"email": "admin''--", "password": "x"}'
response_excerpt: >-                        # 响应摘录：证明差异的关键片段
  200 OK ... {"id": 1, "role": "admin"}
verdict: confirmed                          # confirmed | candidate | not-vulnerable
impact:                                     # 数据 / 功能 / 权限
  data_exposure: false
  privilege_escalation: true
least_destructive: true                     # 是否最小破坏、可逆、无副作用
reproduce_steps:                            # 3-5 步复现
  - 1. 登录获取 token
  - 2. 构造修改后 JWT
  - 3. 重放请求
  - 4. 观察响应差异
```

## 3. 判定标准

- **confirmed**：可复现 ≥2 次 + 响应差异明确 + 影响真实（非自我报告）
- **candidate**：有异常但未完全确认（未复现/差异模糊/需人工复核）
- **not-vulnerable**：对照实验证明无漏洞
- **靶场/挑战解锁可作辅助证据**：本地靶场测试中，漏洞类挑战解锁（solved=True）是强判定信号（如 JWT 挑战解锁证明 token 伪造被接受）；真实 SRC 场景则以业务影响为准

## 4. 证据要求

- 请求/响应原文必须来自真实工具输出（curl/脚本/抓包），不手写伪造
- 敏感字段（密码、token、cookie、个人数据）脱敏或哈希
- 提取数据只保留证明片段，不保留完整数据
- 高危操作（删除、写库）不做——只验证可执行性

## 5. SRC 适用边界

- 适用：所有提交到 SRC 平台的漏洞报告（补天/漏洞盒子/众测）
- 不适用：内部排查记录（可简化为摘要）
- ⚠️ 平台草稿只在 triage 三条件全满足时生成；永不存储平台凭据、永不调用平台提交 API

## 6. 取证实战技巧（2026-08 三靶场 214 关验证）

回显不可用时按优先级换取证通道，**不要死磕一种回显**：

| 回显失效场景 | 替代取证通道 | 实战场次 |
|---|---|---|
| 报错/回显被禁用（PHP 8.3 mysqli 不显示错误） | **时间盲注**（`AND sleep(2)` 对比延迟）或**数据修改实锤**（UPDATE 改 admin 密码后登录验证） | SQLi-Labs Less-5/6/17 |
| 回显被数组混淆锁死（`$unames[$row['id']]`） | **extractvalue 报错注入** → 数据落在 PHP 异常日志侧，`grep "XPATH syntax error: '~(.*?)'"` 提取 | SQLi-Labs Less-58~65 |
| 注入无回显且布尔无差异（MySQL 8 ORDER BY） | **排序差异验证**：`ORDER BY 2 AND 1=1`（表达式=1→按列2排）vs `2 AND 1=2`（=0→插入序）输出顺序对比 | SQLi-Labs Less-48/49 |
| NoSQL/布尔场景 | **三态对比**：正常 1 条 / `'||false||'` 空 / `'||true||'` 全部——三态齐全即 confirmed | Juice Shop NoSQL |
| 头/ Cookie 注入无页面回显 | **DB 直查实锤**：注入落库后 `mysql CLI SELECT` 验证行数据 | SQLi-Labs Less-18~22 |
| 前端 DOM 判定挑战 | **socket.io 事件直发**：`socket.emit('verifyXxxChallenge', payload)` 无需浏览器即解锁 | Juice Shop localXss/xssBonus |
| 挑战类关卡（随机表 + 尝试次数限制） | **日志侧提取流水线**：php -S 日志落盘 → 注入 → grep 提取表名/列名/secret → 提交 | SQLi-Labs Less-54~65 |
| SSRF 无响应回显（curl 扩展缺失/目标无输出） | **监听器旁证**：本地起 TCP 监听，注入指向 `http://127.0.0.1:PORT/marker`——**服务端实收出网请求（连接+请求行日志）强于页面回显**；`file_get_contents` 路径与 curl 路径分开验证（扩展缺失只影响其一） | Pikachu ssrf_fgc（2026-08-25 实收 GET /ssrf-proof-fgc） |

**通用原则**：
- 服务端判定信号（挑战 solved、状态码+响应差异、DB 行变化、**监听器实收请求**）强于自我观察；判定信号必须有**可复现输入 + 对照差异**双要素
- 每条证据链保留：payload 原文 + 请求（含编码方式，标注 requests/curl 差异）+ 响应摘录/日志摘录 + DB 或文件落库验证
- 编码坑要记录在证据里：`requests` 会二次编码 `%09`、base64 cookie 的 `=` 会被编码（改用 curl 原样发送）、URL fragment 的 `#` 需 `%23`
- 尝试次数限制类挑战（如 5~14 次）：把提取次数压缩到最少（GROUP_CONCAT 合并列名），超限就 reset 重来，不浪费次数
