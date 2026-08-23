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

## 4. 证据要求

- 请求/响应原文必须来自真实工具输出（curl/脚本/抓包），不手写伪造
- 敏感字段（密码、token、cookie、个人数据）脱敏或哈希
- 提取数据只保留证明片段，不保留完整数据
- 高危操作（删除、写库）不做——只验证可执行性

## 5. SRC 适用边界

- 适用：所有提交到 SRC 平台的漏洞报告（补天/漏洞盒子/众测）
- 不适用：内部排查记录（可简化为摘要）
- ⚠️ 平台草稿只在 triage 三条件全满足时生成；永不存储平台凭据、永不调用平台提交 API
