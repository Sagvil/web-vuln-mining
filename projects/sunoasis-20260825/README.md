# sunoasis（特变电工新疆新能源）SRC 战役数据归档

## 一、战役概要 (General Information)

| 项目 | 内容 |
|---|---|
| 目标主域 | sunoasis.com.cn（含 info./www 多语言站）+ 关联 tbea.com 子域（sso/ejia/ecm/tbportal/itb，scope 待确认项已标注） |
| 平台/批次 | 补天 #64777 |
| 战役周期 | 2026-08-25 ~ 2026-08-26 |
| 归档根目录 | projects/sunoasis-20260825/ |
| 授权边界 | 无凭据只读验证为主；写入测试仅 1 条带 SECURITY-TEST 标记记录；一切登录面禁爆破/禁凭据提交 |
| 敏感性 | 含内部资料取证副本（evidence-*），仅限授权查阅 |

一句话结论：PbootCMS API 认证失效致 PII 泄露+未授权写入+185 篇隐藏内容越权+内部资料文件本体泄露（S4/S7 高危，报告 butian-S4S7）；OAuth 扫码链三缺陷组合中危（S6）；WNM 硬编码密钥（S5）。

## 二、文件分布与功能 (Data and File Overview)

```
sunoasis-20260825/
├── README.md                        ← 本文件
├── REPORT-R1.md                     # R1 资产测绘阶段草稿
├── IMPACT-CONFIRMED.json            # 危害清单最终版（A-E 五类）
├── TRIAGE-R*.json                   # R7-R17 各轮归档（findings/evidence/blocked）
├── sunoasis-r1-{dns,fingerprint,www}.json   # R1: DNS/指纹/www 基线
├── sunoasis-t{1,2,3,4}-*.json       # T1-T4 梯队资产盘点
├── sunoasis-cname.json              # CNAME 排除记录
├── sunoasis-portscan.nmap           # 13 主机端口扫描原始输出
├── sunoasis-register-blocked.json   # 注册链阻断取证
├── sunoasis-pbootcms-api.json       # ★R4 认证绕过核心取证（19 路由+绕过矩阵）
├── sunoasis-api-modules.json        # api.php 模块面
├── sunoasis-www-dirs.json           # www 目录探测
├── sunoasis-xss-recon.json          # XSS/WAF 面侦察
├── sunoasis-sso-recon.json          # SSO 体系侦察（HS512/captcha/RSA）
├── sunoasis-oauth-redirect.json     # S6 redirect_uri 测试矩阵
├── S6-oauth-final.json              # S6 五组证据 E1-E5
├── sunoasis-cms8443.json            # cms:8443 登录壳观察
├── sunoasis-content-hidden.json     # ★185 篇 sitemap 外内容明细
├── sunoasis-info-idor.json          # ★info 119 篇 IDOR 清单
├── idor-with-link.json              # 53 篇外发链接映射
├── sunoasis-local-files.json        # ★13 篇本地文件清单
├── evidence-manifest.json           # 取证指纹（MD5）
├── evidence-manual-115.pdf          # ⚠️ 内部资料手册副本（勿外传）
├── evidence-tsvg-catalog.pdf        # 公开重复件（仅证冗余入口）
└── wnm-login-portal.js              # WNM 登录页 JS 全文取证
```

### 文件命名规则
- `TRIAGE-R<n>` 与 git commit 一一对应（见附录 commit 链）
- 所有 JSON 不存明文凭据/手机号，敏感值 `[REDACTED]`

## 三、访问与共享约束 (Sharing and Access)

- [x] 本文件夹含「内部资料」级取证副本 → **不得外发**，报告仅引用 MD5
- [x] PII 字段已脱敏
- [x] 提交补天时手动复制 reports/ 终稿文本

## 四、方法论与复现线索 (Methodological Information)

- 主要通道：Python urllib 服务端直连 + browser_exec 浏览器真实 TLS 栈（raw socket 对 .js 被 400 时兜底）
- 关键轮次索引：
  | R# | 主题 | 关键产出 | commit |
  |---|---|---|---|
  | R1 | 三层资产测绘 | r1-*、t1-t4、portscan | b09f18c 起 |
  | R2-R6 | API 面/SSO/XSS | pbootcms-api、sso-recon 等 | f398c1a~14520e5 |
  | R9-R10 | info IDOR/后台排除 | info-idor.json | 6ce3633/9bcbf66 |
  | R11-R12 | 写入闭环/IMPACT | content-hidden、IMPACT-CONFIRMED | f91087f/bf91912 |
  | R13-R15 | 主 SSO 扫码链 | TRIAGE-R13~R15 | aafd076~ffcfa30 |
  | R16-R17 | 文件本体泄露+敏感性判定 | local-files、TRIAGE-R17、evidence-* | cf4aff2/814edb2 |
- 复现依赖：无特殊环境；所有 JSON 可 json.loads 校验

## 五、关联文档 (Related Information)

- 终稿报告：../../reports/butian-S4S7-pbootcms-api-auth-pii.md、butian-S5-wnm-hardcoded-key.md、butian-S6-oauth-hijack.md
- 运行流水：../../runs/<timestamp>-sunoasis-*
