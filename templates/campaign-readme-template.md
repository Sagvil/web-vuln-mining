# README 模板：SRC 战役数据文件夹

> 依据 Cornell University Library《Writing READMEs for Research Data》推荐结构
> （General information / Data and file overview / Sharing and access /
> Methodological information 四节）+ Best-README-Template 的目录树风格，
> 结合渗透取证场景裁剪。每个 `projects/<target>-<date>/` 文件夹必须包含一份
> 填写好的本模板（README.md），与首个 commit 同时入库。

## 模板正文（复制后按实际填写，`<>` 为占位符）

```markdown
# <站名> SRC 战役数据归档

## 一、战役概要 (General Information)

| 项目 | 内容 |
|---|---|
| 目标主域 | <example.com>（含全部子域） |
| 平台/批次 | <补天 #64777 等；未收录则写"自有授权"> |
| 战役周期 | <YYYY-MM-DD ~ YYYY-MM-DD> |
| 归档根目录 | projects/<target>-<YYYYMMDD>/ |
| 授权边界 | <只读验证 / 含带标记写入 PoC / 禁爆破等声明> |
| 敏感性 | <含 PII 脱敏件/内部文件取证副本——仅限授权查阅> |

一句话结论：<本次战役最重的发现 + 对应报告编号>。

## 二、文件分布与功能 (Data and File Overview)

```
<target>-<YYYYMMDD>/
├── README.md                    ← 本文件
├── TRIAGE-R<n>.json             # 第 n 轮归档：findings/evidence/blocked
├── IMPACT-*.json                # 危害量化清单（提交前最终版）
├── REPORT-R*.md                 # 阶段性报告草稿（终稿在 ../../reports/）
├── <target>-<主题>.json         # 原始取证：api/portscan/xss-recon/dns…
├── *.nmap                       # 端口扫描原始输出
├── *.js                         # 取回的前端资产（登录逻辑/API 定义）
├── evidence-*.{pdf,png}         # ⚠️ 敏感文件本体（配 evidence-manifest.json）
└── evidence-manifest.json       # 取证指纹清单（文件名/大小/MD5/性质判定）
```

### 文件命名规则
- `TRIAGE-R<n>` 与 git commit 一一对应，附录可回溯
- 取证 JSON 内不存明文凭据/手机号，敏感值一律 `[REDACTED]`

## 三、访问与共享约束 (Sharing and Access)

- [ ] 本文件夹含内部资料取证副本 → **不得外发**，报告仅引用 MD5
- [ ] PII 相关字段已脱敏（[REDACTED]）
- [ ] 提交平台时手动复制 reports/ 终稿，不带证据文件本体

## 四、方法论与复现线索 (Methodological Information)

- 主要通道：<raw socket / 浏览器 TLS 栈 / 服务端直连 API>
- 关键轮次索引：
  | R# | 主题 | 关键产出文件 | commit |
  |---|---|---|---|
  | R1 | 资产测绘 | r1-dns/fingerprint.json | <hash> |
  | R4 | 认证绕过 | pbootcms-api.json | <hash> |
- 复现依赖：无特殊环境；JSON 可直接 json.loads 校验完整性

## 五、关联文档 (Related Information)

- 终稿报告：../../reports/butian-S*.md
- 运行流水：../../runs/<timestamp>-<target>-*/
```

## 使用规则

1. **建夹即建 README**：`projects/<target>-<date>/` 创建时同步写入，空表也先入库
2. **每轮收官更新一次**：R# 索引表追加行、文件树同步新增文件
3. **四节顺序固定**（Cornell 最佳实践：多 readme 格式一致便于机器解析）
4. **日期一律 ISO 8601**（YYYY-MM-DD）
5. 纯文本 Markdown，禁用专有格式
