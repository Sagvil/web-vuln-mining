# Web-Mining Report Templates (v4.3.1)

Method-level templates distilled from completed SRC engagements. Fill with
run-specific facts; never embed payloads, target data, or credentials in
completed reports beyond redacted evidence.

## T1. Bypass Matrix Table (auth-flaw core evidence)

One row per variable, everything else constant. The cleanest proof that a
server-side check is missing rather than weak.

```markdown
| 参数组合 | 结果 |
|---|---|
| 仅 `appid=x`（任意值） | ✅ 完全放行 |
| `appid=x&timestamp=0`（过期时间戳） | ✅ 放行 |
| `appid=admin&signature=<错值>`（错误签名） | ✅ 放行 |
| 不带任何参数 | ❌ 拒绝（唯一拦截条件） |
```

Rules: vary exactly one parameter per row; the last row names the ONLY enforced
condition; follow with official-repo diff to prove "modified" vs "outdated".

## T2. Write-Loop PoC (unauthorized write, non-destructive)

```markdown
1. 提交：POST <endpoint> 全参数链，每字段带明显测试标记
   （如 user_push=SECURITY-TEST-DO-NOT-PROCESS），单条记录
2. 服务端响应：{"code":1,"data":"提交成功！"}
3. 回读：同源读接口确认记录数 N → N+1，测试记录 id=X 可读
4. 报告标注：测试标记供管理员清理识别
```

Stop after read-back confirmation. Never submit a second record.

## T3. IDOR Three-Stage Escalation

```markdown
① 单点探针：列表不可见 id 经 detail 端点读取成功 = PoC
② 全量枚举：扫描全 id 段（分段+并发+落盘），量化「隐藏集」规模
   （列表 total 与可达数差值即隐藏资源数学证明）
③ 影响放大：对返回的 file/url 字段逐个验证直链可达性，
   区分「元数据泄露」与「文件本体泄露」
```

## T3b. Sensitivity Triple Test Table

```markdown
| 文件 | 判定 | 证据 |
|---|---|---|
| X.pdf | 内部资料实锤 | 首页标注「内部资料」；全网搜索零结果；hash 不在公开集合 |
| Y.png | 未发布物料 | 公开列表无同名、hash 不在公开集合 |
| Z.pdf | 冗余暴露 | 与公开列表条目字节级相同（MD5 一致），无独立价值 |

取证指纹：<file> MD5 <hash>。报告只附指纹不附文件本体。
```

## T4. State-Machine Lexicography (QR login / OAuth flows)

```markdown
环节拆解: 生成 / 轮询 / 确认 / 交换 —— 逐环节测鉴权边界

| 输入变体 | 响应码/字段 | 赋义 |
|---|---|---|
| 真 token（未扫） | 102 | 等待态 |
| 真 token（超时后） | 104 | 超时态 |
| 伪造 hex | 104 | 不区分不存在与超时 = 会话不清理 |
| 跨 appid token | 101 | token-appid 绑定存在 |
| 缺参 | 110 + errorCode | 参数校验 |

结论模板: 各环节鉴权强度不一致本身就是设计缺陷；
防护正确环节一句话作链路边界说明，不展开。
```

## T5. SRC Report Skeleton

```markdown
# 漏洞报告：<资产> <根因缺陷>——<影响1>、<影响2>、<影响3>
## 一、基本信息        # 表格: 名称/资产/类型(CWE)/等级/时间/测试性质(无凭据只读等)
## 二、漏洞描述        # 框架识别→路由→认证机制→缺陷一句话→三类影响预告
## 三、确定不公开但现在匿名可获取的信息清单
### A/B/C/D/E 分层     # PII / 写入 / 下线内容 / 文件本体 / 系统情报
                       # 每层: 复现请求 + 「公开性判定」一句
## 四、认证缺陷证据（根因）  # T1 矩阵 + 官方仓库 diff 对照
## 五、危害影响汇总     # 编号列表，合规风险优先
## 六、修复建议        # 对应危害逐条给可执行动作
## 七、附录            # 归档 commit 链 + 取证 MD5 指纹
```

Writing rules: 只写漏洞面（防护正确面最多一句作链路边界）；价值分层如实标注；
每个发现绑定归档 commit。

## T6. Run Archive JSON Schema

```json
{
  "campaign": "<target> R<N>: <one-line theme>",
  "date": "<YYYY-MM-DD>",
  "findings": {
    "S<n>-<tag>": {
      "severity": "<info|low|medium|high[-candidate]>",
      "title": "...",
      "detail": "...",
      "evidence": {"E1_...": "..."},
      "blocked": "超出边界的部分如实记录"
    }
  },
  "impact_summary": "..."
}
```

Naming: runs/<target>-<slug>.json → cp into projects/<campaign>/ → git commit.
Every finding binds to its commit for zero-cost review.
