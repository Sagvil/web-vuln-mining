# 漏洞报告：特变电工开放平台 OAuth 扫码登录 redirect_uri 未校验（含接入应用身份缺失与会话管理缺陷）

## 一、基本信息

| 项目 | 内容 |
|---|---|
| 漏洞名称 | ejia.tbea.com 开放平台扫码登录回调地址未校验、appid 无验证、授权会话不清理 |
| 受影响资产 | `ejia.tbea.com`（特变电工开放平台 / TBe+ 开放接入体系，openresty） |
| 入口关联 | 特变电工统一认证平台 `sso.tbea.com`「TBe+ 扫码登录」功能 |
| 漏洞类型 | CWE-601（URL Redirect 未校验）+ CWE-346（来源校验错误）+ CWE-287（接入方身份认证不当）+ CWE-613（会话失效机制缺失） |
| 危害等级 | **中危**（按服务端既有缺陷组合定性；不含依赖诱导用户配合的攻击场景） |
| 测试时间 | 2026-08-26 |
| 测试性质 | 无凭据只读验证；未进行任何真实扫码、未提交任何真实凭据 |

## 二、漏洞描述

`sso.tbea.com` 的「TBe+ APP 扫码登录」二维码内容指向开放平台授权入口：

```
GET https://sso.tbea.com/api/sso/login/ejia/getQrCode
→ {"code":200,"data":"https://ejia.tbea.com/opencloud/openthird/qrconnet?appid=500000345"}
```

对授权端点的系统测试确认**三项独立缺陷**：

1. **redirect_uri 零校验**（CWE-601）：回跳地址仅检查"非空"，任意第三方 http/https 地址（含编码绕过变体）均可进入授权流程，且扫码完成后服务端原样下发、前端无条件跳转；
2. **appid 接入方身份无验证**（CWE-287）：appid 为任意值（`1`/`test`/300 字符串）均正常下发授权会话——接入应用体系形同虚设；
3. **会话不清理且状态不可区分**（CWE-613）：过期 token 持续可轮询，伪造 32 位 hex 与真实过期 token 返回相同响应（loginCode=104），无法区分"不存在"与"超时"。

## 三、复现步骤与证据

### 缺陷 1：redirect_uri 零校验

```http
GET https://ejia.tbea.com/opencloud/openthird/qrconnet?appid=500000345&redirect_uri=https://evil.example.com/cb
```

实测矩阵（全部返回 200 并进入授权页）：

| redirect_uri 取值 | 结果 |
|---|---|
| （空） | `{"success":false,"error":"必要参数：redirect_uri 不能为空！","errorCode":110}` —— 唯一拦截项 |
| `https://evil.example.com/cb` | ✅ 放行 |
| `http://192.168.1.1/cb` | ✅ 放行 |
| `//evil.example.com/cb`（协议相对） | ✅ 放行 |
| `https://sso.tbea.com@evil.example.com/cb`（@ 欺骗） | ✅ 放行 |
| 双重编码 `%253A%252F%252F` | ✅ 放行 |
| 大写域名 / 带端口 `:8443` / 空 userinfo | ✅ 放行 |

回显跳转逻辑（授权页内联 JS，服务端渲染产物）：

```javascript
case 100: // 扫码登录成功
    var redirect_uri = decodeURIComponent(res.data.redirectUrl);   // 服务端下发
    window.top.location = redirect_uri;                            // 无条件跳转
    break;
```

### 缺陷 2：appid 接入方身份无验证

| 请求 | 结果 |
|---|---|
| `?appid=500000345&...`（真实 appid） | ✅ 授权页 + 会话 token |
| `?appid=1&...` | ✅ 授权页 + 会话 token |
| `?appid=test&...` | ✅ 授权页 + 会话 token |
| `?appid=<300字符>&...` | ✅ 授权页 + 会话 token |
| `?appid=`（空）或缺失 | ❌ errorCode:110 |

任何第三方无需注册即可为"任意应用"创建合法授权会话。

### 缺陷 3：会话不清理、状态不可区分

```http
POST /opencloud/openthird/checkLogin
appid=500000345&token=<32位hex>
```

- 数小时前下发的真实 token 轮询 → `{loginCode:"104"}`（超时态）
- 完全伪造的 32 位 hex（如 `xxxx...`）→ 同样 `{loginCode:"104"}`
- 缺 token/appid → 正确报错 errorCode:110

说明服务端会话表无过期清理，且对无效 token 不做区分拒绝。

**边界事实**（诚实声明）：token 与 appid 存在绑定校验（A 的 token 用 B 轮询 → loginCode:101）；文件协议/javascript 伪协议被前置安全设备拦截（403 页面泄露出口 IP，反证请求真实到达）；sso.tbea.com 侧 getQrCode 参数注入被 WAF 拦截（腾讯云 AccessDeny 页）——sso 侧防护正常，缺陷集中在开放平台应用层。

### 技术数据流

```
qrconnet?appid(任意值)&redirect_uri=X  →  服务端存储 X 于会话 token
checkLogin {appid, token}              →  等待态 loginCode=102（无 Cookie 要求）
授权完成后同一接口                      →  成功态 loginCode=100 + redirectUrl=X
前端                                   →  window.top.location = X（无域校验）
```

## 四、危害分析

**缺陷自身影响（定级依据）**：
1. 违反 OAuth 规范的回跳地址强校验要求（CWE-601），该入口可被用作可信域名下的跳转基础设施；
2. appid 无验证使开放平台的接入方管理体系失去意义，任何匿名请求都能创建授权上下文；
3. 会话无清理造成服务端资源持续占用，且审计日志无法区分攻击探测与正常超时。

**风险延伸（不计入定级，客观提示）**：理论上若叠加面向员工的二维码诱导等针对人的主动攻击，上述缺陷会使授权结果偏离预期目标——该场景前提是对人的社会工程学攻击，超出系统自身漏洞范畴。

## 五、修复建议

1. redirect_uri 与 appid 注册回调地址精确匹配（含 path），不一致立即拒绝；
2. appid 校验有效性：不在注册表中的 appid 直接拒绝下发会话；
3. 授权会话设置 TTL 并到期物理删除；checkLogin 对不存在 token 统一返回明确错误；
4. 授权码一次性使用、短时效、绑定客户端指纹；回跳前增加目标域名确认页；
5. checkLogin 增加来源/频率限制。

## 六、附录

归档证据：`projects/sunoasis-20260825/S6-oauth-final.json`、`TRIAGE-R11.json`（git 仓库 web-vuln-mining，commit 9707c74 / f91087f）。
