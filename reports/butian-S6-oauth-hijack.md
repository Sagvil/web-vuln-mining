# 漏洞报告：特变电工开放平台 OAuth 扫码登录 redirect_uri 未校验

## 一、基本信息

| 项目 | 内容 |
|---|---|
| 漏洞名称 | ejia.tbea.com 开放平台扫码登录回调地址（redirect_uri）未做域名校验 |
| 受影响资产 | `ejia.tbea.com`（特变电工开放平台 / TBe+ 开放接入体系，openresty） |
| 入口关联 | 特变电工统一认证平台 `sso.tbea.com`「TBe+ 扫码登录」功能（`/api/sso/login/ejia/getQrCode` 返回该入口） |
| 漏洞类型 | CWE-601（URL Redirect 未校验）/ 回跳地址校验缺失 |
| 危害等级 | **低危～中危**（按服务端既有缺陷定性；不含依赖诱导用户配合的攻击场景） |
| 测试时间 | 2026-08-26 |
| 测试性质 | 无凭据只读验证；未进行任何真实扫码、未提交任何真实凭据 |

## 二、漏洞描述

`sso.tbea.com` 的「TBe+ APP 扫码登录」二维码内容指向开放平台授权入口：

```
https://sso.tbea.com/api/sso/login/ejia/getQrCode
→ {"code":200,"data":"https://ejia.tbea.com/opencloud/openthird/qrconnet?appid=500000345"}
```

该授权端点接受外部传入的 `redirect_uri` 参数作为授权完成后的回跳地址。**服务端对该参数不做任何白名单/域名归属校验**——任意第三方 http/https 地址均可携带进入授权流程，且授权完成后服务端将该值原样下发、前端直接跳转，全程无一致性校验。

**本报告的定级边界说明**：以上为系统自身存在的输入校验缺失（回跳地址不校验）。至于该缺陷在实际环境中是否进一步导致凭据/会话被窃取，需要额外叠加"诱导用户扫恶意二维码"等针对人的主动攻击手段——此类场景不属于系统自身的漏洞范畴，**不作为本报告的定级依据**，仅在危害分析中作为风险延伸客观提及。

## 三、复现步骤与证据

### 步骤 1：获取正常授权入口

```http
GET https://sso.tbea.com/api/sso/login/ejia/getQrCode HTTP/1.1
```

响应：

```json
{"code":200,"message":null,"data":"https://ejia.tbea.com/opencloud/openthird/qrconnet?appid=500000345"}
```

### 步骤 2：redirect_uri 白名单缺失实证

在授权入口后追加外域回调地址：

```http
GET https://ejia.tbea.com/opencloud/openthird/qrconnet?appid=500000345&redirect_uri=https://evil.example.com/cb HTTP/1.1
```

实测结果矩阵：

| redirect_uri 取值 | 结果 |
|---|---|
| （空） | `{"success":false,"error":"必要参数：redirect_uri 不能为空！","errorCode":110}` —— 唯一拦截项 |
| `https://evil.example.com/cb`（外域） | ✅ 返回授权页 HTML |
| `http://192.168.1.1/cb`（内网 IP） | ✅ 返回授权页 HTML |
| `//evil.example.com/cb`（协议相对） | ✅ 返回授权页 HTML |
| `https://sso.tbea.com@evil.example.com/cb`（@ 欺骗） | ✅ 返回授权页 HTML |
| `file:///etc/passwd`、`javascript:alert(1)` | 前置安全设备 403（设备存在，但规则未覆盖 http/https 外域场景） |

结论：服务端仅校验"参数非空"，未校验取值合法性——与 OAuth 规范中 redirect_uri 必须精确匹配注册值的要求不符。

### 步骤 3：会话令牌下发与轮询接口可达性

授权页包含服务端下发的隐藏会话令牌：

```html
<input type="hidden" value=96f8c67f74790deda7554b9141c20245 id="token">
```

轮询接口无需 Cookie 即可查询扫码状态：

```http
POST /opencloud/openthird/checkLogin HTTP/1.1
Host: ejia.tbea.com
Content-Type: application/x-www-form-urlencoded

appid=500000345&token=96f8c67f74790deda7554b9141c20245
```

响应（等待扫码状态）：

```json
{"success":true,"error":null,"errorCode":100,"data":{"loginCode":"102"}}
```

> 状态码语义（来自前端代码）：102=等待扫码，100=扫码成功，103=取消，104=超时。
> 对比测试：不同会话生成的 token 各不相同（独立生成），token 与 redirect_uri 的绑定关系由服务端维护。

### 步骤 4：回显跳转逻辑确认（代码级）

授权页内联 JavaScript 关键片段原文：

```javascript
case 100: // 扫码登录成功
    var redirect_uri = decodeURIComponent(res.data.redirectUrl);
    if (parent)
        window.top.location = redirect_uri
    else
        window.location = redirect_uri;
    break;
```

要点：扫码成功时 `res.data.redirectUrl` 由服务端返回——证明 redirect_uri 已随会话存储于服务端并在授权完成后原样下发；前端拿到后直接跳转，无域名校验、无停留提示。

### 数据流示意（技术原理）

```
qrconnet?appid&redirect_uri=X   →   服务端存储 X 于 token 会话
checkLogin {appid, token}       →   等待态返回 loginCode=102
（授权完成后同一接口）            →   成功态返回 loginCode=100 + redirectUrl=X
前端                            →   window.top.location = X（无校验）
```

## 四、真实性核验记录（诚实声明）

1. redirect_uri 全外域放行为行为级实证（E1 矩阵）；回显跳转为页面 JS 代码级实证（服务端渲染产物）；轮询接口状态机实测可达（loginCode=102）；
2. `file://`/`javascript:` 触发前置设备 403 页面泄露出口 IP，反证请求真实到达目标侧安全层，排除响应伪造；
3. 授权成功态（loginCode=100）的真实响应体未捕获（需真实账号完成授权），但上述三项事实已独立成立，不依赖该环节；
4. 定级严格限于"服务端未校验回跳地址"这一既有缺陷本身。

## 五、危害分析

**缺陷自身的影响（定级依据）**：
1. 违反 OAuth/OIDC 规范对 redirect_uri 的强制校验要求，属于认证流程的实现不规范（CWE-601 类开放重定向基础缺陷）；
2. 该入口可被用作可信域名下的跳转基础设施（回跳地址可控），为钓鱼链接提供"看起来来自 tbea.com 授权体系"的外壳；
3. 若开放平台后续接入更多第三方应用（appid 体系），同一缺失将系统性存在于所有接入应用的授权流程。

**风险延伸（不计入定级，仅客观提示）**：理论上若有人额外实施面向员工的二维码诱导（社会工程学攻击），该缺陷会使授权结果偏离预期目标——但该场景的前提是对人的主动攻击，超出系统自身漏洞范围。

## 六、修复建议

1. **redirect_uri 白名单**：服务端严格校验 redirect_uri 与 appid 注册时绑定的回调地址完全一致（精确匹配含 path），不一致立即拒绝；
2. **state 参数**：授权请求签发一次性随机 state 并在回调时强校验；
3. **授权码治理**：一次性使用、有效期 ≤60 秒、与客户端指纹绑定；
4. **回跳前确认页**：展示明确的目标域名供用户确认，避免静默跳转；
5. **轮询接口收敛**：checkLogin 增加来源/频率限制，token 与客户端会话绑定。

## 七、附录

归档证据：`runs/sunoasis-oauth-redirect.json`、`projects/sunoasis-20260825/S6-oauth-final.json`（git 仓库 web-vuln-mining）。
