# 漏洞报告：特变电工多台华为 WNM 网关硬编码加密密钥（可致凭据批量解密）

## 一、基本信息

| 项目 | 内容 |
|---|---|
| 漏洞名称 | 华为 WNM 网管系统前端登录加密使用全局硬编码 AES 密钥 |
| 受影响资产 | `portal.sunoasis.com.cn`、`bigdata.sunoasis.com.cn`、`em.sunoasis.com.cn`、`access.sunoasis.com.cn`、`vpn.sunoasis.com.cn` 共 5 台设备（同一 WNM 网管镜像） |
| 漏洞类型 | CWE-798（硬编码凭据/密钥）+ CWE-321（硬编码密码学密钥） |
| 危害等级 | **中危**（配合明文传输或中间人可升级） |
| 测试时间 | 2026-08-26 |
| 测试性质 | 前端静态资源分析；未提交任何登录请求、未进行任何爆破 |

## 二、漏洞描述

5 台子域均部署华为 WNM 网关（页面特征「Web managerment Home」+「安全产品管理平台」，路径 `/wnm/frame/`）。其登录页脚本 `/wnm/frame/login.js` 将用户凭据的"加密"实现完整暴露在前端，且 **AES 密钥与 IV 直接硬编码在代码中**：

```javascript
var o = u + p;   // 长度前缀(2位) + 用户名 + 长度前缀 + 密码
var k = CryptoJS.enc.Utf8.parse("1111111111111111");   // ★硬编码 Key
var e = CryptoJS.enc.Utf8.parse("2222222222222222");   // ★硬编码 IV
CryptoJS.AES.encrypt(o, k, { iv: e, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 })
```

由于密钥静态且全设备通用：

1. 任何能获取到登录流量（明文 http 模式、中间人、终端代理日志、浏览器缓存）的人均可**离线解密出管理员的明文账号密码**；
2. 同一密钥适用于**全部 5 台设备**，一处泄露全线失守；
3. 该"加密"仅提供混淆作用，不构成任何机密性保护。

另发现同文件存在调试后门代码路径：`localRun` 分支使用硬编码会话标识 `sessionid=abc1234` 直跳管理页（当前服务端不认可该值，仅作为开发调试残留记录）。

## 三、复现步骤与证据

### 步骤 1：确认资产指纹

4 个此前未深挖的子域（portal/bigdata/em/access）经指纹确认为与 vpn 相同的华为 WNM 网关：

```
GET https://portal.sunoasis.com.cn/web/index.html
→ 页面标题含「Web managerment Home」，注释含「安全产品管理平台」，资源路径 /wnm/*
```

> 注：这些站点 TLS 配置异常（旧算法），需宽松握手访问；443 开放，80 端口被 ACL 过滤。

### 步骤 2：提取硬编码密钥

```http
GET https://portal.sunoasis.com.cn/wnm/frame/login.js HTTP/1.1
```

关键代码原文（见第二节引用）：Key=`1111111111111111`，IV=`2222222222222222`，AES-CBC-PKCS7，明文格式为长度前缀拼接的用户名+密码。

### 步骤 3：登录协议逆向（仅协议层，未提交）

- 登录端点：`POST /wnm/frame/login.php`（POST-only，其他方法返回 `{"error":"Invalid request method","ssl":true}`）；
- 加密体格式：`2位长度+username+2位长度+password` 后整体 AES 加密；
- 按【一切登录面禁止爆破/禁止凭据提交】边界，本报告未向 login.php 提交任何构造凭据；上述信息足以支持离线解密验证。

### 步骤 4：影响面确认

5 台设备（portal/bigdata/em/access/vpn）的 login.js 内容一致——同一硬编码密钥覆盖全部实例。

## 四、真实性核验记录（诚实声明）

1. 密钥提取自服务端真实下发的 JS 文件（非猜测），可直接用于解密验证；
2. 未做真实抓包解密演示（需要有效登录流量，而登录测试受授权边界限制）；攻击者视角下该验证仅需一次明文信道抓包；
3. CVE 归因说明：公开检索通道受限，未能定位华为官方对应通告，按"无公开 CVE 可套用"如实记录，不影响漏洞本身成立。

## 五、危害影响

1. **凭据批量破解**：管理员口令一旦被截获即可离线还原，5 台网关同时沦陷；
2. **横向移动跳板**：WNM 为安全管理类平台，失陷后果远超单台 Web 资产；
3. **合规风险**：违反《网络安全等级保护》对密钥管理的强制要求。

## 六、修复建议

1. 移除前端硬编码密钥，改为 HTTPS 通道 + 服务端挑战响应（nonce）方案；
2. 强制 HTTPS 并关闭 ssl=false 明文回退模式；
3. 各设备独立密钥并纳入定期轮换；
4. 清理 localRun 调试分支与硬编码 sessionid；
5. 排查华为官方新版本补丁并升级。

## 七、附录

归档证据：`projects/sunoasis-20260825/TRIAGE-R5.json`（git 仓库 web-vuln-mining，commit 452a3d3）。
