# 【补天公益 SRC 提交草稿】浙大妇院 womanhospital.cn — 知识库系统接口文档公开暴露自动登录(SSO)接口规范

**厂商/项目:** 浙江大学医学院附属妇产科医院（补天项目 64679）
**漏洞等级建议:** 低危（信息泄露 / 敏感接口规范公开）
**发现日期:** 2026-08-25 | **测试依据:** 补天公益 SRC 授权范围（womanhospital.cn 全子域）

---

## 漏洞描述

`ir.womanhospital.cn` 与 `lac.womanhospital.cn`（医院知识库系统，IIS 8.5）的 ASP.NET Web API Help Page 未做访问控制，公开暴露内部单点登录"自动登录"接口的完整规范文档，包含：

1. **接口地址与调用方式**: `GET /API/AutoLogin/Index?param={param}&target={target}`
2. **认证凭据结构**: param 为 JSON 经 **DES 加密**后传递，字段含：
   - `PassKey`（私钥，文档明示"单独获取"——即存在私钥分发渠道）
   - `WorkId`（工号，不可为空）
   - `PassWord`（密码）、`AuthorChName`（作者名）
   - `DepartmentName`（科室名称）
3. **危险业务语义**（文档原文）:
   - "使用param中工号判定用户是否存在，**如果不存在使用传递信息新建一个帐号**"
   - "**作者科室与传递科室不一致直接修改机构库作者科室**为当前传递科室"

## 危害分析

- 接口具备**自动创建账号**与**篡改机构库组织架构数据**的能力；其安全性完全依赖 PassKey 私钥的保密性
- 接口规范（含加密方式 DES、参数结构、业务副作用）的公开大幅降低攻击者逆向成本：一旦 PassKey 从任何分发渠道泄露（小程序包/APP/历史前端/内部文档），攻击者可伪造任意工号登录知识库并污染机构库数据
- 双主机（ir/lac 同源部署）同时暴露，扩大泄露面

## 复现步骤

```
1. 访问 https://ir.womanhospital.cn/api/help          → 返回接口导航页（HTTP 200，无需登录）
2. 点击/直接访问 https://ir.womanhospital.cn/API/Help/APIAutoLogin
   → 返回完整接口文档页（6521B），含上述全部参数说明与业务逻辑描述
3. https://lac.womanhospital.cn/api/help 及同名路径同样可达（同源双实例）
```

*已验证无害性：无参数访问 `/API/AutoLogin/Index` 返回 302 跳转，未进行任何伪造 param 的登录尝试（遵守公益 SRC 写入操作边界）。*

## 修复建议

1. `/api/help`、`/API/Help/*` 文档页面增加访问控制（仅内网/运维可访问），或生产环境直接关闭 HelpPage
2. AutoLogin 接口升级加密算法（DES → AES/HMAC 签名），PassKey 增加时效与绑定校验
3. 审计"自动建号"与"自动改科室"两个业务副作用的必要性，建议改为人工审核流程
4. 排查 PassKey 分发渠道是否有硬编码泄露（小程序/APP/历史版本）

## 附带观察（同轮次，供参考不单独计分）

- wxglht.womanhospital.cn 使用 jQuery 1.8.3（CVE-2012-6708/CVE-2015-9251 已知 XSS）
- www flexoffice SPA 前端壳未授权可达并泄露服务器路径拓扑（API 层认证正常）

---

*证据文件: runs/r3-womanhospital-stage1/stage4-autologin-docs.json 等 | 测试全程只读，无写入型探测*
