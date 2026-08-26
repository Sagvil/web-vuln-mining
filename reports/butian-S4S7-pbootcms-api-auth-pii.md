# 漏洞报告：特变电工新能源 PbootCMS API 认证失效——个人信息泄露、未授权写入与隐藏内容批量越权

## 一、基本信息

| 项目 | 内容 |
|---|---|
| 漏洞名称 | www.sunoasis.com.cn（PbootCMS）API 网关签名认证失效，致个人信息泄露、人才推荐表单可被任意写入、下线内容批量越权读取、内部资料文件本体泄露 |
| 受影响资产 | `www.sunoasis.com.cn`、`info.sunoasis.com.cn`（特变电工新疆新能源股份有限公司，PbootCMS ≥3.2.5 / 自研文档中心，宝塔环境） |
| 漏洞类型 | CWE-287（认证不当）+ CWE-359（个人隐私信息泄露）+ CWE-284（访问控制缺失，未授权写入）+ CWE-538（文件和目录信息泄露） |
| 危害等级 | **高危**（PII 泄露 + 未授权写入 + 批量越权读取的组合） |
| 测试时间 | 2026-08-25 ~ 2026-08-26 |
| 测试性质 | 无凭据只读验证；写入测试仅提交一条带明显安全测试标记的记录用于闭环证明 |

## 二、漏洞描述

官网部署 PbootCMS 内容管理系统，其对外 API 网关为：

```
https://www.sunoasis.com.cn/api.php        （PATHINFO 路由：/api.php/{模块}/{动作}/{参数}/）
```

官方 PbootCMS 的 API 认证要求请求同时携带 `appid`、`timestamp`、`signature` 三个参数，以 `signature = md5(md5(api_appid + api_secret + timestamp))` 双层 MD5 校验并强制 15 秒时间窗防重放。本站点的服务端校验逻辑被修改为**仅检查 appid 参数是否存在**——任意非空值即可通过全部接口认证，防重放机制整体失效；且页面注入的 `appid='admin'` 为官方默认值未修改。

在此认证缺陷之上，实测确认以下三类影响（均为匿名可复现）：

1. **个人信息泄露**：人才推荐表单的历史提交数据（真实姓名、手机号等）可被任意第三方读取；
2. **未授权写入**：同一表单的提交接口完全开放，任何人可伪造人才推荐数据入库；
3. **隐藏内容批量越权**：内容详情接口按 id 遍历可获取 185 篇已从公开渠道下线的内容全文。

## 三、确定不公开但现在匿名可获取的信息清单

### A. 个人信息（原本仅后台可见 → 现在公网匿名可读）

```http
POST /api.php/cms/form/ HTTP/1.1
Content-Type: application/x-www-form-urlencoded

appid=x&fcode=1&page=1
```

返回 2 条真实「内部推荐」人才推荐记录（2022-2023 年），字段包括：

- 推荐人姓名：车展钊 / 被推荐人姓名：王皓（及另一组）
- 手机号两组：158****1289、180****3644（完整值在测试取证中留存）
- 岗位与所在地：值班员 / 王浩屯 等
- 提交者 IP（user_ip）、操作系统、浏览器（Android+Weixin / Windows10+Chrome）
- 内部审计字段：create_user=guest/admin、update_user=admin

**公开性判定**：该表单无任何前台展示页面，数据仅应存在于后台管理界面——确定属于非公开个人信息。《个人信息保护法》合规风险直接成立。

### B. 未授权写入（数据污染实锤）

```http
POST /api.php/cms/addmsg/
appid=x&user_push=SECURITY-TEST-DO-NOT-PROCESS&push_name=安全测试数据请忽略
&push_position=penetration-test&push_number=T0000&push_where=SECURITY-TEST
&user_tel=10000000000&push_tel=10000000001

→ {"code":1,"data":"留言提交成功！"}
```

提交后通过 cms/form 回读确认：**fcode=1 记录数由 2 条变为 3 条，测试记录 id=4 已入库且可被后续读取**——完整写读闭环。攻击者可批量伪造人才推荐数据污染招聘流程。（测试记录带明显标记，供管理员清理识别）

### C. 下线内容批量越权读取（185 篇）

内容详情接口按 id 枚举（`POST /api.php/content/index/ {appid:x, id:N}`），扫描 id 1~1808 共命中 907 篇，其中 **185 篇不在 sitemap.xml 中**（前台导航与 sitemap 均不可见）：

- **171 篇港股公告类内容**（scode=175）：特变电工股份层面的证券变动月报表、董事名单与其角色职能、ESG 报告、股东大会通函/投票表决结果、持续关连交易公告等（2017-2018 年历史合规文件）；
- **14 篇业务方案页**：智慧运维、智慧光伏、智慧风电、柔性储能、电能质量、柔性直流、隐私政策等未挂导航栏目。

**公开性判定**：这些内容已被主动从 sitemap 和前台导航移除（下线处理），但 API 按 id 遍历仍可完整读取正文——属于"已收回公开状态但实际仍暴露"。

### D. 内部资料文件本体泄露（13 篇，其中 1 份明确标注"内部资料"）

文档详情接口返回的 `file` 字段指向站内存储直链 `/backend/storage/files/<32位hex>.<ext>`，该存储目录**无任何鉴权校验**。119 篇隐藏文档中有 13 篇携带本地文件指针，文件本体可匿名直接下载：

```http
POST /backend/v1/detail {"filesId":115}     → file: /backend/storage/files/05986...7c.pdf
GET  /backend/storage/files/0598648072444a19d881673415860d7c.pdf   → 200 OK, 3,424,952B, %PDF-1.7
```

敏感性三重判定（字节级 hash 对照公开列表 + 全网搜索 + 文件自身标注）：

| 文件 | 判定 | 证据 |
|---|---|---|
| **组串式逆变器地面电站通信调试指导手册 V1.0（3.5 数采）.pdf**（42 页，2023-12 编制） | **内部资料实锤** | 首页明确标注「**内部资料 请勿外传**」；全网搜索零结果；官网公开下载页无此资料；泄露编制/校准人真实姓名（刘海侠、王楠、姬周珂） |
| TS330KTL-HV-C1 产品多视图、TS75-110KTL-A10、TS45-60KTL-A20 等 10 张 PNG | 未发布/下线产品外观图 | 公开列表无同名条目、hash 不在公开集合 |
| TSVG画册.pdf（15.7MB）、TSVG单页.pdf | 冗余暴露，无独立价值 | 与公开列表条目**字节级相同**（MD5 一致），属同一文件的重复入口 |

取证指纹：手册 MD5 `42108b1d1cd9175b4997d844e2a2ca63`；TSVG 画册 MD5 `099fdf5c8688bfcc546180984eba72ce`。

其余 106 篇隐藏文档的外链指向 `ecm.tbea.com`（华为文档云），匿名预览被统一认证 SSO 拦截——该部分为元数据与外发链接泄露，全文未验证可读。

### E. 系统情报（辅助攻击价值）

- 服务器绝对路径泄露：`/www/wwwroot/www.sunoasis.com.cn/core/basic/Kernel.php`（宝塔环境指纹）
- API 全部 19 个有效路由结构、站点配置（cms/site、cms/company、cms/label 全量）
- 内部编辑账号名：admin / tb-editor1 / tb-editor2

## 四、认证缺陷证据（根因）

页面每次渲染注入服务端签名三元组（index.html 内联脚本）：

```javascript
let siteKeys = { appid: 'admin', timestamp: '1787679036', signature: '8d0b50...' };
```

绕过矩阵实测（全部 POST /api.php/cms/search/）：

| 参数组合 | 结果 |
|---|---|
| 仅 `appid=x`（任意值） | ✅ 完全放行 |
| `appid=x&timestamp=0`（1970 过期时间戳） | ✅ 放行 |
| `appid=admin&signature=deadbeef`（错误签名） | ✅ 放行 |
| 不带任何参数 | ❌ 拒绝（唯一拦截条件是"appid 缺失"） |

**源码级对照**（PbootCMS 官方仓库 V3.2.5→V3.2.23 git 历史）：官方 `apps/common/ApiController.php::checkAccess()` 明确实现三参数校验 + 双层 MD5 + 15 秒窗口，模板标签 `{pboot:appid}/{pboot:signature}` 注入机制与目标一致——差异仅在服务端校验逻辑被移除，属代码级缺陷而非版本落后。SQL 注入已专项排除（ext_*/rorder 参数为引号包裹精确字符串比较，`00`/`0.0` 判别实验证实），避免误报。

## 五、危害影响汇总

1. **个人信息保护合规风险（最高优先）**：员工/求职者真实姓名+手机号+IP 公网匿名可读，违反《个人信息保护法》最小授权原则；
2. **业务数据完整性**：人才推荐流程可被任意第三方伪造数据污染，已有写入闭环证明；
3. **信息资产管理失效**：185 篇下线内容（含集团层面合规公告）仍可批量枚举，暴露内容治理缺口；
4. **内部资料外泄**：标注「内部资料 请勿外传」的 42 页调试手册可被任意匿名下载（含内部人员姓名），未发布产品外观图一并暴露；
5. **横向情报价值**：绝对路径、账号名、API 全貌为后续定向攻击提供基础。

## 六、修复建议

1. **立即恢复完整签名校验**：补齐 timestamp（±15 秒）+ signature 双层 MD5 校验，或升级官方最新版后重新配置；修改默认 api_appid='admin' 并轮换 api_secret；
2. **关闭公网表单接口**：cms/form、cms/msg、cms/addmsg、cms/addform 若无移动端需求应在网关层禁用；
3. **PII 应急处置**：清除或脱敏存量表单手机号；按《个保法》评估是否涉及通知义务；
4. **内部资料文件立即下架**：`/backend/storage/files/` 目录增加鉴权（或移出 Web 根），对 13 篇本地文件逐一评估去留；「内部资料 请勿外传」级文档严禁挂载于公网可达存储；
5. **清理下线内容**：对 171 篇港股公告类内容设置访问控制或物理删除；
6. **纵深防御**：/api.php 迁出公网或加 IP 白名单；修正 cms/page 异常回显避免泄露绝对路径。

## 七、附录

归档证据（git 仓库 web-vuln-mining）：
- `projects/sunoasis-20260825/pbootcms-api.json`（R4 认证绕过原始取证，commit f398c1a）
- `TRIAGE-R7.json` / `VERIFICATION-FINAL.json`（源码对照核验，commit fa4069a / 9707c74）
- `TRIAGE-R11.json` / `IMPACT-CONFIRMED.json`（写入闭环+危害清单，commit f91087f / bf91912）
- `sunoasis-local-files.json` / `evidence-manifest.json`（文件本体泄露清单+取证指纹，commit cf4aff2）
- `TRIAGE-R17.json`（敏感性三重判定，commit 814edb2）
- 取证副本：`evidence-manual-115.pdf`（内部手册，MD5 42108b1d…）/ `evidence-tsvg-catalog.pdf`（公开重复件，仅证冗余入口）
