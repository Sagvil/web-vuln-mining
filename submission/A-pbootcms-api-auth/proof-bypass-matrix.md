# 证据：签名/时间戳校验失效（脱敏摘录版）

来源：2026-08-25~26 实测记录（原始响应仅内部归档，含 PII 不上传）。
性质：已验证（脱敏摘录）。

## A1. 绕过矩阵（POST /api.php/cms/search/；同型在 cms/form、cms/addmsg 复现）

| # | 参数组合 | 结果 |
|---|---|---|
| 1 | 仅 appid=x（任意非空值） | 放行，返回业务数据 |
| 2 | appid=x&timestamp=0（1970 过期时间戳） | 放行 |
| 3 | appid=admin&signature=deadbeef（错误签名） | 放行 |
| 4 | 不带任何参数 | 拒绝（唯一拦截条件：appid 缺失） |

页面每次渲染注入签名三元组（index.html 内联）：
`let siteKeys = { appid: 'admin', timestamp: '...', signature: '...' };`

## A2. 写入闭环（单条带标记测试记录）

POST /api.php/cms/addmsg/ 提交（全字段带 SECURITY-TEST/安全测试数据标记）
→ 响应 {"code":1,"data":"留言提交成功！"}
→ 回读 cms/form：fcode=1 记录数 2→3，测试记录 id=4 入库可读。
无后续写入；测试记录请求资产方清理。

## A3. PII 字段类型清单（不含任何真实值）

cms/form 返回历史人才推荐记录，含：推荐人姓名、被推荐人姓名、手机号、
岗位、所在地、提交者 IP、OS/浏览器、create_user/update_user 账号名。
真实值已脱敏，仅内部归档。

## 对照依据

官方 PbootCMS V3.2.5→V3.2.23 全历史 `ApiController::checkAccess()` 强制
appid+timestamp+signature 三参数（双层 MD5 + 15 秒窗口）；目标行为偏离官方实现。
SQL 注入候选已专项排除（不构成注入）。
