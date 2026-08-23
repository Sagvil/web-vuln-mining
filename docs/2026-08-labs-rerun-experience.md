# 三靶场全量重测经验总结（2026-08-23）

> 范围：OWASP Juice Shop 20.1.1（106/106 有效挑战）+ Pikachu（43/43）+ SQLi-Labs（65/65）——共 214 关，全部从零部署/硬重置后逐关真实执行。
> 本文是跨靶场经验汇总；各漏洞类别的详细剧本见 `templates/` 下对应模板。

## 1. 环境适配清单（老靶场 × 新运行时）

| 问题 | 现象 | 修复 | 影响 |
|---|---|---|---|
| PHP 8.3 移除 `MYSQL_ASSOC` | Pikachu 全部 SQL 页 Fatal | `define('MYSQL_ASSOC', MYSQLI_ASSOC)` | Pikachu 部署 |
| PHP 8.3 `mysqli_connect_errno()` 拒绝参数 | SQLi-Labs 全站 500 | 全仓 sed 去参数 | SQLi-Labs 部署 |
| PHP 8.3 mysqli 报错不显示（异常模式） | 报错型关卡无回显 | 改时间盲注/数据修改取证（模板 evidence-record §6） | 取证方法 |
| PHP 8.3 mysqlnd 强制 utf8mb4 | 宽字节注入失效 | `mysqli_set_charset($con,'gbk')` 临时 patch（打完回滚） | 注入技法 |
| mysqlnd `real_escape_string` 转义 GBK 首字节 | Less-36/37 宽字节被加固 | ⏭️ 环境限制（记录不硬刚） | 边界认知 |
| `php -S` cwd 影响相对路径 | Pikachu dir 遍历 500 | 以 vul/dir 为 cwd 启动 | 部署 |
| 缺 GD 扩展 | 验证码不显示 | `apt install php8.3-gd` | 部署 |
| RFI 关 | allow_url_include 关闭 | `php -d allow_url_include=1` 重启 | 部署 |
| Docker amd64 镜像 × arm64 主机 | exit 7 无法运行 | 本地源码 `php -S` 部署 | 部署决策 |

**原则**：环境适配改动分两类——可永久保留的（去参数化、define、GD）与必须回滚的（字符集 patch、探针文件）；回滚类用注释标注 `XXX-TEST-ONLY` 防止误提交。

## 2. 注入技法总表（跨靶场验证）

### SQL 注入
| 技法 | 关键点 | 实战场次 |
|---|---|---|
| UNION 回显 | 先 ORDER BY 探测列数；`-1`/`0` 前缀确保第一查询空 | Less-1~4, Juice Shop 搜索 |
| 报错注入 | `extractvalue(1,concat(0x7e,(SELECT ...)))`；数据在日志侧 | Less-58~65 |
| 时间盲注 | `AND sleep(2)` 延迟对比 | Less-5/6/8~10 |
| 宽字节 | **GBK 连接 + 原始字节 + 0 开头**三要素缺一不可 | Less-32~34, Pikachu sqli_widebyte |
| 二次注入 | 注册 `admin'#` → 改密时注释掉 WHERE 的引号/校验 | Less-24 |
| 堆叠注入 | 需 `mysqli_multi_query` 支持；POST 场景找裸拼字段（passwd） | Less-38~45 |
| ORDER BY 注入 | 裸数字=列号（`ORDER BY 0` 报错）、表达式=值（`2 AND 1=1`→列2） | Less-46~53 |
| 过滤绕过 | 无空格用 `/**/` 或括号法 `UNION(SELECT(1),(2),(3))`；`||'1` 闭合尾引号；大小写混合 `UnIoN SeLeCt`；真 `\t` 代替 `%09` | Less-23~31 |
| 挑战关（随机表） | information_schema 提取表名/列名 → 跨库 UNION/报错提取 secret → 双字段提交（answer_key + key） | Less-54~65 |

### 其他类别
| 类别 | 关键发现 | 实战场次 |
|---|---|---|
| XSS | PHP `htmlspecialchars` 不转义单引号 → 单引号属性注入；sanitize-html <2.x 非递归净化绕过；socket.io 事件直发判定 | Pikachu xss_02, Juice Shop 9 关 |
| JWT | alg=none；RS256→HS256（PEM 公钥当 HMAC 密钥，python 手写 HS256） | Juice Shop jwtForged |
| NoSQL | `'||true||'` 三态对比；$where 拼接格式随版本变（先看源码） | Juice Shop NoSQL |
| SSRF/SSTI | 本地监听器证明出网；`#{7*7}` 回显 49；Cookie 会话强制（`Blocked illegal activity` 是认证错非 WAF） | Juice Shop ssrf/ssti |
| 上传 | getimagesize 只验文件头 → GIF89a 图片马 getshell；ZIP Slip 写站内文件 | Pikachu upload, Juice Shop fileWrite |
| 竞态 | 3 线程并发即够；预检-更新间有人工延迟放大窗口 | Juice Shop timingAttack |

## 3. 编码与工具坑清单（最易踩）

1. **requests 二次编码**：`%09` 传参变 `%2509`、base64 cookie 的 `=` 被编码——**改用 curl 原样发送或 Python 传真字符**
2. **URL fragment 截断**：payload 含 `#`（如 z85 码）需 `%23`
3. **`-- ` 注释**：MySQL 需 `--` + 空格；`#` 注释会吃掉语句尾右括号——**payload 自带 `)`**（Pikachu sqli_header 教训）
4. **`-1` 前缀被过滤**：`[--]` 类过滤把 `-` 变 `1`——**统一 `0` 开头**
5. **UNION 列数探测**：报错型先 ORDER BY；回显型直接试 3/4 列
6. **编码/解码层差异**：URL 编码工具二次编码（`%25`）、curl 与 requests 的引号处理不同——**同一 payload 跨工具发送结果可能不同**
7. **Cookie 状态**：挑战类关卡 cookie 关联随机表，提交判定需同一会话
8. **尝试次数限制**：先读源码确认 `$times`（5~14 不等），提取次数压缩（GROUP_CONCAT）

## 4. 取证方法论（回显不可用时）

见 `templates/evidence-record.md` §6 取证实战技巧表——核心：**时间盲注 / 数据修改实锤 / 日志侧提取 / 排序差异 / 三态对比 / DB 直查 / socket.io 直发**，七条替代通道按场景选用，不死磕一种回显。

## 5. 方法论沉淀（五步法）

每关固定流程：**目标确认 → 模板方法执行 → 取证（证据入 evidence/）→ 判定 → 回写 wiki/模板**。

- 判定信号排序：服务端 solved/状态码+响应差异 > DB/文件落库验证 > 日志侧 > 自我观察
- 硬重置策略：删库前归档带时间戳 `.bak`，可回溯
- 挑战状态内存化：服务重启后轻量挑战重打
- 环境约束（本机 arm64）：Docker amd64 镜像不可用 → 源码部署
- 凭据纪律：对话与证据中所有真实凭据 [REDACTED]，测试改写的密码用后恢复

## 6. 遗留边界（诚实记录）

- Less-36/37：mysqlnd 加固转义 GBK 首字节，宽字节注入失效 → ⏭️ 环境限制
- Juice Shop 7 关未解锁：3 Web3（nftMint 等）+ 4 LLM/chatbot（用户指令跳过）
- browser_exec 禁本地地址 → DOM 类挑战用 socket.io 直发绕过
- vision_analyze 403 → ddddocr OCR 替代
