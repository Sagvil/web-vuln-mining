# 补天公益 SRC 目录、官方资产提取与网址初筛

## 事实边界

- 公共接口 GET https://www.butian.net/Reward/pub?name=&p=N 提供项目目录；data.count 是页数。
- 公共响应仅包含项目 ID、公司名和头像，不包含补天官方资产网址。
- Loo/submit?cid=PROJECT_ID 在未登录时会跳转到补天 SSO。因此只有登录后的提交页提取结果才会标记为 source=official_submit_page。
- 提交页解析只接受可见的范围标签、范围字段值和带显式范围声明的 JSON；脚本、样式、导航/页脚链接及无范围声明的 JSON URL 均不会标记为官方资产。
- 历史 Bing/拼音脚本保留为“企业官网候选”材料；候选域名不会自动进入官方范围或初筛输入。

## 安装

~~~bash
cd /home/sagvil/web-vuln-mining/projects/butian-welfare-20260803
python3 -m venv ~/.local/share/butian-src-pipeline/venv
~/.local/share/butian-src-pipeline/venv/bin/pip install -r requirements-butian.txt
~~~

脚本使用现有 /snap/bin/chromium。可在脚本顶部配置区或通过
--browser-path、BUTIAN_BROWSER_PATH 覆盖路径。

## 常用命令

~~~bash
# 只获取公开项目目录；生成的检查点和导出文件位于 runs/butian-src/。
./run_pipeline.sh catalog --resume

# 通过 Hermes 的 VNC :1 打开独立浏览器配置目录；手动完成补天 SSO 后按 Enter。
./run_pipeline.sh login

# 使用私有会话访问提交页并导出正式资产范围。先用小批量验证解析结果。
./run_pipeline.sh extract --project-id 65453 --headful
./run_pipeline.sh extract --resume

# 只对 official_submit_page 的 include 资产做主页加最多四条同源链接的初筛。
./run_pipeline.sh prefilter --resume

# 串联：公开目录 → 已登录资产提取 → 初筛。
./run_pipeline.sh run --resume

# 批量模式：首次从第 1–3 页开始，默认收集 5 个目标；后续运行从 SQLite 游标继续。
# 加 --middle-ai 后仅 DeepSeek 判定为 priority_keep 的网址计入目标。
./run_pipeline.sh batch --target-kept 5 --page-span 3 --resume --middle-ai

# 明确要求复检时才重新访问已经记录的 URL。
./run_pipeline.sh batch --force-recheck --resume
~~~

会话状态默认存放在 ~/.local/share/butian-src-pipeline/storage-state.json，
Chromium 专用 Profile 默认存放在 ~/snap/chromium/common/butian-src-pipeline-profile（仅当前用户可读写）。
这是 Snap Chromium 的受限写入目录，可避免在 ~/.local/share 下创建 `SingletonLock` 时的权限报错；会话状态和 Profile 都不进入仓库、SQLite 导出或日志。
登录命令和带 `--headful` 的提取命令会显式传入 `XAUTHORITY=~/.Xauthority`，使 Snap Chromium 能访问 VNC `:1` 的 X11 Cookie；若 VNC 使用其他 Cookie 文件，可传入 `--xauthority PATH` 或设置 `BUTIAN_XAUTHORITY=PATH`。
如使用非 Snap Chromium，可通过 `--profile-dir PATH` 或 `BUTIAN_BROWSER_PROFILE=PATH` 指定独立 Profile。

## 初筛结果

| 状态 | 含义 |
|---|---|
| keep | 原始规则初筛通过；中筛前会进一步标为 priority_candidate 或 conditional_candidate。 |
| priority_keep | DeepSeek 中筛确认的高优先级网址；批量目标仅计入此层级。 |
| conditional_keep | AI 认为可保留但证据、范围或复杂度仍需后续确认；不计入批量目标。 |
| drop | 无效地址、私有/本地地址、非 HTML 根响应、停放页或低交互静态站。 |
| review | WAF/403/超时、外部跳转、SPA 空壳、信号矛盾或过高复杂度。 |

“没有登录入口”只会在同时缺少其他动态交互信号时参与剔除，避免把公开业务系统误判为静态站。

输出文件：

- catalog.jsonl：公开项目目录；
- official_assets.jsonl：登录后从提交页提取的正式资产及证据；
- prefilter.jsonl：每个网址的分数、理由、跳转链与响应摘要；
- kept_urls.txt：初筛保留网址；
- review.csv：需要人工确认的网址；
- run_manifest.json：本次初筛参数和计数；
- runs/butian-src/batches/batch-XXXX-manifest.json：批量运行的可恢复 manifest；
- ~/wiki/projects/butian-welfare-src-prefilter/url-registry.csv：跨批次 URL 快速比对表；
- ~/wiki/projects/butian-welfare-src-prefilter/batch-XXXX-results.csv：本批次全部 keep/review/drop/reused/excluded 记录；
- ~/wiki/projects/butian-welfare-src-prefilter/batch-XXXX-projects.csv：目录项目及资产提取状态；
- ~/wiki/projects/butian-welfare-src-prefilter/batch-XXXX.md：可阅读批次报告。
- ~/wiki/projects/butian-welfare-src-prefilter/batch-XXXX-subdomains.csv：按根域去重的 DNS 子域发现结果。
- ~/wiki/projects/butian-welfare-src-prefilter/batch-XXXX-middle-results.csv：DeepSeek 中筛结果。
- ~/wiki/projects/butian-welfare-src-prefilter/targets/TARGET_ID.md：逐网址 Wiki 索引页。
- runs/butian-src/targets/TARGET_ID/：初筛证据、子域 CSV/XML、AI 请求摘要和中筛报告。

批量游标以完整目录页块为单位推进。登录失效或页内提取失败不会推进游标；已保存的 URL 初筛结果会在恢复时复用。启用 `--middle-ai` 后，仅 `priority_keep` 计入批量目标，`conditional_keep`、`review` 和 `drop` 均保留在历史表中。


## DNS 子域足迹与 AI 中筛

初筛会对每个唯一注册根域缓存 30 天的 DNS 子域情报：证书透明度公开记录加 Nmap `dns-brute` 10k 字典。Nmap 使用 `-sn -n -Pn`，仅执行 DNS 枚举，不做端口、服务、登录、表单提交或漏洞探测。发现的子域仅写入情报和报告，不会自动标为补天官方范围。

子域加分：0–5 个为 0 分、6–14 个为 +1、15–19 个为 +2、20 个及以上为 +3。该分只会在官方网址、可访问 HTML、非停放/静态/WAF/外部跳转且已有交互证据时参与初筛；静态或营销页面不会因子域数量而通过。

```bash
# 初筛并进行 DNS 子域发现；通过初筛的网址生成独立档案目录。
./run_pipeline.sh prefilter --resume

# 对指定批次的初筛通过网址调用 DeepSeek V4 Flash 进行中筛。
./run_pipeline.sh middle --batch-id batch-XXXX --ai

# 强制刷新根域 DNS 情报或重新调用 DeepSeek。
./run_pipeline.sh middle --batch-id batch-XXXX --ai --force-middle-recheck
./run_pipeline.sh batch --middle-ai --force-subdomain-refresh --resume
```

DeepSeek 中筛从 `/home/sagvil/.hermes/.env` 读取 `DEEPSEEK_API_KEY`，调用 `https://api.deepseek.com/v1/chat/completions` 与 `deepseek-v4-flash`。密钥、Cookie、会话、浏览器 Profile、完整页面正文和表单内容均不写入运行目录、Wiki 或日志。AI 失败、超时、限流或返回无效 JSON 时，网址结论为 `review`。

通过初筛的网址在 `runs/butian-src/targets/TARGET_ID/` 中保留：`initial/` 初筛证据、`subdomains/` 子域 CSV/类型统计/Nmap XML、`middle/` AI 请求摘要、响应摘要和 `middle-report.md`。每个中筛网址都生成报告，即使 AI 调用失败。

## 可选 AI 边界复核

默认不调用模型。仅在规则结果为 review 且分数处于边界时，使用：

~~~bash
export BUTIAN_AI_ENDPOINT='https://HOST/v1/chat/completions'
export BUTIAN_AI_API_KEY='TOKEN'
export BUTIAN_AI_MODEL='MODEL'
./run_pipeline.sh prefilter --ai
~~~

AI 仅收到结构化分数、规则命中和页面摘要，不接收会话状态或完整页面正文。

## 验证

~~~bash
~/.local/share/butian-src-pipeline/venv/bin/python tests/test_butian_src_pipeline.py
./run_pipeline.sh catalog --dry-run
./run_pipeline.sh extract --dry-run
./run_pipeline.sh prefilter --dry-run
~~~

## 初筛并发参数

`prefilter` 与 `batch` 支持 `--prefilter-workers N`，默认 `3`，范围为 `1–8`。该参数只并发主页和最多四个同源浅层链接的 HTTP 探测；SQLite 写入、逐网址档案落盘和 DNS 发现结果写入仍由主线程串行完成，因此断点、CSV 和目标档案保持一致。

```bash
./run_pipeline.sh prefilter --input INPUT.jsonl --prefilter-workers 3
./run_pipeline.sh batch --target-kept 5 --page-span 3 --prefilter-workers 3 --middle-ai
```

全局 `--min-interval` 仍在所有并发工作线程间共享。证书透明度查询为辅助来源，`crt.sh` 异常时采用单次、最长 8 秒的快速失败；Nmap DNS 枚举继续执行并保存其 XML 结果。
