# Web 漏洞挖掘工作台

[English README](README.md)

## 项目目标

本项目提供一个可移植、版本锁定的本地 Web / Web API 漏洞挖掘工作台，面向 SQL 注入、XSS、SSRF、文件上传、路径遍历、开放重定向、依赖风险与 API 参数校验问题输出**候选证据**。IDOR、鉴权和业务逻辑仅是人工审阅线索，绝不自动写成漏洞结论。

项目边界仅覆盖网站、HTTP 服务、OpenAPI、GraphQL 与 Web 源码项目；不包含主机、端口、云资源、无线网络或操作系统侧扫描。`active-dns-discovery` 是显式启用的 DNS 候选资产发现例外：只执行 DNS-brute，不执行端口或 HTTP 扫描。

## 原理与流程

```text
TARGET.yaml
  └─ 定义源码目录、精确 URL 范围、排除路径、速率与爬取预算
       └─ Bootstrap 安装并校验固定版本工具
            ├─ source：Gitleaks → Trivy → Semgrep → CodeQL
            ├─ web-baseline：pd-httpx → Katana → Nuclei → ZAP 被动扫描
            └─ api：Schemathesis → ZAP OpenAPI 导入与被动扫描
                 └─ 原始结果 / SARIF / 证据 → 去重归一化 → Markdown 报告
```

每次执行生成独立的 `runs/<timestamp>-<project>-<profile>/` 目录，保存目标快照、工具状态、原始结果、脱敏 SARIF、schema v2 证据、`summary.json`、英文报告与中文审阅摘要。

HexStrike 是独立的可选远端策略、审计和复核组件。即使远端服务未启用，本地 Profile 仍可完成；报告会分别显示 `LOCAL_TOOL_STATUS` 与 `HEXSTRIKE_STATUS`。

## 所需项目与运行环境

| 分类 | 要求 | 用途 |
| --- | --- | --- |
| 操作系统 | Windows 10/11 x64、Ubuntu/Debian x64、Ubuntu/Debian ARM64 | 工作台运行平台 |
| 基础环境 | Git、Python 3.11+、Java 17、OpenSSH Client、`curl`、`tar`、`unzip` | 拉取仓库、运行 Python 工具与脚本、运行 ZAP、执行 SSH 集成和解压工具包 |
| 包管理器 | Windows 使用 `winget`；Ubuntu/Debian x64 使用 `apt`；Ubuntu/Debian ARM64 无需包管理器 | ARM64 Bootstrap 在用户目录运行 |
| 源码审计 | [Gitleaks](https://github.com/gitleaks/gitleaks)、[Trivy](https://github.com/aquasecurity/trivy)、[Semgrep](https://github.com/semgrep/semgrep)、[CodeQL](https://github.com/github/codeql) | 密钥、依赖/IaC、规则扫描和跨文件数据流分析 |
| Web 基线 | [ProjectDiscovery httpx](https://github.com/projectdiscovery/httpx)、[Katana](https://github.com/projectdiscovery/katana)、[Nuclei](https://github.com/projectdiscovery/nuclei)、[OWASP ZAP](https://www.zaproxy.org/) | HTTP 指纹、路由/JS 爬取、本地模板检查和被动 DAST |
| API 测试 | [Schemathesis](https://github.com/schemathesis/schemathesis)、OWASP ZAP | OpenAPI/GraphQL 性质测试、契约偏差和 API 被动检查 |
| 候选验证 | [Dalfox](https://github.com/hahwul/dalfox)、[sqlmap](https://github.com/sqlmapproject/sqlmap) | 对明确的 XSS 与 SQL 注入候选进行验证 |
| 内容发现 | [ffuf](https://github.com/ffuf/ffuf) | Katana 覆盖不足时进行受预算限制的路由发现 |
| 可选 Agent | Codex、[Hermes](https://github.com/NousResearch/hermes-agent)、[OpenClaw](https://github.com/openclaw/openclaw) | 通过 Skill 调度工作台 |
| 可选 HexStrike 服务 | 具备 Python 3、systemd、SSH 和 `sudo` 的 Linux 主机 | 部署远端策略和审计服务 |

工具精确版本由 `config/tool-lock.windows.json`、`config/tool-lock.linux.json` 和 `config/tool-lock.linux-arm64.json` 的 v2 schema 锁定：每项记录静态下载 URL、artifact SHA-256、安装方法、可执行路径和平台状态。安装器不会运行时拉取 checksum 清单、不会 Go 动态构建，也不会使用可变 Docker tag；它会写入 `provenance.json`，包含 lock digest、最终二进制 digest 与 Python wheel `RECORD` 校验结果。只读预检发现任一不匹配即拒绝执行 Profile。ARM64 的 CodeQL 与 Dalfox 会明确标记不可用，绝不静默降级。

## 安装

### Windows

```powershell
git clone https://github.com/OWNER/web-vuln-mining.git
cd web-vuln-mining
$env:WEB_VULN_MINING_ROOT = $PWD
.\bootstrap\install.ps1 -Profile default -InstallCodexSkill
```

### Ubuntu / Debian

```bash
git clone https://github.com/OWNER/web-vuln-mining.git
cd web-vuln-mining
export WEB_VULN_MINING_ROOT="$PWD"
./bootstrap/install.sh --profile default --install-codex-skill
```

安装器仅安装静态锁定的资产到隔离的用户目录，Python 包通过 `pip --require-hashes` 安装，并写入 provenance 后执行预检；不会使用 Docker、Go、`uvx --from` 或动态 checksum。已有克隆可显式执行 `python scripts/preflight.py --repair --json` 修复；普通预检和 Profile 启动保持只读。

```powershell
.\bootstrap\install.ps1 -DryRun
```

```bash
./bootstrap/install.sh --dry-run
```

工具默认安装位置：Windows 为 `%LOCALAPPDATA%\web-vuln-mining`，Linux/macOS 为 `~/.local/share/web-vuln-mining`；Git 工作树不会保存二进制工具、缓存或扫描结果。

## 配置目标范围

复制 `scopes/TARGET.example.yaml` 为 `scopes/<项目名>.yaml`，配置：

- `source_root`：源码目录。
- `base_urls`、`openapi`、`include_hosts`：精确的 Web/API 范围。
- `exclude_paths`：排除路径，例如登出接口。
- `rate_limit`、`crawl_budget.max_depth`、`crawl_budget.max_pages`：请求和爬取预算。
- `auth.headers_file`：可选认证请求头文件；每行一个 `Name: value`。

本机工具路径或 HexStrike bridge 覆盖项写入 `config/local.runtime.yaml`。先从 `config/runtime.example.yaml` 复制创建；该文件被 Git 忽略。

运行器会在启动前校验项目名、URL、`include_hosts`、排除路径、速率、爬取预算和 Profile 声明；包含凭据、超出 `include_hosts` 或未声明 Profile 的配置会被拒绝。

## 执行 Profile

```powershell
$scope = '.\scopes\PROJECT.yaml'

python .\scripts\preflight.py --json --check-policy
python .\scripts\preflight.py --repair --json
python .\scripts\run_profile.py $scope --profile web-baseline --validate-only
python .\scripts\run_profile.py $scope --profile source
python .\scripts\run_profile.py $scope --profile web-baseline
python .\scripts\run_profile.py $scope --profile api
```

```powershell
python .\scripts\normalize_results.py <RUN_DIR>
python .\scripts\create_report.py <RUN_DIR>
```

真正执行 Profile 前，`run_profile.py` 会自动进行按 Profile 缩小范围的只读预检；`--validate-only` 仅验证 Scope，不下载、不修复。

| Profile | 工具链 | 适用场景 |
| --- | --- | --- |
| `source` | Gitleaks → Trivy → 本地 Semgrep 规则包 → CodeQL，附 CycloneDX SBOM | 有源码的 Web 项目 |
| `web-baseline` | pd-httpx → Katana → 仅 GET/HEAD 的本地 Nuclei 规则 → ZAP 被动扫描 | 网站、后台、HTTP 服务 |
| `api` | Schemathesis → 已下载 schema 的离线 OpenAPI lint → ZAP 被动扫描 | 存在范围内 OpenAPI/GraphQL Schema 的 API |
| `verify-xss` | Dalfox | `--input` 提供的范围内 XSS 候选 URL |
| `verify-sqli` | sqlmap（level 1/risk 1） | `--input` 提供的范围内 SQL 注入候选 URL |
| `content-discovery` | ffuf | `--wordlist` 的受限副本，不递归 |
| `active-dns-discovery` | Nmap dns-brute | 显式根域下的 DNS 候选资产；不自动扩大 Web 范围 |

第二批工具默认安装，但不会随 `source`、`web-baseline` 或 `api` 自动执行。必须先在 TARGET.yaml 声明相应 Profile，再显式运行：

```powershell
python .\scripts\run_profile.py $scope --profile verify-xss --input .\candidates\xss-urls.txt
python .\scripts\run_profile.py $scope --profile verify-sqli --input .\candidates\sqli-urls.txt
python .\scripts\run_profile.py $scope --profile content-discovery --wordlist .\wordlists\paths.txt --max-requests 300
```

## 覆盖矩阵与证据等级

| 范围 | 自动化输出 | 人工审阅线索 | 必须显式验证 |
| --- | --- | --- | --- |
| Python、JavaScript/TypeScript | 本地 Semgrep：注入、动态执行、SSRF、路径、反序列化、模板、上传、加密、JWT、跳转与 DOM sink | IDOR/鉴权形态的对象访问 | 是，规则命中只算 candidate |
| Web 基线 | 仅 GET/HEAD 的本地 Nuclei：Cookie、CORS、缓存、header、调试信息与 HTTPS 跳转 | header/缓存上下文 | 是，需人工核验行为和影响 |
| OpenAPI | 仅解析已下载 schema 的离线 lint | 鉴权声明、敏感操作、传输和约束 | 是；不跟随外部 `$ref` 或 `servers` |
| 平台提交 | 脱敏英文报告、中文审阅摘要、SARIF、JSON 证据 | 无 | `triage.yaml` 中同时满足 `reproduced`、`human_reviewed: true`、`scope_confirmed: true` |

运行 `python scripts/create_report.py <RUN_DIR>` 会生成 `report.md`、`review.zh-CN.md`、SARIF/JSON 证据、起始 `triage.yaml`、`submission/hackerone.md`、`submission/bugcrowd.md`、`submission/intigriti.md` 和提交清单。平台草稿默认排除所有未人工审阅、未复现或未确认 Scope 的 finding；本项目不保存平台凭据、不调用平台 API、不自动提交。

ZAP 仅作为本机控制面：运行器固定绑定 `127.0.0.1`，每次生成高熵 API key 与独立临时会话目录，并在成功、超时、异常路径都回收子进程和临时目录。普通日志不记录启动命令或 API key。

## CI 质量门禁

CI 在 Linux、Windows、ARM64 Runner 全量执行 `python -m unittest discover -s tests -v`。GitHub Action 的 commit SHA 集中记录在 `config/ci-actions.lock.json`，ARM64 容器使用 image digest 固定。CI 仅使用仓库 fixture、临时目录与 loopback 服务，绝不下载后扫描外部目标。

## DNS 候选资产发现

`active-dns-discovery` 默认关闭，必须在 TARGET.yaml 的 `profiles` 与 `active_dns_discovery` 中显式声明。它执行 `nmap -sn -n -Pn --script dns-brute`，保存 XML、截断词表、日志和 `asset-candidates.json`，随后结束。候选资产仅用于清单；只有将经审阅的主机名和 URL 写入新的 `include_hosts`、`base_urls` 与 Profile 声明后，才进入后续 Web 工作。

```yaml
profiles: [active-dns-discovery]
active_dns_discovery:
  roots: [example.test]
  wordlist: wordlists/dns-subdomains.txt
  max_words: 10000
  threads: 20
  max_candidates: 5000
```

## Codex、Hermes 与 OpenClaw

```powershell
python .\scripts\install_agent.py codex
python .\scripts\install_agent.py hermes
python .\scripts\install_agent.py openclaw
```

Hermes 也可从 Git 安装：

```bash
hermes skills tap add OWNER/web-vuln-mining
hermes skills install web-mining
hermes skills install pentest-orchestrator
```

OpenClaw：

```bash
openclaw skills install git:OWNER/web-vuln-mining@main --global
```

## HexStrike 远端部署

复制 `config/hexstrike.remote.example.yaml` 为 `config/hexstrike.remote.local.yaml`，填写 SSH 主机、端口、用户、私钥、Known Hosts、远端目录、服务用户和回环监听地址：

```powershell
.\bootstrap\install.ps1 -WithHexStrike -HexStrikeConfig .\config\hexstrike.remote.local.yaml
python .\scripts\hexstrike_verify.py --config .\config\hexstrike.remote.local.yaml
```

部署器上传组件、创建 `systemd` 服务、启动回环绑定的策略服务，并通过 SSH 验证 `/health`。远端地址、私钥、Token、Known Hosts、审计日志和本机覆盖配置不进入 Git。
