# Web 漏洞挖掘工作台

[English README](README.md)

## 项目目标

本项目提供一个可移植、版本锁定的本地 Web / Web API 漏洞挖掘工作台，面向 SQL 注入、XSS、IDOR、认证与授权缺陷、SSRF、文件上传、路径遍历、开放重定向、依赖风险与 API 参数校验问题。

项目边界仅覆盖网站、HTTP 服务、OpenAPI、GraphQL 与 Web 源码项目；不包含主机、端口、云资源、无线网络或操作系统侧扫描。

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

每次执行生成独立的 `runs/<timestamp>-<project>-<profile>/` 目录，保存目标快照、工具状态、原始结果、SARIF、证据引用、`summary.json` 和 `report.md`。

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

工具精确版本由 `config/tool-lock.windows.json`、`config/tool-lock.linux.json` 和 `config/tool-lock.linux-arm64.json` 锁定。ARM64 安装使用用户目录下的 Python 环境，不需要 `sudo`；原生发布包通过其发布校验清单验证，缺少 ARM64 资产时从锁定 Go tag 构建。Linux ARM64 上的 CodeQL 标记为平台禁用，并由本地 Semgrep taint 规则替代；不使用 AMD64 模拟执行。

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

安装器会安装全部 12 个固定版本工具、校验哈希、写入安装状态并运行预检。ARM64 使用现有的 Python、Java、Docker 与 Go 运行时，不执行 `apt` 或 `sudo`。已有克隆可显式执行 `python scripts/preflight.py --repair --json` 修复缺失、损坏或版本不符的工具；不带 `--repair` 的预检保持只读。

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

| Profile | 工具链 | 适用场景 |
| --- | --- | --- |
| `source` | Gitleaks → Trivy → Semgrep → CodeQL | 有源码的 Web 项目 |
| `web-baseline` | pd-httpx → Katana → 本地 Nuclei 规则 → ZAP 被动扫描 | 网站、后台、HTTP 服务 |
| `api` | Schemathesis → ZAP OpenAPI 导入和被动扫描 | 存在范围内 OpenAPI/GraphQL Schema 的 API |
| `verify-xss` | Dalfox | `--input` 提供的范围内 XSS 候选 URL |
| `verify-sqli` | sqlmap（level 1/risk 1） | `--input` 提供的范围内 SQL 注入候选 URL |
| `content-discovery` | ffuf | `--wordlist` 的受限副本，不递归 |

第二批工具默认安装，但不会随 `source`、`web-baseline` 或 `api` 自动执行。必须先在 TARGET.yaml 声明相应 Profile，再显式运行：

```powershell
python .\scripts\run_profile.py $scope --profile verify-xss --input .\candidates\xss-urls.txt
python .\scripts\run_profile.py $scope --profile verify-sqli --input .\candidates\sqli-urls.txt
python .\scripts\run_profile.py $scope --profile content-discovery --wordlist .\wordlists\paths.txt --max-requests 300
```

## Codex、Hermes 与 OpenClaw

```powershell
python .\scripts\install_agent.py codex
python .\scripts\install_agent.py hermes
python .\scripts\install_agent.py openclaw
```

Hermes 也可从 Git 安装：

```bash
hermes skills tap add https://github.com/OWNER/web-vuln-mining.git
hermes skills install web-vuln-mining
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
