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
| 操作系统 | Windows 10/11 x64、Ubuntu/Debian x64 | 工作台运行平台 |
| 基础环境 | Git、Python 3.11+、Java 17、`uv`/`uvx`、OpenSSH Client、`curl`、`tar`、`unzip` | 拉取仓库、运行 Python 工具与脚本、运行 ZAP、执行 SSH 集成和解压工具包 |
| 包管理器 | Windows 使用 `winget`；Ubuntu/Debian 使用 `apt` | Bootstrap 自动补齐基础环境 |
| 源码审计 | [Gitleaks](https://github.com/gitleaks/gitleaks)、[Trivy](https://github.com/aquasecurity/trivy)、[Semgrep](https://github.com/semgrep/semgrep)、[CodeQL](https://github.com/github/codeql) | 密钥、依赖/IaC、规则扫描和跨文件数据流分析 |
| Web 基线 | [ProjectDiscovery httpx](https://github.com/projectdiscovery/httpx)、[Katana](https://github.com/projectdiscovery/katana)、[Nuclei](https://github.com/projectdiscovery/nuclei)、[OWASP ZAP](https://www.zaproxy.org/) | HTTP 指纹、路由/JS 爬取、本地模板检查和被动 DAST |
| API 测试 | [Schemathesis](https://github.com/schemathesis/schemathesis)、OWASP ZAP | OpenAPI/GraphQL 性质测试、契约偏差和 API 被动检查 |
| 可选 Agent | Codex、[Hermes](https://github.com/NousResearch/hermes-agent)、[OpenClaw](https://github.com/openclaw/openclaw) | 通过 Skill 调度工作台 |
| 可选 HexStrike 服务 | 具备 Python 3、systemd、SSH 和 `sudo` 的 Linux 主机 | 部署远端策略和审计服务 |

工具精确版本由 `config/tool-lock.windows.json` 和 `config/tool-lock.linux.json` 锁定。安装器会下载、校验并登记工具状态；不需要 Docker、Go、Kali，也不会安装系统/网络扫描器。

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

安装器会自动安装基础依赖、下载并校验固定版本工具、写入用户数据目录的安装状态，最后运行预检。先查看将执行的基础依赖操作：

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

`verify-xss`、`verify-sqli`、`content-discovery` 保留给明确候选问题的 Dalfox、sqlmap、ffuf 工作流，不在默认流程中自动执行。

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
