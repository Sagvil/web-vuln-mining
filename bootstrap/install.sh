#!/usr/bin/env bash
set -euo pipefail
# ============================ Configuration zone ============================
# PROFILE: default installs all twelve locked Web/API tools.
# DATA_ROOT: user-owned location for downloaded executable archives.
# WITH_HEXSTRIKE / HEXSTRIKE_CONFIG: deploy the optional remote policy service after local setup.
PROFILE="default"
DATA_ROOT="${WEB_VULN_MINING_DATA:-$HOME/.local/share/web-vuln-mining}"
WITH_HEXSTRIKE=0
HEXSTRIKE_CONFIG=""
INSTALL_CODEX_SKILL=0
REPAIR=0
ONLY_TOOLS=""
DRY_RUN=0
# ============================================================================

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE="$2"; shift 2;;
    --with-hexstrike) WITH_HEXSTRIKE=1; shift;;
    --hexstrike-config) HEXSTRIKE_CONFIG="$2"; shift 2;;
    --install-codex-skill) INSTALL_CODEX_SKILL=1; shift;;
    --repair) REPAIR=1; shift;;
    --only-tools) ONLY_TOOLS="$2"; shift 2;;
    --dry-run) DRY_RUN=1; shift;;
    *) echo "Unknown argument: $1" >&2; exit 2;;
  esac
done

# ARM64 hosts use a user-space installer: no apt, sudo, or system Python writes.
if [[ "$(uname -m)" == "aarch64" || "$(uname -m)" == "arm64" ]]; then
  arm_args=()
  [[ -n "$ONLY_TOOLS" ]] && arm_args+=(--only-tools "$ONLY_TOOLS")
  [[ "$REPAIR" = 1 ]] && arm_args+=(--repair)
  if [[ "$DRY_RUN" = 1 ]]; then
    printf '[dry-run] python3 %q ' "$ROOT/bootstrap/install_arm64.py"; printf '%q ' "${arm_args[@]}"; echo
  else
    WEB_VULN_MINING_DATA="$DATA_ROOT" python3 "$ROOT/bootstrap/install_arm64.py" "${arm_args[@]}"
    if [[ "$REPAIR" != 1 || -z "$ONLY_TOOLS" ]]; then
      WEB_VULN_MINING_DATA="$DATA_ROOT" python3 "$ROOT/scripts/preflight.py" --json --check-policy | tee "$DATA_ROOT/preflight-latest.json"
    fi
  fi
  if [[ "$INSTALL_CODEX_SKILL" = 1 ]]; then
    mkdir -p "$HOME/.codex/skills/web-vuln-mining"
    cp "$ROOT/adapters/codex/SKILL.md" "$HOME/.codex/skills/web-vuln-mining/SKILL.md"
  fi
  if [[ "$WITH_HEXSTRIKE" = 1 ]]; then
    [[ -n "$HEXSTRIKE_CONFIG" ]] || { echo '--with-hexstrike requires --hexstrike-config' >&2; exit 2; }
    [[ "$DRY_RUN" = 1 ]] && echo "[dry-run] deploy HexStrike using $HEXSTRIKE_CONFIG" || python3 "$ROOT/scripts/hexstrike_deploy.py" --config "$HEXSTRIKE_CONFIG"
  fi
  exit 0
fi

run() { if [[ "$DRY_RUN" = 1 ]]; then printf '[dry-run] '; printf '%q ' "$@"; echo; else "$@"; fi; }
selected() { [[ -z "$ONLY_TOOLS" || ",$ONLY_TOOLS," == *",$1,"* ]]; }
selected_any() { local item; for item in "$@"; do selected "$item" && return 0; done; return 1; }
install_prerequisites() {
  if command -v apt-get >/dev/null; then
    run sudo apt-get update
    run sudo apt-get install -y git python3 python3-venv python3-pip openjdk-17-jre-headless curl unzip tar openssh-client
  else
    echo "This bootstrap currently supports Ubuntu/Debian systems with apt-get." >&2; exit 1
  fi
  command -v uvx >/dev/null || run python3 -m pip install --user 'uv>=0.4'
}
download() { local url="$1" output="$2"; run mkdir -p "$(dirname "$output")"; run curl --fail --location --retry 3 --output "$output" "$url"; }
download_verified() {
  local url="$1" output="$2" expected="$3"
  if [[ ! -f "$output" ]] || ! echo "$expected  $output" | sha256sum --check --status; then rm -f "$output"; download "$url" "$output"; fi
  echo "$expected  $output" | sha256sum --check --status
}
checksum_from_manifest() {
  local manifest="$1" asset="$2" cache="$3"
  download "$manifest" "$cache"
  grep -E "(^|[[:space:]])${asset//./\\.}([[:space:]]|$)" "$cache" | head -1 | awk '{print $1}'
}
verified_archive() {
  local name="$1" url="$2" checksums="$3" asset="$4" target="$5"
  local expected cache="${DATA_ROOT}/cache/${name}-checksums.txt"
  expected="$(checksum_from_manifest "$checksums" "$asset" "$cache")"
  [[ -n "$expected" ]] || { echo "Checksum not found for $asset" >&2; exit 1; }
  download "$url" "$target"
  echo "$expected  $target" | sha256sum --check --status
}
install_archive_tool() {
  local name="$1" version="$2" asset="$3" checksums="$4" binary="$5" destination="$6"
  local archive="${DATA_ROOT}/cache/${asset}" url="https://github.com/${name}/releases/download/v${version}/${asset}" extract="${DATA_ROOT}/cache/extract-${name//\//-}"
  verified_archive "$name" "$url" "$checksums" "$asset" "$archive"
  run rm -rf "$extract"; run mkdir -p "$extract" "$(dirname "$destination")"
  case "$asset" in *.zip) run unzip -q -o "$archive" -d "$extract";; *) run tar -xf "$archive" -C "$extract";; esac
  run install -m 0755 "$(find "$extract" -type f -name "$binary" | head -1)" "$destination"
}

install_prerequisites
if [[ "$DRY_RUN" = 0 ]]; then
  if selected codeql; then codeql_archive="${DATA_ROOT}/cache/codeql-bundle-linux64.tar.gz"; download_verified 'https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.26.1/codeql-bundle-linux64.tar.gz' "$codeql_archive" '38eca75ea296a6c48c52aff942b0678f06d3367140a5aa18caf80176943422ba'; rm -rf "${DATA_ROOT}/bin/codeql"; mkdir -p "${DATA_ROOT}/bin"; tar -xzf "$codeql_archive" -C "${DATA_ROOT}/bin"; fi
  if selected trivy; then install_archive_tool 'aquasecurity/trivy' '0.72.0' 'trivy_0.72.0_Linux-64bit.tar.gz' 'https://github.com/aquasecurity/trivy/releases/download/v0.72.0/trivy_0.72.0_checksums.txt' trivy "${DATA_ROOT}/bin/trivy"; fi
  if selected gitleaks; then install_archive_tool 'gitleaks/gitleaks' '8.30.1' 'gitleaks_8.30.1_linux_x64.tar.gz' 'https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_checksums.txt' gitleaks "${DATA_ROOT}/bin/gitleaks"; fi
  if selected nuclei; then install_archive_tool 'projectdiscovery/nuclei' '3.11.0' 'nuclei_3.11.0_linux_amd64.zip' 'https://github.com/projectdiscovery/nuclei/releases/download/v3.11.0/nuclei_3.11.0_checksums.txt' nuclei "${DATA_ROOT}/bin/nuclei"; fi
  if selected pd-httpx; then install_archive_tool 'projectdiscovery/httpx' '1.10.0' 'httpx_1.10.0_linux_amd64.zip' 'https://github.com/projectdiscovery/httpx/releases/download/v1.10.0/httpx_1.10.0_checksums.txt' httpx "${DATA_ROOT}/bin/pd-httpx"; fi
  if selected katana; then install_archive_tool 'projectdiscovery/katana' '1.6.1' 'katana_1.6.1_linux_amd64.zip' 'https://github.com/projectdiscovery/katana/releases/download/v1.6.1/katana-1.6.1-checksums.txt' katana "${DATA_ROOT}/bin/katana"; fi
  if selected zap; then zap_archive="${DATA_ROOT}/cache/ZAP_2.17.0_Crossplatform.zip"; download 'https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Crossplatform.zip' "$zap_archive"; echo '94c8f767b1c2e94f0db66b3ae56514d5e3f5a728ee1b6c798e0c8fe2d61fbff0  '"$zap_archive" | sha256sum --check --status; rm -rf "${DATA_ROOT}/bin/zap"; mkdir -p "${DATA_ROOT}/bin/zap"; unzip -q -o "$zap_archive" -d "${DATA_ROOT}/bin/zap"; fi
  if selected semgrep; then python3 -m venv "${DATA_ROOT}/bin/python-tools"; "${DATA_ROOT}/bin/python-tools/bin/python" -m pip install --upgrade pip 'semgrep==1.171.0' 'PyYAML==6.0.3'; fi
  if selected runtime || [[ -z "$ONLY_TOOLS" ]]; then python3 -m pip install --user -r "$ROOT/requirements-runner.txt"; fi
  if selected_any dalfox sqlmap ffuf; then WEB_VULN_MINING_DATA="$DATA_ROOT" WEB_VULN_MINING_ONLY_TOOLS="$ONLY_TOOLS" "$ROOT/bootstrap/install_extensions.sh"; fi
  if [[ "$REPAIR" = 1 && -n "$ONLY_TOOLS" ]]; then
    echo "Repair subset installed; caller will re-run preflight: $ONLY_TOOLS"
  else
    WEB_VULN_MINING_DATA="$DATA_ROOT" python3 "$ROOT/scripts/preflight.py" --json --check-policy | tee "${DATA_ROOT}/preflight-latest.json"
    WEB_VULN_MINING_DATA="$DATA_ROOT" PROFILE="$PROFILE" ROOT="$ROOT" python3 -c 'import hashlib,json,os,pathlib,datetime; root=pathlib.Path(os.environ["ROOT"]); report=json.loads((pathlib.Path(os.environ["WEB_VULN_MINING_DATA"])/"preflight-latest.json").read_text()); lock=root/"config"/"tool-lock.linux.json"; state={"schema_version":1,"installed_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"platform":"linux","profile":os.environ["PROFILE"],"data_root":os.environ["WEB_VULN_MINING_DATA"],"lock_sha256":hashlib.sha256(lock.read_bytes()).hexdigest(),"tools":report["tools"]}; (pathlib.Path(os.environ["WEB_VULN_MINING_DATA"])/"install-state.json").write_text(json.dumps(state,indent=2))'
  fi
fi
if [[ "$INSTALL_CODEX_SKILL" = 1 ]]; then
  mkdir -p "$HOME/.codex/skills/web-vuln-mining"
  cp "$ROOT/adapters/codex/SKILL.md" "$HOME/.codex/skills/web-vuln-mining/SKILL.md"
fi
if [[ "$WITH_HEXSTRIKE" = 1 ]]; then
  [[ -n "$HEXSTRIKE_CONFIG" ]] || { echo '--with-hexstrike requires --hexstrike-config' >&2; exit 2; }
  if [[ "$DRY_RUN" = 1 ]]; then echo "[dry-run] install HexStrike requirements and deploy using $HEXSTRIKE_CONFIG"
  else python3 -m pip install --user --upgrade -r "$ROOT/requirements-hexstrike.txt"; python3 "$ROOT/scripts/hexstrike_deploy.py" --config "$HEXSTRIKE_CONFIG"; fi
fi
