#!/usr/bin/env bash
set -euo pipefail
# ============================ Configuration zone ============================
# DATA_ROOT: user-owned root containing portable binaries and download cache.
# Versions and SHA-256 values mirror config/tool-lock.linux.json.
DATA_ROOT="${WEB_VULN_MINING_DATA:-$HOME/.local/share/web-vuln-mining}"
DALFOX_VERSION="3.1.2"
DALFOX_SHA256="ef48d30c183cead88eb89da10bdc1a7fa58a484d175319096075b470f3652fd4"
FFUF_VERSION="2.2.1"
FFUF_SHA256="86307885810d3c36ba4a3e9ba5178c2d9027bba0dd7f4ea39e39e7c972b62396"
SQLMAP_VERSION="1.10"
SQLMAP_SHA256="97b8fe8e06ed8b6c75c234f111393bae79e2c3d3283c086351354716277dfff1"
ONLY_TOOLS="${WEB_VULN_MINING_ONLY_TOOLS:-}"
# ============================================================================
CACHE="$DATA_ROOT/cache"
BIN="$DATA_ROOT/bin"
selected() { [[ -z "$ONLY_TOOLS" || ",$ONLY_TOOLS," == *",$1,"* ]]; }
download_verified() {
  local url="$1" output="$2" expected="$3"
  mkdir -p "$CACHE" "$BIN"
  if [[ ! -f "$output" ]] || ! echo "$expected  $output" | sha256sum --check --status; then
    rm -f "$output"; curl --fail --location --retry 3 --output "$output" "$url"
  fi
  echo "$expected  $output" | sha256sum --check --status
}
install_tar_binary() {
  local name="$1" url="$2" archive="$3" expected="$4" binary="$5" destination="$6" extract="$CACHE/extract-$name"
  download_verified "$url" "$archive" "$expected"
  rm -rf "$extract"; mkdir -p "$extract"
  tar -xzf "$archive" -C "$extract"
  install -m 0755 "$(find "$extract" -type f -name "$binary" | head -1)" "$destination"
}
if selected dalfox; then install_tar_binary dalfox "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VERSION}/dalfox-v${DALFOX_VERSION}-linux-x86_64.tar.gz" "$CACHE/dalfox-v${DALFOX_VERSION}-linux-x86_64.tar.gz" "$DALFOX_SHA256" dalfox "$BIN/dalfox"; fi
if selected ffuf; then install_tar_binary ffuf "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz" "$CACHE/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz" "$FFUF_SHA256" ffuf "$BIN/ffuf"; fi
if selected sqlmap; then sqlmap_archive="$CACHE/sqlmap-${SQLMAP_VERSION}.zip"; download_verified "https://codeload.github.com/sqlmapproject/sqlmap/zip/refs/tags/${SQLMAP_VERSION}" "$sqlmap_archive" "$SQLMAP_SHA256"; rm -rf "$CACHE/extract-sqlmap" "$BIN/sqlmap"; mkdir -p "$CACHE/extract-sqlmap"; unzip -q -o "$sqlmap_archive" -d "$CACHE/extract-sqlmap"; sqlmap_source="$(find "$CACHE/extract-sqlmap" -type f -name sqlmap.py -printf '%h\n' | head -1)"; [[ -n "$sqlmap_source" ]] || { echo 'sqlmap archive did not contain sqlmap.py' >&2; exit 1; }; cp -R "$sqlmap_source" "$BIN/sqlmap"; python3 "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/scripts/prepare_sqlmap.py" "$sqlmap_source" "$BIN/sqlmap"; test -f "$BIN/sqlmap/sqlmap_entry.zlib"; fi
printf 'Installed second-batch selection (%s) into %s\n' "${ONLY_TOOLS:-all}" "$BIN"
