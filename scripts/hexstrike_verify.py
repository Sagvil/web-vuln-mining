"""Verify SSH reachability, systemd state, and policy health for HexStrike."""
from __future__ import annotations
import argparse, shutil, subprocess
from pathlib import Path
from common import load_yaml
# ============================ Configuration zone ============================
SERVICE_NAME = "web-vuln-mining-hexstrike.service"  # Managed remote service name.
# ============================================================================
def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--config", type=Path, required=True); args = parser.parse_args(); c = load_yaml(args.config)
    ssh = shutil.which("ssh")
    if not ssh: raise SystemExit("OpenSSH client is required")
    target = f"{c['ssh_user']}@{c['ssh_host']}"
    common = ["-p", str(c["ssh_port"]), "-i", str(c["identity_file"]), "-o", f"UserKnownHostsFile={c['known_hosts_file']}", "-o", "StrictHostKeyChecking=yes"]
    command = f"systemctl is-active --quiet {SERVICE_NAME} && curl --fail --silent http://{c['policy_bind']}/health"
    return subprocess.run([ssh, *common, target, command]).returncode
if __name__ == "__main__": raise SystemExit(main())
