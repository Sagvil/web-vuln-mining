"""Deploy bundled HexStrike policy files to a configured Linux host."""
from __future__ import annotations
import argparse, base64, shutil, subprocess
from pathlib import Path
from common import WORKBENCH_ROOT, load_yaml
# ============================ Configuration zone ============================
REQUIRED_FIELDS = ("ssh_host", "ssh_port", "ssh_user", "identity_file", "known_hosts_file", "remote_root", "service_user", "policy_bind")
SERVICE_NAME = "web-vuln-mining-hexstrike.service"  # Managed remote systemd service name.
# ============================================================================
def checked(command: list[str]) -> None:
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if result.returncode: raise RuntimeError(f"command failed: {' '.join(command)}\n{result.stderr}")
def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--config", type=Path, required=True); args = parser.parse_args()
    c = load_yaml(args.config)
    missing = [key for key in REQUIRED_FIELDS if not str(c.get(key, "")).strip() or str(c.get(key)).strip() in {"HOST", "PORT", "USER", "PATH_TO_SSH_KEY", "PATH_TO_KNOWN_HOSTS", "HEXSTRIKE_USER"}]
    if missing: raise SystemExit(f"Incomplete HexStrike config: {', '.join(missing)}")
    ssh, scp = shutil.which("ssh"), shutil.which("scp")
    if not ssh or not scp: raise SystemExit("OpenSSH client is required")
    target = f"{c['ssh_user']}@{c['ssh_host']}"; port = str(c["ssh_port"]); root = str(c["remote_root"]).rstrip("/")
    common = ["-p", port, "-i", str(Path(str(c["identity_file"])).expanduser()), "-o", f"UserKnownHostsFile={Path(str(c['known_hosts_file'])).expanduser()}", "-o", "StrictHostKeyChecking=yes"]
    checked([ssh, *common, target, f"python3 --version && sudo mkdir -p {root}/app {root}/logs && sudo chown -R {c['service_user']}:{c['service_user']} {root} && test -d /run/systemd/system"])
    for name in ("hexstrike_policy_service.py", "hexstrike_gate.py", "hexstrike_mcp.py"):
        checked([scp, *common, str(WORKBENCH_ROOT / "hexstrike" / name), f"{target}:/tmp/{name}"])
        checked([ssh, *common, target, f"sudo install -m 0755 -o {c['service_user']} -g {c['service_user']} /tmp/{name} {root}/app/{name}"])
    unit = f"""[Unit]
Description=Web Vuln Mining HexStrike policy service
After=network.target
[Service]
Type=simple
User={c['service_user']}
WorkingDirectory={root}/app
ExecStart=/usr/bin/python3 {root}/app/hexstrike_policy_service.py --bind {c['policy_bind']} --audit-log {root}/logs/policy-audit.jsonl
Restart=on-failure
[Install]
WantedBy=multi-user.target
"""
    encoded = base64.b64encode(unit.encode()).decode()
    checked([ssh, *common, target, f"echo {encoded} | base64 -d | sudo tee /etc/systemd/system/{SERVICE_NAME} >/dev/null && sudo systemctl daemon-reload && sudo systemctl enable --now {SERVICE_NAME} && sudo systemctl is-active --quiet {SERVICE_NAME}"])
    print(f"deployed {SERVICE_NAME} to {target}:{c['policy_bind']}"); return 0
if __name__ == "__main__": raise SystemExit(main())
