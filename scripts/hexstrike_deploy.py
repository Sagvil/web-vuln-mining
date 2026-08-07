"""Deploy bundled HexStrike policy files to a configured Linux host."""
from __future__ import annotations
import argparse, base64, re, shlex, shutil, subprocess
from pathlib import Path
from common import WORKBENCH_ROOT, load_yaml
# ============================ Configuration zone ============================
REQUIRED_FIELDS = ("ssh_host", "ssh_port", "ssh_user", "identity_file", "known_hosts_file", "remote_root", "service_user", "policy_bind")
SERVICE_NAME = "web-vuln-mining-hexstrike.service"  # Managed remote systemd service name.
# ============================================================================
SAFE_HOST = re.compile(r"^[A-Za-z0-9_.:-]+$")
SAFE_USER = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
SAFE_ROOT = re.compile(r"^/[A-Za-z0-9_./-]+$")
SAFE_BIND = re.compile(r"^(?:127\.0\.0\.1|::1):[1-9][0-9]{0,4}$")


def checked(command: list[str]) -> None:
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if result.returncode: raise RuntimeError(f"command failed: {' '.join(command)}\n{result.stderr}")


def validate_remote_config(c: dict[str, object]) -> None:
    """Reject values that could change the generated remote shell command."""
    validators = {"ssh_host": SAFE_HOST, "ssh_user": SAFE_USER, "service_user": SAFE_USER, "remote_root": SAFE_ROOT, "policy_bind": SAFE_BIND}
    invalid = [key for key, expression in validators.items() if not expression.fullmatch(str(c.get(key, "")))]
    if invalid:
        raise SystemExit(f"Unsafe HexStrike config values: {', '.join(invalid)}")


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--config", type=Path, required=True); args = parser.parse_args()
    c = load_yaml(args.config)
    missing = [key for key in REQUIRED_FIELDS if not str(c.get(key, "")).strip() or str(c.get(key)).strip() in {"HOST", "PORT", "USER", "PATH_TO_SSH_KEY", "PATH_TO_KNOWN_HOSTS", "HEXSTRIKE_USER"}]
    if missing: raise SystemExit(f"Incomplete HexStrike config: {', '.join(missing)}")
    validate_remote_config(c)
    ssh, scp = shutil.which("ssh"), shutil.which("scp")
    if not ssh or not scp: raise SystemExit("OpenSSH client is required")
    target = f"{c['ssh_user']}@{c['ssh_host']}"; port = str(c["ssh_port"]); root = str(c["remote_root"]).rstrip("/")
    common = ["-p", port, "-i", str(Path(str(c["identity_file"])).expanduser()), "-o", f"UserKnownHostsFile={Path(str(c['known_hosts_file'])).expanduser()}", "-o", "StrictHostKeyChecking=yes"]
    remote_root, service_user = shlex.quote(root), shlex.quote(str(c["service_user"]))
    checked([ssh, *common, target, f"python3 --version && sudo mkdir -p {remote_root}/app {remote_root}/logs && sudo chown -R {service_user}:{service_user} {remote_root} && test -d /run/systemd/system"])
    for name in ("hexstrike_policy_service.py", "hexstrike_gate.py", "hexstrike_mcp.py", "hexstrike_policy_mcp.py"):
        checked([scp, *common, str(WORKBENCH_ROOT / "hexstrike" / name), f"{target}:/tmp/{name}"])
        checked([ssh, *common, target, f"sudo install -m 0755 -o {service_user} -g {service_user} /tmp/{name} {remote_root}/app/{name}"])
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
