"""Install portable skill adapters and merge small managed agent configuration blocks."""
from __future__ import annotations
import argparse, json, shutil, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path
# ============================ Configuration zone ============================
MANAGED_BEGIN = "# BEGIN web-vuln-mining managed block"
MANAGED_END = "# END web-vuln-mining managed block"
# ============================================================================
ROOT = Path(__file__).resolve().parents[1]
def backup(path: Path) -> None:
    if path.exists(): shutil.copy2(path, path.with_suffix(path.suffix + "." + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".bak"))
def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("agent", choices=("codex", "hermes", "openclaw")); parser.add_argument("--skip-repair", action="store_true", help="install only the adapter without first-run tool repair"); args = parser.parse_args()
    home = Path.home(); adapter = ROOT / "adapters" / args.agent / "SKILL.md"
    if args.agent == "codex":
        target = home / ".codex" / "skills" / "web-vuln-mining"; target.mkdir(parents=True, exist_ok=True); shutil.copy2(adapter, target / "SKILL.md")
    elif args.agent == "hermes":
        target = home / ".hermes" / "skills" / "web-vuln-mining"; target.mkdir(parents=True, exist_ok=True); shutil.copy2(adapter, target / "SKILL.md")
        config = home / ".hermes" / "config.yaml"; backup(config); current = config.read_text(encoding="utf-8") if config.exists() else ""
        managed = f"{MANAGED_BEGIN}\n# WEB_VULN_MINING_ROOT: {ROOT}\n# Optional HexStrike hook is configured after remote deployment.\n{MANAGED_END}\n"
        if MANAGED_BEGIN in current: current = current[:current.index(MANAGED_BEGIN)] + managed + current[current.index(MANAGED_END) + len(MANAGED_END):].lstrip("\n")
        else: current += ("\n" if current and not current.endswith("\n") else "") + managed
        config.parent.mkdir(parents=True, exist_ok=True); config.write_text(current, encoding="utf-8")
    else:
        target = home / ".openclaw" / "skills" / "web-vuln-mining"; target.mkdir(parents=True, exist_ok=True); shutil.copy2(adapter, target / "SKILL.md")
        config = home / ".openclaw" / "web-vuln-mining.managed.json"; backup(config); config.write_text(json.dumps({"web_vuln_mining_root": str(ROOT), "skill_path": str(target)}, indent=2), encoding="utf-8")
    if not args.skip_repair:
        result = subprocess.run([sys.executable, str(ROOT / "scripts" / "preflight.py"), "--repair", "--json"])
        if result.returncode:
            return result.returncode
    print(target); return 0
if __name__ == "__main__": raise SystemExit(main())
