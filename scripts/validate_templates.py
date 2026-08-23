"""模板结构校验器：校验 templates/*.md 的 frontmatter 与章节完整性。"""
import re
import sys
from pathlib import Path

REQUIRED_FIELDS = {
    "name": str, "category": str, "source": str, "verified_in": list,
    "src_value": str, "severity_ceiling": str,
    "requires_auth": bool, "payload_count": int,
}
VALID_SRC_VALUES = {"high", "medium", "low"}
REQUIRED_SECTIONS = ["## 1. 识别", "## 2. Payload", "## 3. 判定", "## 4. 证据", "## 5. SRC"]


def parse_frontmatter(text: str) -> dict | None:
    m = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
    if not m:
        return None
    fm = {}
    for line in m.group(1).splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        v = v.strip()
        if v.startswith("[") and v.endswith("]"):
            fm[k.strip()] = [x.strip() for x in v[1:-1].split(",") if x.strip()]
        elif v in ("true", "false"):
            fm[k.strip()] = v == "true"
        elif v.isdigit():
            fm[k.strip()] = int(v)
        else:
            fm[k.strip()] = v
    return fm


def validate_template(text: str, source_base: Path | None = None) -> list[str]:
    errors = []
    fm = parse_frontmatter(text)
    if fm is None:
        return ["缺少 YAML frontmatter"]
    for field, ftype in REQUIRED_FIELDS.items():
        if field not in fm:
            errors.append(f"缺少必需字段: {field}")
        elif not isinstance(fm[field], ftype):
            errors.append(f"字段类型错误: {field} 应为 {ftype.__name__}")
    if "src_value" in fm and fm["src_value"] not in VALID_SRC_VALUES:
        errors.append(f"src_value 非法: {fm['src_value']}")
    if source_base and "source" in fm and fm["source"]:
        src = source_base / fm["source"]
        if not src.exists():
            errors.append(f"source 路径不存在: {fm['source']}")
    for section in REQUIRED_SECTIONS:
        if section not in text:
            errors.append(f"缺少章节: {section}")
    return errors


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    tdir = root / "templates"
    if not tdir.exists():
        print(f"FAIL: {tdir} 不存在")
        return 1
    failed = False
    for f in sorted(tdir.glob("*.md")):
        errors = validate_template(f.read_text(encoding="utf-8"), source_base=Path("/home/sagvil"))
        if errors:
            failed = True
            print(f"FAIL {f.name}:")
            for e in errors:
                print(f"  - {e}")
        else:
            print(f"PASS {f.name}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
