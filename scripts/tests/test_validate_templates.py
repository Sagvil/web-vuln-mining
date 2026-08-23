"""模板结构校验器测试。"""
import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from validate_templates import validate_template, REQUIRED_FIELDS, REQUIRED_SECTIONS

GOOD_TEMPLATE = """---
name: jwt-attacks
category: jwt
source: 渗透/juice-shop-closeout/patterns/jwt-attacks.md
verified_in: [juice-shop-113]
src_value: high
severity_ceiling: high
requires_auth: false
payload_count: 3
---

# JWT 攻击验证剧本

## 1. 识别
## 2. Payload 序列
## 3. 判定标准
## 4. 证据要求
## 5. SRC 适用边界
"""


def test_valid_template_passes():
    errors = validate_template(GOOD_TEMPLATE, source_base=Path("/home/sagvil"))
    assert errors == []


def test_missing_required_field_fails():
    t = GOOD_TEMPLATE.replace("payload_count: 3", "")
    errors = validate_template(t, source_base=Path("/home/sagvil"))
    assert any("payload_count" in e for e in errors)


def test_invalid_src_value_fails():
    t = GOOD_TEMPLATE.replace("src_value: high", "src_value: critical")
    errors = validate_template(t, source_base=Path("/home/sagvil"))
    assert any("src_value" in e for e in errors)


def test_missing_section_fails():
    t = GOOD_TEMPLATE.replace("## 5. SRC 适用边界", "## 5. (已删)")
    errors = validate_template(t, source_base=Path("/home/sagvil"))
    assert any("章节" in e for e in errors)
