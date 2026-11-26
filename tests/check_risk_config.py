#!/usr/bin/env python3
"""P0.5.3: strict pre-deployment validation of Gateway Risk Engine variables.

This is an offline, read-only preflight. It never runs shell code, never loads
secrets into os.environ, never prints dotenv values, and never contacts Docker
or Redis. Run against the .env file that gateway env_file actually consumes.

Usage: python3 tests/check_risk_config.py --env-file /path/to/.env
"""
from __future__ import annotations

import argparse
import math
from pathlib import Path
import re
import sys
from typing import Mapping

REQUIRED = (
    "RISK_LIMIT_THRESHOLD",
    "RISK_BLOCK_THRESHOLD",
    "RISK_DECAY_ENABLED",
    "RISK_DECAY_FACTOR",
)
_ASSIGNMENT = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
_NUMBER = re.compile(r"^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$")
_INLINE_COMMENT = re.compile(r"\s+#")


class RiskConfigError(ValueError):
    """Configuration violates the strict production contract."""


def _parse_value(raw: str, key: str, line_number: int) -> str:
    value = raw.strip()
    if not value:
        raise RiskConfigError(f"line {line_number}: {key} is empty")
    if value[0] in "\"'":
        quote = value[0]
        end = value.find(quote, 1)
        if end == -1:
            raise RiskConfigError(f"line {line_number}: {key} has an unclosed quote")
        remainder = value[end + 1:].strip()
        if remainder and not remainder.startswith("#"):
            raise RiskConfigError(f"line {line_number}: {key} has trailing characters after quote")
        value = value[1:end]
    else:
        value = _INLINE_COMMENT.split(value, maxsplit=1)[0].rstrip()
    if not value:
        raise RiskConfigError(f"line {line_number}: {key} is empty")
    return value


def parse_risk_env(text: str) -> dict[str, str]:
    """Read only supported risk variables. Do not interpret arbitrary .env values."""
    found: dict[str, str] = {}
    for number, line in enumerate(text.lstrip("\ufeff").splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _ASSIGNMENT.fullmatch(line)
        if not match:
            # Malformed risk-prefixed statements must not quietly fall back.
            if re.match(r"^\s*(?:export\s+)?RISK_", line):
                raise RiskConfigError(f"line {number}: malformed risk variable assignment")
            continue
        key, raw = match.groups()
        if key not in REQUIRED:
            continue
        if key in found:
            raise RiskConfigError(f"line {number}: duplicate {key}")
        found[key] = _parse_value(raw, key, number)
    return found


def _number(key: str, raw: str) -> float:
    # Deliberately reject suffixes, underscores and alternative spellings
    # to avoid disagreement with Lua's tonumber and unsafe nan/inf values.
    if not _NUMBER.fullmatch(raw):
        raise RiskConfigError(f"{key} must be a finite decimal number")
    try:
        value = float(raw)
    except (ValueError, OverflowError) as exc:
        raise RiskConfigError(f"{key} must be a finite decimal number") from exc
    if not math.isfinite(value):
        raise RiskConfigError(f"{key} must be finite (no NaN/Infinity)")
    return value


def validate_risk_config(config: Mapping[str, str]) -> None:
    missing = [key for key in REQUIRED if key not in config]
    if missing:
        raise RiskConfigError("missing required explicit variables: " + ", ".join(missing))
    limit = _number("RISK_LIMIT_THRESHOLD", config["RISK_LIMIT_THRESHOLD"])
    block = _number("RISK_BLOCK_THRESHOLD", config["RISK_BLOCK_THRESHOLD"])
    if not (0 < limit < block <= 100):
        raise RiskConfigError("threshold invariant violated: 0 < LIMIT < BLOCK <= 100")
    toggle = config["RISK_DECAY_ENABLED"].lower()
    if toggle not in ("true", "false"):
        raise RiskConfigError("RISK_DECAY_ENABLED must explicitly be true or false")
    factor = _number("RISK_DECAY_FACTOR", config["RISK_DECAY_FACTOR"])
    if not 0 <= factor <= 1:
        raise RiskConfigError("RISK_DECAY_FACTOR must be within [0, 1]")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", required=True, type=Path,
                        help="Existing Gateway env_file to validate (contents never displayed)")
    args = parser.parse_args(argv)
    try:
        # Decode errors fail closed; never output the file content.
        contents = args.env_file.read_text(encoding="utf-8-sig")
        validate_risk_config(parse_risk_env(contents))
    except (OSError, UnicodeError, RiskConfigError) as exc:
        if isinstance(exc, RiskConfigError):
            detail = str(exc)
        else:
            detail = "cannot read the specified UTF-8 environment file"
        print("P05 RISK CONFIG PREFLIGHT: FAIL - " + detail, file=sys.stderr)
        return 2
    print("P05 RISK CONFIG PREFLIGHT: PASS (4 explicit variables; strict mode)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
