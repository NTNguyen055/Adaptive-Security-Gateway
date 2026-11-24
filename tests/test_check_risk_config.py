#!/usr/bin/env python3
"""Offline unit tests for strict Risk Engine configuration preflight."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest

MODULE = Path(__file__).with_name("check_risk_config.py")
spec = importlib.util.spec_from_file_location("check_risk_config", MODULE)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

VALID = """\
# synthetic, no secrets
RISK_LIMIT_THRESHOLD=50
RISK_BLOCK_THRESHOLD=80
RISK_DECAY_ENABLED=false
RISK_DECAY_FACTOR=0.1
"""


class RiskConfigPreflightTests(unittest.TestCase):
    def run_validation(self, raw: str) -> None:
        mod.validate_risk_config(mod.parse_risk_env(raw))

    def test_reference_values(self) -> None:
        self.run_validation(VALID)

    def test_valid_custom_thresholds(self) -> None:
        self.run_validation(VALID.replace("=50", "=40").replace("=80", "=75"))

    def test_explicit_decay_enabled(self) -> None:
        self.run_validation(VALID.replace("ENABLED=false", "ENABLED=true"))

    def test_zero_and_one_decay_factor_allowed(self) -> None:
        self.run_validation(VALID.replace("FACTOR=0.1", "FACTOR=0"))
        self.run_validation(VALID.replace("FACTOR=0.1", "FACTOR=1"))

    def test_quoted_values_and_inline_comments(self) -> None:
        self.run_validation(VALID.replace("=50", "='50' # comment")
                            .replace("=80", '="80" # comment'))

    def test_missing_variable_rejected(self) -> None:
        with self.assertRaisesRegex(mod.RiskConfigError, "missing required"):
            self.run_validation(VALID.replace("RISK_DECAY_FACTOR=0.1\n", ""))

    def test_inverted_thresholds_rejected(self) -> None:
        with self.assertRaisesRegex(mod.RiskConfigError, "threshold invariant"):
            self.run_validation(VALID.replace("=50", "=95").replace("=80", "=20"))

    def test_negative_and_excessive_thresholds_rejected(self) -> None:
        for raw in (VALID.replace("=50", "=-5"), VALID.replace("=80", "=150")):
            with self.subTest(raw=raw.splitlines()[1:3]):
                with self.assertRaises(mod.RiskConfigError):
                    self.run_validation(raw)

    def test_nonfinite_thresholds_rejected(self) -> None:
        for val in ("NaN", "Infinity", "1e10000"):
            with self.subTest(val=val):
                with self.assertRaises(mod.RiskConfigError):
                    self.run_validation(VALID.replace("=80", "=" + val))

    def test_invalid_toggle_rejected(self) -> None:
        with self.assertRaisesRegex(mod.RiskConfigError, "explicitly"):
            self.run_validation(VALID.replace("ENABLED=false", "ENABLED=ture"))

    def test_decay_factor_outside_range_rejected(self) -> None:
        for value in ("-0.1", "2.5", "not_a_number", "Infinity"):
            with self.subTest(value=value):
                with self.assertRaises(mod.RiskConfigError):
                    self.run_validation(VALID.replace("FACTOR=0.1", "FACTOR=" + value))

    def test_duplicate_key_rejected(self) -> None:
        with self.assertRaisesRegex(mod.RiskConfigError, "duplicate"):
            self.run_validation(VALID + "RISK_LIMIT_THRESHOLD=40\n")

    def test_malformed_risk_assignment_rejected(self) -> None:
        with self.assertRaisesRegex(mod.RiskConfigError, "malformed"):
            self.run_validation(VALID + "RISK_LIMIT_THRESHOLD : 40\n")

    def test_missing_file_exits_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            self.assertEqual(mod.main(["--env-file", str(Path(temp) / "missing")]), 2)

    def test_valid_file_exits_success(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "synthetic.env"
            path.write_text(VALID, encoding="utf-8")
            self.assertEqual(mod.main(["--env-file", str(path)]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
