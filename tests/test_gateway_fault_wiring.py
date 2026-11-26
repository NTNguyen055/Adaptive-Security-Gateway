"""P0.5.4 source-wiring regression: fail before Nginx access blocks are hardened.

This test is intentionally static: it verifies actual nginx.conf integration, not
runtime error statuses. Lua contract tests and isolated HTTP tests cover behavior.
"""
from pathlib import Path
import unittest
import re

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "nginx" / "nginx.conf"
ROUTES = (
    "location /static/ {",
    "location /media/ {",
    "location /admin/ {",
    "location = /login/ {",
    "location = /doLogin/ {",
    "location / {",
)

def extract_gateway_location(text: str, marker: str) -> str:
    # Chỉ xét HTTPS main server, không lấy nhầm
    # metrics server (404) hoặc HTTP redirect server (301).
    https_server = re.search(
        r"(?m)^[ \t]*server\s*\{\s*listen\s+443\s+ssl\s*;",
        text,
    )

    if https_server is None:
        raise AssertionError("Missing HTTPS main server")

    start = text.find(marker, https_server.end())

    if start < 0:
        raise AssertionError(f"Missing expected HTTPS route: {marker}")

    end = text.find("proxy_pass http://django_backend;", start)

    if end < 0:
        raise AssertionError(
            f"Cannot find backend boundary for: {marker}"
        )

    snippet = text[start:end]

    if "access_by_lua_block {" not in snippet:
        raise AssertionError(
            f"Missing access phase in HTTPS route: {marker}"
        )

    return snippet

class GatewayFaultWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = CONFIG.read_text(encoding="utf-8")
        cls.route_blocks = {route: extract_gateway_location(cls.text, route)
                            for route in ROUTES}

    def test_guard_loaded_in_init(self):
        self.assertIn('gateway_fault_guard = require "gateway_fault_guard"', self.text)

    def test_same_trusted_map_registered_to_shadow_and_guard(self):
        self.assertRegex(
            self.text,
            r"security_shadow\.register\s*\(\s*"
            r"asg_module_names\s*,\s*"
            r"jwt_auth\.requires_jwt\s*\)"
        )

        self.assertRegex(
            self.text,
            r"gateway_fault_guard\.register\s*\(\s*"
            r"asg_module_names\s*\)"
        )

    def test_all_six_routes_wired(self):
        for route, block in self.route_blocks.items():
            with self.subTest(route=route):
                self.assertEqual(
                    len(re.findall(
                        r"gateway_fault_guard\.run_pipeline\s*\(",
                        block
                    )),
                    1
                )

                self.assertRegex(
                    block,
                    r"gateway_fault_guard\.run_pipeline\s*\(\s*"
                    r"ctx\s*,\s*"
                    r"modules\s*,\s*"
                    r"security_shadow\s*,\s*"
                    r"risk_engine\s*\)"
                )

    def test_legacy_unchecked_module_calls_removed(self):
        for route, block in self.route_blocks.items():
            with self.subTest(route=route):
                self.assertNotIn("security_shadow.run(m, ctx)", block)

    def test_legacy_unchecked_risk_calls_removed(self):
        for route, block in self.route_blocks.items():
            with self.subTest(route=route):
                self.assertNotIn("pcall(risk_engine.run, ctx)", block)

    def test_fault_termination_before_backend(self):
        for route, block in self.route_blocks.items():
            with self.subTest(route=route):
                self.assertIn("if fault_status then", block)
                self.assertIn("return ngx.exit(fault_status)", block)
                self.assertIn("ngx.ctx.security = ctx.security", block)
                self.assertLess(block.index("return ngx.exit(fault_status)"),
                                block.rfind("ngx.ctx.security = ctx.security"))

    def test_prelogin_health_checks_retained(self):
        for route in ("location = /login/ {", "location = /doLogin/ {"):
            block = self.route_blocks[route]
            with self.subTest(route=route):
                self.assertIn("brute_force_login.check_prelogin", block)
                self.assertIn("ngx.HTTP_SERVICE_UNAVAILABLE", block)
                self.assertLess(block.index("brute_force_login.check_prelogin"),
                                block.index("gateway_fault_guard.run_pipeline("))

    def test_original_route_module_lists_preserved(self):
        for route, block in self.route_blocks.items():
            with self.subTest(route=route):
                self.assertIn("local modules = {", block)
                self.assertIn("security_shadow.start(ctx", block)

    def test_fault_decision_recorded_before_exit(self):
        for route, block in self.route_blocks.items():
            with self.subTest(route=route):
                start = block.index("if fault_status then")
                end = block.index(
                    "return ngx.exit(fault_status)",
                    start
                )

                termination = block[start:end]

                self.assertIn(
                    "record_gateway_termination",
                    termination
                )

                self.assertIn(
                    "pcall(",
                    termination
                )

    def test_unavailable_security_events_are_logged(self):
        self.assertRegex(
            self.text,
            r"map\s+\$log_security_block\s+"
            r"\$log_security_event\s*\{"
            r"[^}]*\bunavailable\s+1\s*;",
        )

if __name__ == "__main__":
    unittest.main()
