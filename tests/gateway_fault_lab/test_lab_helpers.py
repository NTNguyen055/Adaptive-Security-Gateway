"""Offline checks for the test runner itself; no Docker needed."""
import unittest

from run_lab import (
    CASES,
    TERMINAL_EXPECTATIONS,
    config_for,
    parse_http,
    normalize,
    parse_metric_samples,
    verify_terminal_metrics,
    parse_security_json,
    find_terminal_decision,
    verify_shadow_record,
    verify_json_record,
)

BASE = '''worker_processes auto;
http {
    error_log /tmp/error.log warn;
    upstream django_backend { server docapp_django:8000; }
    init_by_lua_block { gateway_fault_guard.register(asg_module_names) }
    init_worker_by_lua_block { ngx.log(ngx.INFO, "worker") }
''' + '\n'.join('gateway_fault_guard.run_pipeline(ctx, modules, shadow, risk)' for _ in range(6)) + '\n}'


class LabHelperTests(unittest.TestCase):
    def test_each_case_has_one_fixed_hook(self):
        for case in CASES:
            with self.subTest(case=case[0]):
                conf = config_for(BASE, 'local fixture = true', case[0])
                self.assertEqual(conf.count('local FAULT_LAB_CASE = "' + case[0] + '"'), 1)
                self.assertIn('worker_processes 1;', conf)
                self.assertIn('error_log /dev/stderr warn;', conf)
                self.assertEqual(conf.count('gateway_fault_guard.run_pipeline'), 6)
                self.assertIn('ngx.log(ngx.INFO, "worker")', conf)

    def test_reject_unknown_case(self):
        with self.assertRaises(RuntimeError):
            config_for(BASE, '', 'not-a-case')

    def test_reject_missing_route(self):
        with self.assertRaises(RuntimeError):
            config_for(BASE.replace('gateway_fault_guard.run_pipeline', 'old_call', 1), '', 'E2E-01')

    def test_reject_multiple_worker_hooks(self):
        with self.assertRaises(RuntimeError):
            config_for(BASE + '\ninit_worker_by_lua_block { }', '', 'E2E-01')

    def test_parse_upstream_http11(self):
        self.assertEqual(parse_http('HTTP/1.1 200 OK\r\nX-Fault-Lab-Upstream: reached\r\n\r\n'), (200, True))

    def test_parse_denial_http2(self):
        self.assertEqual(parse_http('HTTP/2 503\r\nserver: openresty\r\n\r\n'), (503, False))

    def test_no_http_response_is_failure(self):
        with self.assertRaises(RuntimeError):
            parse_http('')

    def test_crlf_normalization(self):
        self.assertEqual(normalize(b'a\r\nb\n'), b'a\nb\n')

    def test_matrix_has_all_expected_cases(self):
        self.assertEqual(
            [c[0] for c in CASES],
            [f"E2E-{i:02}" for i in range(1, 18)]
        )

        self.assertEqual(
            [c[3] for c in CASES],
            [
                200, 503, 503, 503,
                200, 200, 200,
                503, 503, 503,
                403, 429, 200,
                503, 503, 503, 503
            ]
        )

class ObservabilityHelperTests(unittest.TestCase):

    def setUp(self):
        self.request_id = "a" * 32

    def metrics(self, status, action, reason,
                decision_count=1, risk_count=None):

        if risk_count is None:
            risk_count = int(status != 503)

        return "\n".join([
            f'nginx_http_requests_total'
            f'{{status="{status}"}} 1',

            f'nginx_security_decisions_total'
            f'{{action="{action}",reason="{reason}"}} '
            f'{decision_count}',

            f'nginx_security_risk_score_count'
            f'{{action="{action}"}} {risk_count}',
        ])

    def test_terminal_expectations_cover_all_denials(self):
        denied = {
            case[0]: case[3]
            for case in CASES
            if case[3] != 200
        }

        self.assertEqual(
            denied,
            {
                cid: expected[0]
                for cid, expected in TERMINAL_EXPECTATIONS.items()
            }
        )

    def test_metric_parser_handles_label_order(self):
        text = (
            'nginx_security_decisions_total'
            '{reason="waf_sqli",action="block"} 1'
        )

        samples = parse_metric_samples(
            text,
            "nginx_security_decisions_total"
        )

        self.assertEqual(
            samples[
                (
                    ("action", "block"),
                    ("reason", "waf_sqli")
                )
            ],
            1
        )

    def test_metric_parser_rejects_duplicate_series(self):
        line = 'nginx_http_requests_total{status="503"} 1'

        with self.assertRaises(RuntimeError):
            parse_metric_samples(
                line + "\n" + line,
                "nginx_http_requests_total"
            )

    def test_metric_parser_rejects_nan(self):
        with self.assertRaises(RuntimeError):
            parse_metric_samples(
                'nginx_http_requests_total{status="503"} NaN',
                "nginx_http_requests_total"
            )

    def test_unavailable_excluded_from_risk_histogram(self):
        text = self.metrics(
            503, "unavailable", "gateway_unavailable"
        )

        result = verify_terminal_metrics(
            "", text,
            503, "unavailable", "gateway_unavailable"
        )

        self.assertEqual(result["decision_delta"], 1)
        self.assertEqual(result["risk_histogram_delta"], 0)

    def test_reject_unavailable_risk_pollution(self):
        text = self.metrics(
            503,
            "unavailable",
            "gateway_unavailable",
            risk_count=1
        )

        with self.assertRaises(RuntimeError):
            verify_terminal_metrics(
                "", text,
                503, "unavailable", "gateway_unavailable"
            )

    def test_reject_duplicate_decision_count(self):
        text = self.metrics(
            503,
            "unavailable",
            "gateway_unavailable",
            decision_count=2
        )

        with self.assertRaises(RuntimeError):
            verify_terminal_metrics(
                "", text,
                503, "unavailable", "gateway_unavailable"
            )

    def test_preserved_block_metrics(self):
        text = self.metrics(
            403, "block", "waf_sqli"
        )

        result = verify_terminal_metrics(
            "", text, 403, "block", "waf_sqli"
        )

        self.assertEqual(result["risk_histogram_delta"], 1)

    def test_preserved_limit_metrics(self):
        text = self.metrics(
            429, "limit", "rate_limit_hard"
        )

        result = verify_terminal_metrics(
            "", text, 429, "limit", "rate_limit_hard"
        )

        self.assertEqual(result["risk_histogram_delta"], 1)

    def test_terminal_decision_requires_unique_record(self):
        line = (
            "[GATEWAY][DECISION] status=503 "
            "action=unavailable reason=gateway_unavailable "
            f"request_id={self.request_id}"
        )

        self.assertEqual(
            find_terminal_decision(
                line, 503,
                "unavailable",
                "gateway_unavailable"
            ),
            self.request_id
        )

        with self.assertRaises(RuntimeError):
            find_terminal_decision(
                line + "\n" + line,
                503,
                "unavailable",
                "gateway_unavailable"
            )

    def test_shadow_terminal_correlation(self):
        line = (
            "[SECURITY_SHADOW] "
            f"request_id={self.request_id} "
            "legacy_action=UNAVAILABLE "
            "legacy_status=503 "
            "legacy_reason=gateway_unavailable "
            "partial=true final_http=503"
        )

        verify_shadow_record(
            line,
            self.request_id,
            503,
            "unavailable",
            "gateway_unavailable"
        )

        with self.assertRaises(RuntimeError):
            verify_shadow_record(
                line,
                "b" * 32,
                503,
                "unavailable",
                "gateway_unavailable"
            )

    def test_security_json_terminal_correlation(self):
        text = (
            '{"request_id":"' + self.request_id + '",'
            '"path":"/login/",'
            '"method":"GET",'
            '"status":503,'
            '"action":"unavailable",'
            '"reason":"login_accounting_unavailable",'
            '"risk_score":0}'
        )

        records = parse_security_json(text)

        record = verify_json_record(
            records,
            self.request_id,
            "/login/",
            "GET",
            503,
            "unavailable",
            "login_accounting_unavailable"
        )

        self.assertEqual(record["status"], 503)

        with self.assertRaises(RuntimeError):
            verify_json_record(
                records + records,
                self.request_id,
                "/login/",
                "GET",
                503,
                "unavailable",
                "login_accounting_unavailable"
            )

if __name__ == '__main__':
    unittest.main()
