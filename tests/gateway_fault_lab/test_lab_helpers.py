"""Offline checks for the test runner itself; no Docker needed."""
import unittest
from run_lab import CASES, config_for, parse_http, normalize

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
        self.assertEqual([c[0] for c in CASES], [f'E2E-{i:02}' for i in range(1, 14)])
        self.assertEqual([c[3] for c in CASES], [200,503,503,503,200,200,200,503,503,503,403,429,200])


if __name__ == '__main__':
    unittest.main()
