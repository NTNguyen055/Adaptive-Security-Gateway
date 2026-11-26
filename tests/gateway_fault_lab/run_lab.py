#!/usr/bin/env python3
"""Gateway HTTPS fault lab: disposable runtime matrix. Python >=3.10, Docker CLI.
Never uses Compose, .env.local, published ports, bind mounts or production state.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import time
import uuid
import math
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CONF = "/usr/local/openresty/nginx/conf/nginx.conf"
LAB_CONF = "/usr/local/openresty/nginx/conf/gateway-fault-lab.conf"
LUA = "/usr/local/openresty/nginx/lua/"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"

# case, route, method, expected status, required trigger names, guard log fragments
CASES = [
    ("E2E-01", "/doLogin/", "POST", 200, (), ()),
    ("E2E-02", "/doLogin/", "POST", 503, ("ip_blacklist",), ("module=ip_blacklist",)),
    ("E2E-03", "/profile/", "GET", 503, ("waf_sqli_xss",), ("module=waf_sqli_xss",)),
    ("E2E-04", "/profile/", "GET", 503, ("jwt_auth",), ("module=jwt_auth",)),
    ("E2E-05", "/doLogin/", "POST", 200, ("bad_bot",), ("module=bad_bot",)),
    ("E2E-06", "/doLogin/", "POST", 200, ("rate_limit",), ("module=rate_limit",)),
    ("E2E-07", "/doLogin/", "POST", 200, ("rate_limit_redis",), ("module=rate_limit_redis",)),
    ("E2E-08", "/doLogin/", "POST", 503, ("rate_limit", "rate_limit_redis"), ("module=both_rate_limit_layers",)),
    ("E2E-09", "/doLogin/", "POST", 503, ("local_init_nil", "redis_connect_nil"), ("module=both_rate_limit_layers",)),
    ("E2E-10", "/doLogin/", "POST", 503, ("risk_engine",), ("module=risk_engine",)),
    ("E2E-11", "/profile/", "GET", 403, ("waf_denial", "risk_engine"), ("module=risk_engine",)),
    ("E2E-12", "/doLogin/", "POST", 429, ("local_rejection", "risk_engine"), ("module=risk_engine",)),
    ("E2E-13", "/doLogin/", "POST", 200, (), ()),
    ("E2E-14", "/static/fault-lab.css", "GET", 503, ("ip_blacklist",), ("module=ip_blacklist",)),
    ("E2E-15", "/media/fault-lab.png", "GET", 503, ("ip_blacklist",), ("module=ip_blacklist",)),
    ("E2E-16", "/login/", "GET", 503, ("login_accounting_health",), ()),
    ("E2E-17", "/doLogin/", "POST", 503, ("login_accounting_health",), ()),
]

SECURITY_JSON_PATH = (
    "/usr/local/openresty/nginx/logs/security.json.log"
)

TERMINAL_EXPECTATIONS = {
    "E2E-02": (503, "unavailable", "gateway_unavailable"),
    "E2E-03": (503, "unavailable", "gateway_unavailable"),
    "E2E-04": (503, "unavailable", "gateway_unavailable"),
    "E2E-08": (503, "unavailable", "gateway_unavailable"),
    "E2E-09": (503, "unavailable", "gateway_unavailable"),
    "E2E-10": (503, "unavailable", "gateway_unavailable"),

    "E2E-11": (403, "block", "waf_sqli"),
    "E2E-12": (429, "limit", "rate_limit_hard"),

    "E2E-14": (503, "unavailable", "gateway_unavailable"),
    "E2E-15": (503, "unavailable", "gateway_unavailable"),

    "E2E-16": (
        503, "unavailable", "login_accounting_unavailable"
    ),
    "E2E-17": (
        503, "unavailable", "login_accounting_unavailable"
    ),
}

SHADOW_ACTIONS = {
    "block": "BLOCK_REQUEST",
    "limit": "THROTTLE",
    "unavailable": "UNAVAILABLE",
}

def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def docker(*args, cwd=None, timeout=90, check=True):
    result = subprocess.run(["docker", *map(str, args)], cwd=cwd,
                            capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"docker {args[0]} failed ({result.returncode}): "
                           + result.stderr.decode("utf-8", errors="replace").strip()[-2000:])
    return result


def out(*args, **kwargs):
    return docker(*args, **kwargs).stdout.decode("utf-8", errors="replace").strip()


def image_id(ref):
    return out("image", "inspect", "--format", "{{.Id}}", ref)


def read_image(image, path):
    return docker("run", "--rm", "--pull", "never", "--network", "none",
                  "--entrypoint", "cat", image, path).stdout


def normalize(data):
    return data.replace(b"\r\n", b"\n")


def config_for(base, fixture, case):
    require(case in {c[0] for c in CASES}, "Unknown scenario")
    # Guard exact integration points; never silently generate a different config.
    for token in ("gateway_fault_guard.register", "gateway_fault_guard.run_pipeline",
                  "init_worker_by_lua_block {", "server docapp_django:8000;"):
        require(token in base, f"Image config lacks {token}")
    require(base.count("gateway_fault_guard.run_pipeline") == 6,
            "Expected six integrated routes")
    require(base.count("init_worker_by_lua_block {") == 1, "Ambiguous worker hook")
    base, count = re.subn(r"(?m)^\s*worker_processes\s+auto\s*;", "worker_processes 1;", base)
    require(count == 1, "Unexpected worker_processes directive")
    base, count = re.subn(r"(?m)^\s*error_log\s+[^;]+;", "    error_log /dev/stderr warn;", base)
    require(count == 1, "Unexpected error_log directives")
    hook = 'init_worker_by_lua_block {\n        do\n            local FAULT_LAB_CASE = ' + json.dumps(case) + '\n' + fixture + '\n        end\n'
    return base.replace("init_worker_by_lua_block {", hook, 1)


def parse_http(text):
    # curl -D - -o /dev/null; no redirects followed. Accept HTTP/1.1 or HTTP/2.
    status = re.search(r"(?m)^HTTP/\S+\s+(\d{3})(?:\s|$)", text)
    require(status is not None, "No HTTP response status")
    reached = re.search(r"(?im)^X-Fault-Lab-Upstream:\s*reached\s*$", text) is not None
    return int(status.group(1)), reached

def parse_metric_samples(text, metric_name):
    """Parse selected ASG Prometheus series with bounded labels."""
    samples = {}

    pattern = re.compile(
        r"^" + re.escape(metric_name)
        + r"(?:\{([^}]*)\})?\s+(\S+)$"
    )

    label_pattern = re.compile(
        r'([a-zA-Z_][a-zA-Z0-9_]*)="([a-zA-Z0-9_]+)"'
    )

    for line in text.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        match = pattern.fullmatch(line)
        if not match:
            continue

        raw_labels = match.group(1) or ""
        pairs = label_pattern.findall(raw_labels)

        canonical = ",".join(
            f'{key}="{value}"'
            for key, value in pairs
        )

        require(
            canonical == raw_labels,
            "Unexpected metric label format: " + raw_labels
        )

        require(
            len(dict(pairs)) == len(pairs),
            "Duplicate Prometheus label"
        )

        labels = tuple(sorted(pairs))
        value = float(match.group(2))

        require(
            math.isfinite(value) and value >= 0,
            "Invalid metric sample"
        )

        require(
            labels not in samples,
            "Duplicate Prometheus series"
        )

        samples[labels] = value

    return samples

def metric_delta(before, after, **labels):
    key = tuple(sorted(labels.items()))

    return after.get(key, 0) - before.get(key, 0)


def total_metric_delta(before, after):
    return sum(after.values()) - sum(before.values())


def verify_terminal_metrics(before_text, after_text,
                            status, action, reason):

    decision_metric = "nginx_security_decisions_total"
    histogram_metric = "nginx_security_risk_score_count"
    request_metric = "nginx_http_requests_total"

    decisions_before = parse_metric_samples(
        before_text, decision_metric
    )

    decisions_after = parse_metric_samples(
        after_text, decision_metric
    )

    risk_before = parse_metric_samples(
        before_text, histogram_metric
    )

    risk_after = parse_metric_samples(
        after_text, histogram_metric
    )

    requests_before = parse_metric_samples(
        before_text, request_metric
    )

    requests_after = parse_metric_samples(
        after_text, request_metric
    )

    decision_change = metric_delta(
        decisions_before,
        decisions_after,
        action=action,
        reason=reason
    )

    total_decision_change = total_metric_delta(
        decisions_before,
        decisions_after
    )

    total_risk_change = total_metric_delta(
        risk_before,
        risk_after
    )

    expected_risk_change = 0 if status == 503 else 1

    status_change = metric_delta(
        requests_before,
        requests_after,
        status=str(status)
    )

    require(
        decision_change == 1,
        f"Expected one security decision, got {decision_change}"
    )

    require(
        total_decision_change == 1,
        f"Unexpected total decision delta: {total_decision_change}"
    )

    require(
        status_change == 1,
        f"Unexpected HTTP status counter delta: {status_change}"
    )

    require(
        total_risk_change == expected_risk_change,
        f"Unexpected risk histogram delta: {total_risk_change}"
    )

    if status in {403, 429}:
        require(
            metric_delta(
                risk_before, risk_after, action=action
            ) == 1,
            "Risk histogram action attribution mismatch"
        )

    for name in ("pass", "block", "limit", "unavailable"):
        expected = int(
            status != 503 and name == action
        )

        require(
            metric_delta(
                risk_before, risk_after, action=name
            ) == expected,
            f"Unexpected risk histogram delta for action={name}"
        )

    return {
        "decision_delta": decision_change,
        "total_decision_delta": total_decision_change,
        "http_status_delta": status_change,
        "risk_histogram_delta": total_risk_change,
    }

def parse_security_json(text):
    records = []

    for line in text.splitlines():
        if line.strip():
            record = json.loads(line)

            require(
                isinstance(record, dict),
                "Security JSON record must be an object"
            )

            records.append(record)

    return records

def find_terminal_decision(logs, status, action, reason):
    pattern = re.compile(
        r"\[GATEWAY\]\[DECISION\]"
        r"\s+status=(\d+)"
        r"\s+action=(\w+)"
        r"\s+reason=(\w+)"
        r"\s+request_id=([a-f0-9]{32})\b"
    )

    matches = list(pattern.finditer(logs))

    require(
        len(matches) == 1,
        f"Expected one terminal decision log, got {len(matches)}"
    )

    match = matches[0]

    require(
        (
            int(match.group(1)),
            match.group(2),
            match.group(3)
        ) == (status, action, reason),
        "Incorrect terminal decision attribution"
    )

    return match.group(4)

def verify_shadow_record(logs, request_id,
                         status, action, reason):

    records = [
        line for line in logs.splitlines()
        if "[SECURITY_SHADOW]" in line
        and f"request_id={request_id} " in line
    ]

    require(
        len(records) == 1,
        "Expected exactly one correlated Shadow record"
    )

    line = records[0]

    expected_fields = (
        f"legacy_action={SHADOW_ACTIONS[action]}",
        f"legacy_status={status}",
        f"legacy_reason={reason}",
        "partial=true",
        f"final_http={status}",
    )

    fields = set(line.split())

    for field in expected_fields:
        require(
            field in fields,
            "Shadow attribution mismatch: " + field
        )

def verify_json_record(records, request_id,
                       route, method,
                       status, action, reason):

    matches = [
        record for record in records
        if record.get("request_id") == request_id
    ]

    require(
        len(matches) == 1,
        "Expected exactly one correlated security JSON record"
    )

    record = matches[0]

    expected = {
        "path": route,
        "method": method,
        "status": status,
        "action": action,
        "reason": reason,
    }

    for key, value in expected.items():
        require(
            record.get(key) == value,
            f"Security JSON mismatch for {key}"
        )

    score = record.get("risk_score")

    require(
        type(score) in (int, float)
        and math.isfinite(score)
        and 0 <= score <= 100,
        "Invalid security JSON risk score"
    )

    return record

class Lab:
    def __init__(self, output):
        self.output = output
        self.prefix = "asg-fault-lab-" + uuid.uuid4().hex[:12]
        self.network = self.prefix + "-net"
        self.containers = []
        self.network_created = False
        self.redis = self.prefix + "-redis"
        self.backend = self.prefix + "-backend"
        self.client = self.prefix + "-client"
        self.gateway = self.prefix + "-gateway"

    def create(self, name, *args):
        require(name.startswith(self.prefix + "-"), "Unsafe container name")
        docker("create", "--name", name, "--label", "asg.gateway_fault_lab=" + self.prefix,
               "--pull", "never", "--network", self.network, "--no-healthcheck", *args)
        self.containers.append(name)

    def remove(self, name):
        if name in self.containers:
            docker("rm", "-f", "-v", name)
            self.containers.remove(name)

    def cleanup(self):
        failures = []
        for name in reversed(self.containers[:]):
            try:
                self.remove(name)
            except Exception as exc:
                failures.append(str(exc))
        if self.network_created:
            try:
                docker("network", "rm", self.network)
            except Exception as exc:
                failures.append(str(exc))
        return failures

    def logs(self, name):
        r = docker("logs", name)
        return (r.stdout + r.stderr).decode("utf-8", errors="replace")

    def copy(self, file, dest):
        # Relative path + native subprocess works on Windows without MSYS conversion.
        docker("cp", file.name, dest, cwd=file.parent)

    def wait(self, fn, name):
        for _ in range(30):
            if fn():
                return
            time.sleep(1)
        raise RuntimeError(f"Readiness timeout: {name}")

    def curl(self, route, method="GET", ready=False):
        args = ["exec", self.client, "curl", "-k", "-sS", "--noproxy", "*",
                "--connect-timeout", "2", "--max-time", "8", "-D", "-", "-o", "/dev/null",
                "-H", "Host: localhost", "-A", UA, "-H", "Accept: text/html",
                "-H", "Accept-Language: en-US,en;q=0.9", "-H", "Accept-Encoding: gzip, deflate, br"]
        if method == "POST":
            args += ["--data", "fault_lab=synthetic"]
        args += ["https://gateway" + route]
        r = docker(*args, check=not ready, timeout=15)
        if ready:
            return r.returncode == 0 and parse_http(r.stdout.decode(errors="replace"))[0] == 200
        return r.stdout.decode("utf-8", errors="replace")

    def scrape_metrics(self):
        return out(
            "exec", self.gateway,
            "curl",
            "-fsS",
            "--noproxy", "*",
            "--max-time", "5",
            "http://127.0.0.1:9145/metrics"
        )

    def read_security_json(self):
        result = docker(
            "exec", self.gateway,
            "cat", SECURITY_JSON_PATH,
            check=False
        )

        if result.returncode != 0:
            return None

        return result.stdout.decode(
            "utf-8", errors="strict"
        )

    def wait_security_record(self, request_id):
        # nginx access_log uses buffer=16k and flush=5s.
        # Read-only polling; no worker reload or forced shutdown.
        for _ in range(20):
            text = self.read_security_json()

            if text is not None:
                records = parse_security_json(text)

                matches = [
                    record for record in records
                    if record.get("request_id") == request_id
                ]

                if matches:
                    return text, records

            time.sleep(1)

        raise RuntimeError(
            "Security JSON flush/correlation timeout: "
            + request_id
        )

    def verify_observability(self, cid, folder,
                             route, method,
                             metrics_before):

        status, action, reason = TERMINAL_EXPECTATIONS[cid]

        # Capture terminal decision and Shadow evidence after log phase.
        logs = self.logs(self.gateway)

        request_id = find_terminal_decision(
            logs, status, action, reason
        )

        # Wait for the actual buffered JSON record.
        json_text, records = self.wait_security_record(
            request_id
        )

        (folder / "security.json.log").write_text(
            json_text, encoding="utf-8"
        )

        record = verify_json_record(
            records,
            request_id,
            route,
            method,
            status,
            action,
            reason
        )

        # Read Shadow log after the access log becomes visible.
        logs = self.logs(self.gateway)

        verify_shadow_record(
            logs,
            request_id,
            status,
            action,
            reason
        )

        require(
            "[GATEWAY][DECISION] recording_failed" not in logs,
            "Gateway decision recorder failed"
        )

        require(
            "[GATEWAY][DECISION] metric_record_failed" not in logs,
            "Gateway metric recorder failed"
        )

        # Metrics are shared asynchronously by the exporter.
        # JSON polling normally provides the synchronization time.
        # Poll metrics until the expected samples become visible.
        last_error = None

        for _ in range(15):
            metrics_after = self.scrape_metrics()

            (folder / "metrics-after.prom").write_text(
                metrics_after + "\n",
                encoding="utf-8"
            )

            try:
                deltas = verify_terminal_metrics(
                    metrics_before,
                    metrics_after,
                    status,
                    action,
                    reason
                )

                last_error = None
                break

            except RuntimeError as exc:
                last_error = exc
                time.sleep(1)

        if last_error is not None:
            raise last_error

        evidence = {
            "case": cid,
            "request_id": request_id,
            "status": status,
            "action": action,
            "reason": reason,
            "security_json": record,
            "shadow_correlated": True,
            "metrics": deltas,
            "result": "PASS",
        }

        (folder / "observability.json").write_text(
            json.dumps(evidence, indent=2),
            encoding="utf-8"
        )

        print(
            f"PASS {cid} OBSERVABILITY "
            f"action={action} reason={reason} "
            f"decision_delta={deltas['decision_delta']} "
            f"risk_delta={deltas['risk_histogram_delta']}",
            flush=True
        )

        return evidence

    def redis_cmd(self, *args):
        return out("exec", self.redis, "redis-cli", "--raw", *args)

    def redis_state(self):
        info = self.redis_cmd("INFO", "keyspace")
        require(not re.search(r"(?m)^db(?:[1-9]\d*):", info), "Unexpected nonzero Redis DB used")
        keys = sorted(set(self.redis_cmd("--scan").splitlines()))
        unexpected = [k for k in keys if not k.startswith("rrl:")]
        # Fresh isolated DB: only rate counters expected, no reputation/ban/accounting keys.
        require(not unexpected, "Unexpected Redis keys: " + repr(unexpected))
        count = sum(int(self.redis_cmd("ZCARD", k)) for k in keys if not k.endswith(":seq"))
        return {"keys": keys, "rate_entries": count}

    def setup(self, gateway_image, app_image, redis_image):
        docker("network", "create", "--internal", "--label", "asg.gateway_fault_lab=" + self.prefix, self.network)
        self.network_created = True
        require(out("network", "inspect", "--format", "{{.Internal}}", self.network) == "true", "Lab network not internal")
        self.create(self.redis, "--network-alias", "redis", redis_image,
                    "redis-server", "--save", "", "--appendonly", "no")
        docker("start", self.redis)
        self.wait(lambda: self.redis_cmd("PING") == "PONG", "Redis")
        self.create(self.backend, "--network-alias", "docapp_django", "--entrypoint", "python",
                    app_image, "-u", "-c", (HERE / "mock_backend.py").read_text(encoding="utf-8"))
        docker("start", self.backend)
        self.create(self.client, "--entrypoint", "sh", gateway_image, "-c", "while :; do sleep 60; done")
        docker("start", self.client)
        self.wait(lambda: docker("exec", self.client, "curl", "-fsS", "--noproxy", "*", "--max-time", "2",
                                 "http://docapp_django:8000/health/", check=False).returncode == 0, "mock backend")

    def case(self, case, base, fixture, image):
        cid, route, method, expected, triggers, faults = case
        folder = self.output / cid
        folder.mkdir()
        config = folder / "gateway-fault-lab.conf"
        config.write_text(config_for(base, fixture, cid), encoding="utf-8", newline="\n")

        # No env file or secrets; rate limits high enough for a sequential matrix.
        env = {"JWT_SECRET_KEY": "fault-lab-test-only-not-a-real-secret", "RATE_LIMIT_RPS": "1000",
               "RATE_LIMIT_BURST": "1000", "REDIS_RATE_LIMIT": "1000", "REDIS_RL_WINDOW": "3600",
               "RISK_LIMIT_THRESHOLD": "50", "RISK_BLOCK_THRESHOLD": "80", "RISK_DECAY_ENABLED": "true",
               "RISK_DECAY_FACTOR": "0.1", "SECURITY_SHADOW_ENABLED": "true", "SECURITY_SHADOW_LOG_ALL": "true",
               "SECURITY_CORRELATOR_SHADOW_ENABLED": "false", "TELEGRAM_BOT_TOKEN": "", "TELEGRAM_CHAT_ID": ""}
        env_args = [x for k, v in env.items() for x in ("-e", f"{k}={v}")]
        self.create(self.gateway, "--network-alias", "gateway", *env_args, "--entrypoint", "openresty",
                    image, "-c", LAB_CONF, "-g", "daemon off;")
        try:
            self.copy(config, self.gateway + ":" + LAB_CONF)

            docker("start", self.gateway)

            self.wait(lambda: self.curl("/health/", ready=True), cid + " HTTPS health")

            metrics_before = None

            if cid in TERMINAL_EXPECTATIONS:
                # Warm up the internal metrics exporter before
                # taking the actual comparison snapshot.
                self.scrape_metrics()
                time.sleep(2)

                metrics_before = self.scrape_metrics()

                (folder / "metrics-before.prom").write_text(
                    metrics_before + "\n",
                    encoding="utf-8"
                )

            prior_backend = self.logs(self.backend).count(f"FAULT_LAB_BACKEND {method} {route}\n")

            before = self.redis_state()
            response = self.curl(route, method)
            (folder / "response.headers.txt").write_text(response, encoding="utf-8")

            status, reached = parse_http(response)
            after = self.redis_state()
            (folder / "redis-state.json").write_text(json.dumps({"before": before, "after": after}, indent=2))

            backend_log = self.logs(self.backend)
            delta = backend_log.count(f"FAULT_LAB_BACKEND {method} {route}\n") - prior_backend
            logs = self.logs(self.gateway)

            require(status == expected, f"Expected {expected}, received {status}")
            require(reached == (expected == 200) and delta == (1 if expected == 200 else 0),
                    f"Upstream mismatch: header={reached}, request count delta={delta}")

            for name in triggers:
                require(f"FAULT_LAB_TRIGGER case={cid} module={name}" in logs, "Missing injection evidence: " + name)

            guard_lines = [line for line in logs.splitlines() if "[GATEWAY][FAULT]" in line]

            for fragment in faults:
                require(any(fragment in line for line in guard_lines), "Missing guard log: " + fragment)

            if cid in TERMINAL_EXPECTATIONS:
                expected_status, expected_action, expected_reason = (
                    TERMINAL_EXPECTATIONS[cid]
                )

                require(
                    expected_status == expected,
                    "Terminal expectation status mismatch"
                )

                find_terminal_decision(
                    logs,
                    expected_status,
                    expected_action,
                    expected_reason
                )

            if not triggers:
                require("FAULT_LAB_TRIGGER" not in logs and not guard_lines, "Unexpected fault in baseline/recovery")

            if cid == "E2E-06":
                require(after["rate_entries"] >= before["rate_entries"] + 2, "Redis rate fallback did not record both counters")

            if cid == "E2E-07":
                require("FAULT_LAB_L1_OK" in logs, "Missing real local limiter fallback evidence")

            if cid == "E2E-09":
                require("FAULT_LAB_SILENT_FLAGS_OK" in logs, "Silent module flags not confirmed")
                require(not any("module=rate_limit " in l or "module=rate_limit_redis " in l for l in guard_lines),
                        "Expected silent degradation, got module exception")

            if cid == "E2E-12":
                require("FAULT_LAB_RATE_DECISION_OK" in logs, "Rate-only decision not established before crash")

            if cid in {"E2E-01", "E2E-13"}:

                # Main-route positive control as well as the doLogin route.
                prior_profile = self.logs(self.backend).count("FAULT_LAB_BACKEND GET /profile/\n")
                profile = self.curl("/profile/")
                (folder / "profile.headers.txt").write_text(profile, encoding="utf-8")

                require(parse_http(profile) == (200, True), "Main-route baseline/recovery failed")
                require(self.logs(self.backend).count("FAULT_LAB_BACKEND GET /profile/\n") == prior_profile + 1,
                        "Main-route upstream count mismatch")

                final = self.redis_state()
                (folder / "redis-state-after-profile.json").write_text(json.dumps(final, indent=2))

                final_logs = self.logs(self.gateway)

                require("FAULT_LAB_TRIGGER" not in final_logs and "[GATEWAY][FAULT]" not in final_logs,
                        "Unexpected main-route fault")

            result = {
                "case": cid,
                "expected": expected,
                "actual": status,
                "upstream_delta": delta,
                "result": "PASS",
            }

            if cid in TERMINAL_EXPECTATIONS:
                require(
                    metrics_before is not None,
                    "Missing baseline metrics"
                )

                evidence = self.verify_observability(
                    cid,
                    folder,
                    route,
                    method,
                    metrics_before
                )

                result["observability"] = evidence["result"]
                result["metrics"] = evidence["metrics"]
                result["request_id"] = evidence["request_id"]

            return result

        finally:
            # Preserve evidence before removing the disposable Gateway.
            try:
                (folder / "gateway.log").write_text(self.logs(self.gateway), encoding="utf-8")
                (folder / "backend.log").write_text(self.logs(self.backend), encoding="utf-8")

            finally:
                self.remove(self.gateway)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--gateway-image", default="adaptive-security-gateway:local")
    p.add_argument("--app-image", default="adaptive-security-app:local")
    p.add_argument("--redis-image", default="redis@sha256:7b1753b4c5ad8458906c272a8132b8c15f5557b000379eb115fb239706a384b7")
    p.add_argument("--expected-image-id", required=True, help="Image ID recorded during FI-08A")
    p.add_argument("--output", type=Path, default=Path("gateway-fault-lab-results"), help="New evidence directory (must not exist)")

    args = p.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    lab = Lab(output)
    results = []
    error = None
    cleanup = []

    try:
        gw, app, redis = map(image_id, (args.gateway_image, args.app_image, args.redis_image))
        require(gw == args.expected_image_id, f"Gateway ID mismatch: expected {args.expected_image_id}, got {gw}")

        # Match image bytes to working-tree source; CRLF is normalized only for comparison.
        files = {CONF: ROOT / "nginx/nginx.conf"}
        files.update({LUA + x + ".lua": ROOT / "nginx/lua" / (x + ".lua") for x in (
            "gateway_fault_guard", "rate_limit", "rate_limit_redis", "risk_engine", "security_shadow",
            "ip_blacklist", "xff_guard", "geo_block", "bad_bot", "waf_sqli_xss", "jwt_auth", "redis_helper", "brute_force_login")})
        hashes = {}
        base = None

        for remote, local in files.items():
            data = read_image(gw, remote)
            require(normalize(data) == normalize(local.read_bytes()), f"Image/source mismatch: {local.relative_to(ROOT)}")
            hashes[str(local.relative_to(ROOT))] = hashlib.sha256(data).hexdigest()
            if remote == CONF:
                base = normalize(data).decode("utf-8")

        fixture = (HERE / "fault_worker.lua").read_text(encoding="utf-8")

        # Validate the full matrix before any live resources are created.
        for c in CASES:
            config_for(base, fixture, c[0])

        (output / "manifest.json").write_text(json.dumps({"lab": lab.prefix, "gateway_image": gw,

            "app_image": app, "redis_image": redis, "image_file_sha256": hashes,

            "fixture_sha256": hashlib.sha256(fixture.encode()).hexdigest(),

            "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),

            "mock_backend_sha256": hashlib.sha256((HERE / "mock_backend.py").read_bytes()).hexdigest(),

            "scope": "mock backend, isolated real Redis, test-only worker hook"}, indent=2))

        print("FAULT LAB image/source match PASS; lab=" + lab.prefix, flush=True)

        lab.setup(gw, app, redis)

        for case in CASES:
            try:
                result = lab.case(case, base, fixture, gw)
                results.append(result)
                print(f"PASS {case[0]} HTTP={result['actual']} upstream_delta={result['upstream_delta']}", flush=True)

            except Exception as exc:
                results.append({"case": case[0], "result": "FAIL", "error": str(exc)})
                raise  # Fail fast; don't continue with possibly contaminated evidence.

    except (Exception, KeyboardInterrupt) as exc:
        error = str(exc) or type(exc).__name__
        print("FAIL: " + error, file=sys.stderr, flush=True)

    finally:
        cleanup = lab.cleanup()
        (output / "summary.json").write_text(json.dumps({"results": results, "error": error, "cleanup_errors": cleanup}, indent=2))

        for e in cleanup:
            print("CLEANUP FAIL: " + e, file=sys.stderr)
        passed = sum(r["result"] == "PASS" for r in results)
        ok = passed == len(CASES) and not error and not cleanup
        print(f"HTTPS FAULT LAB MATRIX: {passed}/{len(CASES)} PASS; cleanup={'FAIL' if cleanup else 'PASS'}", flush=True)

    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
