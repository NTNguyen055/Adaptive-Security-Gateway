#!/usr/bin/env python3
"""Bounded, stdlib-only HTTPS load probe; executed inside a disposable app container."""
import concurrent.futures
import datetime
import json
import math
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from collections import Counter

URL = "https://gateway/userbase/"
CONTEXT = ssl._create_unverified_context()  # Local gateway intentionally uses a self-signed certificate.
HEADERS = {
    "Host": "localhost",
    "User-Agent": "Mozilla/5.0 (compatible; ASGBoundedLoadProbe/1.1)",
    "Accept": "text/html",
}
PHASES = [
    ("baseline", 1, 5),
    ("concurrent_3", 3, 20),
    ("concurrent_6", 6, 36),
]


def request_once(_):
    start = time.monotonic()
    req = urllib.request.Request(URL, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=10, context=CONTEXT) as response:
            response.read()
            status = response.status
        err = None
    except urllib.error.HTTPError as exc:
        status = exc.code
        exc.close()
        err = None
    except Exception as exc:  # Network errors are counted separately from HTTP errors.
        status = 0
        err = f"{type(exc).__name__}: {str(exc)[:160]}"
    return status, round((time.monotonic() - start) * 1000, 3), err


def percentile(values, percent):
    if not values:
        return None
    values = sorted(values)
    return round(values[max(0, math.ceil(percent * len(values)) - 1)], 2)


def run_phase(name, workers, count):
    start = time.monotonic()
    if name == "baseline":
        # The Gateway actively rejects requests whenever the local rate limiter
        # returns a positive delay. Five consecutive calls are a BURST, not a
        # steady baseline. Space baseline calls to observe successful service.
        events = []
        for i in range(count):
            if i:
                time.sleep(1.25)  # <= 0.8 RPS regardless of local defaults.
            events.append(request_once(i))
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            events = list(pool.map(request_once, range(count)))
    wall = time.monotonic() - start
    status = Counter(str(s) if s else "network_error" for s, _, _ in events)
    latency = [ms for code, ms, _ in events if code]
    errors = [str(e) for _, _, e in events if e]
    report = {
        "phase": name,
        "requests": count,
        "concurrency": workers,
        "wall_seconds": round(wall, 3),
        # Response RPS includes 429 rejections; it is NOT accepted throughput.
        "responses_per_second": round(count / max(wall, 0.001), 3),
        "accepted_requests": status.get("200", 0),
        "rate_limited_requests": status.get("429", 0),
        "accepted_requests_per_second": round(status.get("200", 0) / max(wall, 0.001), 3),
        "statuses": dict(sorted(status.items())),
        "latency_ms_p50": percentile(latency, 0.5),
        "latency_ms_p95": percentile(latency, 0.95),
        "latency_ms_max": max(latency) if latency else None,
        "network_errors": len(errors),
        "error_samples": errors[:3],
    }
    print(f"{name}: concurrency={workers}, requests={count}, "
          f"response_RPS={report['responses_per_second']}, accepted_RPS={report['accepted_requests_per_second']}, "
          f"p50={report['latency_ms_p50']}ms, "
          f"p95={report['latency_ms_p95']}ms, "
          f"status={report['statuses']}", flush=True)
    return report


def main():
    report = {
        "kind": "bounded_gateway_load_probe",
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "git_commit": os.environ.get("ASG_COMMIT", "unknown"),
        "route": "/userbase/",
        "environment": "isolated Docker client on local development network",
        "note": "Baseline uses 1.25s spacing; bursts may be HTTP 429. RPS measures responses, not unrestricted Gateway capacity.",
        "phases": [],
    }
    failures = []
    for name, workers, count in PHASES:
        phase = run_phase(name, workers, count)
        report["phases"].append(phase)
        if phase["network_errors"]:
            failures.append(f"{name}: network errors")
        if any(int(code) >= 500 for code in phase["statuses"] if code.isdecimal()):
            failures.append(f"{name}: HTTP 5xx")
        unexpected = sorted(set(phase["statuses"]) - {"200", "429"})
        if unexpected:
            failures.append(f"{name}: unexpected HTTP statuses {unexpected}")
        if name == "baseline" and int(phase["statuses"].get("200", 0)) != count:
            failures.append("baseline: public requests did not all return 200")
    report["passed"] = not failures
    report["failures"] = failures
    print("REPORT_JSON=" + json.dumps(report, ensure_ascii=False, separators=(",", ":")), flush=True)
    if failures:
        print("FAIL: " + "; ".join(failures), file=sys.stderr)
        return 1
    print("BOUNDED GATEWAY LOAD: PASS (61 requests, max 6 concurrent)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
