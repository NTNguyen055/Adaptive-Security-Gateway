#!/usr/bin/env python3
"""Read-only inventory of LOCAL Redis DB 0 security state.

Requires Docker Compose v2 and redis-cli --json (Redis 7).
No FLUSHDB, DEL, SREM, EXPIRE, CONFIG SET or write operations occur.
Raw IPs, account identifiers, credentials and Redis values are NOT reported.

Usage from the repository root:
    python scripts/audit_legacy_bans.py
    python scripts/audit_legacy_bans.py --output /tmp/a34-audit.json

Manual blacklist membership cannot prove whether each member was created by
an operator or a legacy automatic writer. This is an INVENTORY, not migration.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
MAX_SAMPLE = 20
PREFIXES = (
    ("legacy_auto", "blacklist:*"),
    ("legacy_lockout", "brute_force:lockout:*"),
    ("reputation", "risk:v1:*"),
    ("authorized_v2", "ban:v2:ip:*"),
)


class InventoryError(RuntimeError):
    """A read-only audit could not be completed reliably."""


class RedisCLI:
    def __init__(self) -> None:
        self.base = [
            "docker", "compose", "--env-file", ".env.local",
            "-f", "docker-compose.dev.yml", "exec", "-T",
            "redis", "redis-cli", "--json", "-n", "0",
        ]

    def call(self, *arguments: str):
        result = subprocess.run(
            [*self.base, *map(str, arguments)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
            env={**os.environ, "MSYS_NO_PATHCONV": "1"},
        )
        if result.returncode != 0:
            raise InventoryError(
                "Redis CLI unavailable (exit code "
                f"{result.returncode}); check LOCAL compose services"
            )
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise InventoryError("Redis CLI did not return valid JSON") from exc
        if isinstance(value, dict) and "err" in value:
            raise InventoryError(f"Redis replied with an error for {arguments[0]}")
        return value

    def scan(self, command: str, pattern: str | None, cap: int):
        cursor = "0"
        seen: set[str] = set()
        while True:
            args = [command]
            if command == "SSCAN":
                args.append("blacklist_ips")
            args.append(cursor)
            if pattern is not None:
                args += ["MATCH", pattern]
            args += ["COUNT", "200"]
            response = self.call(*args)
            if not isinstance(response, list) or len(response) != 2:
                raise InventoryError(f"Unexpected Redis {command} response")
            cursor, keys = str(response[0]), response[1]
            if not isinstance(keys, list):
                raise InventoryError(f"Unexpected {command} members")
            for key in keys:
                if not isinstance(key, str):
                    raise InventoryError("Unexpected non-string Redis key")
                if key in seen:
                    continue
                seen.add(key)
                if len(seen) > cap:
                    raise InventoryError(
                        f"Inventory exceeded --max-keys={cap}; retry with a larger cap"
                    )
                yield key
            if cursor == "0":
                break


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-keys", type=int, default=10000)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not 1 <= args.max_keys <= 100000:
        parser.error("--max-keys must be between 1 and 100000")
    if not (ROOT / ".env.local").is_file() or not (ROOT / "docker-compose.dev.yml").is_file():
        parser.error("Run only from an existing LOCAL development repository")

    redis = RedisCLI()
    if redis.call("PING") != "PONG":
        raise InventoryError("LOCAL Redis did not answer PONG")

    salt = secrets.token_bytes(32)

    def fingerprint(value: str) -> str:
        return hashlib.sha256(salt + value.encode("utf-8")).hexdigest()[:16]

    report = {
        "schema": 1,
        "environment": "local-development",
        "database": 0,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "operation": "READ_ONLY_INVENTORY",
        "warnings": [
            "Manual SET membership does not prove human/manual provenance.",
            "Legacy automatic key value 1 cannot prove issuance authority.",
            "Never bulk-delete, rewrite or auto-migrate ambiguous state.",
            "Fingerprints are randomly salted per run and are not stable identifiers.",
        ],
        "groups": {},
    }

    manual_count = redis.call("SCARD", "blacklist_ips")
    if not isinstance(manual_count, int):
        raise InventoryError("Could not verify blacklist_ips SCARD")
    manual_sample = [
        fingerprint(ip) for ip in redis.scan("SSCAN", None, args.max_keys)
    ]
    report["groups"]["manual_set"] = {
        "reported_count": manual_count,
        "sample_fingerprints": sorted(manual_sample)[:MAX_SAMPLE],
        "provenance": "UNKNOWN_WITHOUT_OPERATOR_RECORDS",
    }

    for label, pattern in PREFIXES:
        metrics = Counter()
        examples = []
        for key in redis.scan("SCAN", pattern, args.max_keys):
            t = redis.call("TYPE", key)
            ttl_ms = redis.call("PTTL", key)
            if not isinstance(t, str) or not isinstance(ttl_ms, int):
                raise InventoryError("Unexpected TYPE/PTTL result")
            metrics["keys"] += 1
            if ttl_ms == -1:
                metrics["no_expiry"] += 1
            elif ttl_ms == -2:
                metrics["expired_during_scan"] += 1
            elif ttl_ms > 0:
                metrics["expiring"] += 1
            if t != "string":
                metrics["unexpected_type"] += 1

            if label == "legacy_auto" and t == "string":
                raw_legacy = redis.call("GET", key)
                if raw_legacy not in ("1", "0", None):
                    metrics["unexpected_legacy_value"] += 1

            if label == "authorized_v2" and t == "string" and ttl_ms > 0:
                raw = redis.call("GET", key)
                try:
                    record = json.loads(raw)
                    valid = (
                        isinstance(record, dict)
                        and record.get("schema") == 1
                        and record.get("issuer") == "security_correlator"
                        and record.get("reason") == "confirmed_exploit_campaign"
                        and record.get("scope") == "ip"
                        and record.get("ip") == key[len("ban:v2:ip:"):]
                        and isinstance(record.get("incident_id"), str)
                        and 16 <= len(record["incident_id"]) <= 64
                        and all(c in "abcdef0123456789" for c in record["incident_id"])
                        and type(record.get("ttl_seconds")) is int
                        and 1 <= record["ttl_seconds"] <= 300
                        and type(record.get("issued_at")) is int
                        and type(record.get("expires_at")) is int
                        and record["expires_at"] - record["issued_at"] == record["ttl_seconds"]
                        and ttl_ms <= 300000
                    )
                except (ValueError, TypeError):
                    valid = False
                if not valid:
                    metrics["invalid_v2_metadata"] += 1

            if len(examples) < MAX_SAMPLE:
                examples.append({
                    "fingerprint": fingerprint(key),
                    "type": t,
                    "ttl_class": "persistent" if ttl_ms == -1
                        else "expired" if ttl_ms == -2 else "expiring",
                })
        report["groups"][label] = {
            **dict(metrics),
            "sample": examples,
        }

    content = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        target = args.output.resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        # The generated report contains pseudonymous network identifiers only.
        # It should still be kept out of Git unless explicitly reviewed.
        target.write_text(content + "\n", encoding="utf-8")
        print(f"Read-only inventory saved: {target}")
    else:
        print(content)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (InventoryError, subprocess.TimeoutExpired) as exc:
        print(f"A3.4 audit FAILED without mutation: {exc}", file=sys.stderr)
        raise SystemExit(1)
