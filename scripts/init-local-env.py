#!/usr/bin/env python3
"""Generate local-only secrets and write .env.local without printing them."""
from pathlib import Path
import secrets
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / ".env.local.example"
TARGET = ROOT / ".env.local"


def main() -> int:
    if TARGET.exists():
        print(".env.local already exists; leaving it unchanged.")
        return 0
    if not SOURCE.is_file():
        print("Missing .env.local.example; run from the repository root.", file=sys.stderr)
        return 1

    template = SOURCE.read_text(encoding="utf-8")
    placeholders = {
        "__GENERATE_SECRET_KEY__": secrets.token_urlsafe(48),
        "__GENERATE_JWT_SECRET__": secrets.token_hex(32),
        "__GENERATE_DB_PASSWORD__": secrets.token_hex(24),
        "__GENERATE_MYSQL_ROOT_PASSWORD__": secrets.token_hex(24),
        "__GENERATE_GRAFANA_PASSWORD__": secrets.token_hex(24),
    }
    for token, value in placeholders.items():
        if template.count(token) != 1:
            raise RuntimeError(f"Expected exactly one placeholder: {token}")
        template = template.replace(token, value)
    # Exclusive creation prevents accidental overwrite if another process wins.
    try:
        with TARGET.open("x", encoding="utf-8", newline="\n") as env:
            env.write(template)
    except FileExistsError:
        print(".env.local already created by another process; leaving unchanged.")
        return 0
    try:
        TARGET.chmod(0o600)
    except OSError:
        pass  # On Windows, filesystem permissions work differently.
    print("Created .env.local with random local development secrets (not displayed).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
