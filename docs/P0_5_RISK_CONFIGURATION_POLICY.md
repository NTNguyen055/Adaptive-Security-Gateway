# P0.5.3 — Risk Engine Configuration Policy & Deployment Preflight

**Scope:** Adaptive Security Gateway, `feature/p0-security-baseline` (local development and eventual EC2 production).  
**Status:** Proposed patch files and integration instructions. No repository or CI configuration has been changed by this delivery.

## Security decision

| Layer | Policy | Reason |
|---|---|---|
| Local Risk Engine (`get_config()`) | Validated defaults + one warning per worker | Keep local RED/GREEN development predictable; never silently accept broken thresholds |
| CI source/template gate | Run offline validator tests; validate the checked-in `.env.example` and `.env.local.example` | Catch drift and code/test regressions before packaging |
| EC2 deployment preflight | **Strictly reject** invalid/missing Risk config **before migration and Gateway restart** | Prevent deploying unintended mitigation policy; don't change existing live deployment |
| Runtime operational monitoring | Record warnings and alert for configuration mismatch | Preflight does not replace actual deployed-state observability |

## Explicit production contract

All four keys must be present in the **actual env_file consumed by the Gateway**:

```dotenv
RISK_LIMIT_THRESHOLD=50
RISK_BLOCK_THRESHOLD=80
RISK_DECAY_ENABLED=false
RISK_DECAY_FACTOR=0.1
```

- `0 < RISK_LIMIT_THRESHOLD < RISK_BLOCK_THRESHOLD <= 100`.
- `RISK_DECAY_ENABLED`: explicit case-insensitive `true` or `false`, no synonyms or misspellings.
- `RISK_DECAY_FACTOR`: finite decimal in `[0,1]`; values outside this range, including `2.5`, are **rejected** before deployment, **not clamped** for production.
- For local only, the current runtime `get_config()` may still clamp or fall back with a warning to keep existing regression behavior.
- With decay enabled, fraction `0.1` is applied **per elapsed 300-second interval** on a subsequent reputation-worthy event. It is **not** “per hour,” and ordinary clean traffic does not refresh reputation timestamps.
- Factor `1.0` is mathematically permitted by this policy but fully decays previous reputation after one eligible period; it should be chosen only after explicit policy approval, not as a silent fallback.
- Score thresholds apply to Risk Engine `risk_action`, not automatic Redis IP-ban issuance. Other detectors can block a request independently.

## New files

Put `check_risk_config.py` and `test_check_risk_config.py` in the repository's existing `tests/` folder. They are standalone Python 3 standard-library programs (no external dependencies).

Local validation:

```bash
python3 -m unittest discover -s tests -p 'test_check_risk_config.py' -v
python3 tests/check_risk_config.py --env-file .env.example
python3 tests/check_risk_config.py --env-file .env.local.example
python3 tests/check_risk_config.py --env-file .env.local
```

The validator is **read-only**; it does not source the `.env` file, display secret values, access Redis, or rewrite files. It checks four named variables only. It rejects duplicate assignments and malformed `RISK_*` assignments. It does not verify every other application setting.

Before running against a production file, verify that the runtime's Gateway `env_file` path is the one being passed. In the referenced `docker-compose.yml`, the production Gateway uses `/home/ubuntu/appointment-web/.env`.

## Required Jenkinsfile integration (user applies manually)

### A — Pre-build Checks stage

After existing `bash tests/check-ci-suite-parity.sh`, add:

```bash
command -v python3 >/dev/null || { echo 'Missing Python3 for config preflight' >&2; exit 1; }
python3 -m unittest discover -s tests -p 'test_check_risk_config.py' -v
python3 tests/check_risk_config.py --env-file .env.example
python3 tests/check_risk_config.py --env-file .env.local.example
```

Also extend the `for file in ...` required-files list with `tests/check_risk_config.py tests/test_check_risk_config.py` (and the policy document if desired). **Check that the Jenkins agent has Python3 before enabling this stage.** If it does not, install/arrange a versioned offline Python runtime through your CI image instead of silently skipping validation.

### B — Database Migration remote script

Inside `migrationScript`, **after** the release checkout (`git checkout --detach "$SOURCE_COMMIT"`) and definition of `restore_source()`, **before** `[5] Pulling release application image`, add:

```bash
log '[P05] Strict Risk Engine configuration preflight (before migration)...'
if ! command -v python3 >/dev/null || \
   ! python3 "$APP_DIR/tests/check_risk_config.py" --env-file "$ENV_PATH"; then
    restore_source || fail 'Risk preflight failed; source restoration failed'
    fail 'Risk preflight failed; refusing production migration/deployment'
fi
```

This is the earliest code-available position before the first production database migration side effect; the release source is already SHA-verified at that point. It will reject deployments missing required variables.

### C — Deploy & Verify remote script (defense in depth)

In the deploy script, **after** activating the verified source (`git reset --hard "$SOURCE_COMMIT"`) and `git clean`, but **before** `[6] Starting production Compose`, add:

```bash
log '[P05] Re-checking Risk Engine configuration before starting production Gateway...'
if ! command -v python3 >/dev/null || \
   ! python3 "$APP_DIR/tests/check_risk_config.py" --env-file "$ENV_PATH"; then
    do_rollback || fail 'Risk preflight failed and rollback was incomplete'
    fail 'Risk preflight failed; refusing Gateway restart'
fi
```

The second gate protects against `.env` drift between migration and the Gateway restart. Use existing rollback logic rather than adding an unsupervised service stop or `down` action.

**Important:** The exact injection points above were reviewed against the remote repository base `f9cc652`. Reconcile the snippets against your local Jenkinsfile before applying. Never paste logs containing production `.env` values.

## `.env.example` correction (existing file — manual edit)

Replace only the misleading comment near `RISK_DECAY_FACTOR`:

```dotenv
# RISK_DECAY_FACTOR: fraction of previous IP reputation decayed per completed
# 300-second period, evaluated on the next confirmed reputation-worthy request;
# e.g. 0.1 => 10% per period; clean requests do not refresh the timestamp.
# RISK_DECAY_ENABLED: explicit true/false; false disables decay intentionally.
# Unset at runtime defaults to true in get_config(), but deployed env files
# should always declare this explicitly and pass the strict preflight.
RISK_DECAY_FACTOR=0.1
RISK_DECAY_ENABLED=false
```

Do not change `.env.local` or production `.env` automatically. `.env.local.example` already contains explicit values; validate it but do not change the current policy without an operator decision.

## P0.5.3 acceptance criteria

1. New Python validator tests PASS, including invalid/missing, NaN/Infinity, inverted, duplicate and out-of-range configurations.
2. Existing Gateway unit regression still PASS (last user-supplied baseline: **18 suites, 314 cases**).
3. Existing Redis integration contract remains valid (last user-supplied **4 suites, 67 checks**).
4. Jenkins/EC2 deploy **actually executes** the strict validator before migration and restart, using the real deployed env file. CI checks of `.env.example` alone are insufficient.
5. One test with an invalid **synthetic** file exits nonzero, and a valid synthetic file exits 0. Never deliberately change the live production `.env` to test rejection.
6. Record the preflight PASS/FAIL in CI artifacts without displaying secrets.

## CFG issue disposition

- **CFG-01:** Addressed in design and a tested preflight script; **not formally closed** until integrated and executed in Jenkins/EC2.
- **CFG-02:** Corrected in the documentation snippet above; **not closed** until user applies the `.env.example` change.
- **CFG-03:** Strict production rejection in validator; preserve existing local clamp regression. **Not closed** until the deployment gate is active.
- **CFG-04:** Existing per-request `get_config()` remains deliberately unchanged. ENV access overhead has **not been benchmarked**; optimization should be a measured performance change with regression tests, not an unverified correctness fix. Mark **documented/accepted risk**, not performance PASS.
