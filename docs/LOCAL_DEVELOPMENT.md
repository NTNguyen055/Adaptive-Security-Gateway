# Local Development — Adaptive Security Gateway

This guide describes how to run the project on a developer machine for development and testing.

> **Lab/development environment only.** Do not expose the services from `docker-compose.dev.yml` directly to the Internet. Do not use the local Compose file or `.env.local` to deploy production. Production uses the separate `docker-compose.yml` and production environment stored on the EC2 host.

## 1. Requirements

- Docker Engine / Docker Desktop with Docker Compose v2.
- Python 3 to run `scripts/init-local-env.py` (the script does not require third-party Python packages).
- Approximately 4–6 GB RAM available to Docker is a practical starting point for the local stack; image builds may require additional disk space.
- Host ports `80` and `443` must be available. The development Compose configuration binds the gateway to loopback (`127.0.0.1`), not to all network interfaces.

Commands below are run from the repository root (the directory containing `docker-compose.dev.yml`, `nginx/` and `docappsystem/`).

## 2. Create the local environment

Generate `.env.local` from the local example:

```bash
python scripts/init-local-env.py
```

The script is intended to create the local environment file safely. If `.env.local` already exists, inspect it and follow the script's behavior rather than overwriting it blindly.

Do not paste real production credentials into `.env.local`. Do not commit `.env.local`.

## 3. Validate and start the local stack

```bash
docker compose --env-file .env.local -f docker-compose.dev.yml config --quiet

docker compose --env-file .env.local -f docker-compose.dev.yml up -d --build

docker compose --env-file .env.local -f docker-compose.dev.yml ps
```

The development stack uses local MySQL and Redis containers and does not require AWS RDS or production AWS credentials.

The Django container uses `docappsystem.settings_local` with `APP_ENV=local`. Its startup command runs database migrations, collects static files and starts Gunicorn.

The local settings enforce the following safeguards:

- `APP_ENV` must be `local`.
- The database host must be `db`, `localhost` or `127.0.0.1`.
- `USE_S3=True` is rejected.
- MySQL TLS is disabled only for the internal local development database.
- `DEBUG=False` and secure authentication cookies remain enabled.

Check that the expected services are running and inspect health status before testing the application.

## 4. Verify the application and gateway

The local gateway uses a temporary self-signed certificate supplied by the gateway image/configuration. Browsers and `curl` may therefore report a certificate trust error. This is expected only for the local lab certificate; do not disable certificate verification in production.

```bash
curl -k -i https://localhost/health/
```

On Windows PowerShell, call `curl.exe` explicitly if `curl` resolves to the PowerShell alias:

```powershell
curl.exe -k -i https://localhost/health/
```

Open the local application in a browser:

- `https://localhost/login/`
- `http://localhost/` (the gateway is configured to redirect HTTP to HTTPS)

Accept the self-signed certificate warning only for this local test environment.

If the host ports are already occupied, stop the application using those ports before starting the stack. Do not change the production Nginx listener or production Compose configuration to work around a local port conflict.

## 5. Logs and diagnostics

Follow application, database and Redis logs:

```bash
docker compose --env-file .env.local -f docker-compose.dev.yml logs -f app db redis
```

Inspect gateway error logs:

```bash
docker compose --env-file .env.local -f docker-compose.dev.yml exec gateway \
  sh -c 'tail -n 60 /usr/local/openresty/nginx/logs/error.log'
```

Run Django's system check:

```bash
docker compose --env-file .env.local -f docker-compose.dev.yml exec app \
  python manage.py check
```

Check the OpenResty configuration:

```bash
docker compose --env-file .env.local -f docker-compose.dev.yml run --rm --no-deps gateway \
  openresty -t
```

A local self-signed certificate may cause an OCSP stapling warning such as `ssl_stapling ignored, issuer certificate not found`. Interpret it in the context of the local dummy certificate; it is not, by itself, evidence that the production Let's Encrypt certificate is invalid.

To connect to the local MySQL service, use the credentials configured in your own `.env.local`. For example:

```bash
docker compose --env-file .env.local -f docker-compose.dev.yml exec db \
  mysql -u adaptive_user -p adaptive_gateway_dev
```

The command prompts for the local database password. Read it locally from `.env.local`; never paste it into chat or commit it. The database may not contain sample application records, so pages that depend on seeded data can appear empty until you create test data.

## 6. Run tests

The repository provides separate test runners for local development and Jenkins CI.

Read each script and check its prerequisites before execution.

### Unit regression

Run the local unit regression tests:

```bash
bash tests/run-unit.sh
```

This local regression runner executes the Lua regression suites and Django isolated unit tests according to the script configuration.

### Integration tests

Run the local integration checks:

```bash
bash tests/run-integration.sh
```

The integration runner is intended for a configured local development environment. It may require `.env.local`, running Docker Compose services and additional integration dependencies.

### CI runner

`tests/run-ci.sh` is used by Jenkins for the offline regression stage.

The Jenkins `Unit Regression` stage executes this script and archives its output as `ci-unit.log`. It does not run the local `.env.local` or live Redis integration scripts in this stage.

The Jenkins `Smoke Test` stage separately validates the OpenResty configuration and required Lua dependencies in the built gateway image.

Do not interpret a manually executed CI script failure caused by missing pipeline-provided image variables as an application regression failure. Check the current `Jenkinsfile` and `tests/run-ci.sh` for the required CI inputs.

## 7. Optional monitoring profile

Start the optional monitoring services:

```bash
docker compose --env-file .env.local -f docker-compose.dev.yml --profile monitoring up -d
```

When the profile is enabled, the local endpoints are:

- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3000`

Use the Grafana username/password configured in your own `.env.local`. Do not publish these development monitoring ports to a public network.

## 8. Stop the local environment

Stop and remove the local containers and network:

```bash
docker compose --env-file .env.local -f docker-compose.dev.yml down
```

This command retains named volumes, so local database and persistent service data remain available for the next start.

To remove the Compose volumes as well:

```bash
docker compose --env-file .env.local -f docker-compose.dev.yml down -v
```

> **Warning:** `down -v` permanently deletes the local named-volume data, including the local database data. Back up anything needed before running it. This command targets the development Compose project only; verify the `-f docker-compose.dev.yml` argument before execution.

## 9. Environment separation and safety checklist

| Purpose | Environment file | Compose file |
|---|---|---|
| Local development/testing | `.env.local` | `docker-compose.dev.yml` |
| Production deployment | `.env` on the production host | `docker-compose.yml` |

Before running a Compose command, verify that it explicitly references the intended environment file and Compose file.

- Never run `docker compose up` without checking which Compose project and environment it will use.
- Never copy production `.env` values into local development.
- Never commit `.env`, `.env.local`, database dumps containing personal data, private keys or access tokens.
- Do not expose local MySQL, Redis, Prometheus, Grafana or gateway metrics to the public Internet.
- Keep local test data synthetic or anonymized.

## 10. Troubleshooting

**Port 80 or 443 is already in use**

Identify and stop the local process/container that owns the port, then retry. The development gateway is intentionally bound to loopback.

**The browser reports a certificate warning**

The local gateway certificate is self-signed. Continue only for local testing. Do not reuse this certificate in production.

**The application container is running but the page does not load**

Check `docker compose ... ps`, then inspect `app`, `db`, `redis` and `gateway` logs. Confirm that the database is healthy and that the gateway can reach the application service.

**A test runner reports missing containers or environment variables**

Check the script's intended execution context. `run-unit.sh` and `run-integration.sh` are local workflows; `run-ci.sh` is designed for Jenkins and requires CI image variables.

---

**The application refuses to start with local settings**

Check that `.env.local` contains the required local environment configuration:

- `APP_ENV=local`
- `DB_HOST=db` when running through Docker Compose.

The local Django settings intentionally reject non-local database hosts and `USE_S3=True`. Do not bypass these checks to connect the development stack to production services.

For production deployment, AWS operations and release procedures, follow the repository's deployment configuration and approved operational documentation. This file is only a local development guide.
