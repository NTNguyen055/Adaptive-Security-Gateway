# Adaptive Security Gateway

A Layer 7 security gateway for a Django-based appointment application, built with OpenResty, Lua, Redis, Docker and AWS.

The current implemented baseline is a **Rule-Based security gateway**. It combines request validation, WAF checks, authentication protections, rate limiting, IP reputation and risk scoring. Machine-learning detection and the Hybrid Rule-Based + ML evaluation are future project work; they should not be considered implemented until the model, inference service, integration and experiments are completed.

## Project overview

The gateway acts as a reverse proxy in front of the Django application:

```text
Client
  |
  | HTTPS
  v
OpenResty Gateway
  |-- Client IP / X-Forwarded-For validation
  |-- IP blacklist and GeoIP checks
  |-- Bot detection
  |-- Local and Redis rate limiting
  |-- SQLi / XSS inspection
  |-- JWT and login brute-force protections
  |-- Risk aggregation and security metrics
  |
  v
Django + Gunicorn
  |
  +---- Redis (gateway state, counters, cache/session data)
  +---- AWS RDS MySQL (application data)
  +---- AWS S3 (private media uploads)
```

Static assets are served by Django WhiteNoise. S3 is used for media/object uploads; it is not the static-file hosting destination in the current architecture.

## Technology stack

| Layer | Technology | Responsibility |
|---|---|---|
| Security gateway | OpenResty / Nginx | Reverse proxy and request filtering |
| Security logic | Lua 5.1 | Gateway security modules |
| Backend | Python, Django, Gunicorn | Appointment application and authorization |
| State/cache | Redis 7 | Rate-limit state, IP reputation and cache/session data |
| Database | AWS RDS MySQL 8.4 | Persistent application data |
| Object storage | AWS S3 | Private media uploads |
| Static files | WhiteNoise | Django static assets |
| Monitoring | Prometheus, Grafana | Gateway metrics and dashboards |
| Alerting | Telegram Bot API | Security notifications, when configured |
| Containers | Docker, Docker Compose | Local and production service orchestration |
| CI/CD | Jenkins | Pull-request CI and main-branch release/deployment |
| Cloud | AWS EC2, RDS, S3, IAM | Production infrastructure |

## Security capabilities

The current Rule-Based baseline includes the following modules and controls:

- X-Forwarded-For validation and client-IP handling.
- IP blacklist checks using local cache and Redis.
- GeoIP-based risk signals.
- User-Agent / scanner detection.
- Local and Redis-backed rate limiting.
- SQL injection and cross-site scripting (XSS) payload inspection.
- JWT validation and replay-related protections.
- Login brute-force protection.
- Risk aggregation, IP reputation and decay logic.
- Django-side gateway identity validation as an additional defense layer.
- Role-based access for admin, doctor and user accounts.
- Security metrics and operational logging.

The exact behavior and thresholds are defined by the implementation and configuration in the repository. Avoid treating example thresholds in documentation as immutable defaults if the configuration changes.

## Repository layout

```text
Adaptive-Security-Gateway/
├── .env.example
├── .env.local.example
├── docker-compose.yml
├── docker-compose.dev.yml
├── Jenkinsfile
├── scripts/
│   └── init-local-env.py
├── docs/
│   └── LOCAL_DEVELOPMENT.md
├── nginx/
│   ├── Dockerfile
│   ├── nginx.conf
│   └── lua/
├── docappsystem/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── docappsystem/
│       ├── settings.py
│       ├── settings_local.py
│       ├── settings_test.py
│       ├── middleware.py
│       └── ........
├── prometheus/
│   └── prometheus.yml
└── tests/
    ├── run-unit.sh
    ├── run-integration.sh
    └── run-ci.sh
```

Some paths may evolve as the repository changes. Use the actual files in the checked-out branch as the source of truth.

## Getting started

There are separate workflows for local development and production. **For development on your own machine, follow [Local Development](docs/LOCAL_DEVELOPMENT.md).** Do not use the production Compose file or production `.env` for routine local work.

### Local development

The local workflow uses:

- `.env.local`
- `docker-compose.dev.yml`
- Local MySQL and Redis containers
- Local gateway and Django containers

See [docs/LOCAL_DEVELOPMENT.md](docs/LOCAL_DEVELOPMENT.md) for setup, tests, logs, monitoring and cleanup commands.

### Production deployment

Production deployment is managed through the repository's Jenkins pipeline and the production environment on AWS. It uses the production `.env` stored on the EC2 host and `docker-compose.yml`.

Do not copy production secrets into the repository, local development files, issue reports or chat messages. Do not run production deployment commands as a substitute for local development.

At a high level:

1. Changes are developed on feature branches or the integration branch.
2. Pull requests and branches run the common CI stages: Checkout, Pre-build Checks, Build Images, Unit Regression and Smoke Test.
3. The `develop` branch publishes application and gateway images using `dev-<commit SHA>` tags.
4. The `main` branch verifies the release commit before publishing versioned Docker images.
5. The main-branch pipeline runs production database migration on EC2, deploys the verified images and checks HTTP/HTTPS health.
6. After successful deployment, the pipeline publishes the `latest` image tags.

Production deployment includes image revision verification, pinned SSH host-key verification and rollback handling if deployment or health checks fail.

The exact stages and branch conditions are defined by the current `Jenkinsfile`.

## Testing

| Script | Intended use |
|---|---|
| `tests/run-unit.sh` | Developer-local unit regression runner |
| `tests/run-integration.sh` | Developer-local integration checks |
| `tests/run-ci.sh` | Offline regression runner used by Jenkins CI |

The Jenkins `Unit Regression` stage executes `tests/run-ci.sh` and archives its output as `ci-unit.log`.

The Jenkins pipeline does not run the local `.env.local` or live Redis integration scripts in this stage.

The `Smoke Test` stage separately validates the OpenResty configuration and required Lua dependencies in the newly built gateway image.

Check each script for its prerequisites before running it manually.

## AWS production architecture

The current production environment uses:

- **EC2** to run the Docker Compose application stack.
- **RDS MySQL** in `ap-southeast-1` for persistent application data.
- **S3** in `ap-southeast-1` for private media objects.
- An EC2 IAM role (`asg-app-ec2-role`) for application access to S3; long-lived AWS access keys should not be embedded in the application `.env`.
- HTTPS certificates for the public application hostname.
- Redis for gateway state and cache-related workloads.

RDS is configured for TLS certificate/hostname verification by the production Django database configuration. Production-specific values and secrets belong on the EC2 host, not in Git.

## Monitoring

Prometheus scrapes gateway metrics over the Docker network. Grafana is used to view configured dashboards. In production, monitoring interfaces and metrics endpoints must not be exposed publicly unless an explicit, secured access design is in place.

For local optional monitoring, use the `monitoring` Compose profile described in [docs/LOCAL_DEVELOPMENT.md](docs/LOCAL_DEVELOPMENT.md).

## Container and secret handling

- Keep `.env`, `.env.local` and all real credentials out of Git.
- Use the example environment files as templates only.
- Use non-root container users where configured by the Dockerfiles.
- Keep database, Redis and internal application services on their intended private Docker networks.
- Do not publish internal metrics, database or Redis ports to the public Internet.
- Review Compose and Dockerfile changes before deploying them to production.
- Keep `settings_local.py` restricted to local development; it requires `APP_ENV=local` and rejects non-local database hosts or `USE_S3=True`.
- Local MySQL TLS is disabled only for the internal development database. Production database TLS verification must remain enabled.

## Project status and research direction

The current deployed baseline is the Rule-Based gateway and appointment application. The next research phase is to develop and evaluate HTTP Flood / Layer 7 anomaly detection, then assess a Hybrid design without weakening the existing Rule-Based controls.

The ML phase and final performance/security experiments must be documented with reproducible datasets, test scenarios and measured results. Do not report planned functionality or target metrics as completed results.

## License

See [LICENSE](LICENSE).
