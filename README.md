<div align="center">

<img src="https://openresty.org/images/logo.png" alt="OpenResty" width="140"/>

# Adaptive Security Gateway

**A high-performance, production-grade Layer 7 WAF & API Gateway built from scratch with OpenResty and Lua**

[![OpenResty](https://img.shields.io/badge/OpenResty-1.21.4-00ADD8?style=flat-square&logo=nginx)](https://openresty.org/)
[![Lua](https://img.shields.io/badge/Lua-5.1-2C2D72?style=flat-square&logo=lua)](https://www.lua.org/)
[![Django](https://img.shields.io/badge/Django-5.x-092E20?style=flat-square&logo=django)](https://www.djangoproject.com/)
[![Redis](https://img.shields.io/badge/Redis-7-DC382D?style=flat-square&logo=redis)](https://redis.io/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker)](https://www.docker.com/)
[![AWS](https://img.shields.io/badge/AWS-EC2%20%7C%20RDS%20%7C%20S3-FF9900?style=flat-square&logo=amazon-aws)](https://aws.amazon.com/)
[![Jenkins](https://img.shields.io/badge/Jenkins-CI%2FCD-D24939?style=flat-square&logo=jenkins)](https://www.jenkins.io/)
[![Security](https://img.shields.io/badge/OWASP-Top%2010-E44D26?style=flat-square)](https://owasp.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

</div>

---

## 📑 Table of Contents

- [Overview](#-overview)
- [System Architecture](#-system-architecture)
- [Data Flow](#-data-flow)
- [Security Modules (13 Lua Modules)](#-security-modules)
- [Technology Stack](#-technology-stack)
- [Key Security Features](#-key-security-features)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
- [CI/CD Pipeline](#-cicd-pipeline)
- [Monitoring & Alerting](#-monitoring--alerting)
- [Container Security Hardening](#-container-security-hardening)

---

## 🎯 Overview

The **Adaptive Security Gateway** is a reverse-proxy security gateway purpose-built on **OpenResty (Nginx + LuaJIT)** that protects a Django-based healthcare appointment application from Layer 7 attacks. Instead of using an off-the-shelf WAF (such as ModSecurity), the entire security logic is implemented in **13 custom Lua modules** providing real-time, adaptive threat scoring.

The core design philosophy is **Defense in Depth**: every incoming HTTP request traverses a sequential security pipeline where malicious signals are *accumulated* rather than triggering an immediate block. A central **Risk Engine** aggregates signals from all modules, computes a final risk score, and decides whether to pass, rate-limit, or permanently blacklist the client IP.

### What This Project Demonstrates

| Domain | Skills |
|---|---|
| **Application Security (AppSec)** | Custom WAF, JWT attack prevention, brute-force protection, OWASP Top 10 |
| **Secure Architecture** | Defense in Depth, signal aggregation, risk scoring, combo amplification |
| **DevSecOps** | Jenkins CI/CD with security smoke tests, Docker hardening, auto-rollback |
| **Cloud Security** | AWS EC2 / RDS / S3, Let's Encrypt TLS, non-root containers |
| **Performance Engineering** | L1 (shared dict) + L2 (Redis) caching, async timers, Redis pipeline |

---

## 🏗️ System Architecture

```
┌───────────────────────────────────────────────────────────────────────┐
│                            Internet                                    │
└───────────────────────────────┬───────────────────────────────────────┘
                                │ HTTPS (TLS 1.2/1.3)
                                ▼
┌───────────────────────────────────────────────────────────────────────┐
│                    AWS EC2 Ubuntu Instance                             │
│                                                                        │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │              OpenResty Security Gateway (:80 / :443)            │  │
│  │                                                                  │  │
│  │  Security Pipeline  (access_by_lua_block)                       │  │
│  │  ┌───────────┐ ┌────────────┐ ┌───────────┐ ┌───────────────┐ │  │
│  │  │ XFF Guard │→│ IP Blacklist│→│ Geo Block │→│  Bot Detect   │ │  │
│  │  └───────────┘ └────────────┘ └───────────┘ └───────────────┘ │  │
│  │  ┌───────────┐ ┌────────────┐ ┌───────────┐ ┌───────────────┐ │  │
│  │  │Rate Limit │→│Redis Rate  │→│WAF SQLi/  │→│  JWT Auth &   │ │  │
│  │  │(L1 Nginx) │ │Limit (L2)  │ │XSS Scan   │ │  Brute Force  │ │  │
│  │  └───────────┘ └────────────┘ └───────────┘ └───────────────┘ │  │
│  │                          │ Signals                              │  │
│  │                          ▼                                      │  │
│  │                  ┌────────────────┐                             │  │
│  │                  │  Risk Engine   │── Prometheus Metrics        │  │
│  │                  │ (Aggregation + │── Telegram Alert            │  │
│  │                  │  IP Reputation)│── Nginx Security Log        │  │
│  │                  └───────┬────────┘                             │  │
│  │                          │ Pass / Block / Limit                 │  │
│  └──────────────────────────┼──────────────────────────────────────┘  │
│                             │ Proxy Pass (:8000)                     │
│  ┌──────────────────────────▼──────────────────────────────────────┐  │
│  │              Django App + Gunicorn (:8000)                      │  │
│  │              GatewayIdentityMiddleware                          │  │
│  │              Defense-in-Depth: Blocks direct API bypass         │  │
│  └────────────────┬────────────────────────────────────────────────┘  │
│                   │                                                    │
│  ┌────────────────▼────────────────┐  ┌─────────────────────────────┐│
│  │       Redis :6379               │  │  Prometheus :9090           ││
│  │  DB0: Gateway State             │  │  Grafana    :3000           ││
│  │  DB1: Django Session/Cache      │  └─────────────────────────────┘│
│  └─────────────────────────────────┘                                  │
│                                                                        │
└───────────────────────────────────────────────────────────────────────┘
                   │                          │
          ┌────────▼────────┐     ┌──────────▼──────────┐
          │  AWS RDS MySQL  │     │      AWS S3         │
          │ (ap-northeast-1)│     │  Static & Media     │
          └─────────────────┘     └─────────────────────┘
```

---

## 🔄 Data Flow

Every HTTP request follows this processing sequence:

```
Incoming Request
       │
       ├─[1]─► xff_guard.lua        — Strip & validate X-Forwarded-For, extract real client IP
       │
       ├─[2]─► ip_blacklist.lua     — L1 Cache check (shared dict) → L2 Redis check
       │                               Fail-closed if Redis unreachable
       │
       ├─[3]─► geo_block.lua        — MaxMind GeoLite2 lookup, apply country risk multiplier
       │
       ├─[4]─► bad_bot.lua          — User-Agent fingerprinting (42+ scanners, headless browsers)
       │                               Result cached in shared dict with SHA-256 key
       │
       ├─[5]─► rate_limit.lua       — L1 Leaky Bucket (Nginx RAM) — spike/DDoS catcher
       │                               Auto-blacklist IP to Redis on repeated violations
       │
       ├─[6]─► rate_limit_redis.lua — L2 Sliding Window ZSET algorithm — anti-scraper
       │                               Dual limit: global IP limit + per-URI limit (70%)
       │
       ├─[7]─► waf_sqli_xss.lua     — Payload normalization (URL decode + HTML entity decode)
       │                               SQLi (14 patterns) + XSS (13 patterns) scan across:
       │                               URI, query args, headers, cookies, JSON body (recursive)
       │
       ├─[8]─► jwt_auth.lua         — HS256 validation, alg=none attack block
       │                               Token replay detection (token bound to IP)
       │                               Hybrid auth: JWT Bearer or Django session cookie
       │
       └─[9]─► risk_engine.lua      — Aggregate all signals → compute final risk score
                                       Combo amplification → IP Reputation (Redis)
                                       PASS (risk < 50) | LIMIT-429 (50≤risk<80) | BLOCK-403 (risk≥80)
                                       Async Telegram alert on block
```

### Key Design Decisions

| Decision | Rationale |
|---|---|
| **Signal aggregation, not instant block** | Reduces false positives; single suspicious signal alone won't block legitimate users |
| **Combo amplification** | `SQLi + Bot` = +15 risk bonus; adversarial combinations are disproportionately penalized |
| **No-forgiveness reputation** | IPs with a history of attacks accumulate Redis reputation that persists across sessions |
| **IP Reputation Decay** (configurable) | Prevent permanent collateral blocking of shared NAT/CGNAT IPs |
| **Fail-closed on Redis outage** | If Redis is unreachable, blacklisted IPs remain blocked (safety over availability) |
| **Async Redis writes** | `ngx.timer.at(0, ...)` used for all writes so security checks never block request latency |

---

## 🛡️ Security Modules

The entire security layer is implemented as **13 independent Lua modules**, each with a single responsibility:

| # | Module | Purpose | Key Technique |
|---|--------|---------|---------------|
| 1 | `utils.lua` | Shared IP validation utilities | IPv4 / IPv6 / CGNAT `100.64.0.0/10` detection |
| 2 | `redis_helper.lua` | Centralized Redis connection manager | Connection pooling, timeout tuning (200/200/500ms) |
| 3 | `telegram_alert.lua` | Async security alerting | `ngx.timer.at`, anti-spam dedup, `ssl_verify=true` |
| 4 | `xff_guard.lua` | X-Forwarded-For sanitization | Detect chain abuse, private IP injection, spoofing |
| 5 | `ip_blacklist.lua` | Two-tier IP blacklist lookup | L1 shared dict → L2 Redis pipeline; revalidation; stale cleanup |
| 6 | `geo_block.lua` | MaxMind GeoLite2 blocking | Per-country risk multiplier; env-configurable allowlist |
| 7 | `bad_bot.lua` | Scanner & headless browser detection | 42+ tool fingerprints; SHA-256 UA cache key |
| 8 | `rate_limit.lua` | Per-IP local rate limiting | Leaky bucket (resty.limit.req); auto-blacklist on violation |
| 9 | `rate_limit_redis.lua` | Distributed sliding window rate limiting | Redis ZSET + Pipeline; per-IP and per-URI limits |
| 10 | `waf_sqli_xss.lua` | WAF — SQL Injection & XSS | Double-decode normalization; JSON recursive scan; ReDoS protection |
| 11 | `jwt_auth.lua` | JWT authentication enforcement | alg confusion attack block; token replay detection; SHA-256 cache |
| 12 | `brute_force_login.lua` | Login brute-force protection | Reset-exploit prevention; graduated penalty; 1-year permanent ban |
| 13 | `risk_engine.lua` | Central signal aggregation & scoring | Combo amplification; IP reputation decay; Prometheus metrics |

### Risk Score Reference

| Score Range | Action | HTTP Response |
|---|---|---|
| `0 – 49` | Pass | `2xx` (normal response) |
| `50 – 79` | Rate-limit | `429 Too Many Requests` |
| `80 – 100` | Block + Permanent Blacklist | `403 Forbidden` |

### Combo Amplification Table

| Signal Combination | Bonus Risk |
|---|---|
| SQLi + Bad Bot Scanner | +15 |
| XSS + Missing JWT | +15 |
| Rate Limit Hard + Geo Block | +10 |
| JWT Invalid + Rate Limit Hard | +10 |
| Headless Browser + SQLi | +20 |
| XFF Spoof + JWT Invalid | +15 |

---

## 🔧 Technology Stack

| Layer | Technology | Version | Role |
|---|---|---|---|
| **Security Gateway** | OpenResty (Nginx + LuaJIT) | 1.21.4 | Core WAF / Reverse Proxy |
| **Security Logic** | Lua | 5.1 | 13 custom security modules |
| **GeoIP** | MaxMind GeoLite2-Country | — | Country-based risk scoring |
| **Backend App** | Python / Django / Gunicorn | 3.12 / 5.x | Healthcare appointment app |
| **Primary Database** | AWS RDS (MySQL 8) | — | Persistent data (ap-northeast-1) |
| **State / Cache** | Redis 7 (Alpine) | 7 | L2 cache, IP reputation, rate limiting |
| **Object Storage** | AWS S3 | — | Static files & media uploads |
| **Monitoring** | Prometheus + Grafana | latest | Real-time security metrics dashboard |
| **Alerting** | Telegram Bot API | — | Real-time attack notifications |
| **SSL/TLS** | Let's Encrypt (ACME) | — | Automated certificate renewal |
| **Container** | Docker + Docker Compose | — | Service orchestration |
| **CI/CD** | Jenkins (Declarative Pipeline) | — | Automated build → test → deploy |
| **Platform** | AWS EC2 (Ubuntu) | — | Cloud deployment target |

---

## ✨ Key Security Features

### 1. Web Application Firewall (WAF)

The WAF in `waf_sqli_xss.lua` implements a normalization-first approach to defeat common bypass techniques:

```
Raw Input → URL Decode (×2) → HTML Entity Decode → Strip Comments → Regex Scan
```

- **SQLi Patterns (14):** UNION SELECT, time-based blind (SLEEP/BENCHMARK/WAITFOR), stacked queries, `xp_cmdshell`, file read/write, OR/AND 1=1, comment injection
- **XSS Patterns (13):** `<script>`, `javascript:`, `vbscript:`, 13 event handlers, `document.cookie`, SVG/iframe injection
- **Scan Surface:** URI, query string, User-Agent, Referer, XFF, Cookie, Authorization, JSON body (recursive), multipart excluded

### 2. JWT Authentication Guard

```
Token → Format check → alg=none block → Signature verify → exp/nbf/iat check
     → Replay detection (token↔IP binding) → SHA-256 cache → Forward X-User-ID/Role
```

- Blocks **Algorithm Confusion Attacks** (only `HS256` accepted)
- **Token Replay Detection:** Token is bound to the originating IP on first use. A stolen token used from a different IP triggers an instant block with `risk=100`
- **Hybrid Auth:** Supports both JWT Bearer tokens (API clients) and Django session cookies (web browser flows)

### 3. Brute-Force Protection & Reset Exploit Prevention

```
1st–2nd attempt  → Track only
3rd attempt      → Warning + CAPTCHA challenge flag
4th attempt      → Risk +10 penalty
5th+ attempt     → Permanent ban (1 year) + Telegram alert
```

> **Anti-Reset Exploit:** The failed attempt counter is **never reset** upon a successful login. This prevents the common attack pattern where an attacker logs in successfully between bursts to reset the counter.

### 4. Dual-Layer Rate Limiting

| Layer | Algorithm | Storage | Limit | Purpose |
|---|---|---|---|---|
| L1 (local) | Leaky Bucket | Nginx shared dict | 30 req/s burst:60 | DDoS spike catcher |
| L2 (distributed) | Sliding Window ZSET | Redis | 150 req/60s (global) / 105 req/60s (per-URI) | Anti-scraper |

The L2 Sliding Window uses Redis Sorted Sets with millisecond-precision timestamps, avoiding the *boundary spike vulnerability* of fixed-window counters.

### 5. Adaptive IP Reputation System

```
Request arrives
    │
    ├── Bad signals? → base_risk += (signal_scores + combo_bonuses)
    │
    ├── Redis reputation exists? → final_risk = reputation + base_risk
    │
    ├── final_risk ≥ 80? → Write permanent reputation to Redis (1-year TTL)
    │                       Add to blacklist_ips set
    │
    └── RISK_DECAY_ENABLED=true? → Clean requests decay reputation × (1 - factor)
                                    Prevents permanent collateral damage on shared NAT IPs
```

### 6. Defense-in-Depth: Django Middleware Layer

The Django backend includes `GatewayIdentityMiddleware` as a **second line of defense**. If any request somehow bypasses the gateway and hits Django directly, the middleware inspects the `X-User-ID` header (injected by the gateway after JWT validation). Requests to protected routes without this header return `401 Unauthorized`, making direct backend access impossible.

---

## 📁 Project Structure

```
Adaptive-Security-Gateway/
│
├── .env.example                    # ← Configuration template (copy to .env)
├── .gitignore                      # Blocks .env, secrets, __pycache__
├── docker-compose.yml              # Service orchestration (6 services)
├── Jenkinsfile                     # 6-stage CI/CD pipeline
│
├── nginx/
│   ├── Dockerfile                  # Alpine + LuaRocks + non-root 'gateway' user (UID 101)
│   ├── nginx.conf                  # 650+ lines: pipeline routing, TLS, shared memory
│   ├── GeoLite2-Country.mmdb       # MaxMind database (9MB)
│   │
│   ├── lua/                        # ── Core Security Modules ──────────────────
│   │   ├── utils.lua               # IPv4/IPv6/CGNAT validation helpers
│   │   ├── redis_helper.lua        # Centralized Redis connection pool
│   │   ├── telegram_alert.lua      # Async alerting with anti-spam dedup
│   │   ├── xff_guard.lua           # X-Forwarded-For sanitization
│   │   ├── ip_blacklist.lua        # Two-tier blacklist (L1 cache + L2 Redis)
│   │   ├── geo_block.lua           # GeoIP blocking & risk multiplier
│   │   ├── bad_bot.lua             # Scanner/headless browser detection
│   │   ├── rate_limit.lua          # L1 leaky bucket rate limiter
│   │   ├── rate_limit_redis.lua    # L2 sliding window rate limiter
│   │   ├── waf_sqli_xss.lua        # WAF engine (SQLi + XSS)
│   │   ├── jwt_auth.lua            # JWT authentication guard
│   │   ├── brute_force_login.lua   # Login brute-force protection
│   │   └── risk_engine.lua         # Signal aggregation & final scoring
│   │
│   └── vendor/                     # Vendored Lua libraries (Prometheus, MaxMind)
│
├── docappsystem/                   # ── Django Backend Application ─────────────
│   ├── Dockerfile                  # Multi-stage build, non-root 'appuser' (UID 1001)
│   ├── requirements.txt
│   └── docappsystem/
│       ├── settings.py             # Django configuration (reads from .env)
│       ├── middleware.py           # GatewayIdentityMiddleware (2nd defense layer)
│       ├── urls.py
│       └── views.py / ...
│
└── prometheus/
    └── prometheus.yml              # Scrape config for gateway metrics
```

---

## 🚀 Getting Started

### Prerequisites

- Docker Engine 24+ and Docker Compose v2
- Domain with DNS pointing to your server (for Let's Encrypt)
- AWS credentials (for RDS and S3)

### Deployment

**Step 1 — Clone and configure**
```bash
git clone https://github.com/NTNguyen055/Adaptive-Security-Gateway.git
cd Adaptive-Security-Gateway

# Fill in all <CHANGE_ME> values
cp .env.example .env
nano .env
```

**Step 2 — Start all services**
```bash
docker compose --env-file .env up -d --build
```

**Step 3 — Verify health**
```bash
# All services should show "healthy"
docker compose ps

# Test the security pipeline directly
curl -H "Host: your-domain.com" https://your-domain.com/health/

# Trigger a WAF block (should return 403)
curl -H "Host: your-domain.com" "https://your-domain.com/?q=1+UNION+SELECT+1,2,3--"
```

**Service Endpoints**

| Service | URL | Notes |
|---|---|---|
| Application | `https://your-domain.com` | Through the security gateway |
| Grafana Dashboard | `http://server-ip:3000` | Login with `GRAFANA_ADMIN_*` from `.env` |
| Prometheus | `http://server-ip:9090` | Raw metrics (internal use) |
| Gateway Metrics | `http://127.0.0.1:9145/metrics` | Localhost only |

---

## 🔁 CI/CD Pipeline

The Jenkins pipeline automates the full lifecycle from code commit to production deployment:

```
[1] Checkout    → Log branch, commit SHA, author
[2] Lint        → Verify all required files and Lua modules exist
[3] Build       → docker build with BuildKit cache (App + Gateway images)
[4] Smoke Test  → ① Django image boot  ② nginx.conf syntax  ③ All Lua deps
[5] Push        → docker push to DockerHub (versioned tag v{BUILD_NUMBER} + latest)
[6] Deploy      → SSH to EC2 with TOFU host-key verification
                   → git pull latest code
                   → docker compose up (with auto-rollback on failure)
                   → HTTP + Security pipeline health check
                   → Container state verification
```

**Auto-Rollback Logic**

If any step in stage `[6]` fails (compose startup, HTTP health check, or container state check), the pipeline automatically:
1. Restores Docker images to the `:rollback` tag
2. Reverts source code with `git reset --hard ${PREV_COMMIT}`
3. Restarts the previous working deployment

**Security in CI/CD**

- **TOFU SSH:** Host key is scanned and stored on first connection; `StrictHostKeyChecking=yes` on all subsequent connections
- **Secret management:** EC2 IP, Docker Hub credentials, and SSH keys are stored exclusively in Jenkins Credentials Store — never in source code
- **Build reproducibility:** OCI labels embed `COMMIT_SHA`, `BUILD_DATE`, and `VERSION` in every image

---

## 📊 Monitoring & Alerting

### Grafana Security Dashboard

The gateway exposes Prometheus metrics at `/metrics` (localhost-only), tracked per attack type:

| Metric | Description |
|---|---|
| `gateway_requests_blocked_total{reason}` | Total blocked requests by attack category |
| `gateway_risk_score_histogram` | Distribution of risk scores across all requests |
| `gateway_rate_limit_total` | Rate limit triggers (L1 burst / L2 exceeded) |
| `gateway_brute_force_total` | Brute-force attempts per endpoint |
| `gateway_geo_blocked_total` | Geo-blocked requests by country |

### Telegram Real-Time Alerts

When an IP is permanently blacklisted, an alert is fired asynchronously (non-blocking):

```
🛡️ SECURITY GATEWAY ALERT
────────────────────────
Time   : 2026-06-08 22:30:00
IP     : 1.2.3.4
Attack : brute_force_permanent_ban
Score  : 100
Detail : 5 failed login attempts — permanent blacklist
────────────────────────
Status : IP has been BLACKLISTED.
```

Alerts are deduplicated per `(IP, attack_type)` pair with a 10-minute cooldown to prevent notification spam.

---

## 🔒 Container Security Hardening

| Measure | Implementation |
|---|---|
| **Non-root Gateway** | `adduser gateway` (UID 101); `user gateway;` in nginx.conf — workers drop privileges after binding ports |
| **Non-root Backend** | `appuser:appgroup` (UID 1001) via `--chown` in multi-stage Dockerfile |
| **Multi-stage builds** | Build tools absent from runtime image; only compiled wheels copied |
| **Minimal base images** | `openresty:alpine-fat` and `python:3.12-slim` — minimal attack surface |
| **OCI labels** | Every image tagged with `COMMIT_SHA`, `BUILD_DATE`, `VERSION` for traceability |
| **Read-only mounts** | nginx.conf, Lua scripts, and Let's Encrypt certs mounted `:ro` in Compose |
| **Network isolation** | All services on isolated `internal` bridge network (`172.20.0.0/24`); only gateway exposes ports 80/443 |
| **Metrics port binding** | Port `9145` bound to `127.0.0.1` only — Prometheus scrapes internally, never exposed to Internet |
| **Secret management** | All credentials in `.env` (gitignored); Grafana password enforced via `${VAR:?error}` syntax |

---

## 🤝 Defense-in-Depth Summary

```
Layer 1: TLS 1.2/1.3 Only     — Encrypted transport, OCSP Stapling, HSTS + preload
Layer 2: XFF Guard             — Real IP extraction, spoof detection
Layer 3: IP Blacklist          — Known bad actors blocked at L1 cache speed
Layer 4: Geo Blocking          — Country-based risk amplification via MaxMind
Layer 5: Bot Detection         — 42+ offensive tool fingerprints blocked
Layer 6: Rate Limiting         — L1 (burst) + L2 (sustained) with auto-blacklist
Layer 7: WAF (SQLi / XSS)     — Normalization-first bypass-aware detection
Layer 8: JWT Auth Guard        — Algorithm confusion & token replay prevention
Layer 9: Brute-Force Guard     — Reset-exploit-proof graduated lockout
Layer 10: Risk Engine          — Signal aggregation, combo amplification, reputation
Layer 11: Django Middleware    — Backend bypass detection (second line of defense)
Layer 12: Security Headers     — CSP, HSTS, X-Frame-Options, Permissions-Policy
```

---

## 👨‍💻 Author

**Nguyen Trung Nguyen** — Graduation Thesis / Security Research  
Demonstrating the intersection of Application Security (AppSec) and DevSecOps in a production-grade system.

> *"Security is not a product, but a process."* — Bruce Schneier

---

<div align="center">
  <sub>Built with ❤️ using OpenResty, Lua, Django, Docker, and AWS</sub>
</div>
