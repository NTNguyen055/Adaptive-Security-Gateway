# =============================================================================
# STAGE 1: Builder — compile Python wheels
# =============================================================================
FROM python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS builder

WORKDIR /build

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_ROOT_USER_ACTION=ignore \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# Build deps — chỉ cần ở stage này, không copy sang runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        python3-dev \
        default-libmysqlclient-dev \
        pkg-config \
        gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# Build tất cả wheels vào /wheels — cache-friendly layer
RUN pip install --upgrade pip \
 && pip wheel --no-cache-dir --no-deps --wheel-dir /wheels -r requirements.txt

# =============================================================================
# STAGE 2: Runtime — lean image, không có build tools
# =============================================================================
FROM python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS runtime

WORKDIR /app

ARG BUILD_DATE
ARG COMMIT_SHA
ARG VERSION

LABEL org.opencontainers.image.title="Adaptive Security App" \
      org.opencontainers.image.description="Django Backend Application" \
      org.opencontainers.image.authors="NTNguyen055" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${COMMIT_SHA}" \
      org.opencontainers.image.version="${VERSION}"

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_ROOT_USER_ACTION=ignore \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Gunicorn tuning
ENV GUNICORN_WORKERS=2 \
    GUNICORN_THREADS=2 \
    GUNICORN_TIMEOUT=60

# Cài runtime library
# libmariadb3  : shared library để mysqlclient chạy
RUN apt-get update && apt-get install -y --no-install-recommends \
        libmariadb3 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy wheels từ builder và install — không cần build tools
# ── SECURITY: non-root user với UID cố định ──────────────────
# UID cố định 1001 để volume permissions nhất quán giữa các build
COPY --from=builder /wheels /wheels
COPY requirements.txt .

RUN pip install --no-index --no-cache-dir --find-links=/wheels -r requirements.txt \
 && rm -rf /wheels requirements.txt \
 && groupadd -g 1001 appgroup \
 && useradd -u 1001 -g appgroup -m -s /bin/bash appuser

# ── COPY SOURCE CODE ──────────────────────────────────────────
# --chown đảm bảo appuser có quyền đọc ngay từ đầu
# (.dockerignore sẽ chặn .env, __pycache__, .git lọt vào)
COPY --chown=appuser:appgroup . .

# ── TẠO THƯ MỤC VÀ CLEAN SOURCE ──────────────────────────────
RUN find /app -type d -name "__pycache__" -prune -exec rm -rf {} + \
    && find /app -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete \
    && mkdir -p /app/staticfiles /app/media /app/static \
    && chown -R appuser:appgroup \
        /app/staticfiles /app/media /app/static

# ── SWITCH TO NON-ROOT ────────────────────────────────────────
USER appuser

# ── EXPOSE ───────────────────────────────────────────────────
EXPOSE 8000

# ── HEALTHCHECK ──────────────────────────────────────────────
# Dùng thư viện Python có sẵn (urllib) thay vì cài cURL gây nặng file
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=60s \
    CMD python -c \
        "import os, urllib.request; \
         host = next((h.strip() for h in os.environ.get('ALLOWED_HOSTS', '').split(',') if h.strip()), 'localhost'); \
         req = urllib.request.Request( \
             'http://127.0.0.1:8000/health/', \
             headers={'X-Forwarded-Proto': 'https', 'Host': host} \
         ); \
         urllib.request.urlopen(req, timeout=3)" \
    || exit 1
