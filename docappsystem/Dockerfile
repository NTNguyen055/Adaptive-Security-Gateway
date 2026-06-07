# =============================================================================
# STAGE 1: Builder — compile Python wheels
# =============================================================================
FROM python:3.12-slim AS builder

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
FROM python:3.12-slim AS runtime

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
    PYTHONDONTWRITEBYTECODE=1 \
    # Gunicorn tuning
    GUNICORN_WORKERS=2 \
    GUNICORN_THREADS=2 \
    GUNICORN_TIMEOUT=60

# Cài runtime library
# libmariadb3  : shared library để mysqlclient chạy
RUN apt-get update && apt-get install -y --no-install-recommends \
        libmariadb3 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy wheels từ builder và install — không cần build tools
COPY --from=builder /wheels /wheels
COPY requirements.txt .
RUN pip install --no-index --no-cache-dir --find-links=/wheels -r requirements.txt \
 && rm -rf /wheels requirements.txt

# ── SECURITY: non-root user với UID cố định ──────────────────
# UID cố định 1001 để volume permissions nhất quán giữa các build
RUN groupadd -g 1001 appgroup \
 && useradd -u 1001 -g appgroup -m -s /bin/bash appuser

# ── COPY SOURCE CODE ──────────────────────────────────────────
# --chown đảm bảo appuser có quyền đọc ngay từ đầu
# (.dockerignore sẽ chặn .env, __pycache__, .git lọt vào)
COPY --chown=appuser:appgroup . .

# ── TẠO THƯ MỤC CẦN THIẾT ────────────────────────────────────
# static/ phải tồn tại để collectstatic trong settings.py không lỗi
RUN mkdir -p staticfiles media static \
 && chown -R appuser:appgroup staticfiles media static

# ── SWITCH TO NON-ROOT ────────────────────────────────────────
USER appuser

# ── EXPOSE ───────────────────────────────────────────────────
EXPOSE 8000

# ── HEALTHCHECK ──────────────────────────────────────────────
# Dùng thư viện Python có sẵn (urllib) thay vì cài cURL gây nặng file
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=40s \
    CMD python -c \
        "import urllib.request; \
         req = urllib.request.Request( \
             'http://localhost:8000/health/', \
             headers={'X-Forwarded-Proto': 'https', 'Host': 'localhost'} \
         ); \
         urllib.request.urlopen(req)" \
    || exit 1

