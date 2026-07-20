# ---------- Build stage ----------
FROM python:3.12-slim AS builder

WORKDIR /app

# Copy uv from its official image and install the locked production environment.
COPY --from=ghcr.io/astral-sh/uv:0.11.29 /uv /uvx /bin/
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv

COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

# ---------- Runtime stage ----------
FROM python:3.12-slim

LABEL org.opencontainers.image.title="Defender Hunt MCP"
LABEL org.opencontainers.image.description="MCP server for Microsoft Defender Advanced Hunting and Microsoft Entra ID"

WORKDIR /app

# Copy virtualenv from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY config.py server.py server_http.py ./

# Sensible defaults (override via env vars or --env-file at runtime)
ENV HOST=0.0.0.0
ENV PORT=8000
ENV LOG_LEVEL=INFO
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN addgroup --system app \
    && adduser --system --ingroup app --home /app app \
    && chown -R app:app /app

USER app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.getenv('PORT', '8000') + '/health', timeout=3)"]

# Run the HTTP server
CMD ["python", "server_http.py"]
