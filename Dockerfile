# syntax=docker/dockerfile:1
# ─────────────────────────────────────────────────────────────────────────────
# ATHENA ITD — production container image
# Multi-stage: build a wheel, then run on a slim, non-root runtime.
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.15-slim AS build
WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --upgrade pip build && python -m build --wheel --outdir /dist

FROM python:3.15-slim AS runtime
LABEL org.opencontainers.image.title="ATHENA ITD" \
      org.opencontainers.image.description="AI-driven Insider Threat Detection (CLI + Web console)" \
      org.opencontainers.image.authors="Petro Plaku <pplaku799@gmail.com>"

# Non-root runtime user; data lives on a mounted volume.
RUN useradd --create-home --uid 10001 athena \
    && mkdir -p /data && chown athena:athena /data
ENV ATHENA_HOME=/data \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

COPY --from=build /dist/*.whl /tmp/
RUN pip install /tmp/*.whl && rm -f /tmp/*.whl

USER athena
WORKDIR /home/athena
VOLUME ["/data"]
EXPOSE 8000

# Liveness/readiness probe target for orchestrators.
HEALTHCHECK --interval=30s --timeout=4s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; \
        sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health').status==200 else 1)"

# Bind to all interfaces inside the container; trust the front proxy's headers.
ENTRYPOINT ["athena"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--access-log"]
