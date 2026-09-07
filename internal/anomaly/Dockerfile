FROM python:3.14-slim@sha256:cae66f2ef0ec51a9891263eeee7f987dacf0a9879e8aa9353d5606e0530619a5

ARG VERSION=dev
ARG REVISION=unknown

LABEL org.opencontainers.image.source="https://github.com/msaadshabir/ZTAP" \
      org.opencontainers.image.title="ZTAP Anomaly Detector" \
      org.opencontainers.image.description="Anomaly detection service for ZTAP (Zero Trust Access Platform)" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

WORKDIR /app

# Install pinned runtime dependencies (pyproject.toml) together with the
# application module in one layer. No curl/apt packages: the HEALTHCHECK uses
# urllib so the base image stays slim.
COPY pyproject.toml README.md service.py ./
RUN pip install --no-cache-dir .

# Model persistence directory, owned by the non-root runtime user.
RUN mkdir -p /app/models && chown -R 65532:65532 /app
USER 65532

EXPOSE 5000

ENV PYTHONUNBUFFERED=1 \
    ZTAP_ANOMALY_HOST=0.0.0.0 \
    ZTAP_ANOMALY_PORT=5000 \
    MODEL_PATH=/app/models

# Serve via gunicorn, not `flask run` (FLASK_ENV is ignored by modern Flask).
# The container binds 0.0.0.0 so the agent can reach the service from another
# container on the compose network; `python service.py` stays 127.0.0.1 for
# host-local dev runs.
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health')"]
# Keep one worker because the trained model is process-local. The persisted
# model is loaded on startup and /train updates this worker's in-memory model.
# Scale the service only after adding shared model-state coordination.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--timeout", "60", "service:app"]
