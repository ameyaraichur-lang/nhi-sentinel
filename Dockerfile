# NHI Sentinel dev image (slice 0.1).
# The app resolves web/, fixtures/ and data/ relative to the repo root
# (nhi_sentinel/config.py: NHI_WEB_DIR / NHI_FIXTURE_DIR / NHI_DATA_DIR),
# so the repo content is copied to /app and those env vars point at it.
FROM python:3.12-slim

WORKDIR /app

# Project metadata + package + the static assets the portal serves.
# (web/ and fixtures/ are not packaged by pip install . - they are runtime assets.)
COPY pyproject.toml README.md ./
COPY nhi_sentinel/ ./nhi_sentinel/
COPY web/ ./web/
COPY fixtures/ ./fixtures/

RUN pip install --no-cache-dir .

# Synthetic demo data lives on a volume in dev (see docker-compose.dev.yml).
ENV NHI_WEB_DIR=/app/web \
    NHI_FIXTURE_DIR=/app/fixtures \
    NHI_DATA_DIR=/data

EXPOSE 8650

# create_app() is the FastAPI application factory (nhi_sentinel/api/app.py).
CMD ["uvicorn", "nhi_sentinel.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8650"]
