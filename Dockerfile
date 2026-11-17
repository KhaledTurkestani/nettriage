# Stage 1: build the web page. Only its output is carried into the final image.
FROM node:24-slim AS web

WORKDIR /build/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web ./
# The build writes to ../src/nettriage/api/static, the place the API serves the page from.
RUN npm run build


# Stage 2: the server.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NETTRIAGE_DATA_DIR=/data \
    NETTRIAGE_MODEL_DIR=/app/models/flow-classifier

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY --from=web /build/src/nettriage/api/static ./src/nettriage/api/static
RUN pip install --no-cache-dir .

# The trained flow classifier and its model card.
COPY models ./models

# Run as an unprivileged user; captures are untrusted input.
RUN useradd --create-home --uid 10001 nettriage \
    && mkdir -p /data \
    && chown nettriage:nettriage /data
USER nettriage

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"

CMD ["uvicorn", "nettriage.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
