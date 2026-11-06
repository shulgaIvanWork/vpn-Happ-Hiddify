# ---------- sing-box binary ----------
FROM alpine:3.20 AS singbox

ARG SINGBOX_VERSION=1.14.4
ARG TARGETARCH=amd64

RUN apk add --no-cache curl tar \
    && curl -fsSL "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${TARGETARCH}.tar.gz" \
       | tar -xz -C /tmp \
    && mv "/tmp/sing-box-${SINGBOX_VERSION}-linux-${TARGETARCH}/sing-box" /usr/local/bin/sing-box \
    && chmod +x /usr/local/bin/sing-box

# ---------- application ----------
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

COPY --from=singbox /usr/local/bin/sing-box /usr/local/bin/sing-box

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --create-home --uid 10001 app \
    && mkdir -p /data && chown -R app:app /data

COPY app ./app
COPY sources.yaml .

USER app
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/healthz',timeout=3)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--proxy-headers", "--forwarded-allow-ips", "*"]
