FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app \
    BASE_DIR=/app \
    DEBIAN_FRONTEND=noninteractive \
    TEE_USE_TLS=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN python -m pip install --upgrade pip \
    && python -m pip install -r /tmp/requirements.txt

COPY . /app

RUN chmod +x /app/entrypoint.sh \
    && mkdir -p /app/cvm_workflow/buffer /app/cvm_workflow/tls /app/cvm_workflow/logs

EXPOSE 4100

ENTRYPOINT ["/app/entrypoint.sh"]
