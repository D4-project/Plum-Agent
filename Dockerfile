FROM python:3.13-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

RUN mkdir -p src/config src/log src/nse_cache

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

WORKDIR /app/src

VOLUME ["/app/src/config", "/app/src/log", "/app/src/nse_cache"]

ENTRYPOINT ["docker-entrypoint.sh"]
