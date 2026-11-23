FROM python:3.14-slim-trixie

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    XDG_DATA_HOME=/app/data \
    NMAP_PATH=/usr/bin/nmap

WORKDIR /app

# System utilities, network assessment tools, firewall inspection tools,
# and Java 21 for OWASP ZAP.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    dnsutils \
    firewalld \
    iproute2 \
    iptables \
    iputils-ping \
    libdbus-1-3 \
    net-tools \
    nftables \
    nmap \
    openjdk-21-jre-headless \
    procps \
    ufw \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install the project's pinned Python dependencies.
COPY requirements.txt /app/requirements.txt

RUN python -m pip install --no-cache-dir -r requirements.txt

# Install OWASP ZAP 2.17.0 and verify the official release archive.
ARG ZAP_VERSION=2.17.0
ARG ZAP_SHA256=94c8f767b1c2e94f0db66b3ae56514d5e3f5a728ee1b6c798e0c8fe2d61fbff0

RUN set -eux; \
    mkdir -p /usr/share/zaproxy; \
    curl -fL \
      "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Crossplatform.zip" \
      -o /tmp/zap.zip; \
    echo "${ZAP_SHA256}  /tmp/zap.zip" | sha256sum -c -; \
    unzip -q /tmp/zap.zip -d /tmp/zap-extract; \
    zap_jar="$(find /tmp/zap-extract -type f -name "zap-${ZAP_VERSION}.jar" -print -quit)"; \
    test -n "$zap_jar"; \
    zap_dir="$(dirname "$zap_jar")"; \
    cp -a "$zap_dir"/. /usr/share/zaproxy/; \
    test -f "/usr/share/zaproxy/zap-${ZAP_VERSION}.jar"; \
    rm -rf /tmp/zap.zip /tmp/zap-extract

# Copy application source. .dockerignore excludes local databases,
# virtual environments, backups, audit-only files, and Git metadata.
COPY . /app

RUN mkdir -p /app/data

# Explicitly run the application and its subprocesses as container root.
USER root

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=3)" || exit 1

CMD ["python", "app.py"]
