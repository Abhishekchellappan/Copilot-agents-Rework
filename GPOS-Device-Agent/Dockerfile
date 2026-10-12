FROM python:3.11-slim

WORKDIR /app

# Install SSH client and debugging tools available on the host
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    curl \
    gdb-multiarch \
    binutils \
    strace \
    perl \
    git \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/brendangregg/FlameGraph.git /opt/FlameGraph

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY device_server.py .

# Multi-Architecture Tool Vault
RUN mkdir -p /tools
COPY tools/ /tools/

# Target fleet inventory (optional, can also be mounted as ConfigMap)
# COPY inventory.json /app/inventory.json
# ENV TARGET_INVENTORY_JSON=/app/inventory.json

# Copy all Markdown knowledge folders (auto-scanned by Python at startup)
COPY .github/ ./.github/
COPY rules/ ./rules/
COPY skills/ ./skills/

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["python", "device_server.py"]


