FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl build-essential && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy Python server modules
COPY server.py config.py ast_parser.py bitbake_parser.py ./

# Copy all Markdown knowledge folders (auto-scanned by Python at startup)
COPY .github/ ./.github/
COPY rules/ ./rules/
COPY skills/ ./skills/

RUN mkdir -p /app/workspace

EXPOSE 8000
CMD ["python", "server.py"]
