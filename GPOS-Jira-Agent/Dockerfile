FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy Python server
COPY jira_server.py .

# Copy all Markdown knowledge folders (auto-scanned by Python at startup)
COPY .github/ ./.github/
COPY rules/ ./rules/
COPY skills/ ./skills/

EXPOSE 8000
CMD ["python", "jira_server.py"]
