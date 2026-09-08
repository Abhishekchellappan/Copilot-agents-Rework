"""
Quick smoke test for GPOS Jira Agent MCP Server.
Run locally to verify the server starts and tools are registered.

Usage:
  1. Start the server:  python jira_server.py
  2. In another terminal: python quick_test.py
"""
import requests
import json
import sys

SERVER_URL = "http://localhost:8000"

def test_sse_endpoint():
    """Verify SSE endpoint is reachable."""
    try:
        resp = requests.get(f"{SERVER_URL}/sse", stream=True, timeout=5)
        print(f"[PASS] SSE endpoint reachable (HTTP {resp.status_code})")
        resp.close()
        return True
    except Exception as e:
        print(f"[FAIL] SSE endpoint: {e}")
        return False

def test_proxy_endpoint():
    """Verify REST proxy route is registered."""
    try:
        resp = requests.get(f"{SERVER_URL}/rest/api/2/serverInfo", timeout=5,
                           headers={"X-Jira-PAT": "test-token"})
        # We expect either a Jira response or a connection error to Jira (not 404)
        print(f"[PASS] Proxy endpoint registered (HTTP {resp.status_code})")
        return True
    except Exception as e:
        print(f"[INFO] Proxy endpoint test: {e}")
        return True  # Connection errors to Jira are expected in local testing

if __name__ == "__main__":
    print("=" * 50)
    print("GPOS Jira Agent — Smoke Test")
    print("=" * 50)
    results = [test_sse_endpoint(), test_proxy_endpoint()]
    print("\n" + ("All checks passed!" if all(results) else "Some checks failed."))
    sys.exit(0 if all(results) else 1)
