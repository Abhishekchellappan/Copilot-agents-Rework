import asyncio
import httpx
import json

async def main():
    try:
        from fastapi.testclient import TestClient
        from server import app
        
        client = TestClient(app)
        
        payload = {
            "message": "project = SIGPOSDEV AND sprint in openSprints() AND assignee = \"AbhishekC abhishek15.c\" ORDER BY updated DESC",
            "llm_url": "http://exacode-chat.lge.com/v1",
            "llm_key": "dummy_key",
            "project_key": "SIGPOSDEV"
        }
        
        headers = {
            "X-Jira-PAT": "dummy_pat"
        }
        
        resp = client.post("/api/chat", json=payload, headers=headers)
        print("Status:", resp.status_code)
        print("Body:", resp.text)
    except Exception as e:
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
