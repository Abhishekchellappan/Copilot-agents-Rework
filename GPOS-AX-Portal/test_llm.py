import asyncio
import httpx
import os

async def main():
    llm_url = "http://exacode-chat.lge.com/v1/chat/completions"
    llm_key = "1" # Doesn't matter if it's mock
    headers = {
        "Authorization": f"Bearer {llm_key}",
        "Content-Type": "application/json",
        "X-Title": "EXACODE SWE(API)",
        "X-Model": "Chat-EXACODE-A",
        "HTTP-Referer": "http://gpos-ax-portal.lge.com"
    }
    
    tools = [
        {
            "type": "function",
            "function": {
                "name": "test_tool",
                "description": "test",
                "parameters": {"type": "object", "properties": {}}
            }
        }
    ]
    
    payload = {
        "model": "Chat-EXACODE-A",
        "messages": [
            {"role": "user", "content": "hello"}
        ],
        "tools": tools,
        "temperature": 0.1
    }
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(llm_url, json=payload, headers=headers, timeout=60)
            print("Status:", resp.status_code)
            print("Body:", resp.text)
    except Exception as e:
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
