import asyncio
from mcp.client.sse import sse_client
from mcp.client.session import ClientSession
from contextlib import AsyncExitStack

async def main():
    async with AsyncExitStack() as stack:
        try:
            streams = await stack.enter_async_context(sse_client("http://10.221.31.25:31983/sse"))
            session = await stack.enter_async_context(ClientSession(streams[0], streams[1]))
            await session.initialize()
            print("Initialized!")
            tools_resp = await session.list_tools()
            print("Tools:", tools_resp.tools)
        except Exception as e:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
