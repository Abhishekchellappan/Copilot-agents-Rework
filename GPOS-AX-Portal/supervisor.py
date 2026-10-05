async def supervisor_llm_chat(req: ChatRequest, llm_url: str, headers: dict, pat: str):
    from mcp.client.sse import sse_client
    from mcp.client.session import ClientSession
    from contextlib import AsyncExitStack
    import httpx
    import json
    
    async with AsyncExitStack() as stack:
        try:
            # Connect to Jira MCP
            jira_streams = await stack.enter_async_context(sse_client(f"{MCP_SERVER_URL}/sse", headers={"X-Jira-PAT": pat}))
            jira_session = await stack.enter_async_context(ClientSession(jira_streams[0], jira_streams[1]))
            await jira_session.initialize()
            
            # Connect to Device MCP
            device_streams = await stack.enter_async_context(sse_client("http://gpos-device-agent:8000/sse"))
            device_session = await stack.enter_async_context(ClientSession(device_streams[0], device_streams[1]))
            await device_session.initialize()
            
            # Aggregate tools
            jira_tools_resp = await jira_session.list_tools()
            device_tools_resp = await device_session.list_tools()
            
            tools = []
            tool_schemas = {}
            tool_session_map = {}
            
            for t in jira_tools_resp.tools:
                tool_schemas[t.name] = t.input_schema.get("properties", {}) if t.input_schema else {}
                tools.append({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description or "",
                        "parameters": t.input_schema or {"type": "object", "properties": {}}
                    }
                })
                tool_session_map[t.name] = jira_session
                
            for t in device_tools_resp.tools:
                tool_schemas[t.name] = t.input_schema.get("properties", {}) if t.input_schema else {}
                tools.append({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description or "",
                        "parameters": t.input_schema or {"type": "object", "properties": {}}
                    }
                })
                tool_session_map[t.name] = device_session

            # System Prompt
            system_prompt = f\"\"\"You are the GPOS AI Supervisor.
You have access to TWO domains of tools:
1. JIRA TOOLS: For checking tickets, bugs, and governance in project {req.project_key or 'SIGPOSDEV'}.
2. DEVICE TOOLS: For executing SSH commands, running GDB, pulling logs, and swarm testing on target boards.

When checking bugs or triage, check Jira first. 
When investigating a crash, connect to the board and run 'run_gdb_backtrace' or 'auto_triage_service'.
If the user asks to run a swarm test, use 'swarm_execute'.

Format Jira output as a <jira-widget> HTML block.
Format Device output as a <gdb-widget> or <swarm-widget> HTML block.
\"\"\"
            
            messages = [{"role": "system", "content": system_prompt}]
            
            if req.history:
                for h in req.history:
                    role = 'assistant' if h.get('sender') == 'agent' else 'user'
                    messages.append({"role": role, "content": h.get('text', '')})
            
            messages.append({"role": "user", "content": req.message})
            
            payload = {
                "model": "Chat-EXACODE-A",
                "messages": messages,
                "tools": tools,
                "tool_choice": "auto"
            }
            
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(llm_url, headers=headers, json=payload)
                if resp.status_code != 200:
                    return {"intent": "chat", "message": f"?? LLM Error: {resp.text}"}
                
                result = resp.json()
                choice = result['choices'][0]
                message = choice['message']
                
                if message.get("tool_calls"):
                    tool_call = message["tool_calls"][0]
                    func_name = tool_call["function"]["name"]
                    func_args = json.loads(tool_call["function"]["arguments"])
                    
                    target_session = tool_session_map.get(func_name)
                    if not target_session:
                        return {"intent": "chat", "message": f"?? Error: Tool {func_name} not found."}
                    
                    tool_result = await target_session.call_tool(func_name, arguments=func_args)
                    
                    # Send result back to LLM
                    messages.append(message)
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call["id"],
                        "content": str(tool_result.content)
                    })
                    
                    payload["messages"] = messages
                    payload.pop("tools", None)
                    payload.pop("tool_choice", None)
                    
                    resp2 = await client.post(llm_url, headers=headers, json=payload)
                    if resp2.status_code == 200:
                        final_result = resp2.json()
                        return {"intent": "chat", "message": final_result['choices'][0]['message']['content']}
                    return {"intent": "chat", "message": f"?? LLM Error after tool: {resp2.text}"}
                
                return {"intent": "chat", "message": message.get("content", "")}
                
        except Exception as e:
            return {"intent": "chat", "message": f"?? Supervisor Error: {str(e)}"}
