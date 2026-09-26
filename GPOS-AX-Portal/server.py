import os
import re
import logging
from datetime import date
from typing import Optional, Dict, Any, List, Tuple
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import requests
from dotenv import load_dotenv
import jwt
import hashlib
from datetime import datetime, timedelta

# Load env variables
load_dotenv()

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="GPOS AX Portal Backend Gateway")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
MCP_SERVER_URL = os.environ.get('MCP_SERVER_URL', 'http://10.221.31.25:31983').rstrip('/')
JIRA_BASE_URL = os.environ.get('JIRA_BASE_URL', 'http://jira.lge.com/issue').rstrip('/')

# Constants
DONE_STATUSES = {"done", "closed", "resolved", "verified", "complete", "released"}
IN_PROGRESS_STATUSES = {"in progress", "in review", "in development", "code review", "testing", "in testing", "review"}
STORY_POINTS_FIELD = "customfield_10002"
SPRINT_FIELD = "customfield_10005"
VALID_LABELS = {"AX_REQ", "AX_HLD", "AX_SDS", "AX_IMPL", "training", "development", "operations", "Analysis-Done", "unplanned_leave"}

# Authentication Configuration
LDAP_SERVER = os.environ.get('LDAP_SERVER', '').strip()
LDAP_DOMAIN = os.environ.get('LDAP_DOMAIN', '').strip()
LDAP_BASE_DN = os.environ.get('LDAP_BASE_DN', '').strip()
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'gpos-ax-portal-secret-key-change-me')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_HOURS = 24


class AgentAction(BaseModel):
    action: str
    project_key: str = "SIGPOSDEV"


class LoginRequest(BaseModel):
    username: str
    password: str


def _create_jwt_token(username: str) -> str:
    """Generate a JWT token for an authenticated user."""
    payload = {
        'sub': username,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def _verify_jwt_token(token: str) -> dict:
    """Verify and decode a JWT token. Returns the payload dict or None."""
    try:
        return jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def _authenticate_ldap(username: str, password: str) -> bool:
    """Authenticate against LDAP/Active Directory."""
    try:
        from ldap3 import Server, Connection, ALL, NTLM
        server = Server(LDAP_SERVER, get_info=ALL, connect_timeout=5)
        user_dn = f"{LDAP_DOMAIN}\\{username}" if LDAP_DOMAIN else username
        conn = Connection(server, user=user_dn, password=password, authentication=NTLM, auto_bind=True)
        conn.unbind()
        return True
    except Exception as e:
        logger.error(f"LDAP auth failed for {username}: {e}")
        return False


@app.post('/api/login')
async def login(req: LoginRequest):
    """Authenticate user and return JWT token."""
    username = req.username.strip()
    password = req.password
    
    if not username or not password:
        raise HTTPException(status_code=400, detail='Username and password are required')
    
    if LDAP_SERVER:
        # Real LDAP authentication
        if not _authenticate_ldap(username, password):
            raise HTTPException(status_code=401, detail='Invalid credentials. Please check your username and password.')
    else:
        # Mock mode - accept any non-empty credentials
        logger.warning(f"[MOCK AUTH] LDAP_SERVER not configured. Accepting login for user: {username}")
    
    token = _create_jwt_token(username)
    return {
        'token': token,
        'username': username,
        'message': f'Welcome, {username}!'
    }


@app.get('/api/auth/verify')
async def verify_auth(request: Request):
    """Verify if the current JWT token is still valid."""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        raise HTTPException(status_code=401, detail='Not authenticated')
    
    token = auth_header[7:]
    payload = _verify_jwt_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail='Token expired or invalid')
    
    return {'valid': True, 'username': payload.get('sub', '')}

def get_current_user(request: Request) -> str:
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        raise HTTPException(status_code=401, detail='Not authenticated')
    token = auth_header[7:]
    payload = _verify_jwt_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail='Token expired or invalid')
    return payload.get('sub', '')

@app.middleware("http")
async def verify_api_auth(request: Request, call_next):
    if request.url.path.startswith("/api/") and request.url.path not in ["/api/login", "/api/auth/verify"]:
        if request.method != "OPTIONS":  # Skip auth check for CORS preflight
            try:
                get_current_user(request)
            except HTTPException as e:
                from fastapi.responses import JSONResponse
                return JSONResponse(status_code=e.status_code, content={"detail": e.detail})
    return await call_next(request)



def get_jira_pat(request: Request) -> Optional[str]:
    """Extract PAT from X-Jira-PAT header, or fallback to JIRA_PAT env var."""
    pat = request.headers.get("X-Jira-PAT") or request.headers.get("x-jira-pat")
    if not pat:
        pat = os.environ.get("JIRA_PAT")
    return pat.strip() if pat else None


def _classify_status(status_name: str, status_obj: dict = None) -> str:
    if status_obj and "statusCategory" in status_obj:
        cat = status_obj["statusCategory"].get("key", "").lower()
        if cat == "done":
            return "done"
        if cat == "indeterminate":
            return "in_progress"
        if cat == "new":
            return "todo"
    s = (status_name or "").lower()
    if s in DONE_STATUSES:
        return "done"
    elif s in IN_PROGRESS_STATUSES:
        return "in_progress"
    return "todo"


def _jira_headers(pat: str) -> dict:
    """Send both standard Bearer auth and X-Jira-PAT for MCP server proxy compatibility."""
    return {
        "Authorization": f"Bearer {pat}",
        "X-Jira-PAT": pat,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def fetch_jira(endpoint: str, params: Dict[str, Any], pat: str, method: str = "GET", json_body: dict = None) -> Dict[str, Any]:
    """
    Execute request against Jira:
    1. Direct to JIRA_BASE_URL.
    2. Fallback to MCP_SERVER_URL REST proxy.
    """
    headers = _jira_headers(pat)
    clean_endpoint = endpoint.lstrip('/')
    
    # 1. Try Direct to Jira Data Center
    direct_url = f"{JIRA_BASE_URL}/rest/{clean_endpoint}"
    try:
        resp = requests.request(method, direct_url, headers=headers, params=params, json=json_body, timeout=12)
        if resp.status_code == 200:
            return resp.json()
        logger.info(f"Direct Jira returned {resp.status_code}, trying MCP proxy fallback...")
    except Exception as e:
        logger.info(f"Direct Jira call failed ({e}), falling back to MCP proxy...")

    # 2. Try MCP Server REST Proxy
    mcp_url = f"{MCP_SERVER_URL}/rest/{clean_endpoint}"
    resp = requests.request(method, mcp_url, headers=headers, params=params, json=json_body, timeout=15)
    if resp.status_code != 200:
        raise HTTPException(
            status_code=resp.status_code, 
            detail=f"Jira API error ({resp.status_code}): {resp.text}"
        )
    return resp.json()


def _get_field_names(project_key: str, pat: str) -> dict:
    try:
        data = fetch_jira("api/2/search", {"jql": f'project = {project_key}', "maxResults": 1, "expand": "names"}, pat)
        return data.get("names", {})
    except:
        return {}

def _get_sprint_issues(project_key: str, sprint_name: str, pat: str) -> Tuple[List[dict], str, dict]:
    """
    Fetch all issues for the active or requested sprint.
    Returns (issues_list, sprint_name, field_names_dict)
    """
    field_names = _get_field_names(project_key, pat)
    
    # Map fields to fetch
    required_fields = {
        "duedate", STORY_POINTS_FIELD, "components", "labels", "description",
        "summary", "status", "assignee", "issuetype", "priority", "comment"
    }
    for k, v in field_names.items():
        if v:
            vl = v.lower()
            if "sprint" in vl or "ax_phase" in vl or "ax_save" in vl or "original story points" in vl or "start date_alm" in vl or "comment" in vl:
                required_fields.add(k)
                
    fields_str = ",".join(required_fields)

    # 1. Try JQL with openSprints()
    if not sprint_name or sprint_name.lower() == "active":
        jql = f'project = {project_key} AND sprint in openSprints()'
    else:
        jql = f'project = {project_key} AND sprint = "{sprint_name}"'
        
    try:
        data = fetch_jira("api/2/search", {"jql": jql, "maxResults": 500, "fields": fields_str}, pat)
        issues = data.get("issues", [])
        if issues:
            resolved_name = sprint_name
            for k, v in field_names.items():
                if v and "sprint" in v.lower():
                    sinfo = issues[0].get("fields", {}).get(k)
                    if isinstance(sinfo, list) and sinfo:
                        if isinstance(sinfo[0], dict) and sinfo[0].get("name"):
                            resolved_name = sinfo[0]["name"]
                            break
                        elif isinstance(sinfo[0], str):
                            m = re.search(r'name=([^,\]]+)', sinfo[0])
                            if m:
                                resolved_name = m.group(1)
                                break
            return issues, resolved_name or "Active Sprint", field_names
    except Exception as e:
        logger.warning(f"openSprints JQL failed: {e}")

    # 2. Try Agile Board API to resolve active sprint
    try:
        boards_data = fetch_jira("agile/1.0/board", {"projectKeyOrId": project_key}, pat)
        boards = boards_data.get("values", [])
        if boards:
            board_id = boards[0]["id"]
            sprints_data = fetch_jira(f"agile/1.0/board/{board_id}/sprint", {"state": "active"}, pat)
            sprints = sprints_data.get("values", [])
            if sprints:
                sprint_id = sprints[0]["id"]
                sprint_title = sprints[0].get("name", f"Sprint {sprint_id}")
                sprint_jql = f"project = {project_key} AND sprint = {sprint_id}"
                data = fetch_jira("api/2/search", {"jql": sprint_jql, "maxResults": 500, "fields": fields_str}, pat)
                return data.get("issues", []), sprint_title, field_names
    except Exception as e:
        logger.warning(f"Agile Board sprint query failed: {e}")

    # 3. Fallback: Query all recent issues in the project
    jql_fallback = f"project = {project_key} ORDER BY updated DESC"
    data = fetch_jira("api/2/search", {"jql": jql_fallback, "maxResults": 60, "fields": fields_str}, pat)
    return data.get("issues", []), "Current Project Tickets", field_names


# ============================================================================
class ChatRequest(BaseModel):
    message: str
    llm_url: str = ""
    llm_key: str = ""
    llm_model: str = "Chat-EXACODE-A"
    project_key: str = "SIGPOSDEV"
    history: list = []

@app.post("/api/chat")
async def llm_chat(req: ChatRequest, request: Request):
    if not req.llm_url or not req.llm_key:
        raise HTTPException(status_code=400, detail="LLM URL and API Key are required.")
        
    pat = get_jira_pat(request)
    if not pat:
        raise HTTPException(status_code=401, detail="Missing Jira PAT.")
        
    llm_url = req.llm_url.rstrip('/')
    if not llm_url.endswith('chat/completions'):
        if llm_url.endswith('v1'): llm_url += '/chat/completions'
        else: llm_url += '/v1/chat/completions'

    headers = {
        "Authorization": f"Bearer {req.llm_key}",
        "Content-Type": "application/json",
        "X-Title": "EXACODE SWE(API)",
        "X-Model": "Chat-EXACODE-A",
        "HTTP-Referer": "http://gpos-ax-portal.lge.com"
    }
    
    # We will use the official mcp python SDK to connect to the MCP server
    from mcp.client.sse import sse_client
    from mcp.client.session import ClientSession
    from contextlib import AsyncExitStack
    import httpx
    import json
    
    async with AsyncExitStack() as stack:
        try:
            # Connect to MCP server with PAT in headers
            mcp_headers = {"X-Jira-PAT": pat}
            streams = await stack.enter_async_context(sse_client(f"{MCP_SERVER_URL}/sse", headers=mcp_headers))
            session = await stack.enter_async_context(ClientSession(streams[0], streams[1]))
            await session.initialize()
            
            # Get tools
            tools_resp = await session.list_tools()
            tools = []
            for t in tools_resp.tools:
                tools.append({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.input_schema
                    }
                })
                
            sys_prompt = f"""You are the Antigravity Generative UI Assistant for the GPOS project (Project Key: {req.project_key}).
You have access to a suite of MCP tools (Jira, Code Search, etc.).
You must respond to the user's queries using the tools. When tools require a project_key, assume it is {req.project_key} unless specified otherwise.
TIP: If the user asks for "my" tickets (e.g., "my stories", "my bugs"), you MUST use `assignee = currentUser()` in your JQL search.

CRITICAL FORMATTING RULES:
1. **Jira Tickets Array**:
You MUST NEVER output plain-text lists of tickets or custom markdown tables of tickets. 
Whenever you need to display a list of tickets, you MUST output a raw HTML `<table>` wrapped EXACTLY in `<agent-html>` tags.
Use this exact HTML structure:
<agent-html>
<table class="w-full text-sm text-left text-slate-300">
  <thead class="text-xs text-slate-400 bg-slate-800 uppercase">
    <tr><th>Key</th><th>Type</th><th>Status</th><th>Priority</th><th>Summary</th><th>Assignee</th></tr>
  </thead>
  <tbody>
    <tr class="bg-slate-900 border-b border-slate-700">
      <td class="px-3 py-2 font-mono text-blue-400">SIGPOSDEV-1</td>
      <td class="px-3 py-2">Story</td>
      <td class="px-3 py-2 text-emerald-400">Open</td>
      <td class="px-3 py-2 text-amber-400">P2</td>
      <td class="px-3 py-2">Fix bug</td>
      <td class="px-3 py-2">abhishek15.c</td>
    </tr>
  </tbody>
</table>
</agent-html>

2. **General Tables**: When presenting other tabular data (like developer stats), you MUST use STRICT GitHub Flavored Markdown (GFM) tables with the `|` character. NEVER align columns with spaces.

3. **Sprint Health / Report**:
The `jira_generate_sprint_report` tool returns a pre-formatted Markdown string with a Mermaid pie chart and tables. Return this directly to the user as it is already formatted.

4. **Sprint Burndown Chart**:
The `jira_get_sprint_burndown` tool returns a pre-formatted Markdown string with a Mermaid burndown chart. Return it directly to the user.

5. **Sprint Audit / Governance**:
Whenever you audit tickets (e.g. for missing labels or assignees), you MUST output a raw HTML `<table>` summarizing the problematic tickets.
Use this exact HTML structure:
<agent-html>
<div class="bg-slate-800 border border-amber-500/30 rounded-lg p-4 mb-4">
  <h3 class="text-amber-400 font-bold mb-2">⚠️ Governance Audit Findings</h3>
  <table class="w-full text-sm text-left text-slate-300">
    <thead class="text-xs text-slate-400 bg-slate-900 uppercase">
      <tr><th>Key</th><th>Summary</th><th>Missing Element</th></tr>
    </thead>
    <tbody>
      <tr class="bg-slate-800 border-b border-slate-700">
        <td class="px-3 py-2 font-mono text-blue-400">SIGPOSDEV-1</td>
        <td class="px-3 py-2">Fix bug</td>
        <td class="px-3 py-2 text-red-400">No Assignee</td>
      </tr>
    </tbody>
  </table>
</div>
</agent-html>

6. **Other Highly Customized UI**: 
Act as a frontend developer. Output raw HTML styled with Tailwind CSS wrapped exactly in `<agent-html>` tags.

7. **Error Handling**:
If a tool execution returns an error message, an HTTP failure code (e.g., HTTP 403, 400), or indicates that an action failed, you MUST explicitly tell the user that the action failed and provide the reason. DO NOT hallucinate that the action succeeded if the tool returned an error.
  
8. **Confirmation Workflows**:
If you ask the user for confirmation (e.g. "Reply 1 to confirm deletion") and the user confirms, YOU MUST ACTUALLY EXECUTE THE TOOL. Do NOT just output a success message without calling the tool.
"""
            messages = [{"role": "system", "content": sys_prompt}]
            for h in req.history[-10:]: # Limit to last 10 messages for context window
                if h.get("role") and h.get("content"):
                    messages.append({"role": h["role"], "content": h["content"]})
            messages.append({"role": "user", "content": req.message})
            
            async with httpx.AsyncClient() as client:
                for _ in range(15): # Max 15 tool calls per chat
                    payload = {
                        "model": req.llm_model,
                        "messages": messages,
                        "tools": tools,
                        "temperature": 0.1
                    }
                    
                    resp = await client.post(llm_url, json=payload, headers=headers, timeout=60)
                    resp.raise_for_status()
                    result = resp.json()
                    
                    msg = result['choices'][0]['message']
                    messages.append(msg)
                    
                    if not msg.get("tool_calls"):
                        # No more tool calls, return final message
                        return {"intent": "chat", "message": msg.get("content", "")}
                        
                    # Execute tool calls
                    for tool_call in msg["tool_calls"]:
                        func_name = tool_call["function"]["name"]
                        func_args = json.loads(tool_call["function"]["arguments"])
                        
                        # Execute on MCP server
                        try:
                            # If the tool takes a PAT, inject it
                            if "pat" in func_args or "token" in func_args:
                                func_args["pat"] = pat
                            
                            tool_result = await session.call_tool(func_name, arguments=func_args)
                            
                            # Extract text from result
                            res_text = "\n".join([c.text for c in tool_result.content if getattr(c, "type", "") == "text"])
                            
                            if "failed (HTTP" in res_text or "Error in" in res_text:
                                res_text = f"TOOL EXECUTION FAILED: {res_text}\\nCRITICAL INSTRUCTION: You MUST inform the user that the action failed and explain the error. DO NOT say it succeeded."
                            
                            messages.append({
                                "role": "tool",
                                "tool_call_id": tool_call["id"],
                                "content": res_text
                            })
                        except Exception as e:
                            logger.error(f"Tool call failed: {e}")
                            messages.append({
                                "role": "tool",
                                "tool_call_id": tool_call["id"],
                                "content": f"Error executing tool: {str(e)}"
                            })
                            
                return {"intent": "chat", "message": "I reached the maximum number of tool calls and had to stop. I attempted 15 steps but couldn't finalize the answer."}
                
        except Exception as e:
            logger.error(f"MCP/LLM Loop Error: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to execute autonomous agent loop: {str(e)}")

@app.get("/api/user")
def get_user_profile(request: Request):
    pat = get_jira_pat(request)
    if not pat:
        raise HTTPException(status_code=401, detail="Missing Jira PAT.")
    
    try:
        data = fetch_jira("api/2/myself", {}, pat)
        display_name = data.get("displayName", "Jira User")
        return {"name": display_name, "division": "LGSI GPOS & Apps"}
    except Exception as e:
        logger.error(f"Failed to fetch user profile: {e}")
        return {"name": "GPOS User", "division": "LGSI GPOS & Apps"}

@app.get("/api/agents")
def get_agents():
    # Dynamic list of agents in the catalog
    agents = [
        {
            "id": "jira-agent",
            "name": "GPOS Jira & Governance",
            "description": "Real-time sprint health, burndown tracking, AX label compliance, and auto-grooming.",
            "status": "Active",
            "theme": "blue",
            "icon": "check-square",
            "tags": ["SW", "DEV", "ALM"],
            "categories": ["SW", "DevOps"]
        },
        {
            "id": "hld-agent",
            "name": "GPOS HLD Design Studio",
            "description": "Auto-generates High-Level Designs, sequence diagrams, and architecture specs from SRS.",
            "status": "Next",
            "theme": "purple",
            "icon": "pen-tool",
            "tags": ["SW", "RD", "Arch"],
            "categories": ["SW"]
        },
        {
            "id": "impl-agent",
            "name": "GPOS Implementation Agent",
            "description": "Generates C++ daemons, Dart plugins, and Yocto recipes with unit test suites.",
            "status": "Next",
            "theme": "red",
            "icon": "code-2",
            "tags": ["SW", "DEV", "Scaffold"],
            "categories": ["SW"]
        },
        {
            "id": "gerrit-agent",
            "name": "GPOS Gerrit Code Review",
            "description": "Automated Gerrit patchset review, SonarQube rules, and code quality scoring.",
            "status": "Planned",
            "theme": "teal",
            "icon": "git-pull-request",
            "tags": ["SW", "DEV", "Quality"],
            "categories": ["SW", "DevOps"]
        },
        {
            "id": "build-agent",
            "name": "GPOS Build Automation",
            "description": "BitBake / Yocto build triggers, warning detection, log diagnosis.",
            "status": "Planned",
            "theme": "amber",
            "icon": "cpu",
            "tags": ["SW", "DEV", "CI/CD"],
            "categories": ["SW", "DevOps"]
        },
        {
            "id": "hw-agent",
            "name": "GPOS Hardware Device",
            "description": "Remote deployment (SCP/bind-mount), GDB remote debugging, core dump capture.",
            "status": "Planned",
            "theme": "cyan",
            "icon": "monitor-smartphone",
            "tags": ["HW", "Embedded"],
            "categories": ["HW"]
        }
    ]
    return agents

@app.get("/api/mentions")
def get_mentions(request: Request):
    pat = get_jira_pat(request)
    if not pat:
        raise HTTPException(
            status_code=401, 
            detail="Missing Jira PAT. Please click ⚙️ Settings in the top-right corner to enter your Personal Access Token."
        )

    jql = "text ~ currentUser() AND updated >= startOfDay() ORDER BY updated DESC"
    url = f"{JIRA_BASE_URL}/rest/api/2/search"
    headers = {
        "Authorization": f"Bearer {pat}",
        "Content-Type": "application/json",
        "X-Jira-PAT": pat
    }
    payload = {
        "jql": jql,
        "maxResults": 20,
        "fields": ["summary", "status", "updated", "assignee"]
    }
    try:
        resp = requests.post(url, headers=headers, json=payload, verify=False, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        issues = data.get("issues", [])
        
        result = []
        for issue in issues:
            key = issue.get("key", "")
            fields = issue.get("fields", {})
            summary = fields.get("summary", "")
            status = fields.get("status", {}).get("name", "")
            
            result.append({
                "key": key,
                "summary": summary,
                "status": status,
                "url": f"{JIRA_BASE_URL}/browse/{key}"
            })
        return {"mentions": result}
    except Exception as e:
        print(f"Error fetching mentions: {e}")
        return {"mentions": []}

@app.get("/api/sprint/report")
def get_sprint_report(request: Request, project_key: str = "SIGPOSDEV", sprint_name: str = ""):
    pat = get_jira_pat(request)
    if not pat:
        raise HTTPException(
            status_code=401, 
            detail="Missing Jira PAT. Please click ⚙️ Settings in the top-right corner to enter your Personal Access Token."
        )

    try:
        issues, resolved_sprint_name, field_names = _get_sprint_issues(project_key, sprint_name, pat)
        total_tickets = len(issues)
        total_points = 0.0
        done_tickets = 0
        done_points = 0.0
        ip_tickets = 0
        ip_points = 0.0
        todo_tickets = 0
        todo_points = 0.0
        
        dev_stats = {}
        issue_types = {}
        unassigned = []
        overdue_tickets = []
        blocked = []
        
        for issue in issues:
            fields = issue.get("fields", {})
            key = issue.get("key", "")
            summary = fields.get("summary", "")
            
            # Story Points
            points_val = fields.get(STORY_POINTS_FIELD)
            try:
                points = float(points_val) if points_val is not None else 0.0
            except:
                points = 0.0
                
            total_points += points
            
            due_date_str = fields.get("duedate")
            if due_date_str:
                try:
                    due_date = date.fromisoformat(due_date_str)
                    if due_date < date.today() and status_class != "done":
                        overdue_tickets.append({"key": key, "summary": summary, "url": f"{JIRA_BASE_URL}/browse/{key}"})
                except:
                    pass
            
            # Status classification
            status_obj = fields.get("status", {})
            status_name = status_obj.get("name", "To Do") if isinstance(status_obj, dict) else str(status_obj)
            status_class = _classify_status(status_name, status_obj)
            
            if status_class == "done":
                done_tickets += 1
                done_points += points
            elif status_class == "in_progress":
                ip_tickets += 1
                ip_points += points
            else:
                todo_tickets += 1
                todo_points += points
                
            if status_name.lower() in ("blocked", "impediment"):
                blocked.append({"key": key, "summary": summary})
                
            # Assignee
            assignee_obj = fields.get("assignee")
            if not assignee_obj:
                unassigned.append({"key": key, "summary": summary})
                dev_name = "Unassigned"
                dev_username = ""
            else:
                dev_name = assignee_obj.get("displayName") or assignee_obj.get("name") or "Unknown"
                # Robustly extract the Jira login username
                dev_username = assignee_obj.get("name") or assignee_obj.get("key") or ""
                if not dev_username:
                    # Try email prefix
                    email = assignee_obj.get("emailAddress") or ""
                    if "@" in email:
                        dev_username = email.split("@")[0]
                if not dev_username:
                    # displayName often contains username as last word e.g. "Muralidhar N muralidhar.n"
                    name_parts = dev_name.split()
                    if len(name_parts) > 1:
                        dev_username = name_parts[-1]
                    else:
                        dev_username = dev_name
            if dev_name not in dev_stats:
                logger.info(f"[ASSIGNEE DEBUG] dev_name='{dev_name}' dev_username='{dev_username}' raw_assignee_keys={list(assignee_obj.keys()) if assignee_obj else 'None'} name_field={assignee_obj.get('name') if assignee_obj else 'N/A'} key_field={assignee_obj.get('key') if assignee_obj else 'N/A'}")
                dev_stats[dev_name] = {"name": dev_name, "username": dev_username, "tickets": 0, "points": 0.0, "done": 0, "in_progress": 0, "todo": 0, "non_compliant": []}
            
            dev_stats[dev_name]["tickets"] += 1
            dev_stats[dev_name]["points"] += points
            dev_stats[dev_name][status_class] += 1
            
            # Missing Fields Check
            missing = []
            
            # Map required fields to their search names
            required_fields = {
                "Due Date": "duedate",
                "Story Points": STORY_POINTS_FIELD,
                "Component/s": "components",
                "Labels": "labels",
                "Description": "description",
                "Comment": "comment"
            }
            
            # Dynamically map custom fields based on field_names
            custom_targets = {
                "Sprint": "sprint",
                "AX_phase": "ax_phase",
                "AX_Save": "ax_save",
                "Original story points": "original story points",
                "Start Date_ALM": "start date_alm"
            }
            
            # 1. Exact match first
            for k, v in field_names.items():
                if v:
                    vl = v.lower()
                    for display_name, target in custom_targets.items():
                        if vl == target and display_name not in required_fields:
                            required_fields[display_name] = k
                            
            # 2. Substring match fallback for any still missing
            for k, v in field_names.items():
                if v:
                    vl = v.lower()
                    for display_name, target in custom_targets.items():
                        if display_name not in required_fields and target in vl:
                            required_fields[display_name] = k
            
            for display_name, field_key in required_fields.items():
                val = fields.get(field_key)
                # Specialized checks
                if display_name == "Story Points":
                    if points == 0.0: missing.append(display_name)
                elif display_name == "Comment":
                    if isinstance(val, dict):
                        if val.get("total", 0) == 0 and not val.get("comments", []):
                            missing.append(display_name)
                    elif isinstance(val, list):
                        if len(val) == 0:
                            missing.append(display_name)
                    elif val is None or val == "":
                        missing.append(display_name)
                elif val is None or val == "" or val == []:
                    missing.append(display_name)

            if missing:
                dev_stats[dev_name]["non_compliant"].append({
                    "key": key,
                    "summary": summary,
                    "missing": missing
                })
            
            # Issue Type
            itype_obj = fields.get("issuetype", {})
            itype_name = itype_obj.get("name", "Story") if isinstance(itype_obj, dict) else "Story"
            issue_types[itype_name] = issue_types.get(itype_name, 0) + 1
            
        return {
            "sprint_name": resolved_sprint_name,
            "project_key": project_key,
            "overview": {
                "total_tickets": total_tickets,
                "total_points": total_points,
                "done": {"tickets": done_tickets, "points": done_points},
                "in_progress": {"tickets": ip_tickets, "points": ip_points},
                "todo": {"tickets": todo_tickets, "points": todo_points},
                "completion_pct_points": (done_points / total_points * 100) if total_points else 0,
                "completion_pct_tickets": (done_tickets / total_tickets * 100) if total_tickets else 0
            },
            "developers": list(dev_stats.values()),
            "issue_types": issue_types,
            "at_risk": {
                "unassigned": unassigned,
                "overdue_tickets": overdue_tickets,
                "blocked": blocked
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating real sprint report: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to fetch sprint report: {str(e)}")


@app.get("/api/sprint/burndown")
def get_sprint_burndown(request: Request, project_key: str = "SIGPOSDEV", sprint_name: str = ""):
    pat = get_jira_pat(request)
    if not pat:
        raise HTTPException(
            status_code=401, 
            detail="Missing Jira PAT. Please set your Personal Access Token in Settings."
        )
    
    try:
        issues, resolved_sprint_name, field_names = _get_sprint_issues(project_key, sprint_name, pat)
        total_points = 0.0
        done_points = 0.0
        
        for issue in issues:
            fields = issue.get("fields", {})
            sp_val = fields.get(STORY_POINTS_FIELD)
            try:
                sp = float(sp_val) if sp_val is not None else 0.0
            except:
                sp = 0.0
            total_points += sp
            
            status_obj = fields.get("status", {})
            status_name = status_obj.get("name", "") if isinstance(status_obj, dict) else str(status_obj)
            if _classify_status(status_name, status_obj) == "done":
                done_points += sp

        num_days = 10
        ideal = [round(total_points * (1 - i / (num_days - 1)), 1) for i in range(num_days)]
        remaining_now = max(0.0, total_points - done_points)
        
        # Calculate current day dynamically if possible, or default to Day 5 (index 4)
        import datetime
        current_day_idx = 4 # Default to 5th day (0-indexed)
        try:
            # Try to parse sprint dates like 09/14-09/25
            match = re.search(r'\((\d{2}/\d{2})-(\d{2}/\d{2})\)', resolved_sprint_name)
            if match:
                start_str = match.group(1)
                now = datetime.datetime.now()
                # Assuming current year
                start_date = datetime.datetime.strptime(f"{now.year}/{start_str}", "%Y/%m/%d")
                days_passed = 0
                temp_date = start_date
                while temp_date.date() < now.date():
                    if temp_date.weekday() < 5:
                        days_passed += 1
                    temp_date += datetime.timedelta(days=1)
                if 0 <= days_passed < num_days:
                    current_day_idx = days_passed
                elif days_passed >= num_days:
                    current_day_idx = num_days - 1
        except:
            pass

        actual = []
        for day in range(num_days):
            if day <= current_day_idx:
                prog = day / current_day_idx if current_day_idx else 0
                actual.append(round(total_points - (total_points - remaining_now) * prog, 1))
            else:
                actual.append(None)
                
        return {
            "sprint_name": resolved_sprint_name,
            "total_points": total_points,
            "done_points": done_points,
            "days": [f"Day {i+1}" for i in range(num_days)],
            "ideal": ideal,
            "actual": actual
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error calculating real burndown: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to fetch burndown: {str(e)}")


@app.get("/api/search")
def search_issues(request: Request, jql: str = "project = SIGPOSDEV ORDER BY updated DESC", max_results: int = 50):
    pat = get_jira_pat(request)
    if not pat:
        raise HTTPException(status_code=401, detail="Missing Jira PAT. Please set your Personal Access Token.")
        
    try:
        fields = "summary,status,assignee,priority,customfield_10002,labels"
        data = fetch_jira("api/2/search", {"jql": jql, "maxResults": max_results, "fields": fields}, pat)
        formatted_issues = []
        for issue in data.get("issues", []):
            fields = issue.get("fields", {})
            assignee = fields.get("assignee")
            sp = fields.get(STORY_POINTS_FIELD)
            try:
                sp_val = float(sp) if sp is not None else 0.0
            except:
                sp_val = 0.0
                
            formatted_issues.append({
                "key": issue.get("key"),
                "summary": fields.get("summary", ""),
                "status": fields.get("status", {}).get("name", "Unknown"),
                "assignee": assignee.get("displayName") if assignee else "Unassigned",
                "priority": fields.get("priority", {}).get("name", "Medium"),
                "story_points": sp_val,
                "labels": fields.get("labels", []),
                "link": f"{JIRA_BASE_URL}/browse/{issue.get('key')}"
            })
        return {
            "total": len(formatted_issues),
            "issues": formatted_issues
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Search failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")


@app.get("/api/issue/{issue_key}")
def get_issue(request: Request, issue_key: str):
    pat = get_jira_pat(request)
    if not pat:
        raise HTTPException(status_code=401, detail="Missing Jira PAT.")
        
    try:
        return fetch_jira(f"api/2/issue/{issue_key}", {}, pat)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Fetch issue failed: {e}")
        raise HTTPException(status_code=500, detail="Error fetching issue")


@app.post("/api/agent/action")
def agent_action(request: Request, action_req: AgentAction):
    pat = get_jira_pat(request)
    action = action_req.action
    project_key = action_req.project_key or "SIGPOSDEV"
    
    if not pat:
        raise HTTPException(status_code=401, detail="Missing Jira PAT. Please set token in Settings.")
        
    if action == "sprint_audit":
        try:
            issues, sprint_name, field_names = _get_sprint_issues(project_key, "active", pat)
            missing_labels = []
            missing_assignees = []
            overdue_tickets = []
            
            for issue in issues:
                fields = issue.get("fields", {})
                key = issue.get("key")
                summary = fields.get("summary", "")
                
                labels = fields.get("labels", [])
                if not any(l in VALID_LABELS for l in labels):
                    missing_labels.append({"key": key, "summary": summary})
                    
                if not fields.get("assignee"):
                    missing_assignees.append({"key": key, "summary": summary})
                    
                due_date_str = fields.get("duedate")
                if due_date_str:
                    try:
                        due_date = date.fromisoformat(due_date_str)
                        status_obj = fields.get("status", {})
                        status_name = status_obj.get("name", "To Do") if isinstance(status_obj, dict) else str(status_obj)
                        if due_date < date.today() and _classify_status(status_name, status_obj) != "done":
                            overdue_tickets.append({"key": key, "summary": summary})
                    except:
                        pass
                    
            return {
                "audit_results": {
                    "sprint_name": sprint_name,
                    "missing_labels": missing_labels,
                    "missing_assignees": missing_assignees,
                    "overdue_tickets": overdue_tickets
                }
            }
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Audit failed: {e}")
            raise HTTPException(status_code=500, detail=f"Audit failed: {str(e)}")
            
    return {"status": "success", "action": action, "result": f"Action '{action}' processed for {project_key}."}


# Mount static frontend
static_dir = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(static_dir):
    os.makedirs(static_dir)
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/")
def read_root():
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "GPOS AX Portal Backend Running."}
@app.post('/api/weekly_status')
async def weekly_status(req: ChatRequest, request: Request):
    pat = get_jira_pat(request)
    if not pat:
        raise HTTPException(status_code=401, detail='Missing Jira PAT. Please set token in Settings.')
        
    try:
        # 1. Fetch user profile to get account ID/name
        user_data = fetch_jira('api/2/myself', {}, pat)
        account_id = user_data.get('accountId', '')
        user_name = user_data.get('displayName', 'User')
        
        # 2. Fetch active sprint tickets
        # Determine if user asked for all members
        is_all_members = False
        msg_lower = req.message.lower()
        if 'all' in msg_lower or 'team' in msg_lower or 'everyone' in msg_lower:
            is_all_members = True
            
        if is_all_members:
            jql = f'project = {req.project_key} AND sprint in openSprints()'
        else:
            jql = f'project = {req.project_key} AND sprint in openSprints() AND assignee = currentUser()'
            
        search_data = fetch_jira('api/2/search', {'jql': jql, 'maxResults': 500, 'fields': 'summary,status,description,created,updated,assignee'}, pat)
        issues = search_data.get('issues', [])
        
        if not issues:
            return {'intent': 'weekly_status', 'message': f'Hi {user_name}, you don\'t have any tickets assigned to you in the current active sprint!'}
            
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        
        # 3. Figure out Sprint Start Date to enforce Week 1 vs Week 2 boundaries
        target_start = None
        target_end = None
        week_label = "Current Week"
        
        try:
            # Re-use our sprint fetching logic to get the exact sprint name (e.g. 'Sprint 19 (09/14-09/27)')
            _, resolved_sprint_name, _ = _get_sprint_issues(req.project_key, "active", pat)
            import re
            match = re.search(r'\((\d{2}/\d{2})-(\d{2}/\d{2})\)', resolved_sprint_name)
            if match:
                start_str = match.group(1)
                sprint_start = datetime.datetime.strptime(f"{now.year}/{start_str}", "%Y/%m/%d").replace(tzinfo=datetime.timezone.utc)
                week_1_end = sprint_start + datetime.timedelta(days=7)
                
                if now < week_1_end:
                    # We are in the First Half (Week 1)
                    target_start = sprint_start
                    target_end = week_1_end
                    week_label = "First Half (Week 1)"
                else:
                    # We are in the Second Half (Week 2)
                    target_start = week_1_end
                    target_end = sprint_start + datetime.timedelta(days=14)
                    week_label = "Second Half (Week 2)"
        except Exception as e:
            logger.error(f"Failed to parse sprint dates for weekly status: {e}")
            
        # Fallback to rolling 7 days if parsing fails
        if not target_start:
            target_start = now - datetime.timedelta(days=7)
            target_end = now + datetime.timedelta(days=1)
        
        # 4. Fetch comments for each issue
        compiled_data = f'Developer: {user_name}\nReport generated on: {now.strftime("%Y-%m-%d")}\n\n'
        compiled_data += '--- ACTIVE SPRINT TICKETS ---\n'
        
        for issue in issues:
            key = issue.get('key')
            fields = issue.get('fields', {})
            status = fields.get('status', {}).get('name', 'Unknown')
            summary = fields.get('summary', '')
            if 'leave' in summary.lower() or 'vacation' in summary.lower() or 'time off' in summary.lower():
                continue
            description = fields.get('description', '')
            if description and len(str(description)) > 300:
                description = str(description)[:300] + '... [truncated]'
                
            assignee = fields.get('assignee')
            assignee_name = assignee.get('displayName', 'Unassigned') if assignee else 'Unassigned'
            compiled_data += f'\nTicket: {key} (Assigned to: {assignee_name})\nStatus: {status}\nSummary: {summary}\nDescription: {description}\n'
            
            # Fetch comments
            try:
                comments_data = fetch_jira(f'api/2/issue/{key}/comment', {'maxResults': 20, 'orderBy': '-created'}, pat)
                comments = comments_data.get('comments', [])
                
                recent_comments = []
                for c in comments:
                    created_str = c.get('created')
                    # Parse 2026-09-17T06:58:15.549+0000
                    try:
                        c_date = datetime.datetime.strptime(created_str[:19], '%Y-%m-%dT%H:%M:%S').replace(tzinfo=datetime.timezone.utc)
                        if target_start <= c_date <= target_end:
                            author = c.get('author', {}).get('displayName', 'Unknown')
                            body = c.get('body', '').strip()
                            if len(body) > 200: body = body[:200] + '...'
                            recent_comments.append(f'[{created_str[:10]}] {author}: {body}')
                    except:
                        pass
                
                if recent_comments:
                    compiled_data += 'Recent Comments (Last 7 Days):\n' + '\n'.join(recent_comments) + '\n'
                else:
                    compiled_data += 'Recent Comments: None in the last 7 days.\n'
            except:
                compiled_data += 'Recent Comments: [Failed to fetch]\n'
                
        # 5. Call LLM
        base_rules = '''
CRITICAL RULES:
- Categorize each ticket into exactly ONE of the 3 sections based on its 'Status' and 'Comments'.
- If Jira Status is 'Resolved', 'Closed', or 'Done', it MUST go to 'Completed Tasks'.
- If Jira Status is 'In Progress', 'Active', or 'Working', it MUST go to 'In Progress'.
- If Jira Status is 'Open', 'To Do', or 'Backlog', it MUST go to 'ToDo', regardless of comments.
- STRICT DUPLICATION BAN: You MUST ensure no ticket appears more than once. If you place a ticket in 'Completed Tasks', you CANNOT place it in 'ToDo' or 'In Progress'.
- Provide exactly ONE bullet point per ticket containing the ticket number and a brief 2-line summary of the work done (extract heavily from comments).
- DO NOT include tickets related to 'leave', 'vacation', or 'time off'. Completely omit them.
'''
        if is_all_members:
            sys_prompt = f'''You are analyzing the TEAM's weekly progress. Based on the tickets and comments, generate a status report. Group the report by DEVELOPER NAME. Under each developer, include EXACTLY these sections:
            
1. **Completed Tasks**
2. **In Progress**
3. **ToDo**
{base_rules}
Format using Markdown headers and bullet points. DO NOT output any XML or HTML tags.'''
        else:
            sys_prompt = f'''You are analyzing a developer's weekly progress. Based on the tickets and comments, generate a status report with EXACTLY these sections:
            
1. **Completed Tasks**
2. **In Progress**
3. **ToDo**
{base_rules}
Format using Markdown bullet points. DO NOT output any XML or HTML tags. DO NOT output anything else.'''

        messages = [
            {'role': 'system', 'content': sys_prompt},
            {'role': 'user', 'content': f'Here is the data:\n\n{compiled_data}'}
        ]
        
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {req.llm_key}',
            'X-Title': 'EXACODE SWE(API)',
            'X-Model': 'Chat-EXACODE-A'
        }
        
        import httpx
        
        llm_url = req.llm_url.rstrip('/')
        if not llm_url.endswith('chat/completions'):
            if llm_url.endswith('v1'): llm_url += '/chat/completions'
            else: llm_url += '/v1/chat/completions'
            
        async with httpx.AsyncClient() as client:
            resp = await client.post(llm_url, json={'model': req.llm_model, 'messages': messages, 'temperature': 0.1}, headers=headers, timeout=60)
            resp.raise_for_status()
            result = resp.json()
            msg = result['choices'][0]['message']['content']
            return {'intent': 'weekly_status', 'message': msg}
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f'Weekly Status failed: {e}', exc_info=True)
        raise HTTPException(status_code=500, detail=f'Failed to generate weekly status: {str(e)}')
@app.get('/api/quick_action')
def quick_action(action: str, request: Request):
    pat = get_jira_pat(request)
    if not pat:
        raise HTTPException(status_code=401, detail='Missing Jira PAT.')
        
    if action == 'sprint_audit':
        project_key = "SIGPOSDEV"
        jql = f'project = {project_key} AND sprint in openSprints() AND assignee is EMPTY'
        try:
            search_data = fetch_jira('api/2/search', {'jql': jql, 'maxResults': 100, 'fields': 'summary,status,issuetype'}, pat)
            issues = search_data.get('issues', [])
            
            if not issues:
                return {"message": "Great news! There are no unassigned tickets in the active sprint."}
                
            md = "### Audit: Unassigned Sprint Tickets\n\n"
            md += "| Ticket | Type | Status | Summary |\n"
            md += "|---|---|---|---|\n"
            for issue in issues:
                key = issue.get('key', '')
                f = issue.get('fields', {})
                summary = f.get('summary', '')
                status = f.get('status', {}).get('name', '')
                itype = f.get('issuetype', {}).get('name', '')
                md += f"| {key} | {itype} | {status} | {summary} |\n"
                
            return {"message": md}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
            
    raise HTTPException(status_code=400, detail="Unknown action")

