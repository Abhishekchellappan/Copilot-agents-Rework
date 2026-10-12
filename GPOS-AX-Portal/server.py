# --- MCP SSE CLIENT PATCH FOR LARGE SNAPSHOTS ---
import httpx2._sse
class MySSEParser(httpx2._sse._SSEParser):
    def __init__(self, max_event_size=None):
        super().__init__(max_event_size=50000000) # 50 MB
httpx2._sse._SSEParser = MySSEParser
# ------------------------------------------------
import os
import re
import sqlite3
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
from cachetools import TTLCache, cached

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
DEVICE_MCP_SERVER_URL = os.environ.get('DEVICE_MCP_SERVER_URL', 'http://localhost:8000').rstrip('/')
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

# Admin Configuration
ADMIN_USERS = {'abhishek15.c', 'admin'}  # Users who get admin role by default

# Database setup
DB_PATH = os.environ.get('DB_PATH', '/tmp/gpos_portal.db')

def init_db():
    """Initialize SQLite database with required tables."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute('PRAGMA journal_mode=WAL;')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            is_admin INTEGER DEFAULT 0,
            is_allowed INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS agent_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            duration_seconds INTEGER DEFAULT 0,
            recorded_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # Ensure admin users exist
    for admin in ADMIN_USERS:
        c.execute('''
            INSERT OR IGNORE INTO users (username, is_admin, is_allowed)
            VALUES (?, 1, 1)
        ''', (admin,))
    conn.commit()
    conn.close()

def get_db():
    """Get database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute('PRAGMA journal_mode=WAL;')
    conn.row_factory = sqlite3.Row
    return conn

def is_user_allowed(username: str) -> bool:
    """Check if a user is allowed to log in. Creates pending request if new."""
    conn = get_db()
    is_admin_user = username in ADMIN_USERS
    try:
        row = conn.execute('SELECT is_allowed FROM users WHERE username = ?', (username,)).fetchone()
        if row is None:
            # First time user! Insert as pending (0) unless they are an admin
            initial_allow = 1 if is_admin_user else 0
            conn.execute('''
                INSERT INTO users (username, is_admin, is_allowed, last_login)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ''', (username, 1 if is_admin_user else 0, initial_allow))
            conn.commit()
            return bool(initial_allow)
        return bool(row['is_allowed'])
    finally:
        conn.close()

def update_last_login(username: str, is_admin: bool = False):
    """Update last login timestamp for an existing allowed user."""
    conn = get_db()
    try:
        conn.execute('''
            UPDATE users SET 
                last_login = CURRENT_TIMESTAMP,
                is_admin = CASE WHEN username IN ('abhishek15.c','admin') THEN 1 ELSE is_admin END
            WHERE username = ?
        ''', (username,))
        conn.commit()
    finally:
        conn.close()

# Initialize DB on startup
init_db()


class AgentAction(BaseModel):
    action: str
    project_key: str = "SIGPOSDEV"


class LoginRequest(BaseModel):
    username: str
    password: str


def _create_jwt_token(username: str) -> str:
    """Generate a JWT token for an authenticated user."""
    role = 'admin' if username in ADMIN_USERS else 'user'
    payload = {
        'sub': username,
        'role': role,
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
    """Authenticate an EP ID/PW against LGE LDAP."""
    try:
        from ldap3 import Server, Connection, Tls
        import ssl
        
        address_list = [
            'lgesaads01.lge.net',
            'lgesaads02.lge.net',
            'lgesaads03.lge.net',
            'ptkmf10-dc12.lge.net',
        ]
        
        tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLS_CLIENT)
        bind_user = f"{username}@lge.com"
        
        for address in address_list:
            try:
                server = Server(
                    address,
                    port=636,
                    use_ssl=True,
                    tls=tls,
                    get_info=None,
                    connect_timeout=3
                )
                conn = Connection(
                    server,
                    user=bind_user,
                    password=password,
                    auto_bind=True,
                )
                conn.unbind()
                return True
            except Exception as e:
                logger.warning(f"LDAP auth failed for {username} on {address}: {e}")
                continue
                
        logger.error(f"All LDAP servers failed for {username}")
        return False
    except Exception as e:
        logger.error(f"LDAP library error for {username}: {e}")
        return False


@app.post('/api/login')
async def login(req: LoginRequest):
    """Authenticate user and return JWT token."""
    username = req.username.strip()
    password = req.password
    
    if not username or not password:
        raise HTTPException(status_code=400, detail='Username and password are required')
    
    if not _authenticate_ldap(username, password):
        raise HTTPException(status_code=401, detail='Invalid AD credentials. Please check your username and password.')
    
    # Check if user is allowed
    if not is_user_allowed(username):
        raise HTTPException(status_code=403, detail='Account pending admin approval. Please contact the administrator.')

    is_admin = username in ADMIN_USERS
    update_last_login(username, is_admin)
    token = _create_jwt_token(username)
    return {
        'token': token,
        'username': username,
        'is_admin': is_admin,
        'role': 'admin' if is_admin else 'user',
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
    
    return {
        'valid': True,
        'username': payload.get('sub', ''),
        'role': payload.get('role', 'user'),
        'is_admin': payload.get('role', 'user') == 'admin'
    }

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
    if request.url.path.startswith("/api/") and request.url.path not in ["/api/login", "/api/auth/verify", "/api/device/info"]:
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

sprint_cache = TTLCache(maxsize=100, ttl=10)

@cached(cache=sprint_cache, key=lambda project_key, sprint_name, pat: (project_key, sprint_name))
def _get_sprint_issues(project_key: str, sprint_name: str, pat: str) -> Tuple[List[dict], str, dict]:
    """
    Fetch all issues for the active or requested sprint.
    Returns (issues_list, sprint_name, field_names_dict)
    """
    field_names = _get_field_names(project_key, pat)
    
    # Map fields to fetch
    required_fields = {
        "duedate", STORY_POINTS_FIELD, "components", "labels", "description",
        "summary", "status", "assignee", "issuetype", "priority", "comment",
        "resolutiondate", "updated"
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
            resolved_name = None
            for issue in issues:
                for k, v in field_names.items():
                    if v and "sprint" in v.lower():
                        sinfo = issue.get("fields", {}).get(k)
                        if isinstance(sinfo, list) and sinfo:
                            for item in reversed(sinfo):
                                if isinstance(item, dict):
                                    if item.get("state") == "active":
                                        resolved_name = item.get("name")
                                        break
                                    elif not resolved_name and item.get("name"):
                                        resolved_name = item.get("name")
                                elif isinstance(item, str):
                                    if "state=ACTIVE" in item:
                                        m = re.search(r'name=([^,\]]+)', item)
                                        if m:
                                            resolved_name = m.group(1)
                                            break
                                    elif not resolved_name:
                                        m = re.search(r'name=([^,\]]+)', item)
                                        if m:
                                            resolved_name = m.group(1)
                            if resolved_name:
                                break
                if resolved_name:
                    break
            return issues, resolved_name or sprint_name or "Active Sprint", field_names
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
    images: list = []
    llm_url: str = ""
    llm_key: str = ""
    llm_model: str = "Chat-EXACODE-A"
    project_key: str = "SIGPOSDEV"
    history: list = []
    agent_id: str = "jira-agent"

import httpx
import json
import subprocess

async def device_llm_chat(req: ChatRequest, llm_url: str, headers: dict):
    from mcp.client.sse import sse_client
    from mcp.client.session import ClientSession
    from contextlib import AsyncExitStack
    import httpx
    import json
    import re
    import traceback


    sys_prompt = """You are the GPOS Device Agent Studio.
You help embedded Linux developers debug, profile, and deploy to their target webOS boards via SSH.

CRITICAL TOOL EXECUTION RULE:
You MUST actually call the appropriate tool (e.g., `execute_device_command`, `launch_app`, `close_app`) to perform the action. 
DO NOT just output HTML or text confirming the action without first executing the tool!

WEBOS SERVICE API RULES:
1. webOS does NOT use standard Linux desktop utilities (like scrot, nmcli, etc.). For ANY system action (e.g., taking screenshots, networking, media), you MUST dynamically discover the relevant webOS Luna service.
2. DISCOVERY STEPS - follow in order:
   a. Find the service: `ls-monitor -l | grep -i <keyword>` (e.g. grep -i capture)
   b. Introspect to get available METHODS and PARAMETERS: `ls-monitor -i <exact.service.name>`
   c. Call the correct method using luna-send via `execute_device_command`
3. CRITICAL - NO LOOPING RULE: If a luna-send call fails or returns `returnValue: false`, you MUST stop immediately. DO NOT retry with different methods endlessly. Instead: report what service you found, what methods are available (from ls-monitor -i), what you tried, and what error you got. Ask the user if they want to try a specific method.

CRITICAL PRESENTATION RULES (THE WOW FACTOR):
You MUST NEVER just output plain text for command results. You must present the data using beautiful UI widgets via `<agent-html>` tags.

CRITICAL UI RENDERING RULE (SINGLE RESPONSE):
Whenever you output an `<agent-html>` widget, the widget MUST be your ENTIRE response. DO NOT include any conversational text (like "Here is the status:" or "I've checked the device") before or after the widget. Outputting conversational text alongside a widget causes the chat UI to render two separate message bubbles, which breaks the user experience. ONLY output the raw `<agent-html>` block.
1. **CPU Benchmark Results**: When you run a benchmark, output this JSON block so the frontend renders the graph:
<device-benchmark>{"ipc": 1.25, "cacheMiss": 450, "pageFaults": 12, "totalCycles": 12500000}</device-benchmark>
And follow it with this exact beautifully styled summary widget using `<agent-html>`:
<agent-html>
<div class="bg-slate-800 border border-slate-700 rounded-lg p-4">
  <h3 class="text-emerald-400 font-bold mb-2 flex items-center gap-2"><i data-lucide="cpu" class="w-4 h-4"></i> Benchmark Complete</h3>
  <p class="text-sm text-slate-300 mb-3">The CPU benchmark successfully executed on the target board. Here are the highlights:</p>
  <div class="grid grid-cols-2 gap-2 text-xs">
    <div class="bg-slate-900 p-2 rounded border border-slate-700"><span class="text-slate-400 block">Idle</span><span class="text-emerald-400 text-lg font-mono">93.3%</span></div>
    <div class="bg-slate-900 p-2 rounded border border-slate-700"><span class="text-slate-400 block">System</span><span class="text-amber-400 text-lg font-mono">4.4%</span></div>
  </div>
</div>
</agent-html>
2. **App Launch / Action Results**: Use a beautiful card to show the status of the action.
Example for app launch:
<agent-html>
<div class="bg-slate-800 border border-blue-500/30 rounded-lg p-4">
  <h3 class="text-blue-400 font-bold mb-2 flex items-center gap-2"><i data-lucide="play-circle" class="w-4 h-4"></i> Application Launched</h3>
  <div class="bg-slate-900 p-3 rounded border border-slate-700 flex flex-col gap-2">
    <div class="flex justify-between items-center border-b border-slate-700 pb-2">
      <span class="text-slate-400 text-xs uppercase tracking-wider">App ID</span>
      <span class="text-slate-200 font-mono text-sm">com.webos.app.appliance.gallery</span>
    </div>
    <div class="flex justify-between items-center">
      <span class="text-slate-400 text-xs uppercase tracking-wider">Status</span>
      <span class="text-emerald-400 text-sm font-medium flex items-center gap-1"><i data-lucide="check" class="w-3 h-3"></i> Running on Target</span>
    </div>
  </div>
</div>
</agent-html>
3. **API / Luna-Send Results**: When you execute an API call, present the result in a beautiful card.
Example:
<agent-html>
<div class="bg-slate-800 border border-purple-500/30 rounded-lg p-4">
  <h3 class="text-purple-400 font-bold mb-2 flex items-center gap-2"><i data-lucide="radio" class="w-4 h-4"></i> API Call Executed</h3>
  <div class="bg-slate-900 p-3 rounded border border-slate-700 flex flex-col gap-2">
    <div class="flex justify-between items-center border-b border-slate-700 pb-2">
      <span class="text-slate-400 text-xs uppercase tracking-wider">Endpoint</span>
      <span class="text-slate-200 font-mono text-sm">luna://com.webos.service/method</span>
    </div>
    <div class="mt-2">
      <span class="text-slate-400 text-xs uppercase tracking-wider block mb-1">Response JSON</span>
      <pre class="text-emerald-400 text-xs font-mono bg-black/50 p-2 rounded overflow-x-auto">{ "returnValue": true }</pre>
    </div>
  </div>
</div>
</agent-html>
4. **GDB Core Dump Analysis**: When you run `run_gdb_backtrace`, present the stack trace nicely.
Example:
<agent-html>
<div class="bg-slate-800 border border-red-500/30 rounded-lg p-4">
  <h3 class="text-red-400 font-bold mb-2 flex items-center gap-2"><i data-lucide="skull" class="w-4 h-4"></i> Core Dump Analysis</h3>
  <p class="text-sm text-slate-300 mb-2">A segmentation fault was detected. Here is the C++ stack trace:</p>
  <div class="bg-slate-900 p-3 rounded border border-slate-700">
    <pre class="text-red-400 text-xs font-mono overflow-x-auto">#0  0x0000ffffaa... in ?? ()
#1  0x0000ffffaa... in AudioManager::play () at audio.cpp:142</pre>
  </div>
</div>
</agent-html>

4. **Swarm Execution (Multi-Device)**:
<agent-html>
<div class="bg-slate-800 border border-emerald-500/30 rounded-lg p-4">
  <h3 class="text-emerald-400 font-bold mb-2 flex items-center gap-2"><i data-lucide="server" class="w-4 h-4"></i> Swarm Execution</h3>
  <p class="text-sm text-slate-300 mb-2">Command successfully fanned out across multiple targets.</p>
</div>
</agent-html>


5. **System Forensics Snapshot**: When a user asks to investigate a live crash, check memory/CPU state, or take a system forensics snapshot, you MUST call `generate_forensics_snapshot` and present the result in this stunning widget:
<agent-html>
<div class="bg-slate-900 border-2 border-red-500/40 rounded-lg p-5 shadow-lg shadow-red-500/20 font-sans mb-4">
  <div class="flex justify-between items-start mb-4 pb-3 border-b border-slate-700">
    <div class="flex items-center gap-3">
      <div class="p-2 bg-red-500/20 rounded-md animate-pulse">
        <i data-lucide="siren" class="w-6 h-6 text-red-400"></i>
      </div>
      <div>
        <h2 class="text-lg font-bold text-slate-100 m-0 tracking-wider uppercase text-red-400">System Forensics Snapshot</h2>
        <div class="text-xs text-slate-400 font-mono mt-1">Target: {{target_ip}} | Time: {{timestamp}}</div>
      </div>
    </div>
    <div class="bg-slate-800 px-3 py-1 rounded text-xs border border-slate-600 text-slate-300 font-mono flex items-center gap-2">
      <div class="w-2 h-2 rounded-full bg-emerald-400"></div> Connected
    </div>
  </div>
  
  <div class="grid grid-cols-2 gap-4 mb-4">
    <div class="bg-slate-800 p-3 rounded-md border border-slate-700">
      <div class="text-xs text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1"><i data-lucide="cpu" class="w-3 h-3"></i> Top Processes</div>
      <div class="text-xs text-amber-300 font-mono whitespace-pre-wrap">{{top_processes_summary}}</div>
    </div>
    <div class="bg-slate-800 p-3 rounded-md border border-slate-700">
      <div class="text-xs text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1"><i data-lucide="memory-stick" class="w-3 h-3"></i> Memory State</div>
      <div class="text-xs text-blue-300 font-mono whitespace-pre-wrap">{{memory_summary}}</div>
    </div>
  </div>

  <div class="bg-slate-800 rounded-md p-4 border border-slate-700 mb-4">
    <h3 class="text-sm font-bold text-slate-300 flex items-center gap-2 mb-3"><i data-lucide="terminal" class="w-4 h-4 text-emerald-400"></i> Recent Kernel / Luna Activity</h3>
    <div class="bg-black/50 p-2 rounded text-xs font-mono text-emerald-400/80 whitespace-pre-wrap">{{recent_logs}}</div>
  </div>
  
  <div class="bg-red-900/20 rounded-md p-3 border border-red-500/30 flex items-start gap-3">
    <i data-lucide="camera" class="w-5 h-5 text-red-400 mt-0.5 flex-shrink-0"></i>
    <div class="text-sm text-red-200">
      <strong>Screenshot Status:</strong> {{screenshot_status}}
    </div>
  </div>
</div>
</agent-html>

6. **Source-Code Blame (Red-Line)**: When you resolve a crash offset using debug symbols and source code, present it in this widget:
<agent-html>
<div class="bg-slate-900 border-l-4 border-l-red-500 rounded-r-lg p-5 shadow-lg font-sans mb-4">
  <div class="flex items-center justify-between mb-4 pb-3 border-b border-slate-800">
    <div>
      <h2 class="text-lg font-bold text-slate-200 m-0 flex items-center gap-2">
        <i data-lucide="file-code-2" class="w-5 h-5 text-slate-400"></i> {{file_name}}
      </h2>
      <div class="text-xs text-slate-500 font-mono mt-1">Commit: {{commit_hash}} | Symbol: {{symbol_name}}</div>
    </div>
  </div>
  
  <div class="bg-slate-950 rounded-md border border-slate-800 font-mono text-sm overflow-hidden">
    <div class="bg-slate-900 px-4 py-2 border-b border-slate-800 text-xs text-slate-500 flex justify-between">
      <span>C++ Source</span><span>Line {{crash_line_number}}</span>
    </div>
    <div class="p-4 overflow-x-auto">
      <div class="text-slate-400">{{code_above}}</div>
      <div class="bg-red-950/50 -mx-4 px-4 py-1 border-y border-red-900/50 text-red-400 relative">
        <div class="absolute left-0 top-0 bottom-0 w-1 bg-red-500"></div>
        {{crashed_line_code}}
      </div>
      <div class="text-slate-400">{{code_below}}</div>
    </div>
  </div>
</div>
</agent-html>


7. **Interactive Performance Call Tree**: When you run 
un_perf_profile or are asked to generate a call stack execution tree for performance bottlenecks, you MUST use Mermaid.js embedded inside this Flame Graph widget:
<agent-html>
<div class="bg-slate-900 border-t-4 border-t-amber-500 rounded-b-lg p-5 shadow-lg shadow-amber-500/10 font-sans mb-4">
  <div class="flex items-center justify-between mb-4 pb-3 border-b border-slate-800">
    <div>
      <h2 class="text-lg font-bold text-slate-200 m-0 flex items-center gap-2">
        <i data-lucide="flame" class="w-5 h-5 text-amber-500"></i> Performance Call Tree
      </h2>
      <div class="text-xs text-slate-500 font-mono mt-1">Target: {{target_ip}} | Process: {{process_name}} (PID: {{pid}})</div>
    </div>
  </div>
  
  <div class="mt-4 bg-amber-900/20 p-3 rounded text-xs text-amber-200/80 border border-amber-500/20 flex gap-2">
    <i data-lucide="zap" class="w-4 h-4 flex-shrink-0 text-amber-400"></i>
    <div><strong>Insight:</strong> {{bottleneck_insight}}</div>
  </div>
</div>
</agent-html>

```mermaid
{{mermaid_code}}
```

CRITICAL CRASH ANALYSIS RULE:
If `auto_triage_service` detects a "SEGFAULT (CRASH)", automatically chain a call to `run_gdb_backtrace`.

CRITICAL SWARM TESTING RULE:
If the user asks to run a command across multiple devices, or mentions "swarm testing", ALWAYS use the swarm_execute tool. Do NOT use a loop of execute_device_command calls!



If the user's prompt includes a "[Target Board IP: <ip>]" tag, use that IP for your commands. Always make your UI futuristic and professional.
"""

    try:
        async with AsyncExitStack() as stack:


            # Connect Device
            dev_streams = await stack.enter_async_context(sse_client(f"{DEVICE_MCP_SERVER_URL}/sse", headers={}))
            dev_session = await stack.enter_async_context(ClientSession(dev_streams[0], dev_streams[1]))
            await dev_session.initialize()

            tools = []

            dev_tools_resp = await dev_session.list_tools()
            for t in dev_tools_resp.tools:
                tools.append({"type": "function", "function": {"name": t.name, "description": t.description or "", "parameters": t.input_schema}})

            messages = [{"role": "system", "content": sys_prompt}]
            for h in req.history[-10:]:
                if h.get("role") and h.get("content"):
                    messages.append({"role": h["role"], "content": h["content"]})
            messages.append({"role": "user", "content": req.message})

            async with httpx.AsyncClient() as client:
                for _ in range(15):
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
                        return {"intent": "chat", "message": msg.get("content", "")}

                    for tool_call in msg["tool_calls"]:
                        func_name = tool_call["function"]["name"]
                        try:
                            func_args = json.loads(tool_call["function"]["arguments"])
                        except json.JSONDecodeError as e:
                            logger.error(f"Invalid JSON from LLM for tool {func_name}: {e}")
                            messages.append({
                                "role": "tool",
                                "name": func_name,
                                "tool_call_id": tool_call["id"],
                                "content": f"Error: You provided invalid JSON arguments. Please correct your syntax and try again."
                            })
                            continue
                        
                        try:
                            tool_result = await dev_session.call_tool(func_name, arguments=func_args)
                            
                            res_text = ""
                            if isinstance(tool_result.content, list):
                                parts = []
                                for c in tool_result.content:
                                    if hasattr(c, "text"):
                                        parts.append(str(c.text))
                                    elif isinstance(c, dict) and "text" in c:
                                        parts.append(str(c["text"]))
                                    else:
                                        parts.append(str(c))
                                res_text = "\n".join(parts)
                            else:
                                res_text = str(tool_result.content)

                            if func_name == "generate_interactive_flamegraph" and res_text.strip().startswith("<?xml"):
                                import uuid
                                import os
                                svg_filename = f"flamegraph_{uuid.uuid4().hex[:8]}.svg"
                                static_dir = os.path.join(os.path.dirname(__file__), "static")
                                if not os.path.exists(static_dir):
                                    os.makedirs(static_dir)
                                svg_path = os.path.join(static_dir, svg_filename)
                                with open(svg_path, "w", encoding="utf-8") as f:
                                    f.write(res_text)
                                res_text = f"Flame graph SVG generated. Present it using this HTML widget:\n\n<agent-html>\n<div class='bg-slate-900 border-t-4 border-t-amber-500 rounded-lg p-5 shadow-lg shadow-amber-500/10 font-sans mb-4'>\n  <h2 class='text-lg font-bold text-slate-200 mb-4 flex items-center gap-2'><i data-lucide='flame' class='text-amber-500'></i> Interactive Flame Graph</h2>\n  <iframe src='/static/{svg_filename}' width='100%' height='600px' style='border:1px solid #1e293b; border-radius: 8px; background: #0f172a;'></iframe>\n</div>\n</agent-html>"
                                
                            elif func_name == "take_screenshot" and "SNAPSHOT_BASE64:" in res_text:
                                import uuid
                                import os
                                import base64
                                b64_data = res_text.split("SNAPSHOT_BASE64:")[1].strip()
                                img_filename = f"snap_{uuid.uuid4().hex[:8]}.png"
                                static_dir = os.path.join(os.path.dirname(__file__), "static")
                                if not os.path.exists(static_dir):
                                    os.makedirs(static_dir)
                                img_path = os.path.join(static_dir, img_filename)
                                try:
                                    with open(img_path, "wb") as f:
                                        f.write(base64.b64decode(b64_data))
                                    res_text = f"Screenshot successfully captured and downloaded from the target device. Present it to the user using this HTML widget:\n\n<agent-html>\n<div class='bg-slate-900 border-t-4 border-t-blue-500 rounded-lg p-5 shadow-lg shadow-blue-500/10 font-sans mb-4'>\n  <h2 class='text-lg font-bold text-slate-200 mb-4 flex items-center gap-2'><i data-lucide='camera' class='text-blue-500'></i> Live Device Snapshot</h2>\n  <div class='rounded overflow-hidden border border-slate-700 bg-black flex justify-center'>\n    <img src='/static/{img_filename}' alt='Device Screenshot' class='max-w-full h-auto object-contain' style='max-height: 400px;' />\n  </div>\n</div>\n</agent-html>"
                                except Exception as e:
                                    res_text = f"Screenshot captured but failed to decode base64 on portal side: {e}"
                                
                            if not res_text:
                                res_text = "(Command returned empty output)"
                        except Exception as e:
                            res_text = f"[ERROR] Tool execution failed: {str(e)}"

                        messages.append({
                            "role": "tool",
                            "name": func_name,
                            "tool_call_id": tool_call["id"],
                            "content": res_text
                        })

                return {"intent": "chat", "message": "The agent reached the maximum number of iterations without completing the task."}

    except Exception as e:
        return {"intent": "chat", "message": f"?? Could not connect to MCP Servers.\n\nError: {str(e)}"}

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
            device_streams = await stack.enter_async_context(sse_client(f"{DEVICE_MCP_SERVER_URL}/sse"))
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
            system_prompt = f"""You are the GPOS AI Supervisor.
You have access to TWO domains of tools:
1. JIRA TOOLS: For checking tickets, bugs, and governance in project {req.project_key or 'SIGPOSDEV'}.
2. DEVICE TOOLS: For executing SSH commands, running GDB, pulling logs, and swarm testing on target boards.

When checking bugs or triage, check Jira first. 
When investigating a crash, connect to the board and run 'run_gdb_backtrace' or 'auto_triage_service'.
If the user asks to run a swarm test, use 'swarm_execute'.

CRITICAL LOG ANALYSIS RULE:
When a user asks you to analyze an attached crash log (like a .7z or .zip file attached to a Jira ticket), you MUST perform the following sequence:
1. Call `jira_list_attachments` with the issue key to find the internal attachment ID and exact filename.
2. Call `jira_download_attachment` to download the file securely.
3. Call `extract_archive` to unzip it.
4. Do NOT try to read the whole file! Log files are too big. Call `search_log_contents` to find keywords like 'crash', 'SIGSEGV', 'Exception', or 'Call Trace:'.
5. Call `read_log_snippet` using the line numbers you found to read the 50-100 lines surrounding the crash.
6. When summarizing the crash reason for the user, you MUST use a stunning Forensic Crash Analysis UI widget.
Use this exact HTML structure wrapped exactly in <agent-html> tags, filling in the real crash data:
<agent-html>
<div class="bg-slate-900 border border-red-500/30 rounded-lg p-5 shadow-lg shadow-red-500/10 font-sans mb-4">
  <div class="flex items-center gap-3 mb-4 pb-3 border-b border-slate-700">
    <div class="p-2 bg-red-500/20 rounded-md">
      <i data-lucide="alert-triangle" class="w-6 h-6 text-red-400"></i>
    </div>
    <div>
      <h2 class="text-lg font-bold text-slate-100 m-0">Forensic Crash Analysis</h2>
      <div class="text-xs text-slate-400 font-mono mt-1">Target Process: <span class="text-slate-200">{{process_name}}</span> (PID: {{pid}})</div>
    </div>
  </div>
  
  <div class="grid grid-cols-2 gap-4 mb-4">
    <div class="bg-slate-800 p-3 rounded-md border border-slate-700">
      <div class="text-xs text-slate-400 uppercase tracking-wider mb-1">Faulting Module</div>
      <div class="text-sm text-red-300 font-mono font-bold">{{faulting_module}}</div>
    </div>
    <div class="bg-slate-800 p-3 rounded-md border border-slate-700">
      <div class="text-xs text-slate-400 uppercase tracking-wider mb-1">Memory Address</div>
      <div class="text-sm text-amber-300 font-mono font-bold">{{memory_address}}</div>
    </div>
  </div>
  
  <div class="bg-slate-800 rounded-md p-4 border border-slate-700 mb-4">
    <h3 class="text-sm font-bold text-slate-300 flex items-center gap-2 mb-3"><i data-lucide="search" class="w-4 h-4 text-blue-400"></i> Key Findings</h3>
    <ul class="text-sm text-slate-400 space-y-2 list-disc pl-4 marker:text-slate-600">
      <li>{{finding_1}}</li>
      <li>{{finding_2}}</li>
      <li>{{finding_3}}</li>
    </ul>
  </div>
  
  <div class="bg-blue-900/20 rounded-md p-3 border border-blue-500/30 flex items-start gap-3">
    <i data-lucide="info" class="w-5 h-5 text-blue-400 mt-0.5 flex-shrink-0"></i>
    <div class="text-sm text-blue-200">
      <strong>Next Steps:</strong> {{next_steps_recommendation}}
    </div>
  </div>
</div>
</agent-html>

Format Jira output as a <jira-widget> HTML block.
Format Device output as a <gdb-widget> or <swarm-widget> HTML block. For crash snapshots, use the `<forensics-snapshot-widget>`. For source-code correlation, use the `<source-blame-widget>`.
"""
            
            messages = [{"role": "system", "content": system_prompt}]
            
            if req.history:
                for h in req.history:
                    role = 'assistant' if h.get('sender') == 'agent' else 'user'
                    messages.append({"role": role, "content": h.get('text', '')})
            
            messages.append({"role": "user", "content": req.message})
            
            async with httpx.AsyncClient(timeout=120.0) as client:
                for _ in range(15):
                    payload = {
                        "model": "Chat-EXACODE-A",
                        "messages": messages,
                        "tools": tools,
                        "temperature": 0.1
                    }
                    resp = await client.post(llm_url, headers=headers, json=payload)
                    if resp.status_code != 200:
                        return {"intent": "chat", "message": f"?? LLM Error: {resp.text}"}
                    
                    result = resp.json()
                    choice = result['choices'][0]
                    message = choice['message']
                    messages.append(message)
                    
                    if not message.get("tool_calls"):
                        return {"intent": "chat", "message": message.get("content", "")}
                        
                    for tool_call in message["tool_calls"]:
                        func_name = tool_call["function"]["name"]
                        func_args = json.loads(tool_call["function"]["arguments"])
                        
                        target_session = tool_session_map.get(func_name)
                        if not target_session:
                            messages.append({
                                "role": "tool",
                                "tool_call_id": tool_call["id"],
                                "name": func_name,
                                "content": f"Error: Tool {func_name} not found."
                            })
                            continue
                            
                        try:
                            tool_result = await target_session.call_tool(func_name, arguments=func_args)
                            res_text = ""
                            if isinstance(tool_result.content, list):
                                parts = []
                                for c in tool_result.content:
                                    if hasattr(c, "text"):
                                        parts.append(str(c.text))
                                    elif isinstance(c, dict) and "text" in c:
                                        parts.append(str(c["text"]))
                                    else:
                                        parts.append(str(c))
                                res_text = "\n".join(parts)
                            else:
                                res_text = str(tool_result.content)

                            if func_name == "generate_interactive_flamegraph" and res_text.strip().startswith("<?xml"):
                                import uuid
                                import os
                                svg_filename = f"flamegraph_{uuid.uuid4().hex[:8]}.svg"
                                static_dir = os.path.join(os.path.dirname(__file__), "static")
                                if not os.path.exists(static_dir):
                                    os.makedirs(static_dir)
                                svg_path = os.path.join(static_dir, svg_filename)
                                with open(svg_path, "w", encoding="utf-8") as f:
                                    f.write(res_text)
                                res_text = f"Flame graph SVG generated. Present it using this HTML widget:\n\n<agent-html>\n<div class='bg-slate-900 border-t-4 border-t-amber-500 rounded-lg p-5 shadow-lg shadow-amber-500/10 font-sans mb-4'>\n  <h2 class='text-lg font-bold text-slate-200 mb-4 flex items-center gap-2'><i data-lucide='flame' class='text-amber-500'></i> Interactive Flame Graph</h2>\n  <iframe src='/static/{svg_filename}' width='100%' height='600px' style='border:1px solid #1e293b; border-radius: 8px; background: #0f172a;'></iframe>\n</div>\n</agent-html>"
                            if not res_text:
                                res_text = "(Command returned empty output)"
                        except Exception as e:
                            res_text = f"Tool execution failed: {str(e)}"
                            
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tool_call["id"],
                            "name": func_name,
                            "content": res_text
                        })
                    
                    with open('/tmp/llm_debug.txt', 'a') as f:
                        f.write(json.dumps(messages) + "\n\n=======================\n")
                        
                return {"intent": "chat", "message": "The agent reached the maximum number of iterations without completing the task."}
                
        except Exception as e:
            return {"intent": "chat", "message": f"?? Supervisor Error: {str(e)}"}


@app.post("/api/chat")
async def llm_chat(req: ChatRequest, request: Request):
    if not req.llm_url or not req.llm_key:
        raise HTTPException(status_code=400, detail="LLM URL and API Key are required.")
        
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
    
    pat = get_jira_pat(request)
    if not pat and req.agent_id != 'device-agent':
        raise HTTPException(status_code=403, detail="Missing Jira PAT.")
    if req.agent_id == 'supervisor-agent':
        return await supervisor_llm_chat(req, llm_url, headers, pat)
    elif req.agent_id == 'device-agent' or '[Target Board IP:' in req.message:
        return await device_llm_chat(req, llm_url, headers)
    
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
            
            target_project = req.project_key.strip().upper() if req.project_key else "SIGPOSDEV"
            
            # Get tools
            tools_resp = await session.list_tools()
            tools = []
            tool_schemas = {}
            for t in tools_resp.tools:
                tool_schemas[t.name] = t.input_schema.get("properties", {}) if t.input_schema else {}
                desc = t.description or ""
                if target_project != "SIGPOSDEV":
                    desc = re.sub(r'\bSIGPOSDEV\b', target_project, desc)
                tools.append({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": desc,
                        "parameters": t.input_schema
                    }
                })
                
            sys_prompt = f"""You are the GPOS Jira & Governance Agent for Jira Project '{target_project}'.
    You have access to a suite of MCP tools (Jira, Code Search, etc.).
    
    CRITICAL JIRA PROJECT DIRECTIVE:
    You are strictly working with Jira project: '{target_project}'.
    ALL queries, JQL searches, sprint reports, and ticket operations MUST target project '{target_project}'.
    Whenever you call `jira_search`, your JQL MUST explicitly include: `project = {target_project}`.
    DO NOT use project 'SIGPOSDEV' under any circumstances unless '{target_project}' is explicitly 'SIGPOSDEV'.
    When tools accept a project_key argument (e.g. jira_generate_sprint_report, jira_get_sprint_burndown, jira_create_issue), ALWAYS pass project_key="{target_project}".
    TIP: If the user asks for "my" tickets (e.g., "my stories", "my bugs"), you MUST use `project = {target_project} AND assignee = currentUser()` in your JQL search.
    
    CRITICAL LOG ANALYSIS RULE:
    When a user asks you to analyze an attached crash log (like a .7z or .zip file attached to a bug ticket), you MUST perform the following sequence:
    1. Call `jira_list_attachments` with the issue key to find the internal attachment ID and exact filename.
    2. Call `jira_download_attachment` to download the file securely.
    3. Call `extract_archive` to unzip it.
    4. Do NOT try to read the whole file! Log files are too big. Call `search_log_contents` to find keywords like 'crash', 'SIGSEGV', 'Exception', or 'Call Trace:'.
    5. Call `read_log_snippet` using the line numbers you found to read the 50-100 lines surrounding the crash.
    6. When summarizing the crash reason for the user, you MUST use a stunning Forensic Crash Analysis UI widget.
    Use this exact HTML structure wrapped exactly in <agent-html> tags, filling in the real crash data:
    <agent-html>
    <div class="bg-slate-900 border border-red-500/30 rounded-lg p-5 shadow-lg shadow-red-500/10 font-sans mb-4">
      <div class="flex items-center gap-3 mb-4 pb-3 border-b border-slate-700">
    <div class="p-2 bg-red-500/20 rounded-md">
      <i data-lucide="alert-triangle" class="w-6 h-6 text-red-400"></i>
    </div>
    <div>
      <h2 class="text-lg font-bold text-slate-100 m-0">Forensic Crash Analysis</h2>
      <div class="text-xs text-slate-400 font-mono mt-1">Target Process: <span class="text-slate-200">{{process_name}}</span> (PID: {{pid}})</div>
    </div>
      </div>
      
      <div class="grid grid-cols-2 gap-4 mb-4">
    <div class="bg-slate-800 p-3 rounded-md border border-slate-700">
      <div class="text-xs text-slate-400 uppercase tracking-wider mb-1">Faulting Module</div>
      <div class="text-sm text-red-300 font-mono font-bold">{{faulting_module}}</div>
    </div>
    <div class="bg-slate-800 p-3 rounded-md border border-slate-700">
      <div class="text-xs text-slate-400 uppercase tracking-wider mb-1">Memory Address</div>
      <div class="text-sm text-amber-300 font-mono font-bold">{{memory_address}}</div>
    </div>
      </div>
      
      <div class="bg-slate-800 rounded-md p-4 border border-slate-700 mb-4">
    <h3 class="text-sm font-bold text-slate-300 flex items-center gap-2 mb-3"><i data-lucide="search" class="w-4 h-4 text-blue-400"></i> Key Findings</h3>
    <ul class="text-sm text-slate-400 space-y-2 list-disc pl-4 marker:text-slate-600">
      <li>{{finding_1}}</li>
      <li>{{finding_2}}</li>
      <li>{{finding_3}}</li>
    </ul>
      </div>
      
      <div class="bg-blue-900/20 rounded-md p-3 border border-blue-500/30 flex items-start gap-3">
    <i data-lucide="info" class="w-5 h-5 text-blue-400 mt-0.5 flex-shrink-0"></i>
    <div class="text-sm text-blue-200">
      <strong>Next Steps:</strong> {{next_steps_recommendation}}
    </div>
      </div>
    </div>
    </agent-html>
    
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
      <td class="px-3 py-2 font-mono text-blue-400">{target_project}-1</td>
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
      <h3 class="text-amber-400 font-bold mb-2">&#9888; Governance Audit Findings</h3>
      <table class="w-full text-sm text-left text-slate-300">
    <thead class="text-xs text-slate-400 bg-slate-900 uppercase">
      <tr><th>Key</th><th>Summary</th><th>Missing Element</th></tr>
    </thead>
    <tbody>
      <tr class="bg-slate-800 border-b border-slate-700">
        <td class="px-3 py-2 font-mono text-blue-400">{target_project}-1</td>
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
            if hasattr(req, 'images') and req.images:
                content_list = [{"type": "text", "text": req.message}]
                for img_data in req.images:
                    content_list.append({
                        "type": "image_url",
                        "image_url": {"url": img_data}
                    })
                messages.append({"role": "user", "content": content_list})
            else:
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
                        schema = tool_schemas.get(func_name, {})
                        
                        # Execute on MCP server
                        try:
                            # 1. Inject PAT if expected
                            if "pat" in schema or "token" in schema:
                                func_args["pat"] = pat
                            
                            # 2. Inject or override project_key / project arguments
                            if "project_key" in schema or "project_key" in func_args:
                                val = func_args.get("project_key")
                                if not val or val.upper() == "SIGPOSDEV" or target_project != "SIGPOSDEV":
                                    func_args["project_key"] = target_project
                                    
                            if "project" in schema or "project" in func_args:
                                val = func_args.get("project")
                                if not val or val.upper() == "SIGPOSDEV" or target_project != "SIGPOSDEV":
                                    func_args["project"] = target_project
    
                            # 3. Handle JQL queries: replace SIGPOSDEV with target_project or inject project filter
                            if "jql" in func_args and isinstance(func_args["jql"], str):
                                jql_str = func_args["jql"]
                                if target_project != "SIGPOSDEV":
                                    jql_str = re.sub(r'\bSIGPOSDEV\b', target_project, jql_str, flags=re.IGNORECASE)
                                if not re.search(r'\bproject\s*=', jql_str, re.IGNORECASE):
                                    jql_str = f"project = {target_project} AND ({jql_str})"
                                func_args["jql"] = jql_str
                                logger.info(f"Dynamically scoped JQL query to project {target_project}: {jql_str}")
                            
                            tool_result = await session.call_tool(func_name, arguments=func_args)
                            
                            # Extract text from result
                            res_text = ""
                            if isinstance(tool_result.content, list):
                                parts = []
                                for c in tool_result.content:
                                    if hasattr(c, "text"):
                                        parts.append(str(c.text))
                                    elif isinstance(c, dict) and "text" in c:
                                        parts.append(str(c["text"]))
                                    else:
                                        parts.append(str(c))
                                res_text = "\n".join(parts)
                            else:
                                res_text = str(tool_result.content)
    
                            if func_name == "generate_interactive_flamegraph" and res_text.strip().startswith("<?xml"):
                                import uuid
                                import os
                                svg_filename = f"flamegraph_{uuid.uuid4().hex[:8]}.svg"
                                static_dir = os.path.join(os.path.dirname(__file__), "static")
                                if not os.path.exists(static_dir):
                                    os.makedirs(static_dir)
                                svg_path = os.path.join(static_dir, svg_filename)
                                with open(svg_path, "w", encoding="utf-8") as f:
                                    f.write(res_text)
                                res_text = f"Flame graph SVG generated. Present it using this HTML widget:\n\n<agent-html>\n<div class='bg-slate-900 border-t-4 border-t-amber-500 rounded-lg p-5 shadow-lg shadow-amber-500/10 font-sans mb-4'>\n  <h2 class='text-lg font-bold text-slate-200 mb-4 flex items-center gap-2'><i data-lucide='flame' class='text-amber-500'></i> Interactive Flame Graph</h2>\n  <iframe src='/static/{svg_filename}' width='100%' height='600px' style='border:1px solid #1e293b; border-radius: 8px; background: #0f172a;'></iframe>\n</div>\n</agent-html>"
                            
                            # If instructions were fetched, dynamically adapt any references to SIGPOSDEV
                            if func_name == "get_agent_instructions" and target_project != "SIGPOSDEV":
                                res_text = re.sub(r'\bSIGPOSDEV\b', target_project, res_text)
                            
                            if "failed (HTTP" in res_text or "Error in" in res_text:
                                res_text = f"TOOL EXECUTION FAILED: {res_text}\nCRITICAL INSTRUCTION: You MUST inform the user that the action failed and explain the error. DO NOT say it succeeded."
                            
                            messages.append({
                                "role": "tool",
                                "name": func_name,
                                "tool_call_id": tool_call["id"],
                                "content": res_text
                            })
                        except Exception as e:
                            logger.error(f"Tool call failed: {e}")
                            messages.append({
                                "role": "tool",
                                "name": func_name,
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
        raise HTTPException(status_code=403, detail="Missing Jira PAT.")
    
    try:
        data = fetch_jira("api/2/myself", {}, pat)
        display_name = data.get("displayName", "Jira User")
        return {"name": display_name, "division": "LGSI GPOS & Apps"}
    except Exception as e:
        logger.error(f"Failed to fetch user profile: {e}")
        return {"name": "GPOS User", "division": "LGSI GPOS & Apps"}

@app.get("/api/agents")
def get_agents():
    return [
        {
            "id": "supervisor-agent",
            "name": "GPOS AI Supervisor",
            "description": "Unified orchestrator that seamlessly combines Jira Governance with Device Operations.",
            "status": "Active",
            "theme": "indigo",
            "icon": "network",
            "tags": ["AI", "ORCHESTRATION"],
            "categories": ["AI"]
        },
        {
            "id": "device-agent",
            "name": "GPOS Device Agent (HUD)",
            "description": "Dynamic Developer HUD for remote board management, GDB backtraces, and Linux profiling.",
            "status": "Active",
            "theme": "emerald",
            "icon": "cpu",
            "tags": ["HW", "SYS", "OPS"],
            "categories": ["HW", "DevOps"]
        },
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
        }
    ]

@app.get("/api/mentions")
def get_mentions(request: Request):
    pat = get_jira_pat(request)
    if not pat:
        raise HTTPException(
            status_code=403, detail="Missing Jira PAT. Please click Settings in the top-right corner to enter your Personal Access Token."
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
            status_code=403, detail="Missing Jira PAT. Please click Settings in the top-right corner to enter your Personal Access Token."
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


class TelemetryRequest(BaseModel):
    agent_id: str
    session_id: str
    duration_seconds: int = 60


@app.post('/api/telemetry')
async def record_telemetry(req: TelemetryRequest, request: Request):
    """Record agent usage telemetry for analytics."""
    username = get_current_user(request)
    conn = get_db()
    try:
        # Upsert: if same session exists, add duration, else insert new row
        existing = conn.execute(
            'SELECT id, duration_seconds FROM agent_metrics WHERE session_id = ? AND username = ? AND agent_id = ?',
            (req.session_id, username, req.agent_id)
        ).fetchone()
        if existing:
            conn.execute(
                'UPDATE agent_metrics SET duration_seconds = ?, recorded_at = CURRENT_TIMESTAMP WHERE id = ?',
                (existing['duration_seconds'] + req.duration_seconds, existing['id'])
            )
        else:
            conn.execute(
                'INSERT INTO agent_metrics (username, agent_id, session_id, duration_seconds) VALUES (?, ?, ?, ?)',
                (username, req.agent_id, req.session_id, req.duration_seconds)
            )
        conn.commit()
    finally:
        conn.close()
    return {'status': 'ok'}


@app.get('/api/admin/user/{target_user}/stats')
async def get_admin_user_stats(target_user: str, request: Request):
    username = get_current_user(request)
    conn = get_db()
    try:
        user_row = conn.execute('SELECT is_admin FROM users WHERE username = ?', (username,)).fetchone()
        if not user_row or not user_row['is_admin']:
            if username not in ADMIN_USERS:
                raise HTTPException(status_code=403, detail='Admin access required')

        agent_usage = conn.execute('''
            SELECT agent_id, SUM(duration_seconds) as total_seconds
            FROM agent_metrics
            WHERE username = ?
            GROUP BY agent_id
        ''', (target_user,)).fetchall()

        daily = conn.execute('''
            SELECT date(recorded_at) as day, SUM(duration_seconds) as total_seconds
            FROM agent_metrics
            WHERE username = ? AND recorded_at >= datetime('now', '-14 days')
            GROUP BY day
            ORDER BY day
        ''', (target_user,)).fetchall()

        return {
            'username': target_user,
            'agent_usage': [dict(a) for a in agent_usage],
            'daily_activity': [dict(d) for d in daily]
        }
    finally:
        conn.close()

@app.get('/api/admin/stats')
async def get_admin_stats(request: Request):
    """Get admin statistics - only accessible to admin users."""
    username = get_current_user(request)
    # Check admin role from DB
    conn = get_db()
    try:
        user_row = conn.execute('SELECT is_admin FROM users WHERE username = ?', (username,)).fetchone()
        if not user_row or not user_row['is_admin']:
            if username not in ADMIN_USERS:
                raise HTTPException(status_code=403, detail='Admin access required')

        # All users with stats
        users = conn.execute('''
            SELECT u.username, u.is_admin, u.is_allowed, u.last_login,
                   COALESCE(SUM(m.duration_seconds), 0) as total_seconds,
                   COUNT(DISTINCT m.session_id) as total_sessions
            FROM users u
            LEFT JOIN agent_metrics m ON u.username = m.username
            GROUP BY u.username
            ORDER BY total_seconds DESC
        ''').fetchall()

        # Agent usage breakdown
        agent_usage = conn.execute('''
            SELECT agent_id,
                   COUNT(DISTINCT username) as unique_users,
                   COUNT(DISTINCT session_id) as total_sessions,
                   COALESCE(SUM(duration_seconds), 0) as total_seconds
            FROM agent_metrics
            GROUP BY agent_id
            ORDER BY total_seconds DESC
        ''').fetchall()

        # Hourly activity (last 7 days)
        hourly = conn.execute('''
            SELECT strftime('%H', recorded_at) as hour,
                   COUNT(*) as count
            FROM agent_metrics
            WHERE recorded_at >= datetime('now', '-7 days')
            GROUP BY hour
            ORDER BY hour
        ''').fetchall()

        # Daily activity (last 14 days)
        daily = conn.execute('''
            SELECT strftime('%Y-%m-%d', recorded_at) as day,
                   COALESCE(SUM(duration_seconds), 0) as total_seconds
            FROM agent_metrics
            WHERE recorded_at >= datetime('now', '-14 days')
            GROUP BY day
            ORDER BY day
        ''').fetchall()

        # Currently "active" users (had activity in last 10 minutes)
        active_users = conn.execute('''
            SELECT DISTINCT username FROM agent_metrics
            WHERE recorded_at >= datetime('now', '-2 minutes')
        ''').fetchall()

        return {
            'users': [dict(u) for u in users],
            'agent_usage': [dict(a) for a in agent_usage],
            'hourly_activity': [dict(h) for h in hourly],
            'daily_activity': [dict(d) for d in daily],
            'active_users': [u['username'] for u in active_users],
            'total_users': len(users),
            'total_sessions': sum(u['total_sessions'] for u in users)
        }
    finally:
        conn.close()


@app.post('/api/admin/toggle-user')
async def toggle_user_access(request: Request):
    """Admin endpoint to enable/disable user access."""
    username = get_current_user(request)
    conn = get_db()
    try:
        user_row = conn.execute('SELECT is_admin FROM users WHERE username = ?', (username,)).fetchone()
        if not user_row or not user_row['is_admin']:
            if username not in ADMIN_USERS:
                raise HTTPException(status_code=403, detail='Admin access required')

        body = await request.json()
        target_user = body.get('username', '').strip()
        allowed = body.get('allowed', True)

        if not target_user:
            raise HTTPException(status_code=400, detail='Username required')
        if target_user in ADMIN_USERS:
            raise HTTPException(status_code=400, detail='Cannot modify admin users')

        conn.execute(
            'UPDATE users SET is_allowed = ? WHERE username = ?',
            (1 if allowed else 0, target_user)
        )
        conn.commit()
    finally:
        conn.close()
    return {'status': 'ok', 'username': target_user, 'allowed': allowed}

@app.get("/api/sprint/burndown")
def get_sprint_burndown(request: Request, project_key: str = "SIGPOSDEV", sprint_name: str = ""):
    pat = get_jira_pat(request)
    if not pat:
        raise HTTPException(
            status_code=403, detail="Missing Jira PAT. Please set your Personal Access Token in Settings."
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
        start_date = None
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

        # Calculate exact historical burn mapped by day
        points_burned_per_day = [0.0] * num_days
        for issue in issues:
            fields = issue.get("fields", {})
            status_obj = fields.get("status", {})
            status_name = status_obj.get("name", "") if isinstance(status_obj, dict) else str(status_obj)
            
            if _classify_status(status_name, status_obj) == "done":
                sp_val = fields.get(STORY_POINTS_FIELD)
                try:
                    sp = float(sp_val) if sp_val is not None else 0.0
                except:
                    sp = 0.0
                
                res_date_str = fields.get("resolutiondate") or fields.get("updated")
                if res_date_str and start_date:
                    try:
                        clean_date = res_date_str.replace('Z', '+00:00')
                        if '.' in clean_date and clean_date.endswith('+00:00'):
                            clean_date = clean_date.split('.')[0] + '+00:00'
                        res_date = datetime.datetime.fromisoformat(clean_date).date()
                        
                        days_passed = 0
                        temp_date = start_date.date()
                        if res_date <= temp_date:
                            points_burned_per_day[0] += sp
                        else:
                            while temp_date < res_date:
                                if temp_date.weekday() < 5:
                                    days_passed += 1
                                temp_date += datetime.timedelta(days=1)
                            
                            if days_passed < num_days:
                                points_burned_per_day[days_passed] += sp
                            else:
                                points_burned_per_day[num_days - 1] += sp
                    except Exception as e:
                        logger.error(f"Error parsing date {res_date_str}: {e}")
                        points_burned_per_day[current_day_idx] += sp
                else:
                    points_burned_per_day[current_day_idx] += sp

        actual = []
        running_remaining = total_points
        for day in range(num_days):
            if day <= current_day_idx:
                running_remaining -= points_burned_per_day[day]
                actual.append(round(max(0.0, running_remaining), 1))
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


@app.get("/api/device/info")
def get_device_info(ip: str):
    try:
        import subprocess
        # Get all info in one shot. Use top -d 1 -n 2 to bypass the SSH startup CPU spike and get true resting CPU
        cmd = f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=2 root@{ip} 'uname -n; echo \"---\"; cat /etc/os-release; echo \"---\"; cat /proc/uptime; echo \"---\"; top -d 1 -n 2 -b | grep \"Cpu(s)\" | tail -n 1'"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=7)
        
        if res.returncode != 0:
            return {"target": "Unknown Device", "os": "Error", "uptime": "--", "cpu": 0}
            
        parts = res.stdout.split('---')
        
        board_name = parts[0].strip() if len(parts) > 0 and parts[0].strip() else "Unknown Device"
        
        os_name = "webOS"
        if len(parts) > 1:
            for line in parts[1].split('\n'):
                if line.startswith('PRETTY_NAME='):
                    os_name = line.split('=')[1].strip('"').strip("'")
                    break

        uptime_str = "--"
        if len(parts) > 2 and parts[2].strip():
            try:
                seconds = float(parts[2].strip().split()[0])
                hours = int(seconds // 3600)
                minutes = int((seconds % 3600) // 60)
                uptime_str = f"{hours}h {minutes}m"
            except:
                pass
                
        cpu_val = 0
        if len(parts) > 3 and parts[3].strip():
            try:
                import re
                match = re.search(r'(\d+\.\d+)\s*us,\s*(\d+\.\d+)\s*sy', parts[3])
                if match:
                    cpu_val = int(float(match.group(1)) + float(match.group(2)))
            except:
                pass
                
        return {"target": board_name, "os": os_name, "uptime": uptime_str, "cpu": cpu_val}
    except Exception as e:
        return {"target": "Unknown Device", "os": "Error", "uptime": "--", "cpu": 0}

@app.get("/api/search")
def search_issues(request: Request, jql: str = "project = SIGPOSDEV ORDER BY updated DESC", max_results: int = 50):
    pat = get_jira_pat(request)
    if not pat:
        raise HTTPException(status_code=403, detail="Missing Jira PAT. Please set your Personal Access Token.")
        
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
        raise HTTPException(status_code=403, detail="Missing Jira PAT.")
        
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
        raise HTTPException(status_code=403, detail="Missing Jira PAT. Please set token in Settings.")
        
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
        raise HTTPException(status_code=403, detail='Missing Jira PAT. Please set token in Settings.')
        
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
def quick_action(action: str, request: Request, project_key: str = "SIGPOSDEV"):
    pat = get_jira_pat(request)
    if not pat:
        raise HTTPException(status_code=403, detail='Missing Jira PAT.')
        
    if action == 'sprint_audit':
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




















@app.get("/api/watchdog/stream")
async def watchdog_stream(request: Request, ip: str):
    from fastapi.responses import StreamingResponse
    import asyncio
    import subprocess
    
    async def log_generator():
        # A simple simulated or actual watchdog. For a real webOS device, we ssh and tail -F /var/log/messages or journalctl.
        # But for stability in testing without hanging the whole server if SSH blocks, we'll use an async subprocess.
        cmd = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{ip} \"journalctl -f -n 0 | grep -i --line-buffered 'error\\|fatal\\|segfault\\|oom'\""
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )
        
        try:
            while True:
                if await request.is_disconnected():
                    process.kill()
                    break
                    
                line = await process.stdout.readline()
                if not line:
                    break
                    
                text = line.decode('utf-8', errors='replace').strip()
                if text:
                    yield f"data: {text}\n\n"
        except asyncio.CancelledError:
            process.kill()
            
    return StreamingResponse(log_generator(), media_type="text/event-stream")



























