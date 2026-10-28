# --- MCP SSE CLIENT PATCH FOR LARGE SNAPSHOTS ---
import httpx2._sse
class MySSEParser(httpx2._sse._SSEParser):
    def __init__(self, max_event_size=None):
        super().__init__(max_event_size=50000000) # 50 MB
httpx2._sse._SSEParser = MySSEParser
# ------------------------------------------------
import os
import re
import uuid
import base64
import json
import asyncio
import subprocess
import sqlite3
import logging
from datetime import date
from typing import Optional, Dict, Any, List, Tuple
from fastapi import FastAPI, HTTPException, Request, Depends, Response
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
DEVICE_MCP_SERVER_URL = os.environ.get('DEVICE_MCP_SERVER_URL', 'http://gpos-muralidhar-device-service:8000').rstrip('/')
JIRA_BASE_URL = os.environ.get('JIRA_BASE_URL', 'http://jira.lge.com').rstrip('/')
COLLAB_BASE_URL = os.environ.get('COLLAB_BASE_URL', 'http://collab.lge.com/main/spaces/WEBOSDOCS/pages/1473985612/API+Docs').rstrip('/')

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
    if request.url.path.startswith("/api/") and not request.url.path.startswith("/api/artifacts") and request.url.path not in [
        "/api/login", "/api/auth/verify", "/api/device/info", "/api/device/screen/frame",
        "/api/device/webrtc/offer", "/api/device/webrtc/close", "/api/device/screen/stream"
    ]:
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


_DIRECT_JIRA_DISABLED_UNTIL = float('inf')  # Always use MCP proxy (direct http://jira.lge.com:80 drops packets inside K8s)

def fetch_jira(endpoint: str, params: Dict[str, Any], pat: str, method: str = "GET", json_body: dict = None) -> Dict[str, Any]:
    """
    Execute request against Jira via MCP proxy (direct Jira is unreachable from within K8s pods).
    Falls back to direct HTTP only if MCP proxy itself is unavailable.
    """
    global _DIRECT_JIRA_DISABLED_UNTIL
    headers = _jira_headers(pat)
    clean_endpoint = endpoint.lstrip('/')

    # 1. Try MCP Server REST Proxy (primary path - always used inside K8s)
    try:
        mcp_url = f"{MCP_SERVER_URL}/rest/{clean_endpoint}"
        resp = requests.request(method, mcp_url, headers=headers, params=params, json=json_body, timeout=15)
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code in (401, 403):
            raise HTTPException(status_code=resp.status_code, detail=f"Jira Authentication Failed (HTTP {resp.status_code}). Please check your Jira PAT in Settings.")
        logger.info(f"MCP proxy returned {resp.status_code}, trying direct Jira fallback...")
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"MCP proxy call failed ({e}), trying direct Jira as fallback...")

    # 2. Fallback: Direct Jira (only if MCP proxy is down)
    if time.time() >= _DIRECT_JIRA_DISABLED_UNTIL:
        direct_url = f"{JIRA_BASE_URL}/rest/{clean_endpoint}"
        try:
            resp = requests.request(method, direct_url, headers=headers, params=params, json=json_body, timeout=4, verify=False)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code in (401, 403):
                raise HTTPException(status_code=resp.status_code, detail=f"Jira Authentication Failed (HTTP {resp.status_code}). Please check your Jira PAT in Settings.")
        except HTTPException:
            raise
        except Exception as e:
            logger.warning(f"Direct Jira call also failed ({e}). Both paths unavailable.")

    raise HTTPException(status_code=503, detail="Jira service unavailable. Please try again in a few moments.")


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
    collab_pat: str = ""

import httpx
import json
import subprocess

def unwrap_exception(e: BaseException) -> str:
    """Recursively extract the deepest root cause from ExceptionGroup / TaskGroup errors."""
    if hasattr(e, "exceptions") and getattr(e, "exceptions"):
        extracted = []
        for sub in getattr(e, "exceptions"):
            msg = unwrap_exception(sub)
            if msg and "unhandled errors in a TaskGroup" not in msg:
                extracted.append(msg)
        if extracted:
            return "; ".join(extracted)
        return unwrap_exception(getattr(e, "exceptions")[0])
    return str(e)

async def device_llm_chat(req: ChatRequest, llm_url: str, headers: dict):
    from mcp.client.sse import sse_client
    from mcp.client.session import ClientSession
    from contextlib import AsyncExitStack
    import os
    import httpx
    import json
    import re
    import uuid
    import base64
    import traceback


    sys_prompt = """You are the GPOS Device Agent Studio.
You help embedded Linux developers debug, profile, and deploy to their target webOS boards via SSH.

CRITICAL TOOL EXECUTION RULE:
You MUST actually call the appropriate tool (e.g., `execute_device_command`, `launch_app`, `close_app`) to perform the action. 
DO NOT just output HTML or text confirming the action without first executing the tool!

CRITICAL SHELL & FILESYSTEM EXECUTION RULE:
When the user asks to run shell commands on the target board (such as `grep`, `ls`, `cat`, `find`, `ps`, `df`, checking files or packages in `/usr/palm/applications/`, etc.):
- You MUST execute the command directly on the board using `execute_device_command`.
- For finding or searching files/directories (e.g. searching for settings in `/usr/palm/applications`):
  Use a resilient shell command:
  `find /usr/palm/applications -maxdepth 2 -iname "*settings*" 2>/dev/null || ls -la /usr/palm/applications | grep -i settings || grep -ri "settings" /usr/palm/applications/ 2>/dev/null | head -n 30`
- When the user asks to "Run CPU benchmark", ALWAYS call `run_perf_benchmark(target_ip=...)`. It automatically runs the embedded performance profiler and gathers metrics!
- When the user asks to take a screenshot, capture screen, or snapshot of the current window, ALWAYS call `take_screenshot(target_ip=...)`. It captures the screen directly from the webOS surface compositor! When presented with the <agent-html> widget in the tool response, YOU MUST include that exact <agent-html>...</agent-html> block in your response to display the screenshot in the chat UI.
- When the user asks to "Run leaktracer" or check memory leaks with LeakTracer, ALWAYS call `run_leaktracer(target_ip=..., executable=..., duration_seconds=...)`. It automatically resolves binary paths and preloads the LeakTracer library dynamically!
- When the user asks for logs with a specific time window, timestamp, or date (e.g., "between 11:15 and 11:20", "from 10:00 to 10:30"):
  ALWAYS call `stream_device_logs(target_ip=..., filter_keywords=[...], since=..., until=...)` or use `execute_device_command` with `journalctl --since "..." --until "..."`. NEVER refuse, claim you cannot filter by time, or ask the user for permission to run journalctl — execute the query immediately!
- When the user asks to "Download complete system logs" or "Capture all logs" or save logs to the vault:
  ALWAYS call `archive_system_logs(target_ip=...)`. It bundles all system logs into a compressed .tar.gz package on the target device and registers it into the Artifact Vault!

WEBOS LUNA SERVICE API ARCHITECTURE & DYNAMIC DOCUMENTATION LOOKUP:
webOS system operations are managed dynamically by Luna services on the device bus (e.g., settings, audio, wifi, alarms, bluetooth, notifications, camera, display, etc.).

DYNAMIC SERVICE-FIRST WORKFLOW (FOLLOW FOR ALL SYSTEM ACTIONS & SETTINGS):
1. Service Ambiguity & Disambiguation Protocol:
   - When the user asks for a generic feature ("camera", "audio", "display", "wifi", etc.) without specifying the exact service name:
     a) Check active registered services on the device via `introspect_device_apis` or `execute_device_command` with `ls-monitor -l | grep -i <feature>`.
     b) If MULTIPLE services exist on the device (e.g. `com.webos.service.camera` and `com.webos.service.camera2`):
        YOU MUST NOT GUESS OR PICK ONE! YOU MUST STOP AND ASK THE USER:
        "I found multiple registered services for '<feature>' on your device:
        - <service_1>
        - <service_2>
        Which service would you like me to use?"
     c) If only one matching service exists, proceed with that service.
2. Discover Exact APIs via Live On-Board Introspection:
   - To inspect methods of a service on the target device, ALWAYS call `introspect_device_apis(service_name="...")`.
   - It queries `ls-hubd` directly via `ls-monitor -i` and returns the real-time list of all callable methods and categories.
   - NEVER guess or invent method names.
3. Query Documentation & Respect Parameter Schema Nesting:
   - Call `query_collab_api_docs(query="<service_or_method>")` to inspect the JSON parameter schema.
   - MANDATORY NESTING RULE: Many webOS services strictly require nested wrapper objects:
     * `camera2/captureImage`: Requires nested parameters inside a `"params"` wrapper:
       `{"id": "camera1", "params": {"format": "JPEG", "height": 1080, "mode": "MODE_ONESHOT", "nimage": 1, "width": 1920}}`
     * `settingsservice/setSystemSettings`: Requires `"category"` and `"settings"` wrappers:
       `{"category": "picture", "settings": {"brightness": 50}}`
     * NEVER flatten parameters if the documentation or schema defines them nested under `"params"`, `"settings"`, or `"category"`!
4. Execute via `execute_device_command`:
   - Send the command via `luna-send -n 1 -f luna://<service>/<method> '<json_payload>'`.
   - If the call succeeds, present the result. If it fails, report the actual device response rather than endlessly guessing method names in a loop.
5. NO UNSOLICITED REFUSALS:
   - When the user asks for boundary or test values (e.g. 0% or 100%), execute the requested instruction directly without refusal lectures. If the device API returns an error or constraint, report the actual device response.

CRITICAL PRESENTATION RULES (THE WOW FACTOR):
Present your findings, benchmarks, diagnostics, and logs using rich visual UI widgets via `<agent-html>` tags whenever available.
- When an `<agent-html>` widget is provided by a tool (e.g. for screenshots, flamegraphs, system logs, or benchmarks), output that exact `<agent-html>` widget as your response.
- When presenting logs or shell execution results, present them using the provided `<agent-html>` Log Terminal widget or a well-formatted code block. NEVER return an empty response!

1. **CPU & Memory Benchmark Results**:
When you run a benchmark (e.g. `run_perf_benchmark`), ALWAYS emit the `<device-benchmark>` telemetry tag first so the Device HUD gauges update:
<device-benchmark>{"ipc": 1.29, "cacheMiss": 546, "pageFaults": 17, "totalCycles": 13200000}</device-benchmark>

CRITICAL BENCHMARK FORMATTING DIRECTIVE:
You MUST NEVER dump raw terminal `<pre>` blocks of `top` or `/proc/meminfo`!
NEVER output raw lines like `PID USER PR NI...` or `MemTotal: 7958568 kB`.
You MUST parse all data and output this exact, stunning **Executive System Performance Card** using `<agent-html>`:
<agent-html>
<div class="benchmark-report-card bg-slate-800/90 border border-slate-700/80 rounded-xl p-5 shadow-xl font-sans mb-4">
  <div class="flex items-center justify-between pb-3 border-b border-slate-700/80 mb-4">
    <div class="flex items-center gap-2.5">
      <div class="p-2 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20">
        <i data-lucide="activity" class="w-5 h-5"></i>
      </div>
      <div>
        <h2 class="text-base font-bold text-white m-0">System Performance Benchmark</h2>
        <div class="text-xs text-slate-400 font-mono mt-0.5">Target: <span class="text-slate-200">{{target_ip}}</span> &bull; Sample: <span class="text-slate-200">{{duration}}s</span></div>
      </div>
    </div>
    <div class="flex items-center gap-1.5 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
      <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
      {{health_status}} ({{health_score}}/100)
    </div>
  </div>

  <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
    <!-- CPU Utilization -->
    <div class="benchmark-subcard bg-slate-900/60 p-3.5 rounded-lg border border-slate-700/60">
      <div class="flex justify-between items-center mb-1.5">
        <span class="text-xs font-semibold text-slate-300 flex items-center gap-1.5"><i data-lucide="cpu" class="w-3.5 h-3.5 text-blue-400"></i> CPU Load</span>
        <span class="text-xs font-mono font-bold text-blue-400">{{active_cpu_pct}}% active</span>
      </div>
      <div class="benchmark-track w-full h-3 rounded-full bg-slate-800 overflow-hidden flex mb-2">
        <div style="width: {{user_pct}}%" class="bg-blue-500" title="User"></div>
        <div style="width: {{sys_pct}}%" class="bg-amber-500" title="System"></div>
        <div style="width: {{idle_pct}}%" class="bg-emerald-500/40" title="Idle"></div>
      </div>
      <div class="flex justify-between text-[11px] text-slate-400 font-mono">
        <span>User: <strong class="text-blue-300">{{user_pct}}%</strong></span>
        <span>Sys: <strong class="text-amber-300">{{sys_pct}}%</strong></span>
        <span>Idle: <strong class="text-emerald-300">{{idle_pct}}%</strong></span>
      </div>
    </div>

    <!-- RAM Allocation -->
    <div class="benchmark-subcard bg-slate-900/60 p-3.5 rounded-lg border border-slate-700/60">
      <div class="flex justify-between items-center mb-1.5">
        <span class="text-xs font-semibold text-slate-300 flex items-center gap-1.5"><i data-lucide="hard-drive" class="w-3.5 h-3.5 text-emerald-400"></i> Memory (RAM)</span>
        <span class="text-xs font-mono font-bold text-emerald-400">{{used_gb}} / {{total_gb}} GB ({{used_pct}}%)</span>
      </div>
      <div class="benchmark-track w-full h-3 rounded-full bg-slate-800 overflow-hidden flex mb-2">
        <div style="width: {{used_pct}}%" class="bg-emerald-500" title="Used"></div>
        <div style="width: {{cached_pct}}%" class="bg-cyan-500/60" title="Cached"></div>
        <div style="width: {{free_pct}}%" class="bg-slate-700" title="Free"></div>
      </div>
      <div class="flex justify-between text-[11px] text-slate-400 font-mono">
        <span>Used: <strong class="text-emerald-300">{{used_gb}} GB</strong></span>
        <span>Cached: <strong class="text-cyan-300">{{cached_gb}} GB</strong></span>
        <span>Avail: <strong class="text-slate-200">{{avail_gb}} GB</strong></span>
      </div>
    </div>
  </div>

  <!-- Hardware Counters Grid -->
  <div class="grid grid-cols-4 gap-2 mb-4 text-center">
    <div class="benchmark-stat bg-slate-900/40 p-2.5 rounded-lg border border-slate-700/50">
      <div class="text-[10px] uppercase tracking-wider text-slate-400">IPC Efficiency</div>
      <div class="text-sm font-bold font-mono text-emerald-400 mt-0.5">{{ipc}}</div>
    </div>
    <div class="benchmark-stat bg-slate-900/40 p-2.5 rounded-lg border border-slate-700/50">
      <div class="text-[10px] uppercase tracking-wider text-slate-400">Cache Misses</div>
      <div class="text-sm font-bold font-mono text-amber-400 mt-0.5">{{cache_misses}}/s</div>
    </div>
    <div class="benchmark-stat bg-slate-900/40 p-2.5 rounded-lg border border-slate-700/50">
      <div class="text-[10px] uppercase tracking-wider text-slate-400">Page Faults</div>
      <div class="text-sm font-bold font-mono text-blue-400 mt-0.5">{{page_faults}}</div>
    </div>
    <div class="benchmark-stat bg-slate-900/40 p-2.5 rounded-lg border border-slate-700/50">
      <div class="text-[10px] uppercase tracking-wider text-slate-400">CPU Cycles</div>
      <div class="text-sm font-bold font-mono text-purple-400 mt-0.5">{{total_cycles}}</div>
    </div>
  </div>

  <!-- Top Active Processes Table -->
  <div class="benchmark-table-wrapper bg-slate-900/60 rounded-lg border border-slate-700/60 overflow-hidden mb-4">
    <div class="px-3 py-2 bg-slate-900/80 border-b border-slate-700/60 flex items-center justify-between">
      <span class="text-xs font-semibold text-slate-300 flex items-center gap-1.5"><i data-lucide="layers" class="w-3.5 h-3.5 text-blue-400"></i> Top Active Processes</span>
      <span class="text-[10px] text-slate-400">Ranked by CPU consumption</span>
    </div>
    <table class="w-full text-xs text-left">
      <thead class="text-[10px] uppercase text-slate-400 bg-slate-900/40 border-b border-slate-700/40">
        <tr>
          <th class="py-1.5 px-3">Process</th>
          <th class="py-1.5 px-2">PID</th>
          <th class="py-1.5 px-2 text-right">CPU %</th>
          <th class="py-1.5 px-2 text-right">Memory (RSS)</th>
          <th class="py-1.5 px-3 text-right">Status</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-slate-800">
        <!-- Render 3 to 5 real processes (exclude top/profiler commands) -->
        <tr>
          <td class="py-2 px-3 font-semibold text-white flex items-center gap-1.5"><i data-lucide="terminal" class="w-3 h-3 text-slate-400"></i> {{process_name}}</td>
          <td class="py-2 px-2 font-mono text-slate-400">{{pid}}</td>
          <td class="py-2 px-2 text-right font-mono font-bold text-blue-400">{{cpu_pct}}%</td>
          <td class="py-2 px-2 text-right font-mono text-emerald-300">{{mem_mb}} MB</td>
          <td class="py-2 px-3 text-right"><span class="px-1.5 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-medium">Stable</span></td>
        </tr>
      </tbody>
    </table>
  </div>

  <!-- Engineering Insights & Health Verdict -->
  <div class="benchmark-insights p-3 bg-blue-950/20 border border-blue-500/20 rounded-lg text-xs text-slate-300 space-y-1">
    <div class="font-semibold text-blue-400 flex items-center gap-1.5 mb-1"><i data-lucide="check-circle" class="w-3.5 h-3.5"></i> Engineering Insights:</div>
    <div>&bull; <strong>Process Activity:</strong> {{top_proc_name}} is the primary consumer utilizing {{top_proc_cpu}}% CPU and {{top_proc_mem}} MB RAM.</div>
    <div>&bull; <strong>Memory Headroom:</strong> {{avail_gb}} GB available ({{avail_pct}}%). System has ample capacity with zero OOM pressure.</div>
    <div>&bull; <strong>Hardware Pipeline:</strong> IPC of {{ipc}} confirms solid CPU instruction throughput without execution stalls.</div>
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


            collab_pat = req.collab_pat or os.environ.get("COLLAB_PAT", "") or os.environ.get("DEFAULT_COLLAB_PAT", "")
            sse_headers = {"X-Collab-URL": COLLAB_BASE_URL}
            if collab_pat:
                sse_headers["X-Collab-PAT"] = collab_pat

            # Connect Device MCP with retry for container restart/warmup
            dev_session = None
            last_conn_err = None
            for attempt in range(3):
                try:
                    dev_streams = await stack.enter_async_context(sse_client(f"{DEVICE_MCP_SERVER_URL}/sse", headers=sse_headers))
                    dev_session = await stack.enter_async_context(ClientSession(dev_streams[0], dev_streams[1]))
                    await dev_session.initialize()
                    break
                except Exception as conn_err:
                    last_conn_err = conn_err
                    if attempt < 2:
                        import asyncio
                        logger.warning(f"Device MCP connection attempt {attempt+1} failed ({conn_err}). Retrying in 1.5s...")
                        await asyncio.sleep(1.5)
                    else:
                        logger.error(f"Failed to connect to Device MCP after 3 attempts: {conn_err}")
                        raise last_conn_err

            tools = []

            dev_tools_resp = await dev_session.list_tools()
            for t in dev_tools_resp.tools:
                tools.append({"type": "function", "function": {"name": t.name, "description": t.description or "", "parameters": t.input_schema}})

            messages = [{"role": "system", "content": sys_prompt}]
            for h in req.history[-10:]:
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

            last_screenshot_widget = None
            last_flamegraph_widget = None
            last_log_widget = None
            last_tool_output = None
            async with httpx.AsyncClient() as client:
                for _ in range(25):
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
                        content = (msg.get("content") or "").strip()
                        if not content:
                            if last_log_widget:
                                content = last_log_widget
                            elif last_screenshot_widget:
                                content = last_screenshot_widget
                            elif last_flamegraph_widget:
                                content = last_flamegraph_widget
                            elif last_tool_output:
                                content = last_tool_output
                            else:
                                content = "⚠️ Command finished, but no output was returned."
                        else:
                            if last_log_widget and "<agent-html>" not in content:
                                content = f"{content}\n\n{last_log_widget}".strip()
                            elif last_screenshot_widget and "<agent-html>" not in content:
                                content = f"{content}\n\n{last_screenshot_widget}".strip()
                            elif last_flamegraph_widget and "<agent-html>" not in content:
                                content = f"{content}\n\n{last_flamegraph_widget}".strip()
                        return {"intent": "chat", "message": content}

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
                            # Auto-inject Collab credentials and target URL for API doc lookups
                            if func_name == "query_collab_api_docs":
                                if collab_pat and not func_args.get("collab_pat"):
                                    func_args["collab_pat"] = collab_pat
                                if not func_args.get("collab_url"):
                                    func_args["collab_url"] = COLLAB_BASE_URL

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
                                svg_filename = f"flamegraph_{uuid.uuid4().hex[:8]}.svg"
                                static_dir = os.path.join(os.path.dirname(__file__), "static")
                                if not os.path.exists(static_dir):
                                    os.makedirs(static_dir)
                                svg_path = os.path.join(static_dir, svg_filename)
                                with open(svg_path, "w", encoding="utf-8") as f:
                                    f.write(res_text)
                                flame_widget = f"<agent-html>\n<div class='bg-slate-900 border-t-4 border-t-amber-500 rounded-lg p-5 shadow-lg shadow-amber-500/10 font-sans mb-4'>\n  <h2 class='text-lg font-bold text-slate-200 mb-4 flex items-center gap-2'><i data-lucide='flame' class='text-amber-500'></i> Interactive Flame Graph</h2>\n  <iframe src='/static/{svg_filename}' width='100%' height='600px' style='border:1px solid #1e293b; border-radius: 8px; background: #0f172a;'></iframe>\n</div>\n</agent-html>"
                                last_flamegraph_widget = flame_widget
                                res_text = f"Flame graph SVG generated. Present it using this HTML widget:\n\n{flame_widget}"
                                
                            elif func_name == "take_screenshot" and "SNAPSHOT_BASE64:" in res_text:
                                b64_data = res_text.split("SNAPSHOT_BASE64:")[1].strip()
                                b64_clean = re.sub(r'[^A-Za-z0-9+/=]', '', b64_data)
                                img_filename = f"snap_{uuid.uuid4().hex[:8]}.jpg"
                                static_dir = os.path.join(os.path.dirname(__file__), "static")
                                if not os.path.exists(static_dir):
                                    os.makedirs(static_dir, exist_ok=True)
                                img_path = os.path.join(static_dir, img_filename)
                                try:
                                    raw_bytes = base64.b64decode(b64_clean)
                                    if len(raw_bytes) > 64:
                                        with open(img_path, "wb") as f:
                                            f.write(raw_bytes)
                                        try:
                                            os.chmod(img_path, 0o644)
                                        except Exception:
                                            pass
                                        # Also persist in /app/data/artifacts if PVC is mounted
                                        if os.path.exists("/app/data"):
                                            try:
                                                pvc_dir = "/app/data/artifacts"
                                                os.makedirs(pvc_dir, exist_ok=True)
                                                with open(os.path.join(pvc_dir, img_filename), "wb") as pf:
                                                    pf.write(raw_bytes)
                                            except Exception:
                                                pass
                                        widget_html = (
                                            f"<agent-html>\n"
                                            f"<div class='bg-slate-900 border-t-4 border-t-blue-500 rounded-lg p-5 shadow-lg shadow-blue-500/10 font-sans mb-4'>\n"
                                            f"  <div class='flex items-center justify-between mb-3'>\n"
                                            f"    <h2 class='text-lg font-bold text-slate-200 flex items-center gap-2 m-0'><i data-lucide='camera' class='text-blue-500'></i> Live Device Snapshot</h2>\n"
                                            f"    <div class='flex items-center gap-2'>\n"
                                            f"      <a href='/static/{img_filename}' target='_blank' class='text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 font-mono'><i data-lucide='external-link' class='w-3 h-3'></i> View Full Size</a>\n"
                                            f"      <button onclick=\"switchView('device-hud'); if(window.deviceHud) window.deviceHud.loadArtifactVault();\" class='px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 rounded text-xs font-medium flex items-center gap-1 transition-colors'><i data-lucide='vault' class='w-3 h-3 text-emerald-400'></i> View in Vault</button>\n"
                                            f"    </div>\n"
                                            f"  </div>\n"
                                            f"  <div class='rounded overflow-hidden border border-slate-700 bg-black flex justify-center p-1'>\n"
                                            f"    <img src='/static/{img_filename}' alt='Device Screenshot' class='max-w-full h-auto object-contain rounded' style='max-height: 480px;' />\n"
                                            f"  </div>\n"
                                            f"</div>\n"
                                            f"</agent-html>"
                                        )
                                        last_screenshot_widget = widget_html
                                        res_text = (
                                            f"Screenshot successfully captured and downloaded from the target device. Present it to the user using this HTML widget:\n\n"
                                            f"{widget_html}"
                                        )
                                    else:
                                        res_text = f"Screenshot capture returned empty image data ({len(raw_bytes)} bytes)."
                                except Exception as e:
                                    res_text = f"Screenshot captured but failed to decode base64 on portal side: {e}"

                            elif func_name == "archive_system_logs" and "LOG_ARCHIVE_BASE64:" in res_text:
                                parts = res_text.split("LOG_ARCHIVE_BASE64:")[1].strip().split(":", 3)
                                if len(parts) == 4:
                                    arc_name, size_human, size_bytes, b64_clean = parts
                                    b64_clean = re.sub(r'[^A-Za-z0-9+/=]', '', b64_clean)
                                    artifacts_dir = os.path.join(os.path.dirname(__file__), "static", "artifacts")
                                    if not os.path.exists(artifacts_dir):
                                        os.makedirs(artifacts_dir, exist_ok=True)
                                    arc_path = os.path.join(artifacts_dir, arc_name)
                                    try:
                                        raw_bytes = base64.b64decode(b64_clean)
                                        with open(arc_path, "wb") as f:
                                            f.write(raw_bytes)
                                        try:
                                            os.chmod(arc_path, 0o644)
                                        except Exception:
                                            pass
                                        # Also persist in /app/data/artifacts if PVC is mounted
                                        if os.path.exists("/app/data"):
                                            try:
                                                pvc_dir = "/app/data/artifacts"
                                                os.makedirs(pvc_dir, exist_ok=True)
                                                with open(os.path.join(pvc_dir, arc_name), "wb") as pf:
                                                    pf.write(raw_bytes)
                                            except Exception:
                                                pass
                                        widget_html = (
                                            f"<agent-html>\n"
                                            f"<div class='bg-slate-900 border-t-4 border-t-emerald-500 rounded-lg p-5 shadow-lg shadow-emerald-500/10 font-sans mb-4'>\n"
                                            f"  <div class='flex items-center justify-between mb-3'>\n"
                                            f"    <h2 class='text-lg font-bold text-slate-200 flex items-center gap-2 m-0'><i data-lucide='archive' class='text-emerald-400'></i> System Log Archive</h2>\n"
                                            f"    <span class='px-2 py-0.5 bg-emerald-500/20 text-emerald-400 rounded text-xs font-mono font-bold'>{size_human}</span>\n"
                                            f"  </div>\n"
                                            f"  <p class='text-xs text-slate-400 mb-4'>Complete system logs have been bundled into a compressed archive and saved to the <strong>Artifact Vault</strong>.</p>\n"
                                            f"  <div class='flex items-center gap-3'>\n"
                                            f"    <a href='/static/artifacts/{arc_name}' download='{arc_name}' class='px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-bold flex items-center gap-1.5 transition-colors no-underline'><i data-lucide='download' class='w-4 h-4'></i> Download Archive ({size_human})</a>\n"
                                            f"    <button onclick=\"switchView('device-hud'); if(window.deviceHud) window.deviceHud.loadArtifactVault();\" class='px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors'><i data-lucide='vault' class='w-4 h-4 text-emerald-400'></i> View in Artifact Vault</button>\n"
                                            f"  </div>\n"
                                            f"</div>\n"
                                            f"</agent-html>"
                                        )
                                        last_screenshot_widget = widget_html
                                        res_text = (
                                            f"System logs packaged into `{arc_name}` ({size_human}) and published to the Artifact Vault.\n\n"
                                            f"{widget_html}"
                                        )
                                    except Exception as e:
                                        res_text = f"Log archive generated on device, but failed to save to portal vault: {e}"

                            elif func_name == "stream_device_logs":
                                raw_logs = res_text
                                if "```" in res_text:
                                    parts = res_text.split("```")
                                    if len(parts) >= 3:
                                        raw_logs = parts[1].strip()
                                
                                import html as py_html
                                escaped_logs = py_html.escape(raw_logs)
                                target_dev = func_args.get("target_ip") or "Target Device"
                                kw_arg = func_args.get("filter_keywords") or []
                                if isinstance(kw_arg, list):
                                    filter_str = ", ".join(kw_arg)
                                else:
                                    filter_str = str(kw_arg)
                                filter_badge = f"<span class='px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 font-mono text-xs border border-blue-500/30'>{py_html.escape(filter_str)}</span>" if filter_str else ""
                                
                                has_crash = "Crash/Error Pattern" in res_text or "🔴" in res_text
                                status_badge = "<span class='px-2 py-0.5 rounded bg-red-500/20 text-red-400 font-semibold text-xs border border-red-500/30 flex items-center gap-1'><span class='w-2 h-2 rounded-full bg-red-500 animate-pulse'></span> Issue Detected</span>" if has_crash else "<span class='px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-semibold text-xs border border-emerald-500/30 flex items-center gap-1'><span class='w-2 h-2 rounded-full bg-emerald-400'></span> Stream Active</span>"
                                
                                widget_html = (
                                    f"<agent-html>\n"
                                    f"<div class='bg-slate-900 border border-slate-700/80 rounded-xl overflow-hidden shadow-2xl mb-4 font-sans'>\n"
                                    f"  <div class='px-4 py-3 bg-slate-800/90 border-b border-slate-700/80 flex items-center justify-between'>\n"
                                    f"    <div class='flex items-center gap-2.5'>\n"
                                    f"      <div class='p-1.5 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'>\n"
                                    f"        <i data-lucide='terminal' class='w-4 h-4'></i>\n"
                                    f"      </div>\n"
                                    f"      <div>\n"
                                    f"        <h3 class='text-sm font-bold text-slate-100 m-0'>Device Log Terminal</h3>\n"
                                    f"        <div class='text-[11px] text-slate-400 font-mono mt-0.5'>Target: <strong class='text-slate-200'>{target_dev}</strong></div>\n"
                                    f"      </div>\n"
                                    f"    </div>\n"
                                    f"    <div class='flex items-center gap-2'>\n"
                                    f"      {filter_badge}\n"
                                    f"      {status_badge}\n"
                                    f"    </div>\n"
                                    f"  </div>\n"
                                    f"  <div class='p-4 bg-black/95 font-mono text-xs text-slate-300 max-h-[400px] overflow-y-auto overflow-x-auto whitespace-pre leading-relaxed select-text border-b border-slate-800'>\n"
                                    f"<pre class='m-0 p-0 text-slate-300 font-mono text-xs leading-5'>{escaped_logs}</pre>\n"
                                    f"  </div>\n"
                                    f"  <div class='px-4 py-2.5 bg-slate-900/90 text-[11px] text-slate-400 flex items-center justify-between font-mono'>\n"
                                    f"    <span class='flex items-center gap-1'><i data-lucide='cpu' class='w-3.5 h-3.5 text-blue-400'></i> Source: /var/log/messages &bull; pmlogd</span>\n"
                                    f"    <div class='flex items-center gap-2'>\n"
                                    f"      <button onclick=\"navigator.clipboard.writeText(this.closest('.bg-slate-900').querySelector('pre').innerText); this.innerText='Copied!'; setTimeout(() => this.innerText='Copy Logs', 2000);\" class='px-2 py-0.5 bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 rounded text-xs transition-colors flex items-center gap-1'><i data-lucide='copy' class='w-3 h-3'></i> Copy Logs</button>\n"
                                    f"      <button onclick=\"switchView('device-hud'); if(window.deviceHud) window.deviceHud.loadArtifactVault();\" class='px-2 py-0.5 bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 rounded text-xs transition-colors flex items-center gap-1'><i data-lucide='vault' class='w-3 h-3 text-emerald-400'></i> Artifact Vault</button>\n"
                                    f"    </div>\n"
                                    f"  </div>\n"
                                    f"</div>\n"
                                    f"</agent-html>"
                                )
                                last_log_widget = widget_html
                                res_text = (
                                    f"Device logs captured from {target_dev}. Present them using this HTML widget:\n\n"
                                    f"{widget_html}"
                                )

                            if not res_text:
                                res_text = "(Command returned empty output)"
                            last_tool_output = res_text
                        except Exception as e:
                            res_text = f"[ERROR] Tool execution failed: {str(e)}"
                            last_tool_output = res_text

                        messages.append({
                            "role": "tool",
                            "name": func_name,
                            "tool_call_id": tool_call["id"],
                            "content": res_text
                        })

                final_msg = "The agent reached the maximum number of iterations."
                if last_log_widget and "<agent-html>" not in final_msg:
                    final_msg = last_log_widget
                elif last_screenshot_widget and "<agent-html>" not in final_msg:
                    final_msg = last_screenshot_widget
                elif last_flamegraph_widget and "<agent-html>" not in final_msg:
                    final_msg = last_flamegraph_widget
                elif last_tool_output:
                    final_msg = last_tool_output
                return {"intent": "chat", "message": final_msg}

    except Exception as e:
        err_msg = unwrap_exception(e)
        logger.error(f"Device LLM Chat Error: {err_msg}", exc_info=True)
        return {
            "intent": "chat", 
            "message": f"⚠️ Could not connect to the Device MCP Server ({DEVICE_MCP_SERVER_URL}).\n\nThe device container may still be starting up or restarting. Please verify your connection or try again in a few moments.\n\nDetails: {err_msg}"
        }

async def supervisor_llm_chat(req: ChatRequest, llm_url: str, headers: dict, pat: str):
    from mcp.client.sse import sse_client
    from mcp.client.session import ClientSession
    from contextlib import AsyncExitStack
    import os
    import httpx
    import json
    import re
    import uuid
    import base64
    
    async with AsyncExitStack() as stack:
        try:
            # Connect to Jira MCP with retry
            jira_session = None
            last_jira_err = None
            for attempt in range(3):
                try:
                    jira_streams = await stack.enter_async_context(sse_client(f"{MCP_SERVER_URL}/sse", headers={"X-Jira-PAT": pat}))
                    jira_session = await stack.enter_async_context(ClientSession(jira_streams[0], jira_streams[1]))
                    await jira_session.initialize()
                    break
                except (Exception, BaseException) as conn_err:
                    last_jira_err = conn_err
                    if attempt < 2:
                        import asyncio
                        logger.warning(f"Jira MCP connection attempt {attempt+1} failed in supervisor ({unwrap_exception(conn_err)}). Retrying in 1.5s...")
                        await asyncio.sleep(1.5)
                    else:
                        raise last_jira_err
            
            # Connect to Device MCP with retry
            collab_pat = req.collab_pat or os.environ.get("COLLAB_PAT", "") or os.environ.get("DEFAULT_COLLAB_PAT", "")
            sse_headers = {"X-Collab-URL": COLLAB_BASE_URL}
            if collab_pat:
                sse_headers["X-Collab-PAT"] = collab_pat

            device_session = None
            last_dev_err = None
            for attempt in range(3):
                try:
                    device_streams = await stack.enter_async_context(sse_client(f"{DEVICE_MCP_SERVER_URL}/sse", headers=sse_headers))
                    device_session = await stack.enter_async_context(ClientSession(device_streams[0], device_streams[1]))
                    await device_session.initialize()
                    break
                except (Exception, BaseException) as conn_err:
                    last_dev_err = conn_err
                    if attempt < 2:
                        import asyncio
                        logger.warning(f"Device MCP connection attempt {attempt+1} failed in supervisor ({unwrap_exception(conn_err)}). Retrying in 1.5s...")
                        await asyncio.sleep(1.5)
                    else:
                        raise last_dev_err
            
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
            
            last_screenshot_widget = None
            last_flamegraph_widget = None
            last_log_widget = None
            last_tool_output = None
            async with httpx.AsyncClient(timeout=120.0) as client:
                for _ in range(25):
                    payload = {
                        "model": req.llm_model or "Chat-EXACODE-A",
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
                        content = (message.get("content") or "").strip()
                        if not content:
                            if last_log_widget:
                                content = last_log_widget
                            elif last_screenshot_widget:
                                content = last_screenshot_widget
                            elif last_flamegraph_widget:
                                content = last_flamegraph_widget
                            elif last_tool_output:
                                content = last_tool_output
                            else:
                                content = "⚠️ Command finished, but no output was returned."
                        else:
                            if last_log_widget and "<agent-html>" not in content:
                                content = f"{content}\n\n{last_log_widget}".strip()
                            elif last_screenshot_widget and "<agent-html>" not in content:
                                content = f"{content}\n\n{last_screenshot_widget}".strip()
                            elif last_flamegraph_widget and "<agent-html>" not in content:
                                content = f"{content}\n\n{last_flamegraph_widget}".strip()
                        return {"intent": "chat", "message": content}
                        
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
                            if func_name == "query_collab_api_docs":
                                if collab_pat and not func_args.get("collab_pat"):
                                    func_args["collab_pat"] = collab_pat
                                if not func_args.get("collab_url"):
                                    func_args["collab_url"] = COLLAB_BASE_URL

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
                                svg_filename = f"flamegraph_{uuid.uuid4().hex[:8]}.svg"
                                static_dir = os.path.join(os.path.dirname(__file__), "static")
                                if not os.path.exists(static_dir):
                                    os.makedirs(static_dir)
                                svg_path = os.path.join(static_dir, svg_filename)
                                with open(svg_path, "w", encoding="utf-8") as f:
                                    f.write(res_text)
                                flame_widget = f"<agent-html>\n<div class='bg-slate-900 border-t-4 border-t-amber-500 rounded-lg p-5 shadow-lg shadow-amber-500/10 font-sans mb-4'>\n  <h2 class='text-lg font-bold text-slate-200 mb-4 flex items-center gap-2'><i data-lucide='flame' class='text-amber-500'></i> Interactive Flame Graph</h2>\n  <iframe src='/static/{svg_filename}' width='100%' height='600px' style='border:1px solid #1e293b; border-radius: 8px; background: #0f172a;'></iframe>\n</div>\n</agent-html>"
                                last_flamegraph_widget = flame_widget
                                res_text = f"Flame graph SVG generated. Present it using this HTML widget:\n\n{flame_widget}"
                            elif func_name == "take_screenshot" and "SNAPSHOT_BASE64:" in res_text:
                                b64_data = res_text.split("SNAPSHOT_BASE64:")[1].strip()
                                b64_clean = re.sub(r'[^A-Za-z0-9+/=]', '', b64_data)
                                img_filename = f"snap_{uuid.uuid4().hex[:8]}.jpg"
                                static_dir = os.path.join(os.path.dirname(__file__), "static")
                                if not os.path.exists(static_dir):
                                    os.makedirs(static_dir, exist_ok=True)
                                img_path = os.path.join(static_dir, img_filename)
                                try:
                                    raw_bytes = base64.b64decode(b64_clean)
                                    if len(raw_bytes) > 64:
                                        with open(img_path, "wb") as f:
                                            f.write(raw_bytes)
                                        try:
                                            os.chmod(img_path, 0o644)
                                        except Exception:
                                            pass
                                        # Also persist in /app/data/artifacts if PVC is mounted
                                        if os.path.exists("/app/data"):
                                            try:
                                                pvc_dir = "/app/data/artifacts"
                                                os.makedirs(pvc_dir, exist_ok=True)
                                                with open(os.path.join(pvc_dir, img_filename), "wb") as pf:
                                                    pf.write(raw_bytes)
                                            except Exception:
                                                pass
                                        widget_html = (
                                            f"<agent-html>\n"
                                            f"<div class='bg-slate-900 border-t-4 border-t-blue-500 rounded-lg p-5 shadow-lg shadow-blue-500/10 font-sans mb-4'>\n"
                                            f"  <div class='flex items-center justify-between mb-3'>\n"
                                            f"    <h2 class='text-lg font-bold text-slate-200 flex items-center gap-2 m-0'><i data-lucide='camera' class='text-blue-500'></i> Live Device Snapshot</h2>\n"
                                            f"    <div class='flex items-center gap-2'>\n"
                                            f"      <a href='/static/{img_filename}' target='_blank' class='text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 font-mono'><i data-lucide='external-link' class='w-3 h-3'></i> View Full Size</a>\n"
                                            f"      <button onclick=\"switchView('device-hud'); if(window.deviceHud) window.deviceHud.loadArtifactVault();\" class='px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 rounded text-xs font-medium flex items-center gap-1 transition-colors'><i data-lucide='vault' class='w-3 h-3 text-emerald-400'></i> View in Vault</button>\n"
                                            f"    </div>\n"
                                            f"  </div>\n"
                                            f"  <div class='rounded overflow-hidden border border-slate-700 bg-black flex justify-center p-1'>\n"
                                            f"    <img src='/static/{img_filename}' alt='Device Screenshot' class='max-w-full h-auto object-contain rounded' style='max-height: 480px;' />\n"
                                            f"  </div>\n"
                                            f"</div>\n"
                                            f"</agent-html>"
                                        )
                                        last_screenshot_widget = widget_html
                                        res_text = (
                                            f"Screenshot successfully captured and downloaded from the target device. Present it to the user using this HTML widget:\n\n"
                                            f"{widget_html}"
                                        )
                                    else:
                                        res_text = f"Screenshot capture returned empty image data ({len(raw_bytes)} bytes)."
                                except Exception as e:
                                    res_text = f"Screenshot captured but failed to decode base64 on portal side: {e}"

                            elif func_name == "archive_system_logs" and "LOG_ARCHIVE_BASE64:" in res_text:
                                parts = res_text.split("LOG_ARCHIVE_BASE64:")[1].strip().split(":", 3)
                                if len(parts) == 4:
                                    arc_name, size_human, size_bytes, b64_clean = parts
                                    b64_clean = re.sub(r'[^A-Za-z0-9+/=]', '', b64_clean)
                                    artifacts_dir = os.path.join(os.path.dirname(__file__), "static", "artifacts")
                                    if not os.path.exists(artifacts_dir):
                                        os.makedirs(artifacts_dir, exist_ok=True)
                                    arc_path = os.path.join(artifacts_dir, arc_name)
                                    try:
                                        raw_bytes = base64.b64decode(b64_clean)
                                        with open(arc_path, "wb") as f:
                                            f.write(raw_bytes)
                                        try:
                                            os.chmod(arc_path, 0o644)
                                        except Exception:
                                            pass
                                        # Also persist in /app/data/artifacts if PVC is mounted
                                        if os.path.exists("/app/data"):
                                            try:
                                                pvc_dir = "/app/data/artifacts"
                                                os.makedirs(pvc_dir, exist_ok=True)
                                                with open(os.path.join(pvc_dir, arc_name), "wb") as pf:
                                                    pf.write(raw_bytes)
                                            except Exception:
                                                pass
                                        widget_html = (
                                            f"<agent-html>\n"
                                            f"<div class='bg-slate-900 border-t-4 border-t-emerald-500 rounded-lg p-5 shadow-lg shadow-emerald-500/10 font-sans mb-4'>\n"
                                            f"  <div class='flex items-center justify-between mb-3'>\n"
                                            f"    <h2 class='text-lg font-bold text-slate-200 flex items-center gap-2 m-0'><i data-lucide='archive' class='text-emerald-400'></i> System Log Archive</h2>\n"
                                            f"    <span class='px-2 py-0.5 bg-emerald-500/20 text-emerald-400 rounded text-xs font-mono font-bold'>{size_human}</span>\n"
                                            f"  </div>\n"
                                            f"  <p class='text-xs text-slate-400 mb-4'>Complete system logs have been bundled into a compressed archive and saved to the <strong>Artifact Vault</strong>.</p>\n"
                                            f"  <div class='flex items-center gap-3'>\n"
                                            f"    <a href='/static/artifacts/{arc_name}' download='{arc_name}' class='px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-bold flex items-center gap-1.5 transition-colors no-underline'><i data-lucide='download' class='w-4 h-4'></i> Download Archive ({size_human})</a>\n"
                                            f"    <button onclick=\"switchView('device-hud'); if(window.deviceHud) window.deviceHud.loadArtifactVault();\" class='px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors'><i data-lucide='vault' class='w-4 h-4 text-emerald-400'></i> View in Artifact Vault</button>\n"
                                            f"  </div>\n"
                                            f"</div>\n"
                                            f"</agent-html>"
                                        )
                                        last_screenshot_widget = widget_html
                                        res_text = (
                                            f"System logs packaged into `{arc_name}` ({size_human}) and published to the Artifact Vault.\n\n"
                                            f"{widget_html}"
                                        )
                                    except Exception as e:
                                        res_text = f"Log archive generated on device, but failed to save to portal vault: {e}"

                            elif func_name == "stream_device_logs":
                                raw_logs = res_text
                                if "```" in res_text:
                                    parts = res_text.split("```")
                                    if len(parts) >= 3:
                                        raw_logs = parts[1].strip()
                                
                                import html as py_html
                                escaped_logs = py_html.escape(raw_logs)
                                target_dev = func_args.get("target_ip") or "Target Device"
                                kw_arg = func_args.get("filter_keywords") or []
                                if isinstance(kw_arg, list):
                                    filter_str = ", ".join(kw_arg)
                                else:
                                    filter_str = str(kw_arg)
                                filter_badge = f"<span class='px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 font-mono text-xs border border-blue-500/30'>{py_html.escape(filter_str)}</span>" if filter_str else ""
                                
                                has_crash = "Crash/Error Pattern" in res_text or "🔴" in res_text
                                status_badge = "<span class='px-2 py-0.5 rounded bg-red-500/20 text-red-400 font-semibold text-xs border border-red-500/30 flex items-center gap-1'><span class='w-2 h-2 rounded-full bg-red-500 animate-pulse'></span> Issue Detected</span>" if has_crash else "<span class='px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-semibold text-xs border border-emerald-500/30 flex items-center gap-1'><span class='w-2 h-2 rounded-full bg-emerald-400'></span> Stream Active</span>"
                                
                                widget_html = (
                                    f"<agent-html>\n"
                                    f"<div class='bg-slate-900 border border-slate-700/80 rounded-xl overflow-hidden shadow-2xl mb-4 font-sans'>\n"
                                    f"  <div class='px-4 py-3 bg-slate-800/90 border-b border-slate-700/80 flex items-center justify-between'>\n"
                                    f"    <div class='flex items-center gap-2.5'>\n"
                                    f"      <div class='p-1.5 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'>\n"
                                    f"        <i data-lucide='terminal' class='w-4 h-4'></i>\n"
                                    f"      </div>\n"
                                    f"      <div>\n"
                                    f"        <h3 class='text-sm font-bold text-slate-100 m-0'>Device Log Terminal</h3>\n"
                                    f"        <div class='text-[11px] text-slate-400 font-mono mt-0.5'>Target: <strong class='text-slate-200'>{target_dev}</strong></div>\n"
                                    f"      </div>\n"
                                    f"    </div>\n"
                                    f"    <div class='flex items-center gap-2'>\n"
                                    f"      {filter_badge}\n"
                                    f"      {status_badge}\n"
                                    f"    </div>\n"
                                    f"  </div>\n"
                                    f"  <div class='p-4 bg-black/95 font-mono text-xs text-slate-300 max-h-[400px] overflow-y-auto overflow-x-auto whitespace-pre leading-relaxed select-text border-b border-slate-800'>\n"
                                    f"<pre class='m-0 p-0 text-slate-300 font-mono text-xs leading-5'>{escaped_logs}</pre>\n"
                                    f"  </div>\n"
                                    f"  <div class='px-4 py-2.5 bg-slate-900/90 text-[11px] text-slate-400 flex items-center justify-between font-mono'>\n"
                                    f"    <span class='flex items-center gap-1'><i data-lucide='cpu' class='w-3.5 h-3.5 text-blue-400'></i> Source: /var/log/messages &bull; pmlogd</span>\n"
                                    f"    <div class='flex items-center gap-2'>\n"
                                    f"      <button onclick=\"navigator.clipboard.writeText(this.closest('.bg-slate-900').querySelector('pre').innerText); this.innerText='Copied!'; setTimeout(() => this.innerText='Copy Logs', 2000);\" class='px-2 py-0.5 bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 rounded text-xs transition-colors flex items-center gap-1'><i data-lucide='copy' class='w-3 h-3'></i> Copy Logs</button>\n"
                                    f"      <button onclick=\"switchView('device-hud'); if(window.deviceHud) window.deviceHud.loadArtifactVault();\" class='px-2 py-0.5 bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 rounded text-xs transition-colors flex items-center gap-1'><i data-lucide='vault' class='w-3 h-3 text-emerald-400'></i> Artifact Vault</button>\n"
                                    f"    </div>\n"
                                    f"  </div>\n"
                                    f"</div>\n"
                                    f"</agent-html>"
                                )
                                last_log_widget = widget_html
                                res_text = (
                                    f"Device logs captured from {target_dev}. Present them using this HTML widget:\n\n"
                                    f"{widget_html}"
                                )

                            if not res_text:
                                res_text = "(Command returned empty output)"
                            last_tool_output = res_text
                        except Exception as e:
                            res_text = f"Tool execution failed: {str(e)}"
                            last_tool_output = res_text
                            
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tool_call["id"],
                            "name": func_name,
                            "content": res_text
                        })
                    
                    with open('/tmp/llm_debug.txt', 'a') as f:
                        f.write(json.dumps(messages) + "\n\n=======================\n")
                        
                final_msg = "The supervisor reached the maximum number of iterations."
                if last_log_widget and "<agent-html>" not in final_msg:
                    final_msg = last_log_widget
                elif last_screenshot_widget and "<agent-html>" not in final_msg:
                    final_msg = last_screenshot_widget
                elif last_flamegraph_widget and "<agent-html>" not in final_msg:
                    final_msg = last_flamegraph_widget
                elif last_tool_output:
                    final_msg = last_tool_output
                return {"intent": "chat", "message": final_msg}
                
        except Exception as e:
            err_msg = unwrap_exception(e)
            logger.error(f"Supervisor LLM Chat Error: {err_msg}", exc_info=True)
            return {"intent": "chat", "message": f"⚠️ Supervisor Error: {err_msg}"}


@app.on_event("startup")
async def _launch_bug_watchdog():
    from bug_watchdog import start_bug_watchdog
    start_bug_watchdog(MCP_SERVER_URL)


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
    
    # Resolve Collab PAT:
    # 1. Body param (req.collab_pat - from Portal Settings)
    # 2. X-Collab-PAT header from request
    # 3. Pod Environment variables (COLLAB_PAT, DEFAULT_COLLAB_PAT)
    effective_collab_pat = (
        (req.collab_pat or "").strip() or 
        request.headers.get("X-Collab-PAT", "").strip() or 
        request.headers.get("x-collab-pat", "").strip() or 
        os.environ.get("COLLAB_PAT", "").strip() or 
        os.environ.get("DEFAULT_COLLAB_PAT", "").strip()
    )
    req.collab_pat = effective_collab_pat

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
    import re
    import uuid
    import base64
    
    try:
        async with AsyncExitStack() as stack:
            # Connect to MCP server with retry for transient socket drops/container warmup
            mcp_headers = {"X-Jira-PAT": pat}
            session = None
            last_conn_err = None
            for attempt in range(3):
                try:
                    streams = await stack.enter_async_context(sse_client(f"{MCP_SERVER_URL}/sse", headers=mcp_headers))
                    session = await stack.enter_async_context(ClientSession(streams[0], streams[1]))
                    await session.initialize()
                    break
                except (Exception, BaseException) as conn_err:
                    last_conn_err = conn_err
                    if attempt < 2:
                        import asyncio
                        logger.warning(f"Jira MCP connection attempt {attempt+1} failed ({unwrap_exception(conn_err)}). Retrying in 1.5s...")
                        await asyncio.sleep(1.5)
                    else:
                        logger.error(f"Failed to connect to Jira MCP after 3 attempts: {unwrap_exception(conn_err)}")
                        raise last_conn_err
            
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
                        "parameters": t.input_schema or {"type": "object", "properties": {}}
                    }
                })
                
            sys_prompt = f"""You are the GPOS Jira & Governance Agent.
    Your active workspace project is '{target_project}'.
    You have access to a suite of MCP tools (Jira, Code Search, etc.).
    
    JIRA PROJECT & CROSS-PROJECT RULES:
    1. DEFAULT WORKSPACE PROJECT:
       - Default to project '{target_project}' for general queries, sprint reports, burndowns, backlog queries, or when the user asks for "my tickets", "my bugs", or creates an issue without specifying a project key.
       - For general searches without a specific ticket key or project, scope to `project = {target_project}` (e.g., `project = {target_project} AND assignee = currentUser()`).
    2. CROSS-PROJECT TICKETS & KEYS FULLY PERMITTED:
       - NEVER refuse, block, or apologize when the user asks about a specific ticket key (e.g. 'HSWEBOS-2770', or any 'KEY-123' from ANY project), or when the user asks about another project!
       - You MUST fetch and summarize the ticket immediately using `jira_get_issue(issue_key="...")` or `jira_search(jql="key = ...")`.
       - DO NOT claim that your instructions strictly limit you to {target_project}. You have full access to any Jira project or ticket readable by the user's Jira credentials/PAT. Always fetch the requested ticket!
    3. When tools accept a project_key argument (e.g. generate_sprint_report, get_sprint_burndown, create_jira_issue), pass the requested project key if specified by the user, or default to "{target_project}".
    
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
    1. **Jira Tickets & Stories Table (MANDATORY)**:
    You are STRICTLY FORBIDDEN from outputting plain-text lists or markdown pipe tables (`| Key | Type | ... |`) when presenting Jira tickets, stories, bugs, or search results.
    Whenever displaying any list of tickets or search results, you MUST ALWAYS output raw HTML wrapped EXACTLY in `<agent-html>` tags.
    Use this exact HTML structure with semantic badge styling:
    <agent-html>
    <table class="w-full text-sm text-left text-slate-300">
      <thead class="text-xs text-slate-400 bg-slate-800 uppercase">
        <tr><th>Key</th><th>Type</th><th>Status</th><th>Priority</th><th>Summary</th><th>Assignee</th></tr>
      </thead>
      <tbody>
        <tr class="bg-slate-900 border-b border-slate-700">
          <td class="px-3 py-2 font-mono text-blue-400">{target_project}-1</td>
          <td class="px-3 py-2">Story</td>
          <td class="px-3 py-2 text-emerald-400">Resolved</td>
          <td class="px-3 py-2 text-amber-400">P2</td>
          <td class="px-3 py-2">Fix bug</td>
          <td class="px-3 py-2">abhishek15.c</td>
        </tr>
      </tbody>
    </table>
    </agent-html>
    Note for badges: Use `text-emerald-400` for Resolved/Done/Closed/Verified, `text-blue-400` for In Progress/In Review, and `text-slate-400` for Open/To Do. For Priority, use `text-amber-400` for P1/P2/Highest/High.
    
    2. **Non-Jira Tabular Data**: ONLY for non-ticket general comparisons (e.g. system benchmarks), you may use standard Markdown tables.
    
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
            
            last_screenshot_widget = None
            last_flamegraph_widget = None
            last_log_widget = None
            last_tool_output = None
            async with httpx.AsyncClient() as client:
                for _ in range(25): # Max 25 tool calls per chat
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
                        content = (msg.get("content") or "").strip()
                        if not content:
                            if last_log_widget:
                                content = last_log_widget
                            elif last_screenshot_widget:
                                content = last_screenshot_widget
                            elif last_flamegraph_widget:
                                content = last_flamegraph_widget
                            elif last_tool_output:
                                content = last_tool_output
                            else:
                                content = "⚠️ Command finished, but no output was returned."
                        else:
                            if last_log_widget and "<agent-html>" not in content:
                                content = f"{content}\n\n{last_log_widget}".strip()
                            elif last_screenshot_widget and "<agent-html>" not in content:
                                content = f"{content}\n\n{last_screenshot_widget}".strip()
                            elif last_flamegraph_widget and "<agent-html>" not in content:
                                content = f"{content}\n\n{last_flamegraph_widget}".strip()
                        return {"intent": "chat", "message": content}
                        
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
                            
                            # 2. Inject default project_key / project arguments only if not provided
                            if "project_key" in schema or "project_key" in func_args:
                                val = func_args.get("project_key")
                                if not val:
                                    func_args["project_key"] = target_project
                                    
                            if "project" in schema or "project" in func_args:
                                val = func_args.get("project")
                                if not val:
                                    func_args["project"] = target_project
    
                            # 3. Handle JQL queries:
                            if "jql" in func_args and isinstance(func_args["jql"], str):
                                jql_str = func_args["jql"].strip()
                                
                                # Check if a specific ticket key/ID or specific project is already targeted
                                has_specific_key = re.search(r'\b(key|issueKey|issue|id)\s*(=|in|!=)\s*', jql_str, re.IGNORECASE)
                                has_project = re.search(r'\bproject\s*(=|in|!=)\s*', jql_str, re.IGNORECASE)
                                
                                if has_specific_key or has_project:
                                    # Specific ticket key or project specified - do NOT inject target_project!
                                    # Ensure no rogue ORDER BY inside parentheses
                                    jql_str = re.sub(r'\(\s*(.*?)\s+ORDER\s+BY\s+(.*?)\s*\)', r'(\1) ORDER BY \2', jql_str, flags=re.IGNORECASE)
                                else:
                                    # Generic search without key or project (e.g. "my open bugs", "sprint in openSprints()"):
                                    # Scope to default target_project
                                    order_match = re.search(r'\s+(ORDER\s+BY\s+.*)$', jql_str, re.IGNORECASE)
                                    if order_match:
                                        filter_part = jql_str[:order_match.start()].strip()
                                        order_part = order_match.group(1).strip()
                                        if filter_part:
                                            jql_str = f"project = {target_project} AND ({filter_part}) {order_part}"
                                        else:
                                            jql_str = f"project = {target_project} {order_part}"
                                    else:
                                        jql_str = f"project = {target_project} AND ({jql_str})"
                                func_args["jql"] = jql_str
                                logger.info(f"Processed JQL query: {jql_str}")
                            
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
                                svg_filename = f"flamegraph_{uuid.uuid4().hex[:8]}.svg"
                                static_dir = os.path.join(os.path.dirname(__file__), "static")
                                if not os.path.exists(static_dir):
                                    os.makedirs(static_dir)
                                svg_path = os.path.join(static_dir, svg_filename)
                                with open(svg_path, "w", encoding="utf-8") as f:
                                    f.write(res_text)
                                flame_widget = f"<agent-html>\n<div class='bg-slate-900 border-t-4 border-t-amber-500 rounded-lg p-5 shadow-lg shadow-amber-500/10 font-sans mb-4'>\n  <h2 class='text-lg font-bold text-slate-200 mb-4 flex items-center gap-2'><i data-lucide='flame' class='text-amber-500'></i> Interactive Flame Graph</h2>\n  <iframe src='/static/{svg_filename}' width='100%' height='600px' style='border:1px solid #1e293b; border-radius: 8px; background: #0f172a;'></iframe>\n</div>\n</agent-html>"
                                last_flamegraph_widget = flame_widget
                                res_text = f"Flame graph SVG generated. Present it using this HTML widget:\n\n{flame_widget}"
                            elif func_name == "take_screenshot" and "SNAPSHOT_BASE64:" in res_text:
                                b64_data = res_text.split("SNAPSHOT_BASE64:")[1].strip()
                                b64_clean = re.sub(r'[^A-Za-z0-9+/=]', '', b64_data)
                                img_filename = f"snap_{uuid.uuid4().hex[:8]}.png"
                                static_dir = os.path.join(os.path.dirname(__file__), "static")
                                if not os.path.exists(static_dir):
                                    os.makedirs(static_dir)
                                img_path = os.path.join(static_dir, img_filename)
                                try:
                                    raw_bytes = base64.b64decode(b64_clean)
                                    if len(raw_bytes) > 64:
                                        with open(img_path, "wb") as f:
                                            f.write(raw_bytes)
                                        try:
                                            os.chmod(img_path, 0o644)
                                        except Exception:
                                            pass
                                        widget_html = (
                                            f"<agent-html>\n"
                                            f"<div class='bg-slate-900 border-t-4 border-t-blue-500 rounded-lg p-5 shadow-lg shadow-blue-500/10 font-sans mb-4'>\n"
                                            f"  <div class='flex items-center justify-between mb-3'>\n"
                                            f"    <h2 class='text-lg font-bold text-slate-200 flex items-center gap-2 m-0'><i data-lucide='camera' class='text-blue-500'></i> Live Device Snapshot</h2>\n"
                                            f"    <a href='/static/{img_filename}' target='_blank' class='text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 font-mono'><i data-lucide='external-link' class='w-3 h-3'></i> View Full Size</a>\n"
                                            f"  </div>\n"
                                            f"  <div class='rounded overflow-hidden border border-slate-700 bg-black flex justify-center p-1'>\n"
                                            f"    <img src='/static/{img_filename}' alt='Device Screenshot' class='max-w-full h-auto object-contain rounded' style='max-height: 480px;' />\n"
                                            f"  </div>\n"
                                            f"</div>\n"
                                            f"</agent-html>"
                                        )
                                        last_screenshot_widget = widget_html
                                        res_text = (
                                            f"Screenshot successfully captured and downloaded from the target device. Present it to the user using this HTML widget:\n\n"
                                            f"{widget_html}"
                                        )
                                    else:
                                        res_text = f"Screenshot capture returned empty image data ({len(raw_bytes)} bytes)."
                                except Exception as e:
                                    res_text = f"Screenshot captured but failed to decode base64 on portal side: {e}"
                            
                            # If instructions were fetched, dynamically adapt any references to SIGPOSDEV
                            if func_name == "get_agent_instructions" and target_project != "SIGPOSDEV":
                                res_text = re.sub(r'\bSIGPOSDEV\b', target_project, res_text)
                            
                            # Only flag genuine tool execution failures; never flag legitimate Jira bug ticket summaries containing 'Error in...'
                            is_tool_error = (
                                res_text.startswith("Error executing ") or
                                res_text.startswith("Search failed (HTTP") or
                                res_text.startswith("JQL Search failed (HTTP") or
                                res_text.startswith("Failed to fetch ") or
                                res_text.startswith("Error in jira_") or
                                "failed (HTTP 4" in res_text or "failed (HTTP 5" in res_text or
                                "HTTP 401" in res_text or "HTTP 403" in res_text
                            )
                            if is_tool_error and not res_text.startswith("TOOL EXECUTION FAILED"):
                                res_text = f"TOOL EXECUTION FAILED: {res_text}\nCRITICAL INSTRUCTION: You MUST inform the user that the action failed and explain the error. DO NOT say it succeeded."
                            
                            last_tool_output = res_text
                            messages.append({
                                "role": "tool",
                                "name": func_name,
                                "tool_call_id": tool_call["id"],
                                "content": res_text
                            })
                        except Exception as e:
                            logger.error(f"Tool call failed: {e}")
                            res_text = f"Error executing tool: {str(e)}"
                            last_tool_output = res_text
                            messages.append({
                                "role": "tool",
                                "name": func_name,
                                "tool_call_id": tool_call["id"],
                                "content": res_text
                            })
                            
                final_msg = "I reached the maximum number of tool calls and had to stop."
                if last_log_widget and "<agent-html>" not in final_msg:
                    final_msg = last_log_widget
                elif last_screenshot_widget and "<agent-html>" not in final_msg:
                    final_msg = last_screenshot_widget
                elif last_flamegraph_widget and "<agent-html>" not in final_msg:
                    final_msg = last_flamegraph_widget
                elif last_tool_output:
                    final_msg = last_tool_output
                return {"intent": "chat", "message": final_msg}
                
    except Exception as e:
        err_msg = unwrap_exception(e)
        logger.error(f"MCP/LLM Loop Error: {err_msg}", exc_info=True)
        return {"intent": "chat", "message": f"⚠️ Jira Agent Error: {err_msg}"}
    except BaseException as e:
        err_msg = unwrap_exception(e)
        logger.error(f"MCP/LLM Loop Fatal Error: {err_msg}", exc_info=True)
        return {"intent": "chat", "message": f"⚠️ Jira Agent Error: {err_msg}"}
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


class DeviceClickInput(BaseModel):
    ip: str
    x: int
    y: int

class DeviceKeyInput(BaseModel):
    ip: str
    key: str

class DeviceTextInput(BaseModel):
    ip: str
    text: str


def _get_device_mcp_urls():
    primary = os.environ.get('DEVICE_MCP_SERVER_URL', 'http://gpos-muralidhar-device-service:8000').rstrip('/')
    urls = [primary]
    if "device-service-dev" in primary:
        fallback = primary.replace("device-service-dev", "device-service")
        if fallback not in urls:
            urls.append(fallback)
    else:
        fallback = primary.replace("device-service", "device-service-dev")
        if fallback not in urls:
            urls.append(fallback)
    return urls


@app.get("/api/device/screen/frame")
def get_device_screen_frame(ip: str):
    clean_ip = ip.strip()
    if not clean_ip or clean_ip.lower() == "none":
        raise HTTPException(status_code=400, detail="Valid target IP is required")

    # 1. Primary path: Query Device Agent custom route (which holds the SSH key secret)
    for base_url in _get_device_mcp_urls():
        try:
            resp = requests.get(f"{base_url}/screen/frame", params={"ip": clean_ip}, timeout=12)
            if resp.status_code == 200 and len(resp.content) > 64:
                media_type = resp.headers.get("content-type", "image/jpeg")
                if "svg" not in media_type:
                    return Response(
                        content=resp.content,
                        media_type=media_type,
                        headers={
                            "Cache-Control": "no-cache, no-store, must-revalidate",
                            "Pragma": "no-cache",
                            "Expires": "0"
                        }
                    )
        except Exception as e:
            logger.debug(f"Device Agent /screen/frame fetch via {base_url} failed: {e}")

    # 2. Secondary path: Direct SSH (if portal container has SSH key mounted)
    import subprocess
    ssh_opts = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3"
    if os.path.isfile("/root/.ssh/id_rsa"):
        ssh_opts += " -i /root/.ssh/id_rsa"

    target_snap = "/tmp/snapshots/default/live_snap.jpg"
    capture_script = (
        "mkdir -p /tmp/snapshots/default; rm -f /tmp/snapshots/default/live_snap.jpg; "
        "H=$(luna-send -n 1 -a com.webos.surfacemanager luna://com.webos.service.capture/createHandle '{}' 2>/dev/null | grep -o '\"handle\":[0-9]*' | cut -d: -f2); "
        "if [ -n \"$H\" ]; then luna-send -n 1 -a com.webos.surfacemanager luna://com.webos.service.capture/executeOneShot \"{\\\"handle\\\":$H,\\\"path\\\":\\\"/tmp/snapshots/default/live_snap.jpg\\\",\\\"method\\\":\\\"blended\\\",\\\"format\\\":\\\"jpeg\\\",\\\"width\\\":1920,\\\"height\\\":1080}\" 2>/dev/null; fi; "
        "if [ ! -s /tmp/snapshots/default/live_snap.jpg ]; then luna-send -n 1 -a com.webos.surfacemanager luna://com.webos.surfacemanager/captureCompositorOutput '{\"output\":\"HDMI-A-1\",\"path\":\"/tmp/snapshots/default/live_snap.jpg\"}' 2>/dev/null || luna-send -n 1 -a com.webos.surfacemanager luna://com.webos.surfacemanager/captureCompositorOutput '{\"output\":\"default\",\"path\":\"/tmp/snapshots/default/live_snap.jpg\"}' 2>/dev/null; fi; "
        "if [ -s /tmp/snapshots/default/live_snap.jpg ]; then echo '/tmp/snapshots/default/live_snap.jpg'; "
        "else find /tmp/snapshots/default /tmp/snapshots /tmp -maxdepth 2 \( -name '*.jpg' -o -name '*.png' \) -size +1k 2>/dev/null | head -1; fi"
    )

    found_path = ""
    try:
        res = subprocess.run(
            f"ssh {ssh_opts} root@{clean_ip} '{capture_script}'",
            shell=True, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=8
        )
        if res.returncode == 0:
            lines = [l.strip() for l in res.stdout.splitlines() if l.strip().startswith("/tmp/")]
            if lines:
                found_path = lines[-1]
    except Exception as e:
        logger.warning(f"Screen capture attempt failed on {clean_ip}: {e}")

    if found_path:
        try:
            fetch_cmd = f"ssh {ssh_opts} root@{clean_ip} 'cat \"{found_path}\"'"
            cat_res = subprocess.run(fetch_cmd, shell=True, capture_output=True, stdin=subprocess.DEVNULL, timeout=10)
            if cat_res.returncode == 0 and len(cat_res.stdout) > 64:
                media_type = "image/png" if found_path.endswith(".png") else "image/jpeg"
                return Response(
                    content=cat_res.stdout,
                    media_type=media_type,
                    headers={
                        "Cache-Control": "no-cache, no-store, must-revalidate",
                        "Pragma": "no-cache",
                        "Expires": "0"
                    }
                )
        except Exception as e:
            logger.warning(f"Failed to fetch frame binary from {clean_ip}: {e}")

    fallback_svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="1920" height="1080" viewBox="0 0 1920 1080">
        <rect width="1920" height="1080" fill="#0f172a"/>
        <rect x="40" y="40" width="1840" height="1000" rx="20" fill="#1e293b" stroke="#334155" stroke-width="3"/>
        <circle cx="960" cy="460" r="90" fill="#0f172a" stroke="#3b82f6" stroke-width="4"/>
        <text x="960" y="480" font-family="sans-serif" font-size="60" text-anchor="middle">📺</text>
        <text x="960" y="610" font-family="sans-serif" font-size="34" font-weight="bold" fill="#f8fafc" text-anchor="middle">Live Board Display Stream: {clean_ip}</text>
        <text x="960" y="665" font-family="sans-serif" font-size="22" fill="#94a3b8" text-anchor="middle">Compositor frame buffer is standby or waking up...</text>
        <text x="960" y="710" font-family="sans-serif" font-size="18" fill="#64748b" text-anchor="middle">Click "Refresh Frame" or use the Remote D-Pad / Keyboard on the right to wake display</text>
    </svg>"""
    return Response(
        content=fallback_svg.encode('utf-8'),
        media_type="image/svg+xml",
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"}
    )


@app.post("/api/device/webrtc/offer")
async def device_webrtc_offer(request: Request):
    """Forward WebRTC SDP Offer to Device Agent and return SDP Answer."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    ip = body.get("ip", "").strip()
    if not ip or ip.lower() == "none":
        raise HTTPException(status_code=400, detail="Valid target IP is required")

    for base_url in _get_device_mcp_urls():
        try:
            resp = requests.post(f"{base_url}/webrtc/offer", json=body, timeout=15)
            if resp.status_code == 200:
                return resp.json()
            else:
                logger.warning(f"Device Agent /webrtc/offer returned {resp.status_code}: {resp.text}")
        except Exception as e:
            logger.debug(f"Device Agent /webrtc/offer forward via {base_url} failed: {e}")

    raise HTTPException(status_code=502, detail="Failed to establish WebRTC session with Device Agent")


@app.post("/api/device/webrtc/close")
async def device_webrtc_close(request: Request):
    """Notify Device Agent to close WebRTC peer connection."""
    try:
        body = await request.json()
    except Exception:
        body = {}

    for base_url in _get_device_mcp_urls():
        try:
            resp = requests.post(f"{base_url}/webrtc/close", json=body, timeout=5)
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            logger.debug(f"Device Agent /webrtc/close forward via {base_url} failed: {e}")

    return {"status": "ok"}


@app.get("/api/device/screen/stream")
def get_device_screen_stream(ip: str):
    """Stream continuous MJPEG video stream from Device Agent."""
    clean_ip = ip.strip()
    if not clean_ip or clean_ip.lower() == "none":
        raise HTTPException(status_code=400, detail="Valid target IP is required")

    from fastapi.responses import StreamingResponse
    for base_url in _get_device_mcp_urls():
        try:
            req_stream = requests.get(f"{base_url}/screen/stream", params={"ip": clean_ip}, stream=True, timeout=10)
            if req_stream.status_code == 200:
                def iter_stream():
                    for chunk in req_stream.iter_content(chunk_size=4096):
                        yield chunk
                return StreamingResponse(
                    iter_stream(),
                    media_type="multipart/x-mixed-replace; boundary=frame",
                    headers={"Cache-Control": "no-cache, no-store, must-revalidate"}
                )
        except Exception as e:
            logger.debug(f"Device Agent /screen/stream via {base_url} failed: {e}")

    raise HTTPException(status_code=502, detail="MJPEG stream unavailable from Device Agent")


@app.post("/api/device/input/click")
def device_input_click(req: DeviceClickInput):
    ip = req.ip.strip()
    x = int(req.x)
    y = int(req.y)

    # 1. Primary: Forward to Device Agent
    for base_url in _get_device_mcp_urls():
        try:
            resp = requests.post(f"{base_url}/input/click", json={"ip": ip, "x": x, "y": y}, timeout=6)
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            logger.debug(f"Device Agent /input/click forward via {base_url} failed: {e}")

    # 2. Secondary fallback: Direct SSH
    import subprocess
    import base64
    ssh_opts = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3"
    if os.path.isfile("/root/.ssh/id_rsa"):
        ssh_opts += " -i /root/.ssh/id_rsa"

    mouse_payload = json.dumps({"eventtype": "click", "x": x, "y": y})
    b64_mouse = base64.b64encode(mouse_payload.encode('utf-8')).decode('ascii')
    cmd1 = f'luna-send -n 1 -f luna://com.lge.inputgenerator/pushMouseEvent "$(echo {b64_mouse} | base64 -d)" 2>&1'

    combo_payload = json.dumps({
        "events": [
            {"eventtype": "setpos", "x": x, "y": y},
            {"eventtype": "click"},
            {"eventtype": "touch_down", "x": x, "y": y},
            {"eventtype": "touch_up", "x": x, "y": y}
        ]
    })
    b64_combo = base64.b64encode(combo_payload.encode('utf-8')).decode('ascii')
    cmd2 = f'luna-send -n 1 -f luna://com.lge.inputgenerator/pushEvents "$(echo {b64_combo} | base64 -d)" 2>&1'
    cmd = f"{cmd1}; {cmd2}"
    try:
        res = subprocess.run(
            f"ssh -tt {ssh_opts} root@{ip} '{cmd}'",
            shell=True, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=5
        )
        return {"status": "ok", "x": x, "y": y, "target_ip": ip, "detail": res.stdout.strip()[:100]}
    except Exception as e:
        logger.error(f"Failed to execute click on {ip}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/device/input/key")
def device_input_key(req: DeviceKeyInput):
    ip = req.ip.strip()
    key = req.key.strip().upper()
    key_codes_map = {
        "UP": [103],
        "DOWN": [108],
        "LEFT": [105],
        "RIGHT": [106],
        "ENTER": [28, 352],
        "OK": [28, 352],
        "BACK": [412, 158, 1],
        "ESC": [1],
        "HOME": [172, 102],
        "MENU": [139, 141],
        "SETTINGS": [141, 139],
        "POWER": [116],
        "VOL_UP": [115],
        "VOLUME_UP": [115],
        "VOL_DOWN": [114],
        "VOLUME_DOWN": [114],
        "MUTE": [113],
        "CH_UP": [402],
        "CHANNEL_UP": [402],
        "CH_DOWN": [403],
        "CHANNEL_DOWN": [403],
        "RED": [398],
        "GREEN": [399],
        "YELLOW": [400],
        "BLUE": [401],
        "PLAY": [207],
        "PAUSE": [201],
        "STOP": [128],
        "REWIND": [168],
        "FAST_FORWARD": [208]
    }
    codes = key_codes_map.get(key, [28])

    # 1. Primary: Forward to Device Agent
    for base_url in _get_device_mcp_urls():
        try:
            resp = requests.post(f"{base_url}/input/key", json={"ip": ip, "key": key}, timeout=6)
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            logger.debug(f"Device Agent /input/key forward via {base_url} failed: {e}")

    # 2. Secondary fallback: Direct SSH
    import subprocess
    import base64
    ssh_opts = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3"
    if os.path.isfile("/root/.ssh/id_rsa"):
        ssh_opts += " -i /root/.ssh/id_rsa"
    primary_code = codes[0]
    key_payload = json.dumps({"eventtype": "keypress", "keycodenum": primary_code})
    b64_key = base64.b64encode(key_payload.encode('utf-8')).decode('ascii')
    cmd1 = f'luna-send -n 1 -f luna://com.lge.inputgenerator/pushKeyEvent "$(echo {b64_key} | base64 -d)" 2>&1'

    events = []
    for c in codes:
        events.append({"eventtype": "keydown", "keycodenum": c})
        events.append({"eventtype": "keyup", "keycodenum": c})
    events_payload = json.dumps({"events": events})
    b64_events = base64.b64encode(events_payload.encode('utf-8')).decode('ascii')
    cmd2 = f'luna-send -n 1 -f luna://com.lge.inputgenerator/pushEvents "$(echo {b64_events} | base64 -d)" 2>&1'
    cmd = f"{cmd1}; {cmd2}"
    try:
        res = subprocess.run(
            f"ssh -tt {ssh_opts} root@{ip} '{cmd}'",
            shell=True, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=5
        )
        return {"status": "ok", "key": key, "target_ip": ip, "detail": res.stdout.strip()[:100]}
    except Exception as e:
        logger.error(f"Failed to execute key on {ip}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/device/input/text")
def device_input_text(req: DeviceTextInput):
    ip = req.ip.strip()
    text = req.text
    if not text:
        return {"status": "ok", "detail": "Empty text"}

    # 1. Primary: Forward to Device Agent
    for base_url in _get_device_mcp_urls():
        try:
            resp = requests.post(f"{base_url}/input/text", json={"ip": ip, "text": text}, timeout=6)
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            logger.debug(f"Device Agent /input/text forward via {base_url} failed: {e}")

    # 2. Secondary fallback: Direct SSH
    import subprocess
    ssh_opts = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3"
    if os.path.isfile("/root/.ssh/id_rsa"):
        ssh_opts += " -i /root/.ssh/id_rsa"
    char_map = {
        'a': 30, 'b': 48, 'c': 46, 'd': 32, 'e': 18, 'f': 33, 'g': 34, 'h': 35,
        'i': 23, 'j': 36, 'k': 37, 'l': 38, 'm': 50, 'n': 49, 'o': 24, 'p': 25,
        'q': 16, 'r': 19, 's': 31, 't': 20, 'u': 22, 'v': 47, 'w': 17, 'x': 45,
        'y': 21, 'z': 44,
        '1': 2, '2': 3, '3': 4, '4': 5, '5': 6, '6': 7, '7': 8, '8': 9, '9': 10, '0': 11,
        ' ': 57, '-': 12, '=': 13, '.': 52, '/': 53, '\n': 28, '\t': 15, '\b': 14
    }
    events = []
    for ch in text.lower()[:50]:
        code = char_map.get(ch)
        if code:
            events.append({"eventtype": "keydown", "keycodenum": code})
            events.append({"eventtype": "keyup", "keycodenum": code})

    if events:
        payload = json.dumps({"events": events})
        cmd = f"luna-send -n 1 -f luna://com.lge.inputgenerator/pushEvents '{payload}' 2>&1"
        try:
            res = subprocess.run(
                f"ssh -tt {ssh_opts} root@{ip} '{cmd}'",
                shell=True, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=5
            )
            return {"status": "ok", "text": text, "target_ip": ip, "detail": res.stdout.strip()[:100]}
        except Exception as e:
            logger.error(f"Failed to inject text on {ip}: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    return {"status": "ok", "text": text, "target_ip": ip, "detail": "Skipped"}

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
        return FileResponse(index_path, headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0"
        })
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

@app.get('/api/artifacts')
def list_artifacts(request: Request):
    """List all diagnostic files, logs, flamegraphs, and snapshots in the Artifact Vault."""
    from datetime import datetime
    import shutil
    
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
    artifacts_dir = os.path.join(static_dir, "artifacts")
    if not os.path.exists(artifacts_dir):
        os.makedirs(artifacts_dir, exist_ok=True)

    # Sync persistent volume artifacts from /app/data/artifacts if available
    pvc_dir = "/app/data/artifacts"
    if os.path.exists(pvc_dir):
        try:
            for pf in os.listdir(pvc_dir):
                src = os.path.join(pvc_dir, pf)
                dst = os.path.join(artifacts_dir, pf)
                if os.path.isfile(src) and not os.path.exists(dst):
                    shutil.copy2(src, dst)
        except Exception:
            pass
    
    seen_files = {}

    # 1. Scan /static/artifacts/ (Log bundles, tar.gz, snapshots synced from PVC)
    if os.path.exists(artifacts_dir):
        for fname in os.listdir(artifacts_dir):
            fpath = os.path.join(artifacts_dir, fname)
            if os.path.isfile(fpath):
                size = os.path.getsize(fpath)
                mtime = os.path.getmtime(fpath)
                size_mb = round(size / (1024 * 1024), 2)
                size_str = f"{size_mb} MB" if size_mb >= 1.0 else f"{round(size / 1024, 1)} KB"
                
                # Classify type accurately
                if fname.endswith(".tar.gz") or fname.endswith(".zip"):
                    file_type = "Log Archive"
                elif fname.startswith("snap_") and (fname.endswith(".png") or fname.endswith(".jpg")):
                    file_type = "Screen Snapshot"
                elif fname.startswith("flamegraph_") and fname.endswith(".svg"):
                    file_type = "Interactive Flamegraph"
                else:
                    file_type = "Diagnostic File"

                seen_files[fname] = {
                    "name": fname,
                    "type": file_type,
                    "size": size_str,
                    "url": f"/static/artifacts/{fname}",
                    "created_at": datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S"),
                    "mtime": mtime
                }
                
    # 2. Scan /static/ for flamegraphs and snapshots (avoiding duplicate listings)
    if os.path.exists(static_dir):
        for fname in os.listdir(static_dir):
            if fname in seen_files:
                continue
            fpath = os.path.join(static_dir, fname)
            if os.path.isfile(fpath):
                if fname.startswith("flamegraph_") and fname.endswith(".svg"):
                    size = os.path.getsize(fpath)
                    mtime = os.path.getmtime(fpath)
                    seen_files[fname] = {
                        "name": fname,
                        "type": "Interactive Flamegraph",
                        "size": f"{round(size / 1024, 1)} KB",
                        "url": f"/static/{fname}",
                        "created_at": datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S"),
                        "mtime": mtime
                    }
                elif fname.startswith("snap_") and (fname.endswith(".png") or fname.endswith(".jpg")):
                    size = os.path.getsize(fpath)
                    mtime = os.path.getmtime(fpath)
                    seen_files[fname] = {
                        "name": fname,
                        "type": "Screen Snapshot",
                        "size": f"{round(size / 1024, 1)} KB",
                        "url": f"/static/{fname}",
                        "created_at": datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S"),
                        "mtime": mtime
                    }
                    
    # Sort newest first by mtime so latest logs and snapshots always appear at the top
    sorted_artifacts = sorted(seen_files.values(), key=lambda x: x["mtime"], reverse=True)
    return {"artifacts": sorted_artifacts[:100]}


@app.delete('/api/artifacts/{filename}')
async def delete_artifact_by_param(filename: str):
    """Delete an artifact by filename URL parameter."""
    return _do_delete_artifact(filename)


@app.post('/api/artifacts/delete')
async def delete_artifact_by_body(req: Request):
    """Delete an artifact via JSON body {filename: '...'}."""
    try:
        body = await req.json()
        filename = body.get("filename", "")
    except Exception:
        filename = ""
    return _do_delete_artifact(filename)


def _do_delete_artifact(filename: str):
    clean_name = os.path.basename(filename.strip())
    if not clean_name or clean_name in [".", ".."]:
        raise HTTPException(status_code=400, detail="Invalid filename")

    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
    paths_to_check = [
        os.path.join(static_dir, "artifacts", clean_name),
        os.path.join(static_dir, clean_name),
        os.path.join("/app/data/artifacts", clean_name),
        os.path.join("/app/data", clean_name)
    ]
    deleted = False
    for p in paths_to_check:
        if os.path.isfile(p):
            try:
                os.remove(p)
                deleted = True
                logger.info(f"Artifact deleted: {p}")
            except Exception as e:
                logger.error(f"Failed to delete {p}: {e}")

    if not deleted:
        raise HTTPException(status_code=404, detail=f"Artifact '{clean_name}' not found or already deleted")

    return {"status": "success", "message": f"Successfully deleted {clean_name}", "filename": clean_name}



























