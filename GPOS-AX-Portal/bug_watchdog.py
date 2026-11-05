"""
Automated Bug Triage Watchdog (Enterprise Multi-Tenant)
======================================================
Multi-tenant, database-driven bug analysis worker.
No hardcoded usernames or project keys in code or env!
Each engineer configures their preferences via the AX Portal Settings UI:
- Enable/disable auto-triage for their assigned bugs
- Set their Jira project keys
- Set their target board IP (for Device Agent GDB analysis)
- Set their notification email

Workflow:
1. Runs on schedule, queries DB `user_bug_watchdog_config` for all users with `is_enabled = 1`.
2. For each enabled user, queries Jira for bugs assigned to them:
   `project in (<user_projects>) AND assignee = "<username>" AND issuetype = Bug AND labels not in (AX_AutoTriage-Done)`
3. Sorts candidate bugs by priority (P1 -> P2 -> P3).
4. For each bug:
   - Reads all available fields: Summary, Description, Attachments, and complete Comment history.
   - Autonomous Comment Resolution (Rule 2): If a user or QE asks a question in comments that can be answered from ticket context, replies automatically.
   - Conditional Prerequisite Check (Rule 1):
     1. Logs (Always mandatory)
     2. Steps to Reproduce (Always mandatory)
     3. Related Test Cases (Always mandatory)
     4. Core dump file (CONDITIONAL: required ONLY if ticket mentions a crash/abort/SIGSEGV; skipped if non-crashing bug).
5. If prerequisites are MISSING:
   - Posts a comment on the Jira ticket listing missing items.
   - Adds label 'AX_AutoTriage-Pending'.
   - NO EMAIL is sent to reporter or user (zero email spam; discussion stays on Jira ticket).
   - Records audit status PREREQ_MISSING (prereq_ok=False, analysis_ok=0).
6. If prerequisites are PRESENT (or satisfied under conditional rules):
   - Downloads logs/coredumps, performs crash signal search and Device Agent GDB analysis.
   - Posts "### 🔎 Initial Automated Bug Analysis" comment directly to the Jira ticket.
   - Removes 'AX_AutoTriage-Pending', adds label 'AX_AutoTriage-Done'.
   - Sends notification email ONLY to the assigned user:
     "Initial analysis added to <KEY>. Please review and edit if needed."
   - Records audit status ANALYSIS_DONE (prereq_ok=True, analysis_ok=1).
"""

import os
import json
import asyncio
import logging
import sqlite3
import smtplib
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

# ─── System / Infrastructure Config (Platform Level Only) ─────────────────────
BUG_WATCHDOG_INTERVAL_SECONDS = int(os.environ.get('BUG_WATCHDOG_INTERVAL_SECONDS', '60'))
BUG_WATCHDOG_LOOKBACK_DAYS = int(os.environ.get('BUG_WATCHDOG_LOOKBACK_DAYS', '7'))
BUG_WATCHDOG_MAX_ISSUES_PER_USER = int(os.environ.get('BUG_WATCHDOG_MAX_ISSUES_PER_USER', '5'))
BUG_WATCHDOG_REMIND_HOURS = int(os.environ.get('BUG_WATCHDOG_REMIND_HOURS', '24'))

DB_PATH = os.environ.get('DB_PATH', '/tmp/gpos_portal.db')
MCP_SERVER_URL = os.environ.get('MCP_SERVER_URL', 'http://gpos-muralidhar-jira-service:8000').rstrip('/')
DEVICE_MCP_SERVER_URL = os.environ.get('DEVICE_MCP_SERVER_URL', 'http://gpos-muralidhar-device-service:8000').rstrip('/')
JIRA_BASE_URL = os.environ.get('JIRA_BASE_URL', 'http://jira.lge.com/issue').rstrip('/')
DEFAULT_JIRA_PAT = os.environ.get('JIRA_PAT', '').strip() or os.environ.get('BUG_WATCHDOG_JIRA_PAT', '').strip()
LLM_URL = os.environ.get('LLM_API_URL', '').strip() or os.environ.get('BUG_WATCHDOG_LLM_URL', 'http://exacode-chat.lge.com/v1').strip()
LLM_KEY = os.environ.get('LLM_API_KEY', '').strip() or os.environ.get('BUG_WATCHDOG_LLM_KEY', '').strip()

SMTP_HOST = os.environ.get('SMTP_HOST', '').strip()
SMTP_PORT = int(os.environ.get('SMTP_PORT', '25'))
SMTP_FROM = os.environ.get('SMTP_FROM', 'gpos-ax-portal@lge.com').strip()
SMTP_USE_TLS = os.environ.get('SMTP_USE_TLS', 'false').strip().lower() == 'true'
SMTP_USERNAME = os.environ.get('SMTP_USERNAME', '').strip()
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '').strip()

PRIORITY_ORDER = {
    "blocker": 0, "p1": 0,
    "critical": 1, "p2": 1,
    "major": 2, "p3": 2,
    "minor": 3, "p4": 3,
    "trivial": 4, "p5": 4,
}

_audit_log: List[Dict[str, Any]] = []


def _unwrap_exception(e: BaseException) -> str:
    if hasattr(e, "exceptions") and getattr(e, "exceptions"):
        extracted = []
        for sub in getattr(e, "exceptions"):
            msg = _unwrap_exception(sub)
            if msg and "unhandled errors in a TaskGroup" not in msg:
                extracted.append(msg)
        if extracted:
            return "; ".join(extracted)
        return _unwrap_exception(getattr(e, "exceptions")[0])
    return str(e)


def _send_email_to_assignee(to_email: str, subject: str, body: str) -> str:
    """Send notification email strictly to the assigned developer."""
    if not SMTP_HOST:
        logger.info(f"SMTP not configured; simulated email to {to_email}: {subject}")
        return f"Email simulated (SMTP_HOST not set): {subject}"
    if not to_email:
        return "Email skipped: no recipient address."
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = SMTP_FROM
        msg["To"] = to_email
        msg.attach(MIMEText(body, "plain", "utf-8"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            if SMTP_USE_TLS:
                server.starttls()
            if SMTP_USERNAME and SMTP_PASSWORD:
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM, [to_email], msg.as_string())
        return f"Email sent successfully to {to_email}."
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {e}")
        return f"Email send failed: {e}"


def _init_watchdog_db():
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS watchdog_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                issue_key TEXT NOT NULL,
                priority TEXT DEFAULT 'Normal',
                action TEXT NOT NULL,
                prereq_ok INTEGER DEFAULT 0,
                missing_items TEXT DEFAULT '',
                reminded_at TEXT NOT NULL,
                analysis_ok INTEGER DEFAULT 0,
                notes TEXT DEFAULT ''
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_watchdog_audit_key ON watchdog_audit(issue_key)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS watchdog_reminders (
                issue_key TEXT PRIMARY KEY,
                last_reminded_at TEXT NOT NULL
            )
        """)
        for col in ["build_server_ip", "build_root_path"]:
            try:
                conn.execute(f"ALTER TABLE user_bug_watchdog_config ADD COLUMN {col} TEXT DEFAULT ''")
            except Exception:
                pass
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Could not initialize watchdog_audit table: {e}")

_init_watchdog_db()


def _load_audit_history():
    """Seed in-memory audit log from persistent SQLite storage on startup."""
    global _audit_log
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT issue_key, priority, action, prereq_ok, missing_items, reminded_at, analysis_ok, notes "
            "FROM watchdog_audit ORDER BY id DESC LIMIT 100"
        ).fetchall()
        conn.close()
        loaded = []
        seen = set()
        for r in rows:
            k = r["issue_key"]
            if k not in seen:
                seen.add(k)
                notes_val = r["notes"] or ""
                user_str = ""
                if "User:" in notes_val:
                    user_str = notes_val.split("|")[0].replace("User:", "").strip()
                loaded.append({
                    "issue_key": k,
                    "user": user_str,
                    "priority": r["priority"],
                    "action": r["action"],
                    "prereq_ok": bool(r["prereq_ok"]),
                    "missing_items": r["missing_items"] or "",
                    "analysis_ok": int(r["analysis_ok"] or 0),
                    "reminded_at": r["reminded_at"],
                    "notes": notes_val,
                    "cycle_at": r["reminded_at"]
                })
        _audit_log = loaded[::-1]
    except Exception as e:
        logger.warning(f"Could not load audit history from DB: {e}")

_load_audit_history()


def _get_enrolled_users() -> List[Dict[str, Any]]:
    """Retrieve all users who have enabled Bug Auto-Triage in their Portal Settings."""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM user_bug_watchdog_config WHERE is_enabled = 1"
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.warning(f"Could not read user_bug_watchdog_config from DB: {e}")
        return []


def _record_reminder_time(issue_key: str):
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        conn.execute("""
            INSERT INTO watchdog_reminders (issue_key, last_reminded_at)
            VALUES (?, ?)
            ON CONFLICT(issue_key) DO UPDATE SET last_reminded_at = excluded.last_reminded_at
        """, (issue_key, now_iso))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Could not record reminder time for {issue_key}: {e}")


def _get_last_reminder_time(issue_key: str) -> Optional[str]:
    # 1. Check dedicated watchdog_reminders table first
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        row = conn.execute(
            "SELECT last_reminded_at FROM watchdog_reminders WHERE issue_key = ?",
            (issue_key,)
        ).fetchone()
        conn.close()
        if row and row[0]:
            return row[0]
    except Exception:
        pass

    # 2. Check in-memory log
    for e in reversed(_audit_log):
        if e.get("issue_key") == issue_key and e.get("action") == "PREREQ_MISSING":
            t = e.get("reminded_at")
            if t:
                return t

    # 3. Fall back to watchdog_audit table
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        row = conn.execute(
            "SELECT reminded_at FROM watchdog_audit WHERE issue_key = ? AND action = 'PREREQ_MISSING' ORDER BY id DESC LIMIT 1",
            (issue_key,)
        ).fetchone()
        conn.close()
        return row[0] if row else None
    except Exception:
        return None


def _should_post_reminder(issue_key: str) -> bool:
    last = _get_last_reminder_time(issue_key)
    if not last:
        return True
    try:
        last_dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
        elapsed_hours = (datetime.now(timezone.utc) - last_dt).total_seconds() / 3600.0
        return elapsed_hours >= BUG_WATCHDOG_REMIND_HOURS
    except Exception:
        return True


def _record_audit(issue_key: str, user: str, priority: str, action: str, prereq_ok: bool, missing: str, notes: str, analysis_ok: Optional[bool] = None):
    global _audit_log
    now_iso = datetime.now(timezone.utc).isoformat()
    if analysis_ok is None:
        analysis_ok = (action == "ANALYSIS_DONE")

    entry = {
        "issue_key": issue_key,
        "user": user,
        "priority": priority,
        "action": action,
        "prereq_ok": bool(prereq_ok),
        "missing_items": missing,
        "analysis_ok": 1 if analysis_ok else 0,
        "reminded_at": now_iso,
        "notes": notes,
        "cycle_at": now_iso
    }

    # Deduplicate in-memory audit log by issue_key:
    # If the previous action was PREREQ_MISSING, do NOT allow a generic EVALUATED or PENDING action to flip prereq_ok to True!
    existing = next((e for e in reversed(_audit_log) if e.get("issue_key") == issue_key), None)
    if existing:
        if existing.get("action") == "PREREQ_MISSING" and action in ("EVALUATED", "PENDING_AUDIT"):
            existing["cycle_at"] = now_iso
            existing["priority"] = priority
            if missing:
                existing["missing_items"] = missing
            if notes:
                existing["notes"] = notes
            # Strictly preserve prereq_ok = False and analysis_ok = 0
            existing["prereq_ok"] = False
            existing["analysis_ok"] = 0
        else:
            existing.update(entry)
    else:
        _audit_log.append(entry)

    if len(_audit_log) > 200:
        _audit_log = _audit_log[-200:]
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        conn.execute("""
            INSERT INTO watchdog_audit
                (issue_key, priority, action, prereq_ok, missing_items, reminded_at, analysis_ok, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            issue_key, priority, action, 1 if prereq_ok else 0, missing,
            now_iso, 1 if analysis_ok else 0, f"User: {user} | {notes}"
        ))
        conn.commit()
        conn.close()
    except Exception:
        pass


def _sort_by_priority(issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    def _rank(issue: dict) -> int:
        fields = issue.get("fields") if isinstance(issue.get("fields"), dict) else {}
        pri = issue.get("priority") or fields.get("priority")
        name = (pri.get("name") if isinstance(pri, dict) else str(pri or "")).lower()
        return PRIORITY_ORDER.get(name, 99)
    return sorted(issues, key=_rank)


BUG_TRIAGE_PROMPT = """You are the GPOS Automated Bug Triage Agent running unattended.
You are triaging a bug ticket assigned to: {assignee_username}.
Issue Key: {issue_key}
Reporter: {reporter_username}
Current ticket labels: {current_labels}
Should post reminder comment if prerequisites still missing: {allow_reminder}

SPECIAL RULE FOR TICKETS WITH 'AX_AutoTriage-Done':
- If 'AX_AutoTriage-Done' is already present in Current ticket labels, prerequisite checks (Phase 3) and initial automated bug analysis report (Phase 4) have ALREADY been completed. DO NOT re-post prerequisite failure or initial analysis comments!
- Focus on Phase 1 (Ingest) and Phase 2 (Autonomous Comment Resolution).
- Inspect the comments. If a user, QE, or reporter asked an unanswered question (e.g., asking for target board IP, build version, logs, repro steps), answer it autonomously using facts from the ticket description, attachments, or summary.
- Address the user who asked using Jira user mention format `[~username]` (e.g., `[~varun.baba]`).
- Format your reply exactly as:
  [Autonomous Ticket Assistant Reply]
  Hi [~username], based on the ticket description, the target board IP is ... and the build image version is ...
- Post it immediately using `jira_add_comment(issue_key="{issue_key}", body=...)`.
- If all inquiries are already resolved, finish without posting duplicate comments.

You MUST follow this exact 4-phase procedure:

════════════════════════════════════════════════════════════════════════════════
PHASE 1: INGEST ALL TICKET FIELDS & COMMENTS
════════════════════════════════════════════════════════════════════════════════
1. Call `jira_get_issue(issue_key="{issue_key}")` to retrieve full summary, description, fields, attachments, and labels. Verify reporter username (fields.reporter.name).
2. Call `jira_get_comments(issue_key="{issue_key}")` to fetch the complete chronological comment thread.
3. Call `jira_list_attachments(issue_key="{issue_key}")` to inspect all attached artifacts.
4. Thoroughly read and understand ALL available fields: Summary, Description, Attachments, and all prior Comments.

════════════════════════════════════════════════════════════════════════════════
PHASE 2: AUTONOMOUS COMMENT RESOLUTION (RULE 2)
════════════════════════════════════════════════════════════════════════════════
- Monitor the comments section. Check if any user, QE, or developer has asked a question, requested clarification, or inquired about the bug (e.g., asking for build version, device logs, board IP, reproduction steps, test environment details, error codes, or clarification).
- If there is an unanswered question in the comments that CAN be answered using the ticket's summary, description, attachments, or prior comment history:
  - Generate an immediate, clear, professional answer citing the facts from the ticket.
  - Mention the user who asked using Jira user mention format `[~username]`.
  - Format the reply exactly as:
    [Autonomous Ticket Assistant Reply]
    Hi [~username],

    <Your clear, direct answer resolving their question based on the ticket summary, description, or attachments>
  - Post it immediately using `jira_add_comment(issue_key="{issue_key}", body=...)`.
  - Do this autonomously without waiting for human intervention!

════════════════════════════════════════════════════════════════════════════════
PHASE 3: CONDITIONAL PREREQUISITE CHECK (RULE 1)
════════════════════════════════════════════════════════════════════════════════
Evaluate the 4 prerequisites using the following exact conditional rules:
1. System or application Logs (ALWAYS MANDATORY):
   - Attached log file (.log, .txt, .tar, .tar.gz, .tgz, .zip, .7z) or full log snippet pasted in description.
2. Steps to Reproduce (ALWAYS MANDATORY):
   - Clear, numbered or detailed steps to reproduce the bug present in the summary or description.
3. Related Test Cases (ALWAYS MANDATORY):
   - Reference to a test case in description (e.g., 'TC-', 'Test Case', 'Test Scenario', 'TC_') OR a test file/automation script attached.
4. Core dump file or Crash Diagnostics (CONDITIONAL PREREQUISITE):
   - Carefully check the ticket Summary, Description, and Comments: Does the bug explicitly describe a process CRASH, SIGSEGV, segmentation fault, fatal exception, abort, panic, or core dump?
   - CRASHING BUG: 
     a) A physical coredump file (filename containing 'core' or 'dump') attached, OR
     b) An explicit raw backtrace / stack trace provided in the Summary, Description, Comments, or attached logs (e.g., lines containing '#0 0x... (/usr/lib/...)'), OR
     c) An explicit note stating why core dump is not available / N/A.
     If ANY of (a), (b), or (c) is present, mark Crash Diagnostics as SATISFIED (PASS) and proceed with analysis using backtrace symbolication or core analysis!
     Only if it describes a crash and NONE of (a), (b), or (c) is present, flag Core dump / crash diagnostics as MISSING.
   - NON-CRASHING BUG: If the ticket describes a non-crashing issue (such as a UI visual bug, functional defect, display error, button behavior, data synchronization error, or memory leak/retention without crash), SKIP the core dump check! Mark Coredump as NOT REQUIRED (PASS) and proceed with analysis.

════════════════════════════════════════════════════════════════════════════════
PHASE 4: OUTCOME & ACTIONS
════════════════════════════════════════════════════════════════════════════════
- IF ANY MANDATORY PREREQUISITE IS MISSING:
  - If 'AX_AutoTriage-Pending' is NOT in labels:
    - Formulate a clear, professional comment addressed to the reporter using Jira user mention format `[~{reporter_username}]`:
      Hi [~{reporter_username}],

      ### ❌ Prerequisites Check: FAILED
      The following mandatory items are missing from this bug report:
      - [Item Name]: [Clear explanation of what is missing and how to provide it]
      Please attach or provide the missing items so automated root cause analysis can proceed.
    - Post via `jira_add_comment(issue_key="{issue_key}", body=...)`.
    - Update issue labels: add 'AX_AutoTriage-Pending'.
  - Else if 'AX_AutoTriage-Pending' is ALREADY in labels AND allow_reminder is True:
    - Formulate a polite 24-hour follow-up reminder comment:
      Hi [~{reporter_username}],

      ### ⏰ 24-Hour Follow-Up: Prerequisites Still Required
      This is an automated follow-up reminder. Automated root cause analysis cannot proceed because the following mandatory items are still missing:
      - [Item Name]: [Clear explanation]
      Please provide or attach the missing items so automated root cause analysis can proceed.
    - Post via `jira_add_comment(issue_key="{issue_key}", body=...)`.
  - CRITICAL RULE: Never send any notification email when prerequisites are missing. Stop triage for this issue.

- IF ALL PREREQUISITES ARE PRESENT (OR SATISFIED UNDER CONDITIONAL RULES):
  - Download the logs/archives using `jira_download_attachment`.
  - If compressed, extract the archive.
  - Search logs for errors, exceptions, stack traces, or warnings using `search_log_contents` or `read_log_snippet`.
  - If raw backtrace is present in the ticket:
    - Run `symbolicate_backtrace(backtrace_text=..., target_ip=..., build_server=..., build_root=...)`.
  - If coredump is present:
    - Run `analyze_core_dump` or `run_gdb_backtrace`.
  - If a source file and line are resolved:
    - Call `fetch_git_source(file_path=..., start_line=..., end_line=..., build_server=..., build_root=...)` to inspect actual C++ code context.
    - Call `extract_git_blame(file_path=..., line=..., build_server=..., build_root=...)` to identify the regression commit SHA and author.
  - If target IP and crash timestamp are available:
    - Call `extract_pre_crash_timeline(target_ip=..., process_name=...)` to reconstruct the 10-event causal sequence.
  - If reproducible steps and target IP are present, optionally run `autonomous_reproduce_bug`.
  - Synthesize a comprehensive "### 🔎 Antigravity Automated Crash & Root Cause Report" including:
    1. Verified Crash Diagnosis (Signal, Fault Address, Memory State)
    2. Exact Function, Source File & Verified Line Number
    3. Git Blame Regression Metadata (Commit SHA, Author, Date)
    4. Pre-Crash Event Timeline
    5. Proposed C++ Fix Patch (Git Diff)
  - Post the report via `jira_add_comment(issue_key="{issue_key}", body=...)`.
  - Update issue labels: remove 'AX_AutoTriage-Pending' if present, and add 'AX_AutoTriage-Done'.
  - Call `notify_assignee_email(issue_key="{issue_key}")` to notify the assigned developer that root-cause analysis is posted.
"""

NOTIFY_EMAIL_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "notify_assignee_email",
        "description": "Send an email notification ONLY to the assigned user letting them know initial analysis has been posted to Jira.",
        "parameters": {
            "type": "object",
            "properties": {
                "issue_key": {"type": "string", "description": "The Jira issue key."}
            },
            "required": ["issue_key"]
        }
    }
}


async def process_user_bugs(user_config: Dict[str, Any], mcp_server_url: str):
    username = user_config.get("username")
    projects_str = user_config.get("jira_projects") or "SIGPOSDEV"
    projects = [p.strip().upper() for p in projects_str.split(",") if p.strip()]
    if not projects:
        projects = ["SIGPOSDEV"]
    user_pat = user_config.get("jira_pat") or DEFAULT_JIRA_PAT
    user_email = user_config.get("notify_email") or f"{username}@lge.com"
    user_llm_key = user_config.get("llm_key") or LLM_KEY
    user_llm_url = user_config.get("llm_url") or LLM_URL or "http://exacode-chat.lge.com/v1"

    if not user_pat:
        logger.warning(f"Bug watchdog: user '{username}' is enrolled but missing Jira PAT in Settings. Skipping.")
        return
    if not user_llm_key:
        logger.warning(f"Bug watchdog: user '{username}' is enrolled but missing LLM API Key in Settings. Skipping.")
        return

    import httpx
    from mcp.client.sse import sse_client
    from mcp.client.session import ClientSession
    from contextlib import AsyncExitStack

    proj_clause = ", ".join(f'"{p}"' for p in projects)
    jql = (
        f'project in ({proj_clause}) AND assignee = "{username}" AND issuetype = "Bug" '
        f'AND updated >= -{BUG_WATCHDOG_LOOKBACK_DAYS}d '
        f'ORDER BY priority ASC, updated DESC'
    )

    async with AsyncExitStack() as stack:
        try:
            jira_streams = await stack.enter_async_context(
                sse_client(f"{mcp_server_url}/sse", headers={"X-Jira-PAT": user_pat, "Authorization": f"Bearer {user_pat}"})
            )
            jira_session = await stack.enter_async_context(ClientSession(jira_streams[0], jira_streams[1]))
            await jira_session.initialize()
        except Exception as e:
            logger.error(f"Bug watchdog: could not connect to Jira MCP for user {username}: {_unwrap_exception(e)}")
            return

        device_session = None
        device_tools = []
        if DEVICE_MCP_SERVER_URL:
            try:
                dev_streams = await stack.enter_async_context(sse_client(f"{DEVICE_MCP_SERVER_URL}/sse"))
                device_session = await stack.enter_async_context(ClientSession(dev_streams[0], dev_streams[1]))
                await device_session.initialize()
                dev_tools_resp = await device_session.list_tools()
                device_tools = [
                    {
                        "type": "function",
                        "function": {
                            "name": t.name,
                            "description": t.description or "",
                            "parameters": t.input_schema or {"type": "object", "properties": {}},
                        },
                    }
                    for t in dev_tools_resp.tools
                    if t.name in {
                        "run_gdb_backtrace", "analyze_core_dump", "analyze_kernel_panic", 
                        "search_log_contents", "read_log_snippet", "extract_archive", 
                        "profile_memory_leaks", "symbolicate_backtrace", "extract_git_blame", 
                        "fetch_git_source", "fetch_debug_symbols", "extract_pre_crash_timeline", 
                        "autonomous_reproduce_bug", "deploy_and_mount_binary", "find_build_artifact"
                    }
                ]
            except Exception:
                pass

        logger.info(f"Bug watchdog [{username}]: Searching Jira bugs with JQL: {jql}")
        search_result = await jira_session.call_tool(
            "jira_search",
            arguments={"jql": jql, "fields": "summary,assignee,priority,labels,reporter", "max_results": BUG_WATCHDOG_MAX_ISSUES_PER_USER}
        )
        content_text = ""
        if isinstance(search_result.content, list):
            content_text = "\n".join(str(c.text) for c in search_result.content if hasattr(c, "text"))
        else:
            content_text = str(search_result.content)

        if "Search failed" in content_text:
            logger.error(f"Bug watchdog [{username}]: Jira search error: {content_text}")
            return
        if not content_text or "No issues found" in content_text:
            logger.info(f"Bug watchdog [{username}]: No matching bugs found for JQL.")
            return

        try:
            data = json.loads(content_text)
            candidates = data if isinstance(data, list) else data.get("issues", [])
        except Exception as e:
            logger.warning(f"Bug watchdog [{username}]: Failed to parse Jira search response: {e}")
            candidates = []

        if not candidates:
            return

        sorted_candidates = _sort_by_priority(candidates)
        logger.info(f"Bug watchdog [{username}]: Found {len(sorted_candidates)} bug candidates to evaluate.")
        jira_tools_resp = await jira_session.list_tools()
        tools = [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description or "",
                    "parameters": t.input_schema or {"type": "object", "properties": {}},
                },
            }
            for t in jira_tools_resp.tools
        ]
        tools.extend(device_tools)
        tools.append(NOTIFY_EMAIL_TOOL_SCHEMA)

        for candidate in sorted_candidates:
            issue_key = candidate.get("key") or candidate.get("id")
            if not issue_key:
                continue

            raw_fields = candidate.get("fields") if isinstance(candidate.get("fields"), dict) else {}
            labels_val = candidate.get("labels") or raw_fields.get("labels") or []
            if isinstance(labels_val, str):
                current_labels = [l.strip() for l in labels_val.split(",") if l.strip()]
            elif isinstance(labels_val, list):
                current_labels = [str(l) for l in labels_val]
            else:
                current_labels = []

            is_pending = "AX_AutoTriage-Pending" in current_labels
            allow_reminder = _should_post_reminder(issue_key)

            pri_val = candidate.get("priority") or raw_fields.get("priority")
            if isinstance(pri_val, dict):
                pri_name = pri_val.get("name", "Normal")
            else:
                pri_name = str(pri_val or "Normal")

            reporter_val = candidate.get("reporter") or raw_fields.get("reporter")
            if isinstance(reporter_val, dict):
                reporter_username = reporter_val.get("name") or reporter_val.get("key") or ""
            elif isinstance(reporter_val, str):
                reporter_username = reporter_val
            else:
                reporter_username = ""

            # DEDUPLICATION & QUOTA GUARD:
            # If the ticket is already marked AX_AutoTriage-Done, only invoke LLM if there is an actual NEW unresolved inquiry.
            if "AX_AutoTriage-Done" in current_labels:
                try:
                    c_resp = await jira_session.call_tool("jira_get_comments", arguments={"issue_key": issue_key})
                    c_text = ""
                    if isinstance(c_resp.content, list):
                        c_text = "\n".join(str(c.text) for c in c_resp.content if hasattr(c, "text"))
                    else:
                        c_text = str(c_resp.content)
                    c_data = json.loads(c_text)
                    c_list = c_data.get("comments", []) if isinstance(c_data, dict) else (c_data if isinstance(c_data, list) else [])
                    
                    has_unresolved_inquiry = False
                    for c in reversed(c_list[-10:]):
                        body = str(c.get("body") or "")
                        author = c.get("author", {}).get("name") if isinstance(c.get("author"), dict) else str(c.get("author") or "")
                        # If latest relevant comment is already our autonomous reply, all inquiries are resolved!
                        if "[autonomous ticket assistant reply]" in body.lower():
                            has_unresolved_inquiry = False
                            break
                        # If another user posted ANY comment after our assistant reply:
                        if author.lower() != username.lower() and not body.strip().startswith("[Autonomous Ticket Assistant Reply]"):
                            has_unresolved_inquiry = True
                            break
                    
                    if not has_unresolved_inquiry:
                        logger.info(f"Bug watchdog [{username}]: {issue_key} already triaged and no new inquiries. Skipping.")
                        _record_audit(issue_key, username, pri_name, "COMMENT_RESOLVED", True, "", "Analysis completed & all inquiries resolved", analysis_ok=True)
                        continue
                except Exception as check_err:
                    logger.debug(f"Could not check comments pre-filter for {issue_key}: {check_err}")

            # If ticket is AX_AutoTriage-Pending, respect 24h cooldown unless QE submitted new comments or attachments
            elif is_pending:
                allow_reminder = _should_post_reminder(issue_key)
                if not allow_reminder:
                    try:
                        c_resp = await jira_session.call_tool("jira_get_comments", arguments={"issue_key": issue_key})
                        c_text = ""
                        if isinstance(c_resp.content, list):
                            c_text = "\n".join(str(c.text) for c in c_resp.content if hasattr(c, "text"))
                        else:
                            c_text = str(c_resp.content)
                        c_data = json.loads(c_text)
                        c_list = c_data.get("comments", []) if isinstance(c_data, dict) else (c_data if isinstance(c_data, list) else [])

                        has_new_human_comment = False
                        for c in reversed(c_list[-5:]):
                            body = str(c.get("body") or "")
                            author = c.get("author", {}).get("name") if isinstance(c.get("author"), dict) else str(c.get("author") or "")
                            if "prerequisites check: failed" in body.lower() or "24-hour follow-up" in body.lower():
                                break
                            if author.lower() != username.lower() and not body.strip().startswith("[Autonomous Ticket Assistant Reply]"):
                                has_new_human_comment = True
                                break

                        attachments_val = candidate.get("attachment") or raw_fields.get("attachment") or []
                        has_attachments = bool(attachments_val)

                        if not has_new_human_comment and not has_attachments:
                            logger.info(f"Bug watchdog [{username}]: 24h cooldown active for {issue_key} and no new evidence submitted. Skipping.")
                            _record_audit(issue_key, username, pri_name, "PREREQ_MISSING", False, "Missing evidence (cooldown active)", "Pending reporter evidence (24h cooldown active)", analysis_ok=False)
                            continue
                    except Exception as check_err:
                        logger.debug(f"Could not check pending pre-filter for {issue_key}: {check_err}")

            llm_failed = False
            llm_error_msg = ""
            prompt = BUG_TRIAGE_PROMPT.format(
                assignee_username=username,
                issue_key=issue_key,
                reporter_username=reporter_username or "reporter",
                current_labels=json.dumps(current_labels),
                allow_reminder=allow_reminder
            )
            dev_b_ip = user_config.get("build_server_ip", "")
            dev_b_root = user_config.get("build_root_path", "")
            dev_target_ip = user_config.get("target_board_ip", "")
            dev_info = []
            if dev_b_ip:
                dev_info.append(f"Developer Build Server IP: {dev_b_ip}")
            if dev_b_root:
                dev_info.append(f"Developer Build Workspace Root: {dev_b_root}")
            if dev_target_ip:
                dev_info.append(f"Developer Target Board IP: {dev_target_ip}")
            dev_context = ("\nDeveloper Profile Configuration:\n- " + "\n- ".join(dev_info)) if dev_info else ""

            messages = [
                {"role": "system", "content": prompt},
                {"role": "user", "content": f"Begin bug triage for {issue_key}. Reporter: {reporter_username}. Priority: {pri_name}. Existing labels: {current_labels}.{dev_context}"}
            ]

            is_google_api = "googleapis.com" in user_llm_url.lower() or "generativelanguage" in user_llm_url.lower()
            if is_google_api:
                model_name = "gemini-3-flash-preview"
                headers = {
                    "Authorization": f"Bearer {user_llm_key}",
                    "Content-Type": "application/json",
                }
            else:
                model_name = "Chat-EXACODE-A"
                headers = {
                    "Authorization": f"Bearer {user_llm_key}",
                    "Content-Type": "application/json",
                    "X-Title": "EXACODE SWE(API)",
                    "X-Model": "Chat-EXACODE-A",
                }
            llm_url = user_llm_url.rstrip('/')
            if not llm_url.endswith('chat/completions'):
                llm_url += '/chat/completions' if llm_url.endswith('v1') else '/v1/chat/completions'

            async with httpx.AsyncClient(timeout=180.0) as client:
                for _ in range(15):
                    payload = {
                        "model": model_name,
                        "messages": messages,
                        "tools": tools,
                        "tool_choice": "auto",
                        "temperature": 0.1,
                    }
                    try:
                        resp = await client.post(llm_url, headers=headers, json=payload)
                        if resp.status_code == 503 and is_google_api and model_name != "gemini-3.5-flash":
                            model_name = "gemini-3.5-flash"
                            payload["model"] = model_name
                            resp = await client.post(llm_url, headers=headers, json=payload)
                        if resp.status_code != 200:
                            logger.error(f"Bug watchdog LLM error ({resp.status_code}): {resp.text}")
                            llm_failed = True
                            llm_error_msg = f"LLM Error ({resp.status_code})"
                            break
                        res_json = resp.json()
                        msg = res_json["choices"][0]["message"]
                        messages.append(msg)
                        if not msg.get("tool_calls"):
                            break

                        for tool_call in msg["tool_calls"]:
                            fn = tool_call["function"]["name"]
                            try:
                                args = json.loads(tool_call["function"]["arguments"])
                            except Exception:
                                args = {}

                            call_res = ""
                            if fn == "notify_assignee_email":
                                subject = f"[Initial Analysis] {issue_key}: Automated bug analysis updated in Jira"
                                jira_link = f"{JIRA_BASE_URL}/browse/{issue_key}"
                                body = (
                                    f"Hi {username},\n\n"
                                    f"An initial automated analysis has been added to bug ticket {issue_key} in Jira.\n\n"
                                    f"Please review the analysis, verify the findings, and edit/refine the comment if needed:\n"
                                    f"{jira_link}\n\n"
                                    f"— GPOS AX Portal Bug Analyser"
                                )
                                call_res = _send_email_to_assignee(user_email, subject, body)
                                _record_audit(issue_key, username, pri_name, "ANALYSIS_DONE", True, "", "Email sent to assignee", analysis_ok=True)
                            elif device_session and any(t["function"]["name"] == fn for t in device_tools):
                                if fn in ("deploy_and_mount_binary", "find_build_artifact", "fetch_git_source", "extract_git_blame"):
                                    u_b_ip = user_config.get("build_server_ip", "")
                                    u_b_root = user_config.get("build_root_path", "")
                                    if not args.get("build_server") and u_b_ip:
                                        args["build_server"] = u_b_ip
                                    if not args.get("build_root") and u_b_root:
                                        args["build_root"] = u_b_root
                                    if args.get("build_server") and "@" not in str(args["build_server"]):
                                        args["build_server"] = f"{username}@{args['build_server']}"
                                res = await device_session.call_tool(fn, arguments=args)
                                call_res = str(res.content)
                            else:
                                if fn == "jira_add_comment":
                                    if "comment" in args and "body" not in args:
                                        args["body"] = args.pop("comment")
                                    if "text" in args and "body" not in args:
                                        args["body"] = args.pop("text")
                                    comment_text = str(args.get("body") or "")

                                    # Distinguish autonomous comment replies from failure and analysis reports
                                    is_autonomous_reply = "[autonomous ticket assistant reply]" in comment_text.lower() or "autonomous" in comment_text.lower()
                                    is_failure_comment = ("failed" in comment_text.lower() or "missing" in comment_text.lower()) and not is_autonomous_reply
                                    is_analysis_comment = ("initial automated bug analysis" in comment_text.lower() or "🔎" in comment_text) and not is_failure_comment and not is_autonomous_reply

                                    # Guarantee reporter mention in prerequisite failure comment
                                    if is_failure_comment and reporter_username:
                                        mention_tag = f"[~{reporter_username}]"
                                        if mention_tag not in comment_text and f"@{reporter_username}" not in comment_text:
                                            args["body"] = f"Hi {mention_tag},\n\n" + comment_text.lstrip()
                                            comment_text = args["body"]

                                    if is_pending and not allow_reminder and is_failure_comment:
                                        logger.info(f"Bug watchdog [{username}]: 24h cooldown active for {issue_key}; skipping duplicate reminder comment.")
                                        call_res = json.dumps({"status": "skipped", "message": f"Reminder comment skipped: 24h cooldown active. Already reminded within {BUG_WATCHDOG_REMIND_HOURS} hours."})
                                        _record_audit(issue_key, username, pri_name, "PREREQ_MISSING", False, "Missing evidence (cooldown active)", "Reminder skipped due to 24h cooldown", analysis_ok=False)
                                    else:
                                        res = await jira_session.call_tool(fn, arguments=args)
                                        call_res = str(res.content)
                                        if is_failure_comment:
                                            _record_reminder_time(issue_key)
                                            missing_desc = "Missing evidence (logs/coredump/repro/tests)"
                                            for line in comment_text.splitlines():
                                                if "missing" in line.lower() and (":" in line or "-" in line):
                                                    missing_desc = line.strip().lstrip("-*# ").strip()
                                                    break
                                            # Automatically ensure AX_AutoTriage-Pending label is saved to Jira
                                            if "AX_AutoTriage-Pending" not in current_labels:
                                                try:
                                                    new_labels = list(set(current_labels + ["AX_AutoTriage-Pending"]))
                                                    await jira_session.call_tool("jira_update_issue", arguments={"issue_key": issue_key, "fields": {"labels": new_labels}})
                                                    current_labels = new_labels
                                                    is_pending = True
                                                except Exception as err:
                                                    logger.warning(f"Could not update pending label for {issue_key}: {err}")
                                            _record_audit(issue_key, username, pri_name, "PREREQ_MISSING", False, missing_desc, "Prerequisite comment posted to Jira", analysis_ok=False)
                                        elif is_analysis_comment:
                                            # Clean labels: remove Pending, add Done
                                            clean_labels = [l for l in current_labels if l != "AX_AutoTriage-Pending"]
                                            if "AX_AutoTriage-Done" not in clean_labels:
                                                clean_labels.append("AX_AutoTriage-Done")
                                            try:
                                                await jira_session.call_tool("jira_update_issue", arguments={"issue_key": issue_key, "fields": {"labels": clean_labels}})
                                                current_labels = clean_labels
                                            except Exception as err:
                                                logger.warning(f"Could not update done label for {issue_key}: {err}")
                                            _record_audit(issue_key, username, pri_name, "ANALYSIS_DONE", True, "", "Analysis comment posted on ticket", analysis_ok=True)
                                        elif is_autonomous_reply:
                                            _record_audit(issue_key, username, pri_name, "COMMENT_RESOLVED", True, "", "Autonomous answer posted to user/QE inquiry", analysis_ok=True)
                                        else:
                                            _record_audit(issue_key, username, pri_name, "COMMENTED", False, "", "Comment posted on ticket", analysis_ok=False)
                                elif fn == "jira_update_issue":
                                    if "fields" not in args and any(k != "issue_key" for k in args):
                                        sub_fields = {k: v for k, v in args.items() if k != "issue_key"}
                                        args = {"issue_key": args.get("issue_key", issue_key), "fields": sub_fields}
                                    res = await jira_session.call_tool(fn, arguments=args)
                                    call_res = str(res.content)
                                else:
                                    res = await jira_session.call_tool(fn, arguments=args)
                                    call_res = str(res.content)
                                    if fn in ("jira_get_issue", "get_jira_issue"):
                                        try:
                                            issue_data = json.loads(call_res)
                                            fields = issue_data.get("fields", {}) if isinstance(issue_data, dict) else {}
                                            if fields:
                                                clean_issue = {
                                                    "key": issue_data.get("key", issue_key),
                                                    "summary": fields.get("summary"),
                                                    "description": fields.get("description"),
                                                    "reporter": fields.get("reporter", {}).get("name") if isinstance(fields.get("reporter"), dict) else fields.get("reporter"),
                                                    "assignee": fields.get("assignee", {}).get("name") if isinstance(fields.get("assignee"), dict) else fields.get("assignee"),
                                                    "priority": fields.get("priority", {}).get("name") if isinstance(fields.get("priority"), dict) else fields.get("priority"),
                                                    "labels": fields.get("labels", []),
                                                    "attachments": [
                                                        {"id": a.get("id"), "filename": a.get("filename"), "size": a.get("size")}
                                                        for a in fields.get("attachment", []) if isinstance(a, dict)
                                                    ],
                                                    "comments": [
                                                        {
                                                            "id": c.get("id"),
                                                            "author": c.get("author", {}).get("name") if isinstance(c.get("author"), dict) else c.get("author"),
                                                            "created": c.get("created"),
                                                            "body": c.get("body")
                                                        }
                                                        for c in fields.get("comment", {}).get("comments", [])[-15:] if isinstance(c, dict)
                                                    ]
                                                }
                                                call_res = json.dumps(clean_issue, indent=2)
                                                if not reporter_username:
                                                    rep_obj = fields.get("reporter")
                                                    if isinstance(rep_obj, dict):
                                                        reporter_username = rep_obj.get("name") or rep_obj.get("key") or ""
                                                    elif isinstance(rep_obj, str):
                                                        reporter_username = rep_obj
                                        except Exception as parse_err:
                                            logger.warning(f"Failed to compact issue json: {parse_err}")
                                    elif fn == "jira_get_comments":
                                        try:
                                            comments_data = json.loads(call_res)
                                            comment_list = comments_data.get("comments", []) if isinstance(comments_data, dict) else (comments_data if isinstance(comments_data, list) else [])
                                            clean_comments = [
                                                {
                                                    "id": c.get("id"),
                                                    "author": c.get("author", {}).get("name") if isinstance(c.get("author"), dict) else c.get("author"),
                                                    "created": c.get("created"),
                                                    "body": c.get("body")
                                                }
                                                for c in comment_list[-15:] if isinstance(c, dict)
                                            ]
                                            call_res = json.dumps(clean_comments, indent=2)
                                        except Exception:
                                            pass

                            messages.append({
                                "role": "tool",
                                "tool_call_id": tool_call["id"],
                                "name": fn,
                                "content": call_res[:16000]
                            })
                    except Exception as e:
                        logger.error(f"Error during triage of {issue_key}: {e}")
                        break

            # If LLM failed (e.g. 429 quota or network), do not report misleading PREREQ FAIL
            if llm_failed:
                _record_audit(issue_key, username, pri_name, "ERROR", False, llm_error_msg, f"Triage paused due to {llm_error_msg}", analysis_ok=False)
                continue

            # Candidate cycle completion check
            # Preserve existing audit status; do NOT overwrite PREREQ_MISSING with EVALUATED or PASS!
            existing_audit = next((a for a in reversed(_audit_log) if a.get("issue_key") == issue_key), None)
            if not existing_audit:
                if is_pending:
                    _record_audit(issue_key, username, pri_name, "PREREQ_MISSING", False, "Missing evidence (pending reporter response)", "Pending reporter evidence (24h cooldown active)", analysis_ok=False)
                elif "AX_AutoTriage-Done" in current_labels:
                    _record_audit(issue_key, username, pri_name, "ANALYSIS_DONE", True, "", "Analysis already completed", analysis_ok=True)
                else:
                    _record_audit(issue_key, username, pri_name, "EVALUATED", False, "Under triage", "Cycle check complete (no action taken)", analysis_ok=False)
            else:
                existing_audit["cycle_at"] = datetime.now(timezone.utc).isoformat()


async def run_bug_triage_cycle(mcp_server_url: str):
    users = _get_enrolled_users()
    if not users:
        return

    for user_cfg in users:
        try:
            await process_user_bugs(user_cfg, mcp_server_url)
        except Exception as e:
            logger.error(f"Error processing bugs for user {user_cfg.get('username')}: {_unwrap_exception(e)}")


async def _bug_watchdog_loop(mcp_server_url: str):
    logger.info("Multi-Tenant Bug Analyser worker started.")
    await asyncio.sleep(5)
    while True:
        try:
            await run_bug_triage_cycle(mcp_server_url)
        except Exception as e:
            logger.error(f"Bug watchdog loop crashed: {_unwrap_exception(e)}", exc_info=True)
        await asyncio.sleep(BUG_WATCHDOG_INTERVAL_SECONDS)


def start_bug_watchdog(mcp_server_url: str):
    """Starts the multi-tenant background bug triage engine."""
    asyncio.create_task(_bug_watchdog_loop(mcp_server_url))


def get_watchdog_status() -> Dict[str, Any]:
    users = _get_enrolled_users()
    first_project = users[0].get("jira_projects") if (users and users[0].get("jira_projects")) else "SIGPOSDEV"
    return {
        "enabled": len(users) > 0,
        "interval_s": BUG_WATCHDOG_INTERVAL_SECONDS,
        "remind_hours": BUG_WATCHDOG_REMIND_HOURS,
        "project": first_project,
        "jira_base_url": JIRA_BASE_URL,
        "enrolled_users_count": len(users),
        "watched_users": [u.get("username") for u in users],
        "recent_entries": _audit_log[-50:]
    }
