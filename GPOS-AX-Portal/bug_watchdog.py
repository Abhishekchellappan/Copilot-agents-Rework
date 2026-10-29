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
4. For each bug, checks 4 prerequisites:
   - System/Application Logs
   - Coredump file
   - Steps to Reproduce
   - Related Test Cases
5. If prerequisites are MISSING:
   - Posts a comment on the Jira ticket listing missing items.
   - Adds label 'AX_AutoTriage-Pending'.
   - NO EMAIL is sent to reporter or user (zero email spam; discussion stays on Jira ticket).
6. If prerequisites are PRESENT:
   - Downloads logs/coredumps, performs crash signal search and Device Agent GDB analysis.
   - Posts "🔎 Initial Automated Bug Analysis" comment directly to the Jira ticket.
   - Adds label 'AX_AutoTriage-Done'.
   - Sends notification email ONLY to the assigned user:
     "Initial analysis added to <KEY>. Please review and edit if needed."
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
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Could not initialize watchdog_audit table: {e}")

_init_watchdog_db()


def _get_enrolled_users() -> List[Dict[str, Any]]:
    """Retrieve all users who have enabled Bug Auto-Triage in their Portal Settings."""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT username, is_enabled, jira_projects, jira_pat, target_board_ip, notify_email, llm_url, llm_key "
            "FROM user_bug_watchdog_config WHERE is_enabled = 1"
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.warning(f"Could not read user_bug_watchdog_config from DB: {e}")
        return []


def _get_last_reminder_time(issue_key: str) -> Optional[str]:
    # 1. Check in-memory log first
    for e in reversed(_audit_log):
        if e.get("issue_key") == issue_key and e.get("action") == "PREREQ_MISSING":
            t = e.get("reminded_at") or e.get("cycle_at")
            if t:
                return t

    # 2. Fall back to SQLite database
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


def _record_audit(issue_key: str, user: str, priority: str, action: str, prereq_ok: bool, missing: str, notes: str):
    global _audit_log
    now_iso = datetime.now(timezone.utc).isoformat()
    entry = {
        "issue_key": issue_key,
        "user": user,
        "priority": priority,
        "action": action,
        "prereq_ok": prereq_ok,
        "missing_items": missing,
        "analysis_ok": 1 if prereq_ok else 0,
        "reminded_at": now_iso,
        "notes": notes,
        "cycle_at": now_iso
    }

    # Deduplicate in-memory audit log: if same issue and same action exists, update it rather than duplicating
    existing = next((e for e in reversed(_audit_log) if e.get("issue_key") == issue_key and e.get("action") == action), None)
    if existing:
        existing["cycle_at"] = now_iso
        existing["priority"] = priority
        existing["missing_items"] = missing or existing.get("missing_items", "")
        existing["notes"] = notes
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
            now_iso, 1 if prereq_ok else 0, f"User: {user} | {notes}"
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
Current ticket labels: {current_labels}
Should post reminder comment if prerequisites still missing: {allow_reminder}

Your task:
1. Call `jira_get_issue(issue_key="{issue_key}")` to retrieve full description, fields, and labels.
2. Call `jira_list_attachments(issue_key="{issue_key}")` to inspect attached evidence.
3. Check the 4 mandatory prerequisites:
   A. System or application Logs attached (.log, .txt, .tar, .tar.gz, .tgz, .zip, .7z)
   B. Coredump file attached (filename containing 'core' or 'dump') OR explicitly mentioned as N/A in description
   C. Detailed Steps to Reproduce present in description
   D. Related Test Cases referenced in description (e.g. 'TC-', 'Test Case', 'Test Scenario') or test file attached

4. If ANY prerequisite is MISSING:
   - If 'AX_AutoTriage-Pending' is NOT in labels, OR if allow_reminder is True:
     - Formulate a clear, professional comment starting with:
       ### ❌ Prerequisites Check: FAILED
       The following mandatory items are missing:
       - [List missing items here with instructions on what to attach]
       Please attach the required items so automated root cause analysis can proceed.
     - Call `jira_add_comment(issue_key="{issue_key}", body=...)` with this comment text.
     - Call `jira_update_issue(issue_key="{issue_key}", fields={{"labels": existing_labels + ["AX_AutoTriage-Pending"]}})`
   - CRITICAL RULE: Do NOT send any email when prerequisites are missing. Stop triage for this issue.

5. If ALL 4 prerequisites are PRESENT:
   - Download the log/coredump using `jira_download_attachment`.
   - If compressed, call `extract_archive`.
   - Call `search_log_contents` or `read_log_snippet` to locate errors, crashes, SIGSEGV, Call Trace, or assertion failures.
   - If coredump is present and Device Agent tools (e.g., `run_gdb_backtrace`) are available, use them.
   - Call `jira_add_comment(issue_key="{issue_key}", body=...)` with the comprehensive "### 🔎 Initial Automated Bug Analysis" report.
   - Clean labels: remove 'AX_AutoTriage-Pending' if present, and add 'AX_AutoTriage-Done'. Call `jira_update_issue(issue_key="{issue_key}", fields={{"labels": cleaned_labels + ["AX_AutoTriage-Done"]}})`.
   - Call `notify_assignee_email(issue_key="{issue_key}")` so the assigned developer is informed that the initial analysis has been posted and they can review/edit it.
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
        f'AND (labels is EMPTY OR labels not in ("AX_AutoTriage-Done")) '
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
                    if t.name in {"run_gdb_backtrace", "analyze_core_dump", "analyze_kernel_panic", "search_log_contents", "read_log_snippet", "extract_archive"}
                ]
            except Exception:
                pass

        logger.info(f"Bug watchdog [{username}]: Searching Jira bugs with JQL: {jql}")
        search_result = await jira_session.call_tool(
            "jira_search",
            arguments={"jql": jql, "fields": "summary,assignee,priority,labels", "max_results": BUG_WATCHDOG_MAX_ISSUES_PER_USER}
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

            prompt = BUG_TRIAGE_PROMPT.format(
                assignee_username=username,
                issue_key=issue_key,
                current_labels=json.dumps(current_labels),
                allow_reminder=allow_reminder
            )
            messages = [
                {"role": "system", "content": prompt},
                {"role": "user", "content": f"Begin bug triage for {issue_key}. Priority: {pri_name}. Existing labels: {current_labels}."}
            ]

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
                        "model": "Chat-EXACODE-A",
                        "messages": messages,
                        "tools": tools,
                        "tool_choice": "auto",
                        "temperature": 0.1,
                    }
                    try:
                        resp = await client.post(llm_url, headers=headers, json=payload)
                        if resp.status_code != 200:
                            logger.error(f"Bug watchdog LLM error ({resp.status_code}): {resp.text}")
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
                                _record_audit(issue_key, username, pri_name, "ANALYSIS_DONE", True, "", "Email sent to assignee")
                            elif device_session and any(t["function"]["name"] == fn for t in device_tools):
                                res = await device_session.call_tool(fn, arguments=args)
                                call_res = str(res.content)
                            else:
                                if fn == "jira_add_comment":
                                    if "comment" in args and "body" not in args:
                                        args["body"] = args.pop("comment")
                                    if "text" in args and "body" not in args:
                                        args["body"] = args.pop("text")
                                    comment_text = str(args.get("body") or "")
                                    is_failure_comment = "failed" in comment_text.lower() or "missing" in comment_text.lower()

                                    if is_pending and not allow_reminder and is_failure_comment:
                                        logger.info(f"Bug watchdog [{username}]: 24h cooldown active for {issue_key}; skipping duplicate reminder comment.")
                                        call_res = json.dumps({"status": "skipped", "message": f"Reminder comment skipped: 24h cooldown active. Already reminded within {BUG_WATCHDOG_REMIND_HOURS} hours."})
                                        _record_audit(issue_key, username, pri_name, "PREREQ_MISSING", False, "Missing evidence (cooldown active)", "Reminder skipped due to 24h cooldown")
                                    else:
                                        res = await jira_session.call_tool(fn, arguments=args)
                                        call_res = str(res.content)
                                        if is_failure_comment:
                                            missing_desc = "Missing evidence (logs/coredump/repro/tests)"
                                            for line in comment_text.splitlines():
                                                if "missing" in line.lower() and (":" in line or "-" in line):
                                                    missing_desc = line.strip().lstrip("-*# ").strip()
                                                    break
                                            _record_audit(issue_key, username, pri_name, "PREREQ_MISSING", False, missing_desc, "Prerequisite comment posted to Jira")
                                        else:
                                            _record_audit(issue_key, username, pri_name, "ANALYSIS_DONE", True, "", "Analysis comment posted on ticket")
                                elif fn == "jira_update_issue":
                                    if "fields" not in args and any(k != "issue_key" for k in args):
                                        sub_fields = {k: v for k, v in args.items() if k != "issue_key"}
                                        args = {"issue_key": args.get("issue_key", issue_key), "fields": sub_fields}
                                    res = await jira_session.call_tool(fn, arguments=args)
                                    call_res = str(res.content)
                                else:
                                    res = await jira_session.call_tool(fn, arguments=args)
                                    call_res = str(res.content)

                            messages.append({
                                "role": "tool",
                                "tool_call_id": tool_call["id"],
                                "name": fn,
                                "content": call_res[:4000]
                            })
                    except Exception as e:
                        logger.error(f"Error during triage of {issue_key}: {e}")
                        break

            if not any(a["issue_key"] == issue_key for a in _audit_log[-5:]):
                _record_audit(issue_key, username, pri_name, "PENDING_AUDIT" if is_pending else "EVALUATED", not is_pending, "Waiting for developer evidence" if is_pending else "Evaluated", "Cycle check complete")


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
