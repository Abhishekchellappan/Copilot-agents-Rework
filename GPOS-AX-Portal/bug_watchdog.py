"""
Automated Bug Triage Watchdog  v2.0
=====================================
Runs unattended on a timer (no chat session, no logged-in user).

NEW in v2.0
-----------
1. Priority-based ordering  — P1 (Blocker/Critical) bugs are processed first.
2. Four prerequisites        — Logs, Coredump, Reproducible Steps, Related Test Cases.
3. Re-assignment detection   — uses 'updated >= -Nd' so reassigned bugs are caught, not just new ones.
4. Reporter notification     — emails the reporter when prerequisites are missing.
5. Auto-user detection       — reads allowed users from the portal SQLite DB; BUG_WATCHDOG_USERS
                               env var is an optional override/append list.
6. Device Agent integration  — connects to Device MCP alongside Jira MCP so GDB / coredump
                               analysis tools are available to the LLM when coredump files exist.
7. Portal status API         — exposes /api/watchdog/bug-status (GET) and /api/watchdog/bug-status
                               (POST reset) so the frontend can display a live audit log.

LABEL GATING FIX
-----------------
- AX_AutoTriage-Done    → PERMANENT skip.  Analysis is complete; never reprocess.
- AX_AutoTriage-Pending → RE-CHECK every cycle.  If the tester has now attached the missing
                          prerequisites the watchdog will run the full analysis and upgrade the
                          label to AX_AutoTriage-Done.  If prereqs are STILL missing it posts
                          another reminder comment (rate-limited to once per BUG_WATCHDOG_REMIND_HOURS).

Kept in its own module so this opt-in feature never touches server.py's
existing chat/tool-calling code paths.
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
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# ─── Config (env-driven, opt-in) ─────────────────────────────────────────────
BUG_WATCHDOG_ENABLED             = os.environ.get('BUG_WATCHDOG_ENABLED', 'false').strip().lower() == 'true'
BUG_WATCHDOG_INTERVAL_SECONDS    = int(os.environ.get('BUG_WATCHDOG_INTERVAL_SECONDS', '300'))
BUG_WATCHDOG_PROJECT_KEY         = os.environ.get('BUG_WATCHDOG_PROJECT_KEY', 'SIGPOSDEV').strip()
# Optional override / seed list; auto-discovery from DB is the primary source now.
BUG_WATCHDOG_USERS               = [u.strip() for u in os.environ.get('BUG_WATCHDOG_USERS', '').split(',') if u.strip()]
BUG_WATCHDOG_LOOKBACK_DAYS       = int(os.environ.get('BUG_WATCHDOG_LOOKBACK_DAYS', '1'))
BUG_WATCHDOG_MAX_ISSUES_PER_CYCLE= int(os.environ.get('BUG_WATCHDOG_MAX_ISSUES_PER_CYCLE', '10'))
BUG_WATCHDOG_JIRA_PAT            = os.environ.get('BUG_WATCHDOG_JIRA_PAT', '').strip() or os.environ.get('JIRA_PAT', '').strip()
BUG_WATCHDOG_LLM_URL             = os.environ.get('BUG_WATCHDOG_LLM_URL', 'http://exacode-chat.lge.com/v1').strip()
BUG_WATCHDOG_LLM_KEY             = os.environ.get('BUG_WATCHDOG_LLM_KEY', '').strip()
# How many hours must pass before a re-reminder is posted on a still-Pending bug
BUG_WATCHDOG_REMIND_HOURS        = int(os.environ.get('BUG_WATCHDOG_REMIND_HOURS', '24'))
# Portal DB path (shared with server.py)
DB_PATH                          = os.environ.get('DB_PATH', '/tmp/gpos_portal.db')
# Device MCP server URL (for GDB / coredump analysis tools)
DEVICE_MCP_SERVER_URL            = os.environ.get('DEVICE_MCP_SERVER_URL', 'http://gpos-muralidhar-device-service:8000').rstrip('/')

# SMTP relay
SMTP_HOST     = os.environ.get('SMTP_HOST', '').strip()
SMTP_PORT     = int(os.environ.get('SMTP_PORT', '25'))
SMTP_FROM     = os.environ.get('SMTP_FROM', 'gpos-ax-portal@lge.com').strip()
SMTP_USE_TLS  = os.environ.get('SMTP_USE_TLS', 'false').strip().lower() == 'true'
SMTP_USERNAME = os.environ.get('SMTP_USERNAME', '').strip()
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '').strip()

# Priority ordering (lower number = higher priority)
PRIORITY_ORDER: Dict[str, int] = {
    "blocker":  0, "p1": 0,
    "critical": 1, "p2": 1,
    "major":    2, "p3": 2,
    "minor":    3, "p4": 3,
    "trivial":  4, "p5": 4,
}

# ─── In-memory audit log (last N cycles; also persisted in watchdog_audit table) ───
_audit_log: List[Dict[str, Any]] = []
_audit_max = 200


# ─────────────────────────────────────────────────────────────────────────────
# Helper utilities
# ─────────────────────────────────────────────────────────────────────────────

def _unwrap_exception(e: BaseException) -> str:
    """Recursively extract the deepest root cause from ExceptionGroup / TaskGroup errors."""
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


def _send_email_notification(
    to_email: str, subject: str, body: str, cc_email: str = ""
) -> str:
    """Deliver a real SMTP email so notification doesn't depend on Jira's notification scheme.
    Supports an optional CC address (used to copy the reporter when notifying the assignee).
    """
    if not SMTP_HOST:
        return "Email skipped: SMTP_HOST is not configured on the portal."
    if not to_email:
        return "Email skipped: no recipient email address was provided."
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = SMTP_FROM
        msg["To"]      = to_email
        if cc_email:
            msg["Cc"] = cc_email
        msg.attach(MIMEText(body, "plain", "utf-8"))
        recipients = [to_email] + ([cc_email] if cc_email else [])
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            if SMTP_USE_TLS:
                server.starttls()
            if SMTP_USERNAME and SMTP_PASSWORD:
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM, recipients, msg.as_string())
        cc_note = f" (CC: {cc_email})" if cc_email else ""
        return f"Email sent to {to_email}{cc_note}."
    except Exception as e:
        return f"Email failed to send to {to_email}: {e}"


def _get_watched_users_from_db() -> List[str]:
    """Read currently allowed/active users from the portal SQLite DB.
    Falls back gracefully if the DB is unavailable.
    """
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        rows = conn.execute(
            "SELECT username FROM users WHERE is_allowed = 1"
        ).fetchall()
        conn.close()
        return [r[0] for r in rows if r[0]]
    except Exception as e:
        logger.warning(f"Bug watchdog: could not read users from portal DB: {e}")
        return []


def _get_all_watched_users() -> List[str]:
    """Merge DB users with any manually configured BUG_WATCHDOG_USERS env var (deduped)."""
    db_users  = _get_watched_users_from_db()
    env_users = BUG_WATCHDOG_USERS
    merged    = list(dict.fromkeys(db_users + env_users))  # preserve order, dedupe
    return merged


def _init_watchdog_db():
    """Ensure the watchdog audit table exists in the portal DB."""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS watchdog_audit (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                cycle_at     TEXT DEFAULT CURRENT_TIMESTAMP,
                issue_key    TEXT NOT NULL,
                priority     TEXT,
                action       TEXT,
                prereq_ok    INTEGER DEFAULT 0,
                missing_items TEXT,
                reminded_at  TEXT,
                analysis_ok  INTEGER DEFAULT 0,
                notes        TEXT
            )
        """)
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Bug watchdog: could not init audit DB table: {e}")


def _write_audit(record: Dict[str, Any]):
    """Write a single triage event to the audit DB and in-memory log."""
    global _audit_log
    _audit_log.append({**record, "cycle_at": datetime.now(timezone.utc).isoformat()})
    if len(_audit_log) > _audit_max:
        _audit_log = _audit_log[-_audit_max:]
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("""
            INSERT INTO watchdog_audit
                (issue_key, priority, action, prereq_ok, missing_items, reminded_at, analysis_ok, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            record.get("issue_key", ""),
            record.get("priority", ""),
            record.get("action", ""),
            1 if record.get("prereq_ok") else 0,
            record.get("missing_items", ""),
            record.get("reminded_at", ""),
            1 if record.get("analysis_ok") else 0,
            record.get("notes", ""),
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Bug watchdog: audit DB write failed: {e}")


def _get_last_reminded_at(issue_key: str) -> str | None:
    """Return the ISO timestamp of the last reminder posted for this issue, or None."""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        row  = conn.execute(
            "SELECT reminded_at FROM watchdog_audit WHERE issue_key = ? AND action = 'REMINDED' ORDER BY id DESC LIMIT 1",
            (issue_key,)
        ).fetchone()
        conn.close()
        return row[0] if row else None
    except Exception:
        return None


def _should_remind(issue_key: str) -> bool:
    """Return True if enough time has passed since the last reminder for this Pending bug."""
    last = _get_last_reminded_at(issue_key)
    if not last:
        return True
    try:
        last_dt  = datetime.fromisoformat(last.replace("Z", "+00:00"))
        elapsed  = (datetime.now(timezone.utc) - last_dt).total_seconds() / 3600
        return elapsed >= BUG_WATCHDOG_REMIND_HOURS
    except Exception:
        return True


def _sort_candidates_by_priority(raw_json_text: str) -> str:
    """Parse the JQL result JSON, sort issues by priority rank, and return re-serialised text.
    If parsing fails the original text is returned unchanged so the LLM still gets something.
    """
    try:
        data   = json.loads(raw_json_text)
        issues = data if isinstance(data, list) else data.get("issues", [])
        if not issues:
            return raw_json_text

        def _rank(issue: dict) -> int:
            pri = (
                issue.get("fields", {}).get("priority", {}) or {}
            )
            name = (pri.get("name") or "").lower()
            return PRIORITY_ORDER.get(name, 99)

        sorted_issues = sorted(issues, key=_rank)
        if isinstance(data, list):
            return json.dumps(sorted_issues, indent=2)
        data["issues"] = sorted_issues
        return json.dumps(data, indent=2)
    except Exception:
        # If it's not parseable JSON (plain-text JQL result), fall through unchanged
        return raw_json_text


def get_watchdog_status() -> Dict[str, Any]:
    """Return a summary dict for the /api/watchdog/bug-status endpoint."""
    try:
        conn  = sqlite3.connect(DB_PATH, timeout=5)
        rows  = conn.execute(
            "SELECT issue_key, priority, action, prereq_ok, missing_items, analysis_ok, cycle_at, notes "
            "FROM watchdog_audit ORDER BY id DESC LIMIT 50"
        ).fetchall()
        conn.close()
        entries = [
            {
                "issue_key":     r[0],
                "priority":      r[1],
                "action":        r[2],
                "prereq_ok":     bool(r[3]),
                "missing_items": r[4],
                "analysis_ok":   bool(r[5]),
                "cycle_at":      r[6],
                "notes":         r[7],
            }
            for r in rows
        ]
        return {
            "enabled":        BUG_WATCHDOG_ENABLED,
            "interval_s":     BUG_WATCHDOG_INTERVAL_SECONDS,
            "project":        BUG_WATCHDOG_PROJECT_KEY,
            "watched_users":  _get_all_watched_users(),
            "remind_hours":   BUG_WATCHDOG_REMIND_HOURS,
            "recent_entries": entries,
            "in_memory_log":  _audit_log[-20:],
        }
    except Exception as e:
        return {"error": str(e), "in_memory_log": _audit_log[-20:]}


# ─────────────────────────────────────────────────────────────────────────────
# Tool schemas
# ─────────────────────────────────────────────────────────────────────────────

SEND_EMAIL_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "send_email_notification",
        "description": (
            "Send a direct email to the bug's assignee (and optionally CC the reporter). "
            "Always call this exactly once per issue immediately after posting your Jira comment."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "to_email":  {"type": "string", "description": "Assignee's email address (from fields.assignee.emailAddress)."},
                "cc_email":  {"type": "string", "description": "Reporter's email address (from fields.reporter.emailAddress). Optional but preferred."},
                "subject":   {"type": "string", "description": "Email subject, e.g. 'Prerequisites missing: SIGPOSDEV-1234'."},
                "body":      {"type": "string", "description": "Plain-text email body — should mirror the Jira comment content exactly."},
            },
            "required": ["to_email", "subject", "body"],
        },
    },
}

SEND_REPORTER_EMAIL_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "send_reporter_email",
        "description": (
            "Send a separate direct email to the REPORTER who assigned this bug, "
            "informing them that the prerequisites are still missing. "
            "Call this once per issue when prerequisites are missing, after notifying the assignee."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "to_email":    {"type": "string", "description": "Reporter's email address (from fields.reporter.emailAddress)."},
                "issue_key":   {"type": "string", "description": "The Jira issue key, e.g. SIGPOSDEV-1234."},
                "assignee":    {"type": "string", "description": "The assignee's Jira username or displayName."},
                "missing":     {"type": "string", "description": "Comma-separated list of missing prerequisites."},
            },
            "required": ["to_email", "issue_key", "assignee", "missing"],
        },
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# System prompt
# ─────────────────────────────────────────────────────────────────────────────

BUG_WATCHDOG_SYSTEM_PROMPT = """\
You are the GPOS Automated Bug Triage Watchdog v2.0, running unattended on a schedule.
There is NO human in this conversation — NEVER ask a question, NEVER wait for confirmation.

The candidate bug list has already been sorted by priority (P1 first, then P2, then P3).
Process bugs in the order they appear in the list — highest priority first.

════════════════════════════════════════════════════════════════
STEP-BY-STEP WORKFLOW (execute for EACH issue key, in order)
════════════════════════════════════════════════════════════════

STEP 1 — Fetch full issue details
  Call `jira_get_issue` with the issue key.
  Extract:
    • fields.assignee.name          → assignee_username  (for [~mention])
    • fields.assignee.emailAddress  → assignee_email
    • fields.reporter.name          → reporter_username
    • fields.reporter.emailAddress  → reporter_email
    • fields.description            → description text
    • fields.labels                 → current label list
    • fields.priority.name          → priority string

STEP 2 — List attachments
  Call `jira_list_attachments` with the issue key.
  Classify each attachment:
    • LOGS       : filenames ending in .log, .txt, .tar, .tar.gz, .tgz, .zip, .7z
    • COREDUMP   : filenames containing 'core' or 'dump' (case-insensitive)
    • TEST CASES : filenames containing 'tc', 'testcase', 'test_case', 'test-case' (case-insensitive)

STEP 3 — Check FOUR Prerequisites
  Evaluate each independently:
    PREREQ A — LOGS:         At least one LOGS attachment found (Step 2).
    PREREQ B — COREDUMP:     At least one COREDUMP attachment found (Step 2) OR description
                             explicitly states "no coredump available" / "N/A" for coredump.
    PREREQ C — REPRO STEPS:  The description contains a non-empty "Steps to Reproduce" (or
                             "Reproduction Steps", "How to Reproduce") section.
    PREREQ D — TEST CASES:   The description references a test case (e.g. "TC-", "Test Case:",
                             "Related TC") OR a TEST CASES attachment exists (Step 2).

STEP 4a — IF ANY PREREQUISITE IS MISSING
  (Also applies if the issue already has label AX_AutoTriage-Pending and prereqs are STILL missing.)

  a. Build a clear missing-items list, e.g.:
       Missing prerequisites detected ❌:
       • [LOGS]           — No log file attached.
       • [COREDUMP]       — No coredump file attached.
       • [REPRO STEPS]    — Steps to Reproduce section is empty or missing.
       • [TEST CASES]     — No related test case reference found.

  b. Call `jira_add_comment` with this exact message body (Jira wiki markup):
       🤖 *GPOS Automated Bug Triage* — Prerequisites Check FAILED ❌
       ----
       [~{assignee_username}], this bug cannot be triaged automatically because one or
       more required prerequisites are missing:
       {missing-items list}
       Please attach the required files / update the description, and the watchdog will
       re-analyse automatically on the next cycle.
       _— Automated by GPOS AX Portal Bug Watchdog_

  c. Call `send_email_notification`:
       to_email  = assignee_email
       cc_email  = reporter_email   ← ALWAYS include the reporter
       subject   = "Prerequisites missing: {KEY} — action needed"
       body      = same text as the Jira comment (plain text)

  d. Call `send_reporter_email`:
       to_email   = reporter_email
       issue_key  = KEY
       assignee   = assignee_username
       missing    = comma-separated list of missing prereq names

  e. Call `jira_update_issue` with `fields` = existing labels PLUS "AX_AutoTriage-Pending".
     NEVER remove existing labels.

  f. Move to the next issue. Do NOT attempt analysis.

STEP 4b — IF ALL FOUR PREREQUISITES ARE PRESENT
  (Also handles upgrading from AX_AutoTriage-Pending → AX_AutoTriage-Done when prereqs are now met.)

  a. Call `jira_download_attachment` for the most relevant log/coredump attachment(s).

  b. If the file is a compressed archive (.7z / .zip / .tar.gz / .tgz), call `extract_archive`.

  c. Call `search_log_contents` on the extracted path for crash signals:
       Pattern: 'SIGSEGV|SIGABRT|SIGBUS|SIGILL|SIGFPE|Segmentation fault|core dumped|
                 Assertion.*failed|FATAL|CRITICAL|OOM|Killed process|Exception|Call Trace|
                 panic|BUG:|Oops|kernel BUG'

  d. Call `read_log_snippet` around matched line numbers (50-100 lines of context).

  e. If a coredump file exists AND Device Agent tools are available:
       Call `run_gdb_backtrace` (or `analyze_core_dump` / `analyze_kernel_panic` as appropriate)
       to obtain a full C++ stack trace for deeper root-cause analysis.

  f. Compose a concise root-cause analysis:
       • What crashed (process name, PID if available)
       • Signal / fault type
       • Probable cause (null deref, OOM, assertion failure, etc.)
       • Stack trace summary (top 3–5 frames)
       • Suggested next step for the developer

  g. Call `jira_add_comment` with this format:
       🔎 *Automated Bug Analysis* — GPOS AX Portal Watchdog
       ----
       [~{assignee_username}], the automated triage is complete. Here is the analysis:

       *Crash Signal:*   {signal}
       *Faulting Module:* {module}
       *Probable Cause:*  {cause}

       *Stack Trace (top frames):*
       {code}
       {stack frames}
       {code}

       *Recommended Next Steps:*
       {next_steps}

       _— Automated by GPOS AX Portal Bug Watchdog_

  h. Call `send_email_notification`:
       to_email = assignee_email
       cc_email = reporter_email
       subject  = "Analysis ready: {KEY} — bug triage complete"
       body     = same as the Jira comment (plain text)

  i. Call `jira_update_issue` with existing labels PLUS "AX_AutoTriage-Done".
     If "AX_AutoTriage-Pending" is in the existing labels, KEEP it — do not remove it;
     simply ADD "AX_AutoTriage-Done". Jira history will show both.

════════════════════════════════════════════════════════════════
STRICT RULES
════════════════════════════════════════════════════════════════
• NEVER transition issue status. NEVER delete anything.
• Only ADD labels; NEVER remove existing labels.
• NEVER skip the label update step — it is the idempotency guard.
• NEVER skip send_email_notification — the Jira comment alone cannot guarantee delivery.
• Process issues in the EXACT ORDER given (priority order, P1 first).
• If a tool call fails, log it and move to the next issue; do not retry more than once.
• Process ONLY the issue keys in the candidate list. Do NOT call jira_search again.
• After ALL issues are processed, output a short plain-text summary of what was done
  per issue key (no further tool calls). That ends the cycle.
"""


# ─────────────────────────────────────────────────────────────────────────────
# Core triage cycle
# ─────────────────────────────────────────────────────────────────────────────

async def run_bug_triage_cycle(mcp_server_url: str):
    """One unattended pass: find newly assigned / re-assigned bugs and triage them."""
    if not BUG_WATCHDOG_ENABLED:
        return

    watched_users = _get_all_watched_users()
    if not watched_users:
        logger.warning("Bug watchdog cycle skipped: no watched users found in DB or BUG_WATCHDOG_USERS env var.")
        return
    if not (BUG_WATCHDOG_JIRA_PAT and BUG_WATCHDOG_LLM_KEY):
        logger.warning("Bug watchdog cycle skipped: BUG_WATCHDOG_JIRA_PAT and BUG_WATCHDOG_LLM_KEY must both be set.")
        return

    import httpx
    from mcp.client.sse import sse_client
    from mcp.client.session import ClientSession
    from contextlib import AsyncExitStack

    users_clause = ", ".join(f'"{u}"' for u in watched_users)

    # ── Query 1: New bugs that have never been touched by the watchdog ──────
    jql_new = (
        f'project = {BUG_WATCHDOG_PROJECT_KEY} AND issuetype = Bug '
        f'AND assignee in ({users_clause}) '
        f'AND labels not in (AX_AutoTriage-Pending, AX_AutoTriage-Done) '
        f'AND updated >= -{BUG_WATCHDOG_LOOKBACK_DAYS}d '
        f'ORDER BY priority ASC, updated DESC'
    )
    # ── Query 2: Pending bugs (prereqs were missing; re-check if tester has now attached them) ──
    jql_pending = (
        f'project = {BUG_WATCHDOG_PROJECT_KEY} AND issuetype = Bug '
        f'AND assignee in ({users_clause}) '
        f'AND labels = AX_AutoTriage-Pending '
        f'AND labels not in (AX_AutoTriage-Done) '
        f'AND updated >= -{BUG_WATCHDOG_LOOKBACK_DAYS}d '
        f'ORDER BY priority ASC, updated DESC'
    )

    async with AsyncExitStack() as stack:
        # ── Connect to Jira MCP ────────────────────────────────────────────
        try:
            jira_streams = await stack.enter_async_context(
                sse_client(f"{mcp_server_url}/sse", headers={"X-Jira-PAT": BUG_WATCHDOG_JIRA_PAT})
            )
            jira_session = await stack.enter_async_context(
                ClientSession(jira_streams[0], jira_streams[1])
            )
            await jira_session.initialize()
        except Exception as e:
            logger.error(f"Bug watchdog: could not connect to Jira MCP: {_unwrap_exception(e)}")
            return

        # ── Optionally connect to Device MCP (non-fatal if unavailable) ───
        device_session = None
        device_tools   = []
        if DEVICE_MCP_SERVER_URL:
            try:
                dev_streams = await stack.enter_async_context(
                    sse_client(f"{DEVICE_MCP_SERVER_URL}/sse")
                )
                device_session = await stack.enter_async_context(
                    ClientSession(dev_streams[0], dev_streams[1])
                )
                await device_session.initialize()
                dev_tools_resp = await device_session.list_tools()
                device_tools   = [
                    {
                        "type": "function",
                        "function": {
                            "name": t.name,
                            "description": f"[DEVICE-AGENT] {t.description or ''}",
                            "parameters": t.input_schema or {"type": "object", "properties": {}},
                        },
                    }
                    for t in dev_tools_resp.tools
                    if t.name in {
                        "run_gdb_backtrace", "analyze_core_dump",
                        "analyze_kernel_panic", "detect_silent_crashes",
                        "search_log_contents", "read_log_snippet", "extract_archive",
                    }
                ]
                logger.info(f"Bug watchdog: Device MCP connected; {len(device_tools)} analysis tools loaded.")
            except Exception as e:
                logger.warning(f"Bug watchdog: Device MCP unavailable (non-fatal): {_unwrap_exception(e)}")

        # ── Fetch candidates ───────────────────────────────────────────────
        all_candidates_text = ""
        for jql, label in [(jql_new, "NEW"), (jql_pending, "PENDING")]:
            try:
                result = await jira_session.call_tool(
                    "jira_search",
                    arguments={
                        "jql": jql,
                        "fields": "summary,assignee,reporter,priority,labels",
                        "max_results": BUG_WATCHDOG_MAX_ISSUES_PER_CYCLE,
                    },
                )
                raw = (
                    "\n".join(str(c.text) for c in result.content if hasattr(c, "text"))
                    if isinstance(result.content, list)
                    else str(result.content)
                )
                if raw and "No issues found" not in raw:
                    # Filter PENDING bugs: only include those whose reminder cooldown has elapsed
                    if label == "PENDING":
                        # We pass the full list to the LLM; the LLM checks each via jira_get_issue.
                        # Cooldown enforcement is done via the system prompt's re-remind instruction
                        # and _should_remind() called per-issue inside the tool-call loop below.
                        pass
                    sorted_raw = _sort_candidates_by_priority(raw)
                    all_candidates_text += f"\n\n=== {label} BUGS ===\n{sorted_raw}"
            except Exception as e:
                logger.warning(f"Bug watchdog: JQL for {label} bugs failed: {_unwrap_exception(e)}")

        if not all_candidates_text.strip():
            logger.info("Bug watchdog: no new or pending unprocessed bugs found this cycle.")
            return

        # ── Build tool list ────────────────────────────────────────────────
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
        tools.append(SEND_EMAIL_TOOL_SCHEMA)
        tools.append(SEND_REPORTER_EMAIL_TOOL_SCHEMA)

        # ── LLM agentic loop ───────────────────────────────────────────────
        messages = [
            {"role": "system", "content": BUG_WATCHDOG_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Candidate bugs (sorted by priority — process P1 first):\n"
                    f"{all_candidates_text}\n\n"
                    f"Watched users: {watched_users}\n"
                    f"Device Agent tools available: {'YES' if device_tools else 'NO'}"
                ),
            },
        ]
        llm_headers = {
            "Authorization": f"Bearer {BUG_WATCHDOG_LLM_KEY}",
            "Content-Type": "application/json",
            "X-Title": "EXACODE SWE(API)",
            "X-Model": "Chat-EXACODE-A",
        }
        llm_url = BUG_WATCHDOG_LLM_URL.rstrip("/")
        if not llm_url.endswith("chat/completions"):
            llm_url += "/chat/completions" if llm_url.endswith("v1") else "/v1/chat/completions"

        async with httpx.AsyncClient(timeout=300.0) as client:
            for iteration in range(40):  # generous upper bound
                payload = {
                    "model": "Chat-EXACODE-A",
                    "messages": messages,
                    "tools": tools,
                    "tool_choice": "auto",
                    "temperature": 0.1,
                }
                try:
                    resp = await client.post(llm_url, headers=llm_headers, json=payload)
                except Exception as e:
                    logger.error(f"Bug watchdog: LLM HTTP error: {_unwrap_exception(e)}")
                    return

                if resp.status_code != 200:
                    logger.error(f"Bug watchdog: LLM error {resp.status_code}: {resp.text[:300]}")
                    return

                result  = resp.json()
                message = result["choices"][0]["message"]
                messages.append(message)

                if not message.get("tool_calls"):
                    summary = (message.get("content") or "")[:2000]
                    logger.info(f"Bug watchdog cycle complete (iter {iteration}):\n{summary}")
                    return

                # ── Dispatch tool calls ────────────────────────────────────
                for tool_call in message["tool_calls"]:
                    func_name = tool_call["function"]["name"]
                    try:
                        func_args = json.loads(tool_call["function"]["arguments"])
                    except Exception:
                        func_args = {}

                    res_text = ""
                    try:
                        # ── Local email tools ──────────────────────────────
                        if func_name == "send_email_notification":
                            res_text = _send_email_notification(
                                to_email  = func_args.get("to_email", ""),
                                subject   = func_args.get("subject", ""),
                                body      = func_args.get("body", ""),
                                cc_email  = func_args.get("cc_email", ""),
                            )

                        elif func_name == "send_reporter_email":
                            issue_key = func_args.get("issue_key", "")
                            assignee  = func_args.get("assignee", "unknown")
                            missing   = func_args.get("missing", "")
                            body = (
                                f"Hi,\n\n"
                                f"This is an automated message from the GPOS AX Portal Bug Watchdog.\n\n"
                                f"You assigned bug {issue_key} to {assignee}, but the required prerequisites "
                                f"are still missing:\n\n"
                                f"  Missing: {missing}\n\n"
                                f"Please ensure the assignee attaches the required evidence so the automated "
                                f"analysis can proceed.\n\n"
                                f"— GPOS AX Portal Bug Watchdog"
                            )
                            res_text = _send_email_notification(
                                to_email = func_args.get("to_email", ""),
                                subject  = f"Action needed: {issue_key} — prerequisites missing (assigned to {assignee})",
                                body     = body,
                            )
                            # Record the reminder time
                            _write_audit({
                                "issue_key":    issue_key,
                                "priority":     "",
                                "action":       "REMINDED",
                                "prereq_ok":    False,
                                "missing_items": missing,
                                "reminded_at":  datetime.now(timezone.utc).isoformat(),
                                "analysis_ok":  False,
                                "notes":        f"Reporter reminder sent",
                            })

                        # ── Device MCP tools (if device session is available) ──
                        elif device_session and any(
                            t["function"]["name"] == func_name for t in device_tools
                        ):
                            tool_result = await device_session.call_tool(func_name, arguments=func_args)
                            res_text    = _extract_tool_text(tool_result)

                        # ── Jira MCP tools (everything else) ──────────────
                        else:
                            tool_result = await jira_session.call_tool(func_name, arguments=func_args)
                            res_text    = _extract_tool_text(tool_result)

                            # Side-effect tracking for audit log
                            if func_name == "jira_update_issue":
                                _write_audit({
                                    "issue_key":    func_args.get("issue_key", ""),
                                    "priority":     "",
                                    "action":       "LABEL_UPDATED",
                                    "prereq_ok":    "AX_AutoTriage-Done" in json.dumps(func_args),
                                    "missing_items": "",
                                    "reminded_at":  "",
                                    "analysis_ok":  "AX_AutoTriage-Done" in json.dumps(func_args),
                                    "notes":        f"Labels updated",
                                })

                    except Exception as e:
                        res_text = f"[ERROR] Tool '{func_name}' failed: {_unwrap_exception(e)}"
                        logger.warning(res_text)

                    messages.append({
                        "role":         "tool",
                        "tool_call_id": tool_call["id"],
                        "name":         func_name,
                        "content":      res_text[:5000],
                    })

        logger.warning(f"Bug watchdog cycle reached max iterations ({40}) without a final summary.")


def _extract_tool_text(tool_result) -> str:
    """Pull plain text out of an MCP tool result regardless of whether content is a list or str."""
    if isinstance(tool_result.content, list):
        parts = []
        for c in tool_result.content:
            if hasattr(c, "text"):
                parts.append(str(c.text))
            elif isinstance(c, dict) and "text" in c:
                parts.append(str(c["text"]))
            else:
                parts.append(str(c))
        return "\n".join(parts)
    return str(tool_result.content)


# ─────────────────────────────────────────────────────────────────────────────
# Loop + startup
# ─────────────────────────────────────────────────────────────────────────────

async def _bug_watchdog_loop(mcp_server_url: str):
    """Runs run_bug_triage_cycle() forever on a fixed interval."""
    _init_watchdog_db()
    logger.info(
        f"Bug watchdog v2.0 started — interval={BUG_WATCHDOG_INTERVAL_SECONDS}s  "
        f"project={BUG_WATCHDOG_PROJECT_KEY}  remind_every={BUG_WATCHDOG_REMIND_HOURS}h"
    )
    while True:
        try:
            await run_bug_triage_cycle(mcp_server_url)
        except Exception as e:
            logger.error(f"Bug watchdog cycle crashed: {_unwrap_exception(e)}", exc_info=True)
        await asyncio.sleep(BUG_WATCHDOG_INTERVAL_SECONDS)


def start_bug_watchdog(mcp_server_url: str):
    """Call once from the FastAPI startup event. No-op unless BUG_WATCHDOG_ENABLED=true."""
    if BUG_WATCHDOG_ENABLED:
        asyncio.create_task(_bug_watchdog_loop(mcp_server_url))
        logger.info(
            f"Bug watchdog enabled: polling every {BUG_WATCHDOG_INTERVAL_SECONDS}s  "
            f"env_users={BUG_WATCHDOG_USERS}  db_auto_detect=ON"
        )
