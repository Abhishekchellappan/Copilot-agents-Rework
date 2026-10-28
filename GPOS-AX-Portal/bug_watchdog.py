"""
Automated Bug Triage Watchdog
==============================
Runs unattended on a timer (no chat session, no logged-in user). Detects new
Bug tickets assigned to watched users, requests missing logs/coredump/repro
steps if absent, otherwise analyzes attached evidence and posts the result —
via the same Jira MCP tools the interactive agents already use — then emails
the assignee directly over SMTP (does not rely on Jira's own notification
scheme, which the portal cannot guarantee is enabled for every user).

Kept in its own module so this opt-in feature never touches server.py's
existing chat/tool-calling code paths.
"""

import os
import json
import asyncio
import logging
import smtplib
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)

# ─── Config (env-driven, opt-in — fully disabled unless explicitly turned on) ──
BUG_WATCHDOG_ENABLED = os.environ.get('BUG_WATCHDOG_ENABLED', 'false').strip().lower() == 'true'
BUG_WATCHDOG_INTERVAL_SECONDS = int(os.environ.get('BUG_WATCHDOG_INTERVAL_SECONDS', '300'))
BUG_WATCHDOG_PROJECT_KEY = os.environ.get('BUG_WATCHDOG_PROJECT_KEY', 'SIGPOSDEV').strip()
BUG_WATCHDOG_USERS = [u.strip() for u in os.environ.get('BUG_WATCHDOG_USERS', '').split(',') if u.strip()]
BUG_WATCHDOG_LOOKBACK_DAYS = int(os.environ.get('BUG_WATCHDOG_LOOKBACK_DAYS', '1'))
BUG_WATCHDOG_MAX_ISSUES_PER_CYCLE = int(os.environ.get('BUG_WATCHDOG_MAX_ISSUES_PER_CYCLE', '5'))
BUG_WATCHDOG_JIRA_PAT = os.environ.get('BUG_WATCHDOG_JIRA_PAT', '').strip() or os.environ.get('JIRA_PAT', '').strip()
BUG_WATCHDOG_LLM_URL = os.environ.get('BUG_WATCHDOG_LLM_URL', 'http://exacode-chat.lge.com/v1').strip()
BUG_WATCHDOG_LLM_KEY = os.environ.get('BUG_WATCHDOG_LLM_KEY', '').strip()

# SMTP relay for direct assignee email (independent of Jira's own notification scheme)
SMTP_HOST = os.environ.get('SMTP_HOST', '').strip()
SMTP_PORT = int(os.environ.get('SMTP_PORT', '25'))
SMTP_FROM = os.environ.get('SMTP_FROM', 'gpos-ax-portal@lge.com').strip()
SMTP_USE_TLS = os.environ.get('SMTP_USE_TLS', 'false').strip().lower() == 'true'
SMTP_USERNAME = os.environ.get('SMTP_USERNAME', '').strip()
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '').strip()


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


def _send_email_notification(to_email: str, subject: str, body: str) -> str:
    """Deliver a real SMTP email so notification doesn't depend on Jira's notification scheme."""
    if not SMTP_HOST:
        return "Email skipped: SMTP_HOST is not configured on the portal."
    if not to_email:
        return "Email skipped: no recipient email address was provided."
    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = SMTP_FROM
        msg["To"] = to_email
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            if SMTP_USE_TLS:
                server.starttls()
            if SMTP_USERNAME and SMTP_PASSWORD:
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM, [to_email], msg.as_string())
        return f"Email sent to {to_email}."
    except Exception as e:
        return f"Email failed to send to {to_email}: {e}"


SEND_EMAIL_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "send_email_notification",
        "description": (
            "Send a direct email to the bug's assignee. Always call this exactly once per issue, "
            "immediately after posting your Jira comment, using the same content as the comment."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "to_email": {"type": "string", "description": "Assignee's email address, from fields.assignee.emailAddress (jira_get_issue)."},
                "subject": {"type": "string", "description": "Email subject, e.g. 'Action needed: SIGPOSDEV-1234 is missing triage info'."},
                "body": {"type": "string", "description": "Plain-text email body — should mirror the Jira comment content."},
            },
            "required": ["to_email", "subject", "body"],
        },
    },
}

BUG_WATCHDOG_SYSTEM_PROMPT = """You are the GPOS Automated Bug Triage Watchdog, running unattended on a schedule. There is NO human in this conversation — never ask a question, never wait for confirmation.

You were given a JSON list of candidate Jira Bug tickets below that are newly assigned and not yet triaged (they lack the label 'AX_AutoTriage-Pending' or 'AX_AutoTriage-Done').

For EACH issue key in the candidate list, one at a time, do the following:
1. Call `jira_get_issue` (NOT jira_search) with the issue key to get full raw fields, including `fields.assignee.name` (Jira login, for @mentions), `fields.assignee.emailAddress` (for direct email), `fields.description`, and `fields.labels`.
2. Call `jira_list_attachments` for the issue key to check for log/coredump evidence. Treat filenames ending in .log, .txt, .tar, .tar.gz, .tgz, .zip, .7z, or containing 'core' as valid evidence.
3. Decide if BOTH prerequisites are satisfied:
   a. At least one log/coredump/evidence attachment exists.
   b. The description contains a real 'Steps to Reproduce' (or similar) section with actual non-empty content, not just a heading.
4. IF PREREQUISITES ARE MISSING:
   - Call `jira_add_comment` with a short, specific message listing exactly what is missing, mentioning the assignee with Jira wiki syntax `[~<assignee_username>]`.
   - Call `send_email_notification` with the same content (subject like "Action needed: <KEY> is missing triage info") to `fields.assignee.emailAddress`.
   - Call `jira_update_issue` with `fields` JSON containing the EXISTING labels (from step 1) PLUS the new label "AX_AutoTriage-Pending". NEVER remove existing labels.
   - Move to the next issue. Do not attempt analysis.
5. IF PREREQUISITES ARE PRESENT:
   - Call `jira_download_attachment` for the relevant log/coredump attachment(s).
   - If the downloaded file is a compressed archive (.7z/.zip/.tar.gz/.tgz), call `extract_archive` on it.
   - Call `search_log_contents` on the downloaded/extracted path for patterns like 'SIGSEGV|SIGABRT|SIGBUS|SIGILL|SIGFPE|Segmentation fault|core dumped|Assertion.*failed|FATAL|CRITICAL|OOM|Killed process|Exception|Call Trace'.
   - Call `read_log_snippet` around the matched line numbers (50-100 lines of context) to understand the crash.
   - Compose a concise root-cause analysis (what crashed, probable cause, a suggested next step).
   - Call `jira_add_comment` with the analysis prefixed "🔎 Automated Bug Analysis:", mentioning the assignee `[~<assignee_username>]`.
   - Call `send_email_notification` with the same analysis (subject like "Analysis ready: <KEY>") to `fields.assignee.emailAddress`.
   - Call `jira_update_issue` with the EXISTING labels PLUS the new label "AX_AutoTriage-Done". NEVER remove existing labels.

STRICT RULES:
- NEVER transition issue status and NEVER delete anything. Only add comments and ADD (never remove) labels.
- NEVER skip the label update step — it prevents this ticket from being reprocessed next cycle.
- NEVER skip the send_email_notification step — the comment alone is not guaranteed to reach the assignee by email.
- Process ONLY the issues given to you below. Do not run additional jira_search queries.
- If a tool call fails, note it and move on; do not retry more than once per issue.
- Once ALL issues are processed, reply with a short plain-text summary (no further tool calls) listing what you did per issue key. This ends the cycle.
"""


async def run_bug_triage_cycle(mcp_server_url: str):
    """One unattended pass: find newly assigned bugs and triage them via the Jira MCP tools."""
    if not BUG_WATCHDOG_ENABLED:
        return
    if not (BUG_WATCHDOG_JIRA_PAT and BUG_WATCHDOG_LLM_KEY and BUG_WATCHDOG_USERS):
        logger.warning("Bug watchdog cycle skipped: BUG_WATCHDOG_JIRA_PAT, BUG_WATCHDOG_LLM_KEY, and BUG_WATCHDOG_USERS must all be set.")
        return

    import httpx
    from mcp.client.sse import sse_client
    from mcp.client.session import ClientSession
    from contextlib import AsyncExitStack

    users_clause = ", ".join(f'"{u}"' for u in BUG_WATCHDOG_USERS)
    jql = (
        f'project = {BUG_WATCHDOG_PROJECT_KEY} AND issuetype = Bug '
        f'AND assignee in ({users_clause}) '
        f'AND labels not in (AX_AutoTriage-Pending, AX_AutoTriage-Done) '
        f'AND created >= -{BUG_WATCHDOG_LOOKBACK_DAYS}d ORDER BY created DESC'
    )

    async with AsyncExitStack() as stack:
        try:
            jira_streams = await stack.enter_async_context(
                sse_client(f"{mcp_server_url}/sse", headers={"X-Jira-PAT": BUG_WATCHDOG_JIRA_PAT})
            )
            jira_session = await stack.enter_async_context(ClientSession(jira_streams[0], jira_streams[1]))
            await jira_session.initialize()
        except Exception as e:
            logger.error(f"Bug watchdog: could not connect to Jira MCP: {_unwrap_exception(e)}")
            return

        search_result = await jira_session.call_tool(
            "jira_search",
            arguments={"jql": jql, "fields": "summary,assignee", "max_results": BUG_WATCHDOG_MAX_ISSUES_PER_CYCLE},
        )
        candidates_text = "\n".join(
            str(c.text) for c in search_result.content if hasattr(c, "text")
        ) if isinstance(search_result.content, list) else str(search_result.content)

        if not candidates_text or "No issues found" in candidates_text:
            logger.info("Bug watchdog: no new unprocessed bugs found this cycle.")
            return

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
        tools.append(SEND_EMAIL_TOOL_SCHEMA)

        messages = [
            {"role": "system", "content": BUG_WATCHDOG_SYSTEM_PROMPT},
            {"role": "user", "content": f"Candidate bugs JQL result:\n{candidates_text}"},
        ]
        headers = {
            "Authorization": f"Bearer {BUG_WATCHDOG_LLM_KEY}",
            "Content-Type": "application/json",
            "X-Title": "EXACODE SWE(API)",
            "X-Model": "Chat-EXACODE-A",
        }
        llm_url = BUG_WATCHDOG_LLM_URL.rstrip('/')
        if not llm_url.endswith('chat/completions'):
            llm_url += '/chat/completions' if llm_url.endswith('v1') else '/v1/chat/completions'

        async with httpx.AsyncClient(timeout=180.0) as client:
            for _ in range(25):
                payload = {
                    "model": "Chat-EXACODE-A",
                    "messages": messages,
                    "tools": tools,
                    "tool_choice": "auto",
                    "temperature": 0.1,
                }
                resp = await client.post(llm_url, headers=headers, json=payload)
                if resp.status_code != 200:
                    logger.error(f"Bug watchdog: LLM error {resp.status_code}: {resp.text[:300]}")
                    return
                result = resp.json()
                message = result["choices"][0]["message"]
                messages.append(message)

                if not message.get("tool_calls"):
                    logger.info(f"Bug watchdog cycle summary: {(message.get('content') or '')[:1000]}")
                    return

                for tool_call in message["tool_calls"]:
                    func_name = tool_call["function"]["name"]
                    try:
                        func_args = json.loads(tool_call["function"]["arguments"])
                    except Exception:
                        func_args = {}

                    try:
                        if func_name == "send_email_notification":
                            res_text = _send_email_notification(
                                func_args.get("to_email", ""),
                                func_args.get("subject", ""),
                                func_args.get("body", ""),
                            )
                        else:
                            tool_result = await jira_session.call_tool(func_name, arguments=func_args)
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
                    except Exception as e:
                        res_text = f"[ERROR] Tool execution failed: {_unwrap_exception(e)}"

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call["id"],
                        "name": func_name,
                        "content": res_text[:4000],
                    })

        logger.warning("Bug watchdog cycle reached max iterations without a final summary.")


async def _bug_watchdog_loop(mcp_server_url: str):
    """Runs run_bug_triage_cycle() forever on a fixed interval for the lifetime of the pod."""
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
        logger.info(f"Bug watchdog enabled: polling every {BUG_WATCHDOG_INTERVAL_SECONDS}s for users {BUG_WATCHDOG_USERS}")
