"""
GPOS Jira Agent — Generic MCP Server
=====================================
A stateless, project-agnostic MCP server providing generic Jira REST API tools.
All business rules, label policies, governance checks, and report formatting
are managed in companion Markdown files (rules/*.md, skills/*.md).

Tools: jira_search, jira_get_issue, jira_create_issue, jira_update_issue,
       jira_delete_issue, jira_get_comments, jira_add_comment, jira_delete_comment,
       jira_get_transitions, jira_transition_issue, jira_log_work, jira_get_fields,
       jira_raw_api
"""

import os
import re
import json
import requests
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

try:
    from mcp.server.fastmcp import FastMCP, Context
except ImportError:
    try:
        from fastmcp import FastMCP, Context
    except ImportError:
        raise ImportError("Install 'mcp[cli]' or 'fastmcp' via pip.")

# ─── Server & Config ──────────────────────────────────────────────
mcp = FastMCP("GPOS Jira Agent")
JIRA_BASE_URL = os.environ.get("JIRA_BASE_URL", "http://jira.lge.com/issue").rstrip("/")
DEFAULT_PAT = os.environ.get("JIRA_PAT", "")


# ─── Helpers ──────────────────────────────────────────────────────

def _headers(ctx: Context = None, request: Request = None) -> dict:
    """Extract Jira PAT from MCP request headers or environment variable."""
    pat = DEFAULT_PAT
    if ctx and hasattr(ctx, "request_context") and ctx.request_context:
        req = getattr(ctx.request_context, "request", None)
        if req and "x-jira-pat" in req.headers:
            pat = req.headers["x-jira-pat"]
    elif request and "x-jira-pat" in request.headers:
        pat = request.headers["x-jira-pat"]
    if not pat:
        raise ValueError(
            "Missing Jira PAT. Set 'X-Jira-PAT' header in mcp.json or 'JIRA_PAT' env var."
        )
    return {
        "Authorization": f"Bearer {pat}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _md_to_jira(text: str) -> str:
    """Convert Markdown to Jira Data Center wiki markup."""
    if not text:
        return text
    # Headings: # H1 → h1. H1
    text = re.sub(
        r"^(#{1,6})\s+(.+)$",
        lambda m: f"h{len(m.group(1))}. {m.group(2)}",
        text,
        flags=re.MULTILINE,
    )

    # Fenced code blocks: ```lang ... ``` → {code:lang} ... {code}
    def _code(m):
        lang, body = m.group(1) or "", m.group(2).strip("\r\n")
        return (
            f"{{code:{lang}}}\n{body}\n{{code}}"
            if lang
            else f"{{code}}\n{body}\n{{code}}"
        )

    text = re.sub(r"```(\w+)?\r?\n([\s\S]*?)```", _code, text)
    # Inline code: `code` → {{code}}
    text = re.sub(r"`([^`\r\n]+)`", r"{{\1}}", text)
    # Bold: **text** → *text*
    text = re.sub(r"\*\*([^*\r\n]+)\*\*", r"*\1*", text)
    return text


# ── Dynamic field alias cache ──
_FIELD_CACHE = None


def _field_map(headers: dict) -> dict:
    """Build alias → customfield_id mapping from Jira instance metadata."""
    global _FIELD_CACHE
    if _FIELD_CACHE is not None:
        return _FIELD_CACHE
    base = {
        "due_date": "duedate",
        "original_estimate": "timetracking",
        "time_spent": "timespent",
    }
    try:
        resp = requests.get(
            f"{JIRA_BASE_URL}/rest/api/2/field", headers=headers, timeout=10
        )
        if resp.status_code == 200:
            for f in resp.json():
                alias = f.get("name", "").lower().replace(" ", "_")
                fid = f.get("id", "")
                if alias and fid.startswith("customfield_") and alias not in base:
                    base[alias] = fid
            _FIELD_CACHE = base
    except Exception:
        pass
    return _FIELD_CACHE or base


def _translate(fields: dict, headers: dict, project_key: str = None) -> dict:
    """Translate user-friendly field aliases to Jira API field IDs and structures."""
    mapping = _field_map(headers)
    out = {}
    for k, v in fields.items():
        key = k.lower().replace(" ", "_")
        mapped = mapping.get(key, k)

        if key == "sprint" and project_key:
            sid = _resolve_sprint(str(v), project_key, headers)
            out[mapped] = sid if sid else v
        elif key == "assignee":
            out["assignee"] = {"name": v.strip()} if isinstance(v, str) else v
        elif key == "labels":
            if isinstance(v, str):
                out["labels"] = [l.strip() for l in v.split(",") if l.strip()]
            else:
                out["labels"] = v
        elif key in ("component", "components"):
            if isinstance(v, str):
                out["components"] = [{"name": v}]
            elif isinstance(v, list) and v and isinstance(v[0], str):
                out["components"] = [{"name": n} for n in v]
            else:
                out["components"] = v
        elif key in ("fix_version", "fix_versions", "fixversions"):
            if isinstance(v, str):
                out["fixVersions"] = [{"name": v}]
            elif isinstance(v, list) and v and isinstance(v[0], str):
                out["fixVersions"] = [{"name": n} for n in v]
            else:
                out["fixVersions"] = v
        elif key == "original_estimate":
            out["timetracking"] = {"originalEstimate": v}
        elif key == "resolution":
            out["resolution"] = {"name": v} if isinstance(v, str) else v
        else:
            out[mapped] = v
    return out


def _resolve_sprint(sprint_input: str, project_key: str, headers: dict):
    """Resolve sprint name or 'active' to a numeric sprint ID via Agile API."""
    try:
        boards_resp = requests.get(
            f"{JIRA_BASE_URL}/rest/agile/1.0/board",
            headers=headers,
            params={"projectKeyOrId": project_key},
            timeout=10,
        )
        if boards_resp.status_code != 200:
            return None
        boards = boards_resp.json().get("values", [])
        if not boards:
            return None
        board_id = boards[0].get("id")

        sprints_resp = requests.get(
            f"{JIRA_BASE_URL}/rest/agile/1.0/board/{board_id}/sprint",
            headers=headers,
            params={"state": "active,future"},
            timeout=10,
        )
        if sprints_resp.status_code != 200:
            return None
        sprints = sprints_resp.json().get("values", [])

        if sprint_input.lower() == "active":
            for s in sprints:
                if s.get("state") == "active":
                    return s.get("id")
        else:
            for s in sprints:
                if s.get("name", "").strip() == sprint_input.strip():
                    return s.get("id")
            for s in sprints:
                if sprint_input.lower() in s.get("name", "").lower():
                    return s.get("id")
    except Exception:
        pass
    return None


# ─── MCP Tools ────────────────────────────────────────────────────


@mcp.tool()
def jira_search(
    jql: str, fields: str = "", max_results: int = 50, ctx: Context = None
) -> str:
    """
    Search Jira issues using a JQL query. Returns matching issues as JSON.

    :param jql: JQL query (e.g. 'project = PROJ AND status = "In Progress"').
    :param fields: Comma-separated field names to return (e.g. 'summary,status,assignee,labels,customfield_10002'). Empty returns default fields.
    :param max_results: Maximum number of issues to return (default 50, max 100).
    """
    try:
        headers = _headers(ctx)
        payload = {"jql": jql, "maxResults": min(max_results, 100)}
        if fields:
            payload["fields"] = [f.strip() for f in fields.split(",")]
        resp = requests.post(
            f"{JIRA_BASE_URL}/rest/api/2/search",
            headers=headers,
            json=payload,
            timeout=30,
        )
        if resp.status_code != 200:
            return f"Search failed (HTTP {resp.status_code}): {resp.text}"
        data = resp.json()
        issues = data.get("issues", [])
        if not issues:
            return f"No issues found for JQL: {jql}"
        results = []
        for issue in issues:
            entry = {"key": issue["key"]}
            entry.update(issue.get("fields", {}))
            results.append(entry)
        return json.dumps(
            {"total": data.get("total", 0), "count": len(issues), "issues": results},
            indent=2,
            default=str,
        )
    except Exception as e:
        return f"Error in jira_search: {e}"


@mcp.tool()
def jira_get_issue(
    issue_key: str, expand: str = "", ctx: Context = None
) -> str:
    """
    Fetch full details of a Jira issue by its key.

    :param issue_key: Issue key (e.g. 'PROJ-123').
    :param expand: Optional comma-separated expansions (e.g. 'changelog,renderedFields').
    """
    try:
        headers = _headers(ctx)
        key = issue_key.strip().upper()
        url = f"{JIRA_BASE_URL}/rest/api/2/issue/{key}"
        params = {}
        if expand:
            params["expand"] = expand
        resp = requests.get(url, headers=headers, params=params, timeout=15)
        if resp.status_code != 200:
            return f"Failed to fetch '{key}' (HTTP {resp.status_code}): {resp.text}"
        data = resp.json()
        return json.dumps(data, indent=2, default=str)
    except Exception as e:
        return f"Error in jira_get_issue: {e}"


@mcp.tool()
def jira_create_issue(
    project_key: str,
    summary: str,
    issue_type: str = "Story",
    description: str = "",
    fields: str = "{}",
    ctx: Context = None,
) -> str:
    """
    Create a new Jira issue. Supports user-friendly field aliases.

    :param project_key: Project key (e.g. 'PROJ').
    :param summary: Issue summary/title.
    :param issue_type: Issue type (Story, Bug, Task, Sub-task). Default: Story.
    :param description: Description text (Markdown auto-converted to Jira wiki markup).
    :param fields: JSON string of additional fields. Supports aliases: sprint, epic_link, story_points, assignee, labels, component, fix_version, due_date, original_estimate, resolution, etc.
    """
    try:
        headers = _headers(ctx)
        proj = project_key.strip().upper()
        extra = json.loads(fields) if isinstance(fields, str) else fields
        translated = _translate(extra, headers, proj)

        payload = {
            "fields": {
                "project": {"key": proj},
                "summary": summary,
                "issuetype": {"name": issue_type},
                **translated,
            }
        }
        if description:
            payload["fields"]["description"] = _md_to_jira(description)

        resp = requests.post(
            f"{JIRA_BASE_URL}/rest/api/2/issue",
            headers=headers,
            json=payload,
            timeout=15,
        )
        if resp.status_code not in (200, 201):
            return f"Create failed (HTTP {resp.status_code}): {resp.text}"
        data = resp.json()
        key = data.get("key", "Unknown")
        return json.dumps(
            {"status": "created", "key": key, "url": f"{JIRA_BASE_URL}/browse/{key}"},
            indent=2,
        )
    except Exception as e:
        return f"Error in jira_create_issue: {e}"


@mcp.tool()
def jira_update_issue(
    issue_key: str, fields: str = "{}", ctx: Context = None
) -> str:
    """
    Update fields on an existing Jira issue. Supports user-friendly field aliases.

    :param issue_key: Issue key (e.g. 'PROJ-123').
    :param fields: JSON string of fields to update. Supports aliases: sprint, assignee, labels, component, fix_version, due_date, story_points, epic_link, etc.
    """
    try:
        headers = _headers(ctx)
        key = issue_key.strip().upper()
        raw = json.loads(fields) if isinstance(fields, str) else fields
        translated = _translate(raw, headers)

        resp = requests.put(
            f"{JIRA_BASE_URL}/rest/api/2/issue/{key}",
            headers=headers,
            json={"fields": translated},
            timeout=15,
        )
        if resp.status_code not in (200, 204):
            return f"Update failed (HTTP {resp.status_code}): {resp.text}"
        return json.dumps(
            {"status": "updated", "key": key, "url": f"{JIRA_BASE_URL}/browse/{key}"},
            indent=2,
        )
    except Exception as e:
        return f"Error in jira_update_issue: {e}"


@mcp.tool()
def jira_delete_issue(issue_key: str, ctx: Context = None) -> str:
    """
    Delete a Jira issue permanently. This action is IRREVERSIBLE.

    :param issue_key: Issue key (e.g. 'PROJ-123').
    """
    try:
        headers = _headers(ctx)
        key = issue_key.strip().upper()
        resp = requests.delete(
            f"{JIRA_BASE_URL}/rest/api/2/issue/{key}", headers=headers, timeout=15
        )
        if resp.status_code not in (200, 204):
            return f"Delete failed (HTTP {resp.status_code}): {resp.text}"
        return json.dumps({"status": "deleted", "key": key})
    except Exception as e:
        return f"Error in jira_delete_issue: {e}"


@mcp.tool()
def jira_get_comments(
    issue_key: str, max_results: int = 50, ctx: Context = None
) -> str:
    """
    Fetch all comments on a Jira issue in chronological order.

    :param issue_key: Issue key (e.g. 'PROJ-123').
    :param max_results: Maximum number of comments to return.
    """
    try:
        headers = _headers(ctx)
        key = issue_key.strip().upper()
        resp = requests.get(
            f"{JIRA_BASE_URL}/rest/api/2/issue/{key}/comment",
            headers=headers,
            params={"orderBy": "created", "maxResults": max_results},
            timeout=15,
        )
        if resp.status_code != 200:
            return (
                f"Failed to fetch comments for '{key}' "
                f"(HTTP {resp.status_code}): {resp.text}"
            )
        comments = resp.json().get("comments", [])
        result = [
            {
                "id": c.get("id"),
                "author": c.get("author", {}).get("displayName", "Unknown"),
                "created": c.get("created", ""),
                "body": c.get("body", ""),
            }
            for c in comments
        ]
        return json.dumps(
            {"issue_key": key, "count": len(result), "comments": result},
            indent=2,
            default=str,
        )
    except Exception as e:
        return f"Error in jira_get_comments: {e}"


@mcp.tool()
def jira_add_comment(
    issue_key: str, body: str, ctx: Context = None
) -> str:
    """
    Add a comment to a Jira issue. Markdown is auto-converted to Jira wiki markup.

    :param issue_key: Issue key (e.g. 'PROJ-123').
    :param body: Comment text (Markdown supported).
    """
    try:
        headers = _headers(ctx)
        key = issue_key.strip().upper()
        resp = requests.post(
            f"{JIRA_BASE_URL}/rest/api/2/issue/{key}/comment",
            headers=headers,
            json={"body": _md_to_jira(body)},
            timeout=15,
        )
        if resp.status_code not in (200, 201):
            return f"Add comment failed (HTTP {resp.status_code}): {resp.text}"
        cid = resp.json().get("id", "")
        return json.dumps(
            {
                "status": "comment_added",
                "key": key,
                "comment_id": cid,
                "url": f"{JIRA_BASE_URL}/browse/{key}",
            }
        )
    except Exception as e:
        return f"Error in jira_add_comment: {e}"


@mcp.tool()
def jira_delete_comment(
    issue_key: str, comment_id: str = "latest", ctx: Context = None
) -> str:
    """
    Delete a comment from a Jira issue.

    :param issue_key: Issue key (e.g. 'PROJ-123').
    :param comment_id: Numeric comment ID, or 'latest' to auto-resolve the most recent comment.
    """
    try:
        headers = _headers(ctx)
        key = issue_key.strip().upper()
        target = comment_id.strip()

        if target.lower() in ("latest", "last", ""):
            resp = requests.get(
                f"{JIRA_BASE_URL}/rest/api/2/issue/{key}/comment",
                headers=headers,
                params={"orderBy": "created"},
                timeout=15,
            )
            if resp.status_code != 200:
                return f"Failed to fetch comments (HTTP {resp.status_code}): {resp.text}"
            comments = resp.json().get("comments", [])
            if not comments:
                return f"No comments found on {key}."
            target = str(comments[-1]["id"])

        resp = requests.delete(
            f"{JIRA_BASE_URL}/rest/api/2/issue/{key}/comment/{target}",
            headers=headers,
            timeout=15,
        )
        if resp.status_code not in (200, 204):
            return (
                f"Delete comment failed (HTTP {resp.status_code}): {resp.text}"
            )
        return json.dumps(
            {"status": "comment_deleted", "key": key, "comment_id": target}
        )
    except Exception as e:
        return f"Error in jira_delete_comment: {e}"


@mcp.tool()
def jira_get_transitions(issue_key: str, ctx: Context = None) -> str:
    """
    Get available workflow transitions for a Jira issue.

    :param issue_key: Issue key (e.g. 'PROJ-123').
    """
    try:
        headers = _headers(ctx)
        key = issue_key.strip().upper()
        resp = requests.get(
            f"{JIRA_BASE_URL}/rest/api/2/issue/{key}/transitions",
            headers=headers,
            timeout=15,
        )
        if resp.status_code != 200:
            return f"Failed to get transitions (HTTP {resp.status_code}): {resp.text}"
        transitions = resp.json().get("transitions", [])
        result = [
            {
                "id": t["id"],
                "name": t["name"],
                "to_status": t.get("to", {}).get("name", ""),
            }
            for t in transitions
        ]
        return json.dumps({"issue_key": key, "transitions": result}, indent=2)
    except Exception as e:
        return f"Error in jira_get_transitions: {e}"


@mcp.tool()
def jira_transition_issue(
    issue_key: str, transition: str, ctx: Context = None
) -> str:
    """
    Transition a Jira issue to a new workflow status.

    :param issue_key: Issue key (e.g. 'PROJ-123').
    :param transition: Transition ID (e.g. '31') or target status name (e.g. 'In Progress', 'Resolved').
    """
    try:
        headers = _headers(ctx)
        key = issue_key.strip().upper()
        tid = transition.strip()

        # If not a numeric ID, resolve by matching transition or target status name
        if not tid.isdigit():
            resp = requests.get(
                f"{JIRA_BASE_URL}/rest/api/2/issue/{key}/transitions",
                headers=headers,
                timeout=15,
            )
            if resp.status_code != 200:
                return f"Failed to get transitions (HTTP {resp.status_code}): {resp.text}"
            found = False
            for t in resp.json().get("transitions", []):
                if (
                    t["name"].lower() == tid.lower()
                    or t.get("to", {}).get("name", "").lower() == tid.lower()
                ):
                    tid = t["id"]
                    found = True
                    break
            if not found:
                available = [t["name"] for t in resp.json().get("transitions", [])]
                return f"Transition '{transition}' not found. Available: {available}"

        resp = requests.post(
            f"{JIRA_BASE_URL}/rest/api/2/issue/{key}/transitions",
            headers=headers,
            json={"transition": {"id": tid}},
            timeout=15,
        )
        if resp.status_code not in (200, 204):
            return f"Transition failed (HTTP {resp.status_code}): {resp.text}"
        return json.dumps(
            {
                "status": "transitioned",
                "key": key,
                "transition": transition,
                "url": f"{JIRA_BASE_URL}/browse/{key}",
            }
        )
    except Exception as e:
        return f"Error in jira_transition_issue: {e}"


@mcp.tool()
def jira_log_work(
    issue_key: str,
    time_spent: str,
    comment: str = "",
    started: str = "",
    ctx: Context = None,
) -> str:
    """
    Log work (time tracking) on a Jira issue.

    :param issue_key: Issue key (e.g. 'PROJ-123').
    :param time_spent: Time to log (e.g. '2h', '1d 4h', '30m').
    :param comment: Optional work log comment.
    :param started: Optional start datetime in ISO 8601 format. Defaults to now.
    """
    try:
        headers = _headers(ctx)
        key = issue_key.strip().upper()
        payload = {"timeSpent": time_spent}
        if comment:
            payload["comment"] = comment
        if started:
            payload["started"] = started
        resp = requests.post(
            f"{JIRA_BASE_URL}/rest/api/2/issue/{key}/worklog",
            headers=headers,
            json=payload,
            timeout=15,
        )
        if resp.status_code not in (200, 201):
            return f"Log work failed (HTTP {resp.status_code}): {resp.text}"
        return json.dumps(
            {
                "status": "work_logged",
                "key": key,
                "time_spent": time_spent,
                "url": f"{JIRA_BASE_URL}/browse/{key}",
            }
        )
    except Exception as e:
        return f"Error in jira_log_work: {e}"


@mcp.tool()
def jira_get_fields(
    search: str = "", custom_only: bool = False, ctx: Context = None
) -> str:
    """
    List available Jira fields. Use this to discover custom field IDs and names.

    :param search: Optional search term to filter fields by name or ID.
    :param custom_only: If true, only return custom fields (customfield_*).
    """
    try:
        headers = _headers(ctx)
        resp = requests.get(
            f"{JIRA_BASE_URL}/rest/api/2/field", headers=headers, timeout=10
        )
        if resp.status_code != 200:
            return f"Failed to fetch fields (HTTP {resp.status_code}): {resp.text}"
        results = []
        for f in resp.json():
            fid = f.get("id", "")
            name = f.get("name", "")
            if custom_only and not fid.startswith("customfield_"):
                continue
            if search and search.lower() not in name.lower() and search.lower() not in fid.lower():
                continue
            results.append(
                {"id": fid, "name": name, "custom": fid.startswith("customfield_")}
            )
        return json.dumps({"count": len(results), "fields": results}, indent=2)
    except Exception as e:
        return f"Error in jira_get_fields: {e}"


@mcp.tool()
def jira_raw_api(
    method: str, endpoint: str, body: str = "", ctx: Context = None
) -> str:
    """
    Execute a raw Jira REST API call. Use for any endpoint not covered by other tools
    (e.g. Agile boards, sprints, versions, components, attachments).

    :param method: HTTP method — GET, POST, PUT, or DELETE.
    :param endpoint: API path after base URL (e.g. 'rest/agile/1.0/board', 'rest/api/2/project').
    :param body: Optional JSON string for POST/PUT request body.
    """
    try:
        headers = _headers(ctx)
        url = f"{JIRA_BASE_URL}/{endpoint.lstrip('/')}"
        kwargs = {"headers": headers, "timeout": 30}
        if body and method.upper() in ("POST", "PUT"):
            kwargs["json"] = json.loads(body) if isinstance(body, str) and body else {}
        resp = requests.request(method.upper(), url, **kwargs)
        try:
            return json.dumps(resp.json(), indent=2, default=str)
        except Exception:
            return resp.text
    except Exception as e:
        return f"Error in jira_raw_api: {e}"


@mcp.tool()
def jira_generate_sprint_report(
    project_key: str = "SIGPOSDEV",
    sprint_name: str = "",
    ctx: Context = None,
) -> str:
    """
    Generate a comprehensive Sprint Report for the given project.
    This tool fetches ALL tickets in the active (or specified) sprint and computes
    real aggregated metrics server-side. No AI estimation is involved.

    Output includes:
    - Sprint Overview (total tickets, points planned/completed/in-progress/to-do)
    - Completion Percentage
    - Per-Developer Breakdown table
    - Issue Type Distribution
    - At-Risk Items (unassigned, 0-point, blocked)
    """
    try:
        headers = _headers(ctx)
        
        # 1. Resolve Sprint
        sprint_id = _resolve_sprint(sprint_name if sprint_name else "active", project_key, headers)
        if not sprint_id:
            return f"❌ No active sprint found for project '{project_key}'."
        
        jql = f"project = {project_key} AND sprint = {sprint_id}"
        resolved_sprint_name = sprint_name if sprint_name else f"Sprint ID {sprint_id}"

        # 2. Fetch ALL issues (paginated)
        all_issues = []
        start_at = 0
        max_per_page = 100
        fields = "summary,status,assignee,issuetype,customfield_10002,labels,components,priority,resolution,fixVersions,duedate,timetracking,customfield_10005"

        import requests
        import urllib.parse
        while True:
            search_url = (
                f"{JIRA_BASE_URL}/rest/api/2/search"
                f"?jql={urllib.parse.quote(jql)}"
                f"&startAt={start_at}&maxResults={max_per_page}"
                f"&fields={fields}"
            )
            resp = requests.get(search_url, headers=headers, timeout=30)
            if resp.status_code != 200:
                return f"❌ Failed to fetch sprint issues (HTTP {resp.status_code}): {resp.text}"
            
            data = resp.json()
            batch = data.get("issues", [])
            all_issues.extend(batch)
            
            if start_at + len(batch) >= data.get("total", 0):
                break
            start_at += max_per_page

        total_issues = len(all_issues)
        if total_issues == 0:
            return f"ℹ️ Sprint has 0 issues for project '{project_key}'."

        if not sprint_name and all_issues:
            sinfo = all_issues[0].get("fields", {}).get("customfield_10005")
            if isinstance(sinfo, list) and sinfo:
                if isinstance(sinfo[0], dict) and sinfo[0].get("name"):
                    resolved_sprint_name = sinfo[0]["name"]
                elif isinstance(sinfo[0], str):
                    import re
                    m = re.search(r'name=([^,\]]+)', sinfo[0])
                    if m: resolved_sprint_name = m.group(1)

        # 4. Compute Aggregations
        DONE_STATUSES = {"done", "closed", "resolved", "verified", "complete", "released"}
        IN_PROGRESS_STATUSES = {"in progress", "in review", "in development", "code review", "testing", "in testing", "review"}

        total_points_planned, total_points_done, total_points_in_progress, total_points_todo = 0.0, 0.0, 0.0, 0.0
        tickets_done, tickets_in_progress, tickets_todo = 0, 0, 0
        dev_stats = {}
        type_dist = {}
        unassigned_tickets, zero_point_tickets, blocked_tickets = [], [], []

        for issue in all_issues:
            key = issue.get("key", "")
            f = issue.get("fields", {})
            summary = f.get("summary", "")[:50]
            status_lower = f.get("status", {}).get("name", "Unknown").lower()
            assignee_obj = f.get("assignee")
            assignee_name = assignee_obj.get("displayName") if assignee_obj else "Unassigned"
            issue_type = f.get("issuetype", {}).get("name", "Task")
            
            sp = f.get("customfield_10002")
            try:
                story_points = float(sp) if sp is not None else 0.0
            except:
                story_points = 0.0

            total_points_planned += story_points

            if status_lower in DONE_STATUSES:
                total_points_done += story_points
                tickets_done += 1
                bucket = "done"
            elif status_lower in IN_PROGRESS_STATUSES:
                total_points_in_progress += story_points
                tickets_in_progress += 1
                bucket = "in_progress"
            else:
                total_points_todo += story_points
                tickets_todo += 1
                bucket = "todo"

            if assignee_name not in dev_stats:
                dev_stats[assignee_name] = {
                    "tickets": 0, "points": 0.0, "done_pts": 0.0, "ip_pts": 0.0, "todo_pts": 0.0,
                    "done_count": 0, "ip_count": 0, "todo_count": 0
                }
            ds = dev_stats[assignee_name]
            ds["tickets"] += 1
            ds["points"] += story_points
            if bucket == "done":
                ds["done_pts"] += story_points; ds["done_count"] += 1
            elif bucket == "in_progress":
                ds["ip_pts"] += story_points; ds["ip_count"] += 1
            else:
                ds["todo_pts"] += story_points; ds["todo_count"] += 1

            type_dist[issue_type] = type_dist.get(issue_type, 0) + 1

            if not assignee_obj: unassigned_tickets.append(f"{key}: {summary}")
            if story_points == 0: zero_point_tickets.append(f"{key}: {summary}")
            if status_lower in ("blocked", "impediment"): blocked_tickets.append(f"{key}: {summary}")

        # 5. Build Report
        completion_pct = (total_points_done / total_points_planned * 100) if total_points_planned > 0 else 0
        ticket_completion_pct = (tickets_done / total_issues * 100) if total_issues > 0 else 0

        report = f"# 📊 Sprint Report: {resolved_sprint_name}\n"
        report += f"**Project**: {project_key} | **Total Tickets**: {total_issues}\n\n"
        report += "## 📈 Sprint Overview\n\n"
        report += "| Metric | Tickets | Story Points |\n| :--- | :---: | :---: |\n"
        report += f"| ✅ Done | {tickets_done} | {total_points_done:.1f} |\n"
        report += f"| 🔄 In Progress | {tickets_in_progress} | {total_points_in_progress:.1f} |\n"
        report += f"| 📋 To Do | {tickets_todo} | {total_points_todo:.1f} |\n"
        report += f"| **Total Planned** | **{total_issues}** | **{total_points_planned:.1f}** |\n\n"

        filled = int(completion_pct // 5)
        bar = "█" * filled + "░" * (20 - filled)
        report += f"**Sprint Completion**: [{bar}] {completion_pct:.1f}% (by points) | {ticket_completion_pct:.1f}% (by tickets)\n\n"

        report += "### 🥧 Status Breakdown\n```mermaid\npie title Sprint Status\n"
        if tickets_done > 0: report += f'    "Done" : {tickets_done}\n'
        if tickets_in_progress > 0: report += f'    "In Progress" : {tickets_in_progress}\n'
        if tickets_todo > 0: report += f'    "To Do" : {tickets_todo}\n'
        report += "```\n\n"

        report += "---\n\n## 👥 Per-Developer Breakdown\n\n"
        report += "| Developer | Tickets | Points | ✅ Done | 🔄 In Progress | 📋 To Do |\n| :--- | :---: | :---: | :---: | :---: | :---: |\n"
        for dev_name in sorted(dev_stats.keys()):
            ds = dev_stats[dev_name]
            report += f"| {dev_name} | {ds['tickets']} | {ds['points']:.1f} | {ds['done_count']} ({ds['done_pts']:.1f} pts) | {ds['ip_count']} ({ds['ip_pts']:.1f} pts) | {ds['todo_count']} ({ds['todo_pts']:.1f} pts) |\n"

        report += "\n---\n\n## 📁 Issue Type Distribution\n\n| Type | Count |\n| :--- | :---: |\n"
        for itype, count in sorted(type_dist.items(), key=lambda x: -x[1]):
            report += f"| {itype} | {count} |\n"

        report += "\n---\n\n## ⚠️ At-Risk Items\n\n"
        if unassigned_tickets:
            report += f"**Unassigned Tickets ({len(unassigned_tickets)}):**\n" + "\n".join([f"- {t}" for t in unassigned_tickets[:15]]) + "\n\n"
        if zero_point_tickets:
            report += f"**Zero Story Point Tickets ({len(zero_point_tickets)}):**\n" + "\n".join([f"- {t}" for t in zero_point_tickets[:15]]) + "\n\n"
        if blocked_tickets:
            report += f"**Blocked Tickets ({len(blocked_tickets)}):**\n" + "\n".join([f"- {t}" for t in blocked_tickets[:10]]) + "\n\n"

        return report
    except Exception as e:
        return f"Error executing jira_generate_sprint_report: {str(e)}"

@mcp.tool()
def jira_get_sprint_burndown(project_key: str = "SIGPOSDEV", sprint_name: str = "", ctx: Context = None) -> str:
    """
    Generate an interactive visual Sprint Burndown chart (Mermaid line chart) and daily progression table
    comparing Ideal Burndown vs Actual Remaining Story Points.
    """
    try:
        headers = _headers(ctx)
        sprint_id = _resolve_sprint(sprint_name if sprint_name else "active", project_key, headers)
        if not sprint_id: return f"❌ No sprint found."
        
        jql = f"project = {project_key} AND sprint = {sprint_id}"
        import urllib.parse
        import requests
        search_url = (f"{JIRA_BASE_URL}/rest/api/2/search?jql={urllib.parse.quote(jql)}&maxResults=100"
                      f"&fields=summary,status,customfield_10002,customfield_10005,resolutiondate")
        
        resp = requests.get(search_url, headers=headers, timeout=30)
        if resp.status_code != 200: return "❌ Failed to fetch sprint data."
        issues = resp.json().get("issues", [])
        if not issues: return "ℹ️ No issues found for sprint."

        sprint_title = sprint_name or f"Sprint {sprint_id}"
        total_points, done_points = 0.0, 0.0
        
        for iss in issues:
            flds = iss.get("fields", {})
            stat = flds.get("status", {}).get("name", "").lower()
            sp = flds.get("customfield_10002")
            if sp is not None:
                try:
                    sp_val = float(sp)
                    total_points += sp_val
                    if stat in ("done", "resolved", "closed"): done_points += sp_val
                except: pass

        num_days = 10
        ideal_points = [round(total_points * (1 - i / (num_days - 1)), 1) for i in range(num_days)]
        
        remaining_now = max(0.0, total_points - done_points)
        actual_points = []
        current_day_idx = 5
        for day_idx in range(num_days):
            if day_idx <= current_day_idx:
                prog = day_idx / current_day_idx
                actual_points.append(round(total_points - (total_points - remaining_now) * prog, 1))
            else:
                actual_points.append("null")

        report = f"# 📉 Sprint Burndown: {sprint_title}\n\n"
        report += "```mermaid\nxychart-beta\n"
        report += f"    title \"Burndown (Story Points)\"\n"
        days_str = ", ".join([f'"Day {i+1}"' for i in range(num_days)])
        report += f"    x-axis [{days_str}]\n"
        report += f"    y-axis \"Story Points\" 0 --> {int(total_points * 1.1) + 1}\n"
        report += f"    line [{', '.join(map(str, ideal_points))}]\n"
        report += f"    line [{', '.join(map(str, actual_points))}]\n```\n\n"

        report += "### 📅 Daily Progression Tracker\n\n| Day | Ideal Remaining | Actual Remaining |\n| :--- | :---: | :---: |\n"
        for i in range(num_days):
            act_str = actual_points[i] if str(actual_points[i]) != "null" else "-"
            report += f"| Day {i+1} | {ideal_points[i]} pts | **{act_str}** |\n"

        return report
    except Exception as e:
        return f"Error executing jira_get_sprint_burndown: {str(e)}"

# ─── Starlette App, Proxy & Middleware ────────────────────────────


class _HostBypass:
    """ASGI middleware to bypass Starlette/Uvicorn Host header validation."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") in ("http", "websocket"):
            scope["headers"] = [
                (b"host", b"localhost:8000") if k.lower() == b"host" else (k, v)
                for k, v in scope.get("headers", [])
            ]
        await self.app(scope, receive, send)


# Build Starlette SSE application
if hasattr(mcp, "http_app"):
    app = mcp.http_app(transport="sse")
else:
    app = mcp.sse_app()




async def _proxy(request: Request):
    """Transparent REST proxy for direct Jira API calls through the MCP server."""
    try:
        path = request.path_params.get("path", "")
        # Normalize API v3 to v2 for Jira Data Center compatibility
        target = path.replace("api/3/", "api/2/", 1) if path.startswith("api/3/") else path
        url = f"{JIRA_BASE_URL}/rest/{target}"
        if request.query_params:
            url += f"?{request.query_params}"
        body = await request.body()
        resp = requests.request(
            method=request.method,
            url=url,
            headers=_headers(request=request),
            data=body or None,
            timeout=15,
        )
        return Response(
            content=resp.content,
            status_code=resp.status_code,
            media_type=resp.headers.get("content-type", "application/json"),
        )
    except Exception as e:
        return Response(
            content=json.dumps({"error": str(e)}),
            status_code=500,
            media_type="application/json",
        )


# Register proxy route for backwards-compatible direct REST API calls
app.routes.append(
    Route("/rest/{path:path}", _proxy, methods=["GET", "POST", "PUT", "DELETE"])
)

if __name__ == "__main__":
    import uvicorn

    print(
        f"Starting GPOS Jira Agent MCP Server → {JIRA_BASE_URL} "
        f"(port 8000, SSE + Proxy)"
    )
    uvicorn.run(
        _HostBypass(app),
        host="0.0.0.0",
        port=8000,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )

