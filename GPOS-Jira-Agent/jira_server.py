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
        result = {"key": data["key"], "self": data.get("self", "")}
        result.update(data.get("fields", {}))
        return json.dumps(result, indent=2, default=str)
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
