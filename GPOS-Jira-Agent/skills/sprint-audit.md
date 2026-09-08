# Skill: Sprint Governance Audit

When the user asks to "audit the sprint", "audit labels", or "check missing items in sprint", follow these steps:

## Step 1: Fetch Sprint Tickets
Call `jira_search` with JQL:
```
project = <PROJECT_KEY> AND sprint in openSprints() ORDER BY key DESC
```
Request fields: `summary,status,assignee,labels,priority,issuetype,customfield_10002`

Use `SIGPOSDEV` as default project key if the user doesn't specify one.

## Step 2: Audit Each Ticket

For each ticket returned, check against the governance rules in `rules/jira-governance.md`:

1. **Assignee Check**: Flag tickets with no assignee as `⚠️ Missing Assignee`
2. **Story Points Check**: Flag tickets where `customfield_10002` is null, empty, or 0 as `⚠️ Missing Story Points`
3. **Label Check**: Flag tickets that do NOT have at least one valid label from the whitelist in `rules/jira-governance.md` as `⚠️ Missing Category/AX Label`

## Step 3: Output Audit Report

If violations found, output as a Markdown table:
```
| Key | Summary | Assignee | Labels | Violations |
|:----|:--------|:---------|:-------|:-----------|
| [PROJ-123](link) | Fix auth bug... | ⚠️ Unassigned | None | Missing Assignee, Missing Label |
```

If all tickets pass: output a success message like:
> ✅ **Sprint Governance Audit PASSED** — All N tickets have valid labels, assignees, and story points.

## Important
- **NEVER invent or pass non-existent labels** like `AX-Approved` or `Reviewed`.
- Use ONLY the valid labels defined in `rules/jira-governance.md`.
