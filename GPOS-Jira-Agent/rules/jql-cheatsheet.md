# JQL Cheat Sheet

LLMs frequently struggle to translate natural language into accurate Jira Query Language (JQL).
Before executing `jira_search`, you MUST apply these strict translation rules to ensure you don't fetch other people's tickets by mistake.

## 1. Assignee Filtering
If the user asks for "my" tickets, or tickets assigned to "me", you MUST append:
`AND assignee = currentUser()`

If the user asks for tickets assigned to someone else (e.g., "Muralidhar's tickets"), use their exact username or email:
`AND assignee = "muralidhar.n"`

## 2. Backlog / Open Tickets
If the user asks for "backlog" or "open" tickets, you MUST exclude tickets that are already done and tickets in the active sprint:
`AND statusCategory != Done AND sprint IS EMPTY`

## 3. Active Sprint
If the user asks for tickets in the "active sprint" or "current sprint":
`AND sprint in openSprints()`

## 4. Ordering
Always append a logical sort order unless the user specifies otherwise:
`ORDER BY created DESC`

## Example Translations:
**User:** "List my backlog stories in SIGPOSDEV"
**Bad JQL (DO NOT USE):** `project = SIGPOSDEV` (This fetches EVERYONE'S tickets!)
**Correct JQL:** `project = SIGPOSDEV AND assignee = currentUser() AND statusCategory != Done AND sprint IS EMPTY ORDER BY created DESC`
