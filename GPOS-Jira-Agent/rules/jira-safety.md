# Jira Safety Controls — 2-Phase Confirmation Protocol

## 🛑 CRITICAL MANDATORY RULE

Agent actions that **modify or delete** Jira data MUST NEVER be executed automatically on your first response. You are **STRICTLY FORBIDDEN** from calling mutating tools on your first turn.

Your FIRST response MUST ONLY display the draft action and ask for confirmation.

## Confirmation Workflows

### Adding a Comment
1. If needed, call `jira_get_issue` or `jira_get_comments` to read ticket context.
2. Draft the comment following the template in `rules/jira-comments.md`.
3. Show the draft comment text to the user in chat.
4. **STOP and ask**: *"Reply 1 to Post, or 2 to Cancel."*
5. Only call `jira_add_comment` after the user replies with `1` or positive confirmation.

### Deleting a Ticket
1. Display the target ticket key and summary.
2. **Ask**: *"Reply 1 to Delete, or 2 to Cancel."*
3. Only call `jira_delete_issue` after user confirms.

### Deleting a Comment
1. When asked to delete a comment, **NEVER ask the user for the comment ID**.
2. Auto-resolve it using `jira_get_comments` or by passing `comment_id='latest'`.
3. Display the comment snippet and ticket key.
4. **Ask**: *"Reply 1 to Delete, or 2 to Cancel."*
5. Only call `jira_delete_comment` after user confirms.

### Updating Ticket Fields
1. Display the modified fields and target ticket key.
2. **Ask**: *"Reply 1 to Update, or 2 to Cancel."*
3. Only call `jira_update_issue` after user confirms.

### Transitioning Status
1. Display: *"I will transition **[KEY]** to status **'NewStatus'**. Reply **1** to Confirm, or **2** to Cancel."*
2. Only call `jira_transition_issue` after user confirms.

### Logging Work
1. Display: *"I will log **2h** on **[KEY]** with comment '...'. Reply **1** to Confirm, or **2** to Cancel."*
2. Only call `jira_log_work` after user confirms.

## Read Operations (No Confirmation Needed)

These tools can be called immediately without asking:
- `jira_search`
- `jira_get_issue`
- `jira_get_comments`
- `jira_get_transitions`
- `jira_get_fields`
- `jira_raw_api` (GET only)
