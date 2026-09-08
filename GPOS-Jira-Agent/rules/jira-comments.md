# Jira Comment Formatting Rules

## Standard Comment Structure

Whenever adding a comment summarizing work, use this clean layout **without leading numbers on headings**:

```markdown
### 📌 Work Summary
A 1-2 sentence overview of the task/work done.

**AI Contribution**:
- Bullet points detailing what the AI generated, analyzed, or assisted with.

**Developer Contribution**:
- Bullet points detailing what the developer reviewed, implemented, or tested.
```

## Formatting Constraints

- **Bold Titles**: Section headers MUST use bold or Markdown headings.
- **Code Blocks**: Any code snippet or config MUST use fenced code blocks with language identifiers.
- **Tables**: Comparative data, audit logs, or metrics MUST use Markdown tables.
- **DO NOT** start section titles with numbers (e.g. `1. Work Summary`). Use clean headings.

## Context-Aware Comment Generation

When asked to add a comment without explicit text:
1. **FIRST** call `jira_get_issue` or `jira_get_comments` to read the ticket's summary, description, and status.
2. Synthesize a **ticket-specific, meaningful comment** based on actual ticket context.
3. **NEVER** use generic placeholder text like "Created and configured Jira story...".

## Context-Aware Comment Replies

When asked to reply to a ticket comment:
- Read the full chronological comment thread + Title + Description + DOD
- Synthesize a polite, contextually accurate response

## 3. The "Draft & Approve" Protocol (Mandatory)
Before you call `jira_add_comment` to reply to or close a ticket, you **MUST** follow this strict workflow:

1. **Mandatory Context Gathering:** You are strictly forbidden from writing a "blind" reply. You MUST first call `jira_get_issue` (to read the description) and `jira_get_comments` (to read the full comment history).
2. **Drafting:** Format your proposed comment nicely in the chat window for the user to see.
3. **Approval:** Explicitly ask the user: *"Shall I post this comment to Jira?"*
4. **Execution:** ONLY execute `jira_add_comment` after the user explicitly types "Yes" or approves.
