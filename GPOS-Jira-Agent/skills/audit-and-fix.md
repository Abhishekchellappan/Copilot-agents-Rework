# Bulk Audit & Auto-Fix Skill

This skill replaces rigid hardcoded audits. It allows you to dynamically search for issues missing specific governance fields (components, labels, Epic links) and bulk-update them intelligently based on their context.

## Workflow Execution Steps

When the user asks you to "find and fix missing components/labels/fields" or "audit my past stories":

### 1. Dynamic JQL Auditing
- Ask the user for the specific filter, sprint, or criteria if not provided (e.g., "Which past sprints or filters should I check?").
- Construct a dynamic JQL query using `jira_search`. 
  - *Example:* If searching for missing components assigned to the user: `assignee = currentUser() AND component is EMPTY`.
- Retrieve the affected tickets (ensure you request `summary,description,labels,components,customfield_10014` in the `fields` parameter to avoid JSON bloat).

### 2. Contextual Evaluation (The "Brain" Step)
- Do **NOT** blindly apply a single component or label to all tickets.
- For **EACH** ticket found:
  1. Read its summary and description.
  2. Open and consult `rules/jira-governance.md`.
  3. Determine the correct **Label** (e.g., `AX_IMPL`), the correct **AX_phase Number** (e.g., `2`), and the correct **Component** (defaulting to `2026_HS_GPOS_PLATFORM`).

### 3. Proposed Fix Table (Draft & Approve)
- Output your findings and proposed fixes in a beautifully aligned Markdown table for the user to review.
- **Table Format:**
  `| Issue Key | Summary | Current Status | Proposed Label | Proposed AX_phase | Proposed Component |`
- **Wait for Approval:** Explicitly ask the user: *"Does this bulk update plan look correct? Shall I proceed with updating all these tickets?"*

### 4. Auto-Execution (Bulk Update)
- ONLY after the user approves, loop through each ticket and call `jira_update_issue` with the proposed fields.
- **Confirmation:** Once finished, output a final success table confirming the exact fields updated for each ticket.
