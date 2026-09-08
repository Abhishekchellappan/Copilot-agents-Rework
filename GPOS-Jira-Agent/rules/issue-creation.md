# Jira Issue Creation: Mandatory Pre-Flight Checklist

Before you construct a JSON payload to call `jira_create_issue`, you **MUST** follow this checklist step-by-step.

## 1. Project Fallback
- If the user does not specify a project key, ALWAYS default to **`SIGPOSDEV`**.
- If the user specifies a project key, respect it.

## 2. Strict Governance Enforcement (Anti-Hallucination)
- **CRITICAL RULE:** You are strictly forbidden from inventing or hallucinating labels (e.g., do NOT use `automation`, `jira`, `agent`).
- Before you pick a label, you **MUST** open and read `rules/jira-governance.md`.
- You may only use labels explicitly defined in the governance whitelist.

## 3. Intelligent AX_phase (Number) Mapping
- Analyze the user's summary and map it to the workflows defined in `rules/jira-governance.md`.
- **Labels:** Add the exact category label (e.g., `AX_REQ`, `AX_IMPL`) to the `labels` array.
- **AX_phase Field:** Insert the exact **NUMBER** (e.g., `1`, `2`, `3`) corresponding to the workflow task into the `AX_phase` field.

## 4. AX_Save Default
- ALWAYS initialize `AX_Save` to the number **`0`**.
- Only change this if the user explicitly instructs you otherwise.

## 5. Contextual Components
- ALWAYS format components strictly as a JSON array of objects: `"components": [{"name": "<ComponentName>"}]`.
- Default to `"2026_HS_GPOS_PLATFORM"` unless the context clearly points to a training/leave component (refer to `jira-governance.md`).

## 6. Sprint Resolution & Epic Linking
- **Sprint:** If the user asks for the "current" or "active" sprint, use `jira_search` to find the active sprint ID before submitting the creation payload.
- **Epic Link:** If requested, set the Epic Link field to the target Epic key.

## 7. Issue Type Constraints (Strict Exclusions)
- If the `issuetype` is **`Epic`** or **`Initiative`**, you MUST NEVER include `AX_phase`, `AX_Save`, or `Sprint` fields in the payload. Those fields are strictly forbidden for higher-level issue types.

## 8. Post-Creation Output Formatting
- When you successfully create an issue, you **MUST NEVER** confirm it using a raw bulleted list.
- You **MUST** output the confirmation details as a beautifully aligned Markdown table:
  `| Issue Key | Type | Summary | Assignee | Priority | Labels | AX_phase |`
