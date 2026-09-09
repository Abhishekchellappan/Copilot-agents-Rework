# Jira Field Mappings & Defaults

## Default Project Configuration
- **Default Project Key**: `SIGPOSDEV`
- **Default Issue Type**: `Story`
- **Default Sprint**: `active` (auto-resolves to the currently active sprint)
- **Default Component**: `2026_HS_GPOS_PLATFORM` (unless overridden by component auto-assignment rules)

## Custom Field Aliases

The MCP server automatically translates these friendly names to Jira custom field IDs:

| Friendly Name | Jira Field ID | Description |
|:--------------|:--------------|:------------|
| `sprint` | Auto-resolved via Agile API | Active sprint or named sprint |
| `epic_link` | Auto-discovered | Parent epic key |
| `story_points` | Auto-discovered | Story point estimate |
| `original_story_points` | Auto-discovered | Original story points |
| `start_date` / `start_date_alm` | Auto-discovered | Start Date_ALM (format: YYYY-MM-DD) |
| `due_date` | `duedate` | Due date (format: YYYY-MM-DD) |
| `fix_version` / `fix_versions` | `fixVersions` | Auto-wrapped to `[{"name": "..."}]` |
| `original_estimate` | `timetracking.originalEstimate` | e.g. "2d", "4h" |
| `resolution` | `resolution` | Auto-wrapped to `{"name": "..."}` |
| `assignee` | `assignee` | Auto-wrapped to `{"name": "username"}` |
| `labels` | `labels` | Comma-separated or list |
| `component` / `components` | `components` | Auto-wrapped to `[{"name": "..."}]` |

> **Tip**: Use `jira_get_fields` tool to discover any field name or ID in your Jira instance.

## Mandatory Field Checklist (Issue Creation)

When the user provides fields for a new issue, process ALL of them. Do NOT skip any:

| User Field | Tool Parameter |
|:-----------|:---------------|
| Summary | `summary` |
| Description | `description` |
| Assignee | `fields: {"assignee": "username"}` |
| Story Points | `fields: {"story_points": <number>}` |
| Labels | `fields: {"labels": ["label1", "label2"]}` |
| Priority | `fields: {"priority": {"name": "P2"}}` |
| Sprint | `fields: {"sprint": "active" or "SprintName"}` |
| Component | `fields: {"component": "ComponentName"}` |
| Epic Link | `fields: {"epic_link": "PROJ-XXXX"}` |
| Fix Version/s | `fields: {"fix_version": "v1.0"}` |
| Start Date | `fields: {"start_date": "2026-08-10"}` |
| Due Date | `fields: {"due_date": "2026-08-15"}` |
| Original Estimate | `fields: {"original_estimate": "2d"}` |

> **⚠️ CRITICAL**: Before calling `jira_create_issue`, cross-check your tool call arguments against the user's request. Every field mentioned MUST be present.

## AX Field Custom Mappings
The following fields do not have automatic friendly aliases and MUST be explicitly passed in the `custom_fields` dictionary when calling `jira_create_issue` or `jira_update_issue`:

| Friendly Name | Jira Field ID | Value Format |
|:--------------|:--------------|:-------------|
| `AX_phase` | `customfield_46609` | STRICTLY a single-digit string (e.g. `"1"`, `"2"`). NEVER text like `"AX_SDS"`! |
| `AX_Save` | `customfield_47009` | Always string `"0"` unless requested otherwise |

> **⚠️ CRITICAL**: When adding AX fields, you MUST use `customfield_46609` and `customfield_47009`. Do NOT pass "AX_phase" as a key.

## Description Generation Rule

When the user asks for a "meaningful description" or "add description based on summary":
- Generate a **detailed, expanded description** (3-5 sentences minimum)
- Explain the purpose, scope, and expected outcome
- Do NOT simply copy the summary as the description
