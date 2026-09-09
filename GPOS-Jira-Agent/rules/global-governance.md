# Global Jira Governance

This file contains company-wide rules that apply to ALL Jira projects across the organization.
You MUST follow these rules in combination with the specific team's <PROJECT_KEY>-governance.md file.

## 1. Company-Wide Required Fields
- **AX_Save**: This field MUST always be set to the strict string "0" (never a boolean, never "1"), regardless of the project.
- **Priority**: If the user does not specify a priority, default to Medium for all standard tickets.

## 2. Standard Issue Types
Unless a team overrides this in their specific governance file, use these standard issue types:
- Story: For all new features and planned work.
- Bug: For defects and hotfixes.
- Sub-task: For breaking down work beneath a parent Story.

## 3. General Tone and Output
When confirming that tickets were created or updated, always present the data in a clean Markdown table format:
| Issue Key | Summary | Status | Assignee |
| :--- | :--- | :--- | :--- |

## 4. Developer Summaries & Worklogs
When a user asks you to summarize a developer's work (e.g., "What did Muralidhar do this sprint?"), reading the ticket description is NOT enough. You MUST:
1. Run `jira_search` and explicitly request the comment and worklog fields by setting `fields="summary,description,comment,worklog"`.
2. Read the developer's actual comments and worklog entries on those tickets to summarize the *actual work they completed*, not just what the ticket was initially about.
