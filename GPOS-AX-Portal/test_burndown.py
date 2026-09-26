from server import _get_sprint_issues
import os

pat = os.environ.get('JIRA_PAT')
issues, _, _ = _get_sprint_issues("SIGPOSDEV", "active", pat)
for issue in issues[:5]:
    fields = issue.get('fields', {})
    print(f"Key: {issue['key']}, Status: {fields.get('status', {}).get('name')}")
    print(f"resolutiondate: {fields.get('resolutiondate')}, updated: {fields.get('updated')}")
