from server import _classify_status, _get_sprint_issues
import os
import json

pat = os.environ.get('JIRA_PAT')
issues, _, _ = _get_sprint_issues("SIGPOSDEV", "active", pat)
for issue in issues:
    fields = issue.get('fields', {})
    key = issue.get('key')
    assignee = fields.get('assignee', {})
    assignee_name = assignee.get('name') if assignee else 'Unassigned'
    status_obj = fields.get('status', {})
    status_class = _classify_status(status_obj.get('name'), status_obj)
    
    if '2980' in key or 'abhishek' in assignee_name:
        print(f"Key: {key}, Assignee: {assignee_name}, Status: {status_obj.get('name')}, Category: {status_obj.get('statusCategory', {}).get('key')}, Class: {status_class}")
