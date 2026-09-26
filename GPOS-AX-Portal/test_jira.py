from server import fetch_jira
import os
import json

pat = os.environ.get('JIRA_PAT')
data = fetch_jira('api/2/issue/SIGPOSDEV-2980', {}, pat)
print(json.dumps(data.get('fields', {}).get('status', {}), indent=2))
print("Assignee:")
print(json.dumps(data.get('fields', {}).get('assignee', {}), indent=2))
