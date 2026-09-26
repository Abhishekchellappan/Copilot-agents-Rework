import re

with open('static/index.html', 'r', encoding='utf-8') as f:
    content = f.read()

target_str = '''                  let jql = \project = SIGPOSDEV AND sprint in openSprints() AND assignee = "\\\"\;
                  if (statusStr) {
                      jql += \ AND status = "\\\"\;
                  }'''

target_str = target_str.replace('\', '')

replacement = '''                  let actualUser = username;
                  let parts = username.split(' ');
                  if (parts.length > 1) actualUser = parts[parts.length - 1];
                  let jql = \project = SIGPOSDEV AND sprint in openSprints() AND assignee ~ "\"\;
                  if (statusStr) {
                      if (statusStr === 'To Do') jql += \ AND status in ("Open", "To Do", "Reopened", "Backlog")\;
                      else if (statusStr === 'In Progress') jql += \ AND status in ("In Progress", "Active", "Working")\;
                      else if (statusStr === 'Done') jql += \ AND status in ("Done", "Resolved", "Closed", "Completed")\;
                      else jql += \ AND status = "\"\;
                  }'''

content = content.replace(target_str, replacement)

with open('static/index.html', 'w', encoding='utf-8') as f:
    f.write(content)

print('done')
