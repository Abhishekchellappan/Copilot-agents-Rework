const fs = require('fs');
let content = fs.readFileSync('static/index.html', 'utf8');

let target = "                  let jql = \project = SIGPOSDEV AND sprint in openSprints() AND assignee = \"\\"\;\r\n                  if (statusStr) {\r\n                      jql += \ AND status = \"\\"\;\r\n                  }";

if (!content.includes(target)) {
    target = target.replace(/\r\n/g, '\n');
}

let replacement =                   let actualUser = username;
                  let parts = username.split(' ');
                  if (parts.length > 1) actualUser = parts[parts.length - 1];
                  let jql = \\\project = SIGPOSDEV AND sprint in openSprints() AND assignee ~ "\"\\\;
                  if (statusStr) {
                      if (statusStr === 'To Do') jql += \\\ AND status in ("Open", "To Do", "Reopened", "Backlog")\\\;
                      else if (statusStr === 'In Progress') jql += \\\ AND status in ("In Progress", "Active", "Working")\\\;
                      else if (statusStr === 'Done') jql += \\\ AND status in ("Done", "Resolved", "Closed", "Completed")\\\;
                      else jql += \\\ AND status = "\"\\\;
                  };

content = content.replace(target, replacement);
fs.writeFileSync('static/index.html', content, 'utf8');
console.log('done');
