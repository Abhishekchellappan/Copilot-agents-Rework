# GPOS Jira Agent — Generic MCP Server

A **generic, stateless MCP server** for Jira Data Center integration with GitHub Copilot in VS Code.

> **Design Philosophy**: The Python MCP server provides only generic Jira REST API tools. All business rules, label policies, governance checks, report formatting, and workflow logic live in **Markdown files** that Copilot reads at runtime. This means you can modify agent behavior by editing `.md` files — **no Docker rebuilds or Kubernetes redeployments required**.

---

## 📂 Project Structure

```
GPOS-Jira-Agent/
├── .github/
│   └── copilot-instructions.md       ← Master instruction file (auto-loaded by VS Code Copilot)
├── rules/
│   ├── jira-governance.md            ← AX labels, context labels, component auto-assignments
│   ├── jira-fields.md                ← Project defaults, custom field aliases, field checklists
│   ├── jira-safety.md                ← 2-Phase Confirmation Protocol for destructive actions
│   └── jira-comments.md              ← Structured comment templates
├── skills/
│   ├── sprint-audit.md               ← Sprint governance audit workflow
│   ├── sprint-report.md              ← Sprint health report workflow
│   ├── sprint-burndown.md            ← Burndown chart rendering workflow
│   └── epic-grooming.md              ← Epic/Initiative grooming workflow
├── jira_server.py                    ← Generic Python MCP Server (13 tools + REST proxy)
├── quick_test.py                     ← Local smoke test
├── Dockerfile                        ← Container build
├── requirements.txt                  ← Python dependencies
├── gpos-jira-mcp-k8s.yaml           ← Kubernetes Deployment & Service manifest
├── mcp.json                         ← VS Code MCP configuration sample
└── README.md                        ← This file
```

---

## 🛠️ Build & Deploy

### Step 1: Build Docker Image
```bash
cd GPOS-Jira-Agent
docker build -t abhishek15c/gpos-jira-agent:latest .
docker push abhishek15c/gpos-jira-agent:latest
```

### Step 2: Deploy to Kubernetes
```bash
# Update image tag in gpos-jira-mcp-k8s.yaml line 18
kubectl apply -f gpos-jira-mcp-k8s.yaml
kubectl get pods -l app=gpos-jira-mcp
kubectl get svc gpos-jira-mcp-service
```

### Step 3: VS Code Configuration
Copy `mcp.json` to `.vscode/mcp.json` in your project (or add to User Settings) and update:
- `<YOUR_PERSONAL_ACCESS_TOKEN>` with your Jira PAT

---

## 🔧 Available MCP Tools

| Tool | Description |
|:-----|:------------|
| `jira_search` | Search issues via JQL query |
| `jira_get_issue` | Fetch full issue details by key |
| `jira_create_issue` | Create a new issue with field aliases |
| `jira_update_issue` | Update issue fields |
| `jira_delete_issue` | Delete an issue (irreversible) |
| `jira_get_comments` | Fetch comment history |
| `jira_add_comment` | Add comment (Markdown → Jira markup) |
| `jira_delete_comment` | Delete a comment by ID or latest |
| `jira_get_transitions` | List available workflow transitions |
| `jira_transition_issue` | Change issue status |
| `jira_log_work` | Log time on an issue |
| `jira_get_fields` | Discover field names and IDs |
| `jira_raw_api` | Execute any raw Jira REST API call |

---

## 📝 How to Modify Agent Behavior (No Rebuild Needed!)

| Want to... | Edit this file |
|:-----------|:---------------|
| Change default project key | `rules/jira-fields.md` |
| Add/remove valid labels | `rules/jira-governance.md` |
| Change safety confirmation rules | `rules/jira-safety.md` |
| Modify comment templates | `rules/jira-comments.md` |
| Update sprint audit criteria | `skills/sprint-audit.md` |
| Modify report format | `skills/sprint-report.md` |
| Change burndown chart style | `skills/sprint-burndown.md` |
| Update epic grooming logic | `skills/epic-grooming.md` |

---

## 🧪 Testing

```bash
# Start the server locally
python jira_server.py

# In another terminal, run smoke tests
python quick_test.py
```

---

## 🧪 Test with Copilot Chat

- **Fetch Issue**: `"Fetch details for Jira issue PROJ-101"`
- **Search Issues**: `"Search Jira for all open tasks in project PROJ"`
- **Create Issue**: `"Create a Jira task in project PROJ with summary 'Add unit test'"`
- **Audit Sprint**: `"Audit the active sprint for missing labels and story points"`
- **Sprint Report**: `"Generate a sprint health report for SIGPOSDEV"`
