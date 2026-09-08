# Skill: Sprint Burndown Chart

When the user asks for a "burndown chart", "sprint burndown", or "burn progress":

## Step 1: Get Sprint Info
Use `jira_raw_api` to fetch the active sprint details:
- Method: `GET`
- Endpoint: `rest/agile/1.0/board/<BOARD_ID>/sprint` with `state=active`

Note the sprint start date and end date.

## Step 2: Get Sprint Issues with Resolution Dates
Call `jira_search` with JQL:
```
project = <PROJECT_KEY> AND sprint = <SPRINT_ID>
```
Request fields: `summary,status,customfield_10002,resolutiondate,created`

## Step 3: Calculate Burndown

For each day from sprint start to today:
1. **Ideal Remaining** = Total Points × (Remaining Days / Total Days)
2. **Actual Remaining** = Total Points - (Points resolved on or before this date)

## Step 4: Render Chart

Output a Mermaid xychart-beta line chart:
```mermaid
xychart-beta
    title "Sprint Burndown"
    x-axis ["Day 1", "Day 2", "Day 3", ...]
    y-axis "Story Points" 0 --> <MAX>
    line "Ideal" [20, 18, 16, 14, ...]
    line "Actual" [20, 20, 18, 15, ...]
```

Also output a daily progression table:
```
| Day | Date | Ideal | Actual | Delta |
|:----|:-----|:------|:-------|:------|
```
