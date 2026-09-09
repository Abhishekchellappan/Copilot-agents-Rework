# Jira Governance Rules — Labels, Components & Auto-Assignment

> **🚨 CRITICAL DISTINCTION (AX_phase vs Labels)**:
> You must NEVER confuse the `AX_phase` custom field with the AX Labels!
> - The **Label** field (`labels`) gets the text string (e.g., `"AX_SDS"`, `"AX_IMPL"`).
> - The **AX_phase custom field** (`customfield_46609`) MUST ONLY BE A SINGLE DIGIT STRING (e.g., `"1"`, `"2"`, `"3"`, `"4"`, `"5"`, `"6"`, `"7"`). 
> - The **AX_Save custom field** (`customfield_47009`) MUST ALWAYS BE THE STRING `"0"`. It is NEVER a boolean (`true`/`false`).
> **NEVER** put text like `"AX_SDS"` or `"Implementation"` into the `AX_phase` custom field! It will corrupt the database.

## Automatic Labeling Rules by AX Phase

When creating, updating, or auditing Jira stories, analyze the title, description, and context, then automatically assign the corresponding labels:

### 1. Requirements & Analysis Phase
- **Label**: `AX_REQ`
- **Workflows & AX_phase Numbers**:
  - Going through the entire requirements / SRS / RFC documents -> **AX_phase: 1**
  - Defining functional and non-functional requirements -> **AX_phase: 2**
  - Reviewing the Feasibility of implementation -> **AX_phase: 3**
  - Scope estimation (effort, timeline, complexity) -> **AX_phase: 4**
- **Output Label**: Add `Analysis-Done` when analysis is complete

### 2. High-Level Design (HLD) Phase
- **Label**: `AX_HLD`
- **Workflows & AX_phase Numbers**:
  - Define system context & boundaries -> **AX_phase: 1**
  - Static (Class) Diagram -> **AX_phase: 2**
  - Dynamic (Sequence) Diagram -> **AX_phase: 3**
  - Design data flow -> **AX_phase: 4**
  - HLD review -> **AX_phase: 5**

### 3. Detailed Software Design (SDS) Phase
- **Label**: `AX_SDS`
- **Workflows & AX_phase Numbers**:
  - Design module internals (classes, methods, state machines) -> **AX_phase: 1**
  - Define interfaces & logic flows -> **AX_phase: 2**
  - Detailed Design Review -> **AX_phase: 3**

### 4. Software Implementation Phase
- **Label**: `AX_IMPL`
- **Workflows & AX_phase Numbers**:
  - Implement module code (classes, methods, logic) -> **AX_phase: 1**
  - Write unit tests & mocks -> **AX_phase: 2**
  - Run static analysis (lint, security) -> **AX_phase: 3**
  - Local Build and package artifacts -> **AX_phase: 4**
  - Peer code review -> **AX_phase: 5**
  - Fixing review comments & bug fixes -> **AX_phase: 6**
  - Maintenance & Stabilization -> **AX_phase: 7**
- **Output Label**: Add `code_merged` when code is merged

## Context-Based Labels

In addition to AX phase labels, apply these context labels:

| Context | Label | Trigger Keywords |
|:--------|:------|:-----------------|
| Training & Skill Up | `training` | SWPCT, LSET, Skill Up, training, certification, exam, practising, learning |
| Implementation / Development | `development` | Coding, implementation, feature development, bug fix, integration, deploy, build |
| Exploration / Research (No Dev) | `Analysis-Done` | Exploration, research, investigation, feasibility — with NO implementation |
| Operations & Ceremonies | `operations` | Sprint grooming, planning, retrospective, standup, backlog refinement |
| Planned Leave | `planned_leave` | Planned leave, vacation, PTO, holiday, out of office |
| Unplanned Leave | `unplanned_leave` | Unplanned leave, sick leave, emergency leave, medical |

> **Multi-Labeling**: A story can have BOTH an AX phase label AND a context label. Apply all that match.

> **⚠️ STRICT LABEL WHITELIST**: The ONLY valid labels are: `AX_REQ`, `AX_HLD`, `AX_SDS`, `AX_IMPL`, `Analysis-Done`, `code_merged`, `training`, `development`, `operations`, `planned_leave`, `unplanned_leave`. **NEVER invent new label names.**

## Component Auto-Assignment Rules

| Story Context | Component Name | Trigger Keywords |
|:--------------|:---------------|:-----------------|
| LSET / Skill Up / SWPCT / Training | `2026_HS_GPOS_Platform_SkillUp` | LSET, SWPCT, Skill Up, training, certification |
| Planned Leave | `2026_HS_Planned_Leave` | Planned leave, vacation, PTO, holiday |
| Unplanned Leave | `2026_HS_Unplanned_Leave` | Unplanned leave, sick leave, emergency leave |
| Default (All Others) | `2026_HS_GPOS_PLATFORM` | Fallback when no specific component matches |

> If the user explicitly specifies a component, use that instead of the auto-assigned one.
