# 📱 Device Debugging & Automated Triage MCP Server (`device-agent`)

> A production-grade **Model Context Protocol (MCP)** server that connects AI coding assistants (GitHub Copilot, Antigravity Agent) directly to embedded Linux / webOS target devices. Provides live binary discovery, non-destructive deployment (SCP + bind-mount), crash capture (GDB, Valgrind, Core Dumps), silent crash detection, security audits (ACG, SMACK, DAC), and live Collab (Confluence) documentation integration.

---

## 📑 Table of Contents
1. [Architecture Overview](#-architecture-overview)
2. [Complete Inventory of 26 Tools](#-complete-inventory-of-26-tools)
3. [Safety Guardrails & 2-Phase Confirmation](#-safety-guardrails--2-phase-confirmation)
4. [Live Collab (Confluence) Wiki Integration](#-live-collab-confluence-wiki-integration)
5. [Multi-Architecture Tool Vault](#-multi-architecture-tool-vault)
6. [Target Fleet Inventory Setup](#-target-fleet-inventory-setup)
7. [Kubernetes Deployment Guide](#-kubernetes-deployment-guide)
8. [VS Code & IDE Configuration (`mcp.json`)](#-vs-code--ide-configuration-mcpjson)
9. [Developer Prompt Cheatsheet](#-developer-prompt-cheatsheet)
10. [Verification & Health Check](#-verification--health-check)

---

## 🏛️ Architecture Overview

```mermaid
flowchart TD
    subgraph Developer PC
        VSCode[VS Code / Copilot Agent]
        MCP_JSON[mcp.json\nHeaders: X-Collab-URL, X-Collab-PAT]
    end

    subgraph Kubernetes Cluster [Namespace: ai-user2]
        NodePort[NodePort Service :30724]
        Pod[device-mcp-server Pod\nFastMCP SSE Transport :8000]
        Vault[/tools Multi-Arch Vault]
    end

    subgraph Enterprise Services
        Collab[Collab / Confluence REST API]
        Target[Embedded Target Device\nwebOS / Linux via SSH]
    end

    VSCode -->|SSE Request + Headers| NodePort
    NodePort --> Pod
    Pod -->|REST API Query| Collab
    Pod -->|SSH / SCP / GDB / Bind-Mount| Target
    Pod -.->|Auto-provision gdbserver/tools| Vault
```

- **Transport**: Server-Sent Events (SSE) via FastMCP 2.x / Uvicorn.
- **Port**: NodePort `30724` $\rightarrow$ Container `8000`.
- **Target OS**: webOS / Embedded Linux (SquashFS read-only rootfs supported via bind-mounts).

---

## 🛠️ Complete Inventory of 26 Tools

| # | Tool Name | Category | Description |
| :---: | :--- | :---: | :--- |
| **1** | `discover_build_binary` | Build & Deploy | Scans Yocto (`build/tmp/work`) and CMake workspaces for the freshest compiled binaries. |
| **2** | `deploy_and_mount_binary` | Build & Deploy | SCPs binary + executes `mount --bind` on read-only SquashFS + restarts service + **10s Auto-Rollback Guard**. |
| **3** | `stream_device_logs` | Logs & Tracing | Real-time `tail -f /var/log/messages*` with automated regex crash highlighting. |
| **4** | `control_pmlog_level` | Platform Control | Dynamic PmLog verbosity control (`debug`, `info`, `warning`, etc.) without restarting services. |
| **5** | `run_ls_monitor` | Platform Control | Real-time Luna Service 2 (LS2) IPC bus traffic tracing. |
| **6** | `run_gdb_backtrace` | Crash Triage | Multi-arch auto-provisioning `gdbserver` to target + host cross-GDB batch backtrace (`bt full`). |
| **7** | `run_valgrind_profiler` | Memory Profiling | Memory violation & leak analysis (`memcheck`, `massif`, `callgrind`, `helgrind`). |
| **8** | `run_leaktracer` | Memory Profiling | Lightweight dynamic memory allocation tracker via `LD_PRELOAD=/usr/lib/libleaktracer.so`. |
| **9** | `analyze_core_dump` | Crash Triage | Auto-fetches `/tmp/core*` or `/var/lib/systemd/coredump/` and matches with unstripped binary symbols. |
| **10** | `diagnose_security_denials` | Security Audit | Multi-layer security audit: ACG (`ls-hubd` denials), MAC (SMACK/AppArmor), and DAC (Unix permissions). |
| **11** | `call_luna_service` | Luna Testing | Single endpoint testing with JSON payload via `luna-send` / `luna-send-pub`. |
| **12** | `check_resource_regression` | Monitoring | Monitors RSS memory and CPU usage; flags regressions when memory exceeds baseline by >20%. |
| **13** | `clean_device_environment` | Maintenance | Unmounts bind-mounts, kills dangling debug tools (`gdbserver`, `valgrind`, `strace`), and cleans `/tmp/`. |
| **14** | `generate_crash_report` | Reporting | Aggregates syslog, dmesg, process state, and core dumps into structured Markdown for Jira tickets. |
| **15** | `detect_silent_crashes` | Silent Crash Triage | Deep inspection of `NRestarts`, exit codes (139/134/137/132), process vs system uptime delta, dmesg traps, LS2 drops, and zombies. |
| **16** | `query_collab_api_docs` | Collab Knowledge | Queries team Collab/Confluence wiki live via REST API for API docs, ACG matrices, and SMACK specs. |
| **17** | `execute_collab_scenario` | Collab Knowledge | End-to-end test runner: queries docs $\rightarrow$ runs Luna command $\rightarrow$ captures logs $\rightarrow$ performs crash triage $\rightarrow$ outputs PASS/FAIL verdict. |
| **18** | `find_debug_symbols` | Build & Deploy | Locates unstripped `.debug` binaries with full symbols in the Yocto build workspace. |
| **19** | `run_luna_smoke_test` | Luna Testing | Batch smoke tests all methods of a Luna service, recording pass/fail rates and latency in ms. |
| **20** | `analyze_kernel_panic` | Crash Triage | Post-mortem panic analysis extracting call traces from persistent `pstore`/`ramoops` and `dmesg.old`. |
| **21** | `run_strace` | Tracing & Profiling | Syscall tracing with error highlighting (file I/O, socket, IPC errors). |
| **22** | `run_perf_profile` | Tracing & Profiling | CPU hotspot function profiling via `perf record` (with `top` fallback). |
| **23** | `introspect_device_apis` | Discovery | Zero-setup on-board API and ACG discovery from `/usr/share/luna-service2/` and `listMethods`. |
| **24** | `launch_and_diagnose_app` | Diagnostics | Unified app launch, delta log stream, ACG audit, and in-RAM GDB crash forensics. |
| **25** | `close_app` | Maintenance | Cleanly terminate running apps via WebOS ApplicationManager. |
| **26** | `copy_file_to_device` | Build & Deploy | Direct SCP file/binary transfer to target device with automatic directory creation and `chmod +x` support without mounting. |

---

## 🔒 Safety Guardrails & 2-Phase Confirmation

### 1. Mandatory 2-Phase Confirmation
The agent enforces explicit user confirmation before executing any state-modifying action:
- `deploy_and_mount_binary`
- `call_luna_service` (state-modifying endpoints)
- `clean_device_environment`

**Workflow:**
1. Agent presents the plan: Target IP, binary path, mount location, and service to restart.
2. Agent prompts: *"Reply **1** to Proceed, or **2** to Cancel."*
3. Only proceeds upon receiving **`1`**.

### 2. Auto-Rollback Safety Guard
During deployment, after restarting the service, the agent observes the target for **10 seconds**:
- If `systemctl is-active` reports `failed`/`inactive` or `NRestarts > 2`:
  - **Auto-Unmounts** `/usr/bin/<binary>` immediately.
  - Deletes `/tmp/<staging_binary>`.
  - Restores the original factory binary.
  - Prevents bricking read-only target devices.

---

## 📚 Live Collab (Confluence) Wiki Integration

Developers don't need to manually copy-paste API documentation or ACG matrices. The agent queries live Confluence pages:
1. Configure `X-Collab-URL` and `X-Collab-PAT` in `mcp.json`.
2. The agent calls Confluence REST API:
   - Supports `/display/SPACE/Title` and `pageId=12345` formats.
   - Automatically converts storage format HTML to Markdown using `html2text` / `BeautifulSoup`.
   - Discovers child pages and linked specifications automatically.

---

## 🏗️ Multi-Architecture Tool Vault

The server supports heterogeneous target devices (`aarch64`, `armv7l`, `x86_64`):
1. Detects target architecture via `uname -m`.
2. Automatically looks up the matching pre-built binary in `/tools/`:
   - `aarch64` $\rightarrow$ `/tools/gdbserver-aarch64`, `/tools/libleaktracer-aarch64.so`
   - `armv7l` $\rightarrow$ `/tools/gdbserver-armv7`, `/tools/libleaktracer-armv7.so`
   - `x86_64` $\rightarrow$ `/tools/gdbserver-x86_64`, `/tools/libleaktracer-x86_64.so`
3. Auto-provisions and executes on `/tmp/` without requiring host toolchain rebuilds.

---

## 🖥️ Target Fleet Inventory Setup

Instead of typing raw IP addresses every time, you can define target board aliases:

Create `inventory.json`:
```json
{
  "audio-board-1": { "ip": "10.178.140.22", "arch": "aarch64", "owner": "audio-team" },
  "display-board-2": { "ip": "10.178.140.45", "arch": "armv7l", "owner": "display-team" }
}
```
Set `TARGET_INVENTORY_JSON=/path/to/inventory.json`. You can now use `@device-agent test on audio-board-1`.

---

## ☸️ Kubernetes Deployment Guide

### 1. Build and Push Image
```bash
docker build -t abhishek15c/device-mcp-server:latest .
docker push abhishek15c/device-mcp-server:latest
```

### 2. Apply Manifest to Cluster
```bash
kubectl apply -f device-mcp-k8s.yaml -n ai-user2
```

### 3. Restart Deployment
```bash
kubectl rollout restart deployment/muralidhar-device-mcp -n ai-user2
```

---

## 💻 VS Code & IDE Configuration (`mcp.json`)

Add to your VS Code user or workspace `mcp.json`:

```json
{
  "servers": {
    "device-agent": {
      "type": "sse",
      "url": "http://<YOUR_K8S_NODE_IP>:30724/sse",
      "headers": {
        "X-Collab-URL": "https://collab.lge.com/wiki/display/<YOUR_SPACE>/<API_DOC_PAGE>",
        "X-Collab-PAT": "<YOUR_PERSONAL_ACCESS_TOKEN>"
      }
    }
  }
}
```

Reload VS Code window (`Ctrl+Shift+P` $\rightarrow$ `Developer: Reload Window`).

---

## 💬 Developer Prompt Cheatsheet

### 1. Build Artifact Discovery & Transfer (Terminal — Local Filesystem)

> **Architecture Note**: Build artifact search and file transfer run via **terminal commands**
> because the build workspace is on your local machine, not inside the K8s pod.

```text
find the audiod IPK package in my build workspace and copy it to /home/root on target 10.x.x.x
search for lib32-webappmanager IPK in /home/user/build_dir/build-starfish and scp to 10.x.x.x
```

### 2. Device Deployment (MCP — @device-agent)
```text
@device-agent deploy /tmp/audiod to /usr/bin/audiod on target 10.x.x.x and restart the audiod service
@device-agent locate unstripped debug symbols for webappmanager
```

### 3. Documentation & Collab Queries (MCP — @device-agent)
```text
@device-agent what are the Luna API methods and ACG permissions defined in our Collab doc?
@device-agent run the Collab test scenario for webview launch on target 10.x.x.x
```

### 4. Crash Debugging & Silent Triage (MCP — @device-agent)
```text
@device-agent detect any silent crashes or hidden auto-restarts on target 10.x.x.x for audiod
@device-agent attach GDB to audiod on target 10.x.x.x and capture full stack trace
@device-agent analyze the latest core dump on target 10.x.x.x with binary /build/audiod.unstripped
@device-agent check kernel panic and reboot history on target 10.x.x.x
```

### 5. Memory Profiling & Tracing (MCP — @device-agent)
```text
@device-agent run valgrind memcheck on /usr/bin/audiod on target 10.x.x.x for 30 seconds
@device-agent run strace on audiod on target 10.x.x.x for 10 seconds and report failed syscalls
@device-agent profile CPU hotspots on audiod on target 10.x.x.x
```

### 6. Luna Testing & Platform Monitoring (MCP — @device-agent)
```text
@device-agent run a batch smoke test on com.webos.service.audio on target 10.x.x.x
@device-agent diagnose ACG and SMACK security denials for com.webos.service.audio on target 10.x.x.x
@device-agent set PmLog context audiod.main to DEBUG on target 10.x.x.x
@device-agent clean up debug processes and temporary files on target 10.x.x.x
```

---

## 🔍 Verification & Health Check

1. **Verify Pod Status**: `kubectl get pods -n ai-user2 -l app=muralidhar-device-mcp`
2. **Verify SSE Stream**: `curl -i http://<K8S_NODE_IP>:30724/sse`
3. **Verify Tool Count**: Confirm 26 tools visible in VS Code MCP Servers tab.
