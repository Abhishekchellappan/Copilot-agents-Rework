# 📱 Device Debugging Agent — Copilot Instructions

> These rules govern how the AI assistant interacts with the Device Agent MCP tools.

---

## 🚫 webOS Strict Command Mandates & Anti-Patterns

> **⚠️ MANDATORY WEBOS COMMAND RULES (NEVER VIOLATE):**
> 1. **NEVER use `palm-launch`**: `palm-launch` is an obsolete legacy command that causes `"Syntax error: Unterminated quoted string"` shell errors on modern webOS 12.0. Always launch apps via `launch_and_diagnose_app` or `luna-send -n 1 -f luna://com.webos.applicationManager/launch '{"id": "<app_id>"}'`.
> 2. **NEVER use `pmlogctl` (lowercase)**: The webOS logging utility is case-sensitive: always use `PmLogCtl` (capitalized) or the `control_pmlog_level` tool.
> 3. **DO NOT guess raw shell loops for app triage**: Always delegate app launch and crash forensics to `launch_and_diagnose_app(target_ip, app_name_or_id)` which handles SAM bus communication, delta log capture, and in-RAM GDB diagnostics in a single atomic step.

---

## 🔒 Critical Safety Rules

> **⚠️ MANDATORY 2-PHASE CONFIRMATION FOR ALL DESTRUCTIVE ACTIONS:**
> The following tools MODIFY device state and require user confirmation BEFORE execution:
> - `deploy_and_mount_binary` — Deploys and mounts a binary on the target.
> - `call_luna_service` — Calls a Luna API that may change device settings.
> - `clean_device_environment` — Unmounts binaries and kills debug processes.
>
> **Workflow:**
> 1. Display the planned action in chat (target IP, binary, service, command).
> 2. Ask: *"Reply **1** to Proceed, or **2** to Cancel."*
> 3. Only execute the tool after the user replies **1**.


## 🔍 Build Artifact Discovery & Transfer (Terminal — Local Machine)

> **⚠️ CRITICAL RULE FOR FINDING FILES (IPK / BINARY) IN BUILD WORKSPACE:**
> The `BUILD/work` directory contains millions of source files. A naive `find` command will take **10+ minutes** and crash/hang the terminal.
> 
> 1. **NEVER** invent your own `find` commands. 
> 2. **NEVER** run `find /home/.../BUILD/work -name "*component*"`.
> 3. **ALWAYS** use the `generate_fast_search_command` tool to get the exact, optimized (`-maxdepth 4`) command.
> 4. Run the generated command EXACTLY as it is returned. DO NOT modify it.

### Fast IPK Search (< 1 second)
If you must run it manually, ONLY use this exact pattern:
```bash
find /home/$USER/build_dir/build-starfish/BUILD/work -maxdepth 4 -name "deploy-ipks" -type d -exec find {} -type f -name "*<component>*.ipk" \; 2>/dev/null | head -10
```

### Fast Binary / Executable Search (< 1 second)
```bash
find /home/$USER/build_dir/build-starfish/BUILD/work -maxdepth 4 -name "image" -type d -exec find {} -type f \( -path "*/usr/bin/<component>" -o -path "*/usr/sbin/<component>" \) \; 2>/dev/null | head -5
```

### Important Rules
- **Multilib naming**: The component `audiod` may be built as `lib32-audiod`. Search for BOTH names: `*audiod*` will match both.
- **Replace `<component>`** with the actual component name (e.g., `audiod`, `webappmanager`).
- **Replace the build workspace path** with the user's actual workspace if they specify one.

### Copying Files to Target Devices
After finding the artifact path, use a direct terminal `scp` command:
```bash
scp -O -o StrictHostKeyChecking=no <local_path> root@<target_ip>:<remote_path>
```

---

## 🚀 Binary Deployment & Auto-Rollback (`deploy_and_mount_binary`)

When the user asks to "deploy", "push", "mount binary", or "update binary on target":
1. If the user hasn't specified the full local binary path, use `generate_fast_search_command` to find it automatically. DO NOT ask the user to provide the path.
2. Show the deployment plan:
   - Binary: `/path/to/binary`
   - Target: `10.x.x.x`
   - Mount Point: `/usr/bin/<binary>`
   - Service Restart: `<service_name>`
3. Wait for 2-Phase Confirmation.
4. Call `deploy_and_mount_binary` with all parameters.
5. **Auto-Rollback Guard**: The tool automatically verifies stability over a 10-second window. If the service enters `failed`/`inactive` state or `NRestarts > 2`, it unmounts the staging binary immediately to restore device health.

---

## 📚 Collab (Confluence) Wiki Integration (`query_collab_api_docs`, `execute_collab_scenario`)

- **Query Docs** (`query_collab_api_docs`): When the user asks to "check API docs", "what is the schema for X", "check ACG permissions for service", or "look at Collab page":
  1. Call `query_collab_api_docs(query="...")`.
  2. Uses `X-Collab-URL` and `X-Collab-PAT` configured in `mcp.json`.
- **Run Scenario** (`execute_collab_scenario`): When the user asks to "verify scenario", "run test case from Collab", "test webview launch":
  1. Call `execute_collab_scenario(scenario_description, target_ip, luna_uri, luna_payload)`.
  2. Captures pre/post logs, runs silent crash detection, and delivers a structured PASS/FAIL report.

---

## 🩺 Automated Triage and Security Patching

- **Auto-Triage** (`auto_triage_service`): If the user says a service is crashing or not working but doesn't specify why, immediately run `auto_triage_service(service_name, target_ip)` to diagnose OOM, Segfaults, SMACK, or ACG issues automatically.
- **Security Patching** (`patch_security_permissions`): If `auto_triage_service` or `diagnose_security_denials` detects a SMACK or ACG permission block, you MUST ask the user: "Would you like me to automatically patch the SMACK/ACG permissions for this service?". If they confirm, run `patch_security_permissions`.



## 📡 Log Streaming (`stream_device_logs`)

When the user asks for "logs", "tail logs", "stream logs", "check syslog", or "what's happening on target":
1. Call `stream_device_logs(target_ip, lines=200)`.
2. The tool uses `tail -f /var/log/messages*` (NOT journalctl).
3. Highlight any crash patterns detected in the output.

---

## 🐛 GDB Debugging & Symbol Discovery (`run_gdb_backtrace`, `find_debug_symbols`)

When the user asks to "debug", "attach gdb", "get backtrace", or "why is it crashing":
1. Use `find_debug_symbols` to locate unstripped `.debug` binaries in the build workspace.
2. Call `run_gdb_backtrace`. The tool auto-detects target architecture (`uname -m`) and provisions `gdbserver` from `/tools/` if missing.
3. Host cross-GDB connects remotely and extracts `thread apply all bt full`.
4. **ANTI-HALLUCINATION GUARDRAIL**: If GDB fails to extract a clear stack trace, or if the output says "No debugging symbols found" or "??", **DO NOT GUESS OR HALLUCINATE THE ROOT CAUSE**. You MUST immediately halt analysis and explicitly inform the user: *"Inconclusive Root Cause: Unstripped .debug symbols are missing or the trace is corrupted. Please provide the correct unstripped binary path."*

---

## 🔬 Memory Analysis (`run_valgrind_profiler`, `run_leaktracer`)

When the user asks about "memory leaks", "valgrind", "memory profiling":
1. Call `run_valgrind_profiler` with the target command (memcheck, massif, callgrind, helgrind).
2. For lightweight dynamic allocation tracking, use `run_leaktracer`.

---

## 💥 Core Dump Analysis & Kernel Panics (`analyze_core_dump`, `analyze_kernel_panic`)

- **User Space Core Dumps** (`analyze_core_dump`): Auto-discovers `/tmp/core*` or `/var/lib/systemd/coredump/` and symbols-matches with host GDB.
- **Kernel Panics / Reboots** (`analyze_kernel_panic`): Inspects persistent storage (`pstore`/`ramoops`), `dmesg.old`, and previous boot reboot logs.

---

## 🔒 Security Diagnostics (`diagnose_security_denials`)

When the user reports "permission denied", "ACG error", "SMACK denial", or "access denied":
1. Call `diagnose_security_denials(target_ip, service_name)`.
2. The tool checks ACG roles/permissions, SMACK kernel logs, and DAC file permissions.

---

## 🚀 Luna Service Testing (`call_luna_service`, `run_luna_smoke_test`)

- **Single Endpoint** (`call_luna_service`): Test specific Luna API with JSON payload (public/private bus).
- **Batch Smoke Test** (`run_luna_smoke_test`): Introspects and tests all methods of a service, tracking pass/fail and latency in ms.

---

## 🔬 Deep Tracing & Profiling (`run_strace`, `run_perf_profile`)

- **Syscall Tracing** (`run_strace`): Trace syscalls of a running process (file I/O, socket, IPC errors).
- **CPU Hotspots** (`run_perf_profile`): Identify hotspot functions consuming CPU via `perf record` or `top` fallback.

---

## 📡 webOS Platform Tools

- **PmLogCtl** (`control_pmlog_level`): Dynamically change PmLog verbosity without restarting the service.
- **ls-monitor** (`run_ls_monitor`): Capture real-time Luna Service 2 (LS2) bus traffic.

---

## 📊 Resource Monitoring (`check_resource_regression`)

When the user asks about "memory usage", "CPU regression", "resource monitoring":
1. Call `check_resource_regression(target_ip, process_name, baseline_mem_mb)`.
2. Flags alerts if RSS memory exceeds baseline by >20%.

---

## 🧹 Cleanup (`clean_device_environment`)

When the user asks to "clean up", "unmount", "cleanup target", or "free space":
1. Call `clean_device_environment(target_ip, binary_name)`.
2. This unmounts bind-mounts, kills debug processes, and purges temp files.

---

## 🕵️ Silent Crash & Health Detection (`detect_silent_crashes`)

When the user asks to "check health", "did it crash?", "silent crash", "service died", or when syslog shows no errors:
1. Call `detect_silent_crashes(target_ip, process_name, service_name)`.
2. Inspects:
   - Systemd `NRestarts` counter (detects silent background auto-restarts).
   - Last exit code decoded (e.g. 139=SIGSEGV, 134=SIGABRT, 137=SIGKILL/OOM, 132=SIGILL).
   - Process uptime vs System uptime delta.
   - Kernel dmesg page faults, unhandled translation faults, and OOM reaps.
   - LS2 bus unexpected client disconnects.
   - Zombie / `<defunct>` processes.

---

## 📝 Crash Report (`generate_crash_report`)

When the user asks to "generate crash report", "create bug report", or "summarize crash":
1. Call `generate_crash_report(target_ip, process_name, issue_key)`.
2. Aggregates syslog, dmesg, process state, core dumps, and suggests root causes.

---

## 🚀 App Launch & Close (MOST IMPORTANT — READ FIRST)

> **⚠️ CRITICAL RULE FOR APP LAUNCHING:**
> When the user asks to "launch", "open", "start", or "run" an app on a target device, you MUST use the `launch_and_diagnose_app` tool. 
> **DO NOT** use `generate_fast_search_command`, terminal `find` commands, or search for IPK files.
> **DO NOT** try to install or deploy the app. The app is already installed on the target device.
> **DO NOT** run raw `luna-send` commands manually. Use the tool.

- **Launch App** (`launch_and_diagnose_app`): The ONE tool for launching any app on a webOS target.
  - Pass the app name (e.g. `youtube`, `ytconformance`, `settings`) or full ID (e.g. `com.webos.app.test.youtube`).
  - The tool auto-resolves partial names to full app IDs by searching application directories on the target.
  - **CRITICAL**: If the tool fails to find the app, DO NOT invent raw ssh terminal commands (like `ssh root@ip ls ...`) to search for it. Instead, politely ask the user for the exact App ID.
  - It launches via the Luna ApplicationManager API, streams delta logs, audits ACG security, and if a crash occurs, extracts diagnostics.
  - **Display Rule**: Default `display_id` is `0`. Only change if the user explicitly requests a different display.

- **Close App** (`close_app`): When the user asks to "close", "stop", or "kill" an app. Cleanly terminates apps via ApplicationManager and force-kills lingering processes.

---

## 🔍 On-Board API Introspection

- **Discover APIs** (`introspect_device_apis`): When the user asks to "check APIs for service", "what permissions does X need", or "list methods for X". The tool extracts live ground-truth from `/usr/share/luna-service2/` and `listMethods`.

---

## 🎥 GStreamer (GST) Media Pipeline Recipes
- When debugging media/video playback:
  - Check plugin capabilities: `gst-inspect-1.0 <element>`
  - Trace pipeline errors: `GST_DEBUG="*:3,v4l2*:5" gst-launch-1.0 ...`
  - Catch caps negotiation failures: scan logs for "caps negotiation failed" / "not-negotiated".

## 🔊 Audio & ALSA Subsystem Recipes
- When debugging audio routing or missing sound:
  - Check hardware sound cards: `aplay -l && arecord -l`
  - Check PulseAudio sinks: `pactl list sinks short`
  - Check PCM device locks: `lsof /dev/snd/pcm*`

## 🖥️ Display & WebAppManager (WAM) Recipes
- When debugging black screens or UI render failures:
  - Check Wayland compositor: `ls -la /var/run/wayland-0`
  - Check WAM render status: `luna-send -n 1 -f luna://com.webos.service.wam/inspect '{}'`
  - Check DRM / KMS display status: `cat /sys/class/drm/card*-*/status`

## 🛠️ webOS Troubleshooting Cheatsheet & Remote Command Execution

**IMPORTANT:** NEVER attempt to run `ssh` commands directly in the user's VS Code terminal when restarting services or checking OS state, as VS Code will prompt the user and block the command.
**ALWAYS** use the `execute_device_command(target_ip, command)` tool to run background shell commands on the target TV.

### Key webOS Service Names (Do NOT guess service names!):
- **Application Manager (SAM)**: The service that launches apps.
  - Restart command: `systemctl restart sam`
  - Use when apps are stuck "launching" (errorCode -203).
- **Surface Manager / Compositor**: The UI display service.
  - Restart command: `systemctl restart surface-manager`
- **Security Managers**:
  - SMACK: `systemctl restart smackd`
  - ACG / LS2: `systemctl restart palm-service`
