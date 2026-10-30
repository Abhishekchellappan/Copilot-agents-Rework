# Debugging Workflows

## GDB Debugging & Symbol Discovery
1. Use `find_debug_symbols` to locate unstripped `.debug` binaries in the build workspace.
2. Call `run_gdb_backtrace`. The tool auto-detects architecture and provisions `gdbserver` if missing.
3. **ANTI-HALLUCINATION GUARDRAIL**: If GDB output says "No debugging symbols found" or "??", DO NOT GUESS. Halt analysis and inform the user: "Inconclusive Root Cause: Unstripped .debug symbols are missing."

## Memory Analysis
1. Use `profile_memory_leaks` for universal memory leak profiling across ANY webOS application (Flutter, Web, QML), Luna service, or native daemon. Supports runtime soak profiling (e.g. 60s, 300s), lifecycle open/close stress testing, and Luna service request load.
2. Use `run_valgrind_profiler` for deep binary memory leak checks.
3. Use `run_leaktracer` for standalone C/C++ daemons.

## Core Dump Analysis & Kernel Panics
1. **User Space**: Use `analyze_core_dump` to discover `/tmp/core*` or `/var/lib/systemd/coredump/`.
2. **Kernel Panics**: Use `analyze_kernel_panic` to inspect `pstore`/`ramoops` and `dmesg.old`.

## Silent Crash & Health Detection
Use `detect_silent_crashes` when service dies without obvious syslog errors. It inspects:
- Systemd `NRestarts`
- Process exit codes
- Process vs System uptime delta
- Kernel dmesg page faults and OOM reaps

## App Launching (CRITICAL)
- When launching apps, use the `launch_and_diagnose_app` tool.
- DO NOT use `find` or `luna-send` manually.
- If the app is not found, ask the user for the exact App ID.
- Default `display_id` is 0.

## Cleanup
- Use `clean_device_environment` to unmount bind-mounts, kill debug processes, and purge temp files.
