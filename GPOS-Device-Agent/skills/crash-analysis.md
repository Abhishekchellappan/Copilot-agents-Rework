# Crash Analysis Patterns and Exit Codes

When analyzing device logs, look for these crash patterns:
- SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGFPE
- "Segmentation fault", "core dumped", "Assertion.*failed"
- "[FATAL]", "[CRITICAL]", "OOM-killer"
- "process died with status", "NullPointerException"
- "BufferOverflow", "use-after-free", "double free"

Stealth / Silent crash indicators:
- "unhandled (level \d+ )?translation fault"
- "general protection fault", "Out of memory: Kill process"
- "Killed process \d+", "disconnected unexpectedly", "connection reset by peer"
- "Main process exited, code=(exited|killed), status=\d+"
- "Failed with result '(core-dump|signal|exit-code|oom-kill|watchdog)'"
- "Unit .* entered failed state", "watchdog: .* did not send heartbeat"
- "status=(139|134|137|143|136|135|132|255)"

## Exit Code Decoder
If a process exits with these codes, this is what it means:
- 139: SIGSEGV (Segmentation Fault - memory corruption / invalid pointer dereference)
- 134: SIGABRT (Aborted - assertion failure or deliberate abort() call)
- 137: SIGKILL (Killed - Out-of-Memory / OOM-Killer or manual kill -9)
- 143: SIGTERM (Terminated - polite shutdown signal)
- 136: SIGFPE (Floating Point Exception - division by zero / arithmetic error)
- 135: SIGBUS (Bus Error - unaligned memory access or hardware error)
- 132: SIGILL (Illegal Instruction - invalid opcode or wrong CPU architecture)
- 1: General Error (Uncaught exception or explicit exit(1))
- 2: Misuse of shell builtins / command error
- 127: Command Not Found / Missing shared library dependency (.so)
- 126: Command Invoked Cannot Execute / Permission denied
- 255: Fatal Exit / Systemd Service Termination
