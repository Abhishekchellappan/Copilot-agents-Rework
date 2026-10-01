# Device Constraints and Environment Rules

## Architecture Rules
- Use `uname -m` to detect target architecture.
- For `aarch64` / `arm64`, deploy `gdbserver-aarch64`.
- For `armv7l` / `armv6`, deploy `gdbserver-armv7`.
- For `x86_64`, deploy `gdbserver-x86_64`.
- The tool vault is located at `/tools/` inside the MCP container.

## Security Constraints (ACG/MAC/DAC)
- webOS uses ACG (Access Control Groups), SMACK (Simplified Mandatory Access Control Kernel), and DAC (Discretionary Access Control).
- When encountering "permission denied", check ACG roles and permissions.
- Inspect SMACK kernel logs and DAC file permissions.
- Restart SMACK with `systemctl restart smackd`.
- Restart ACG/LS2 with `systemctl restart palm-service`.

## Service Execution Rules
- NEVER run interactive ssh commands via the terminal. Always use the `execute_device_command` tool.
- Application Manager (SAM) launches apps: `systemctl restart sam`
- Surface Manager renders UI: `systemctl restart surface-manager`
