# webOS Luna Service Reference

This document contains **hints and guidance** to help the agent dynamically discover and use the correct webOS Luna services. The agent MUST still run `ls-monitor -i` to introspect and confirm methods before calling them.

---

## Screenshots / Screen Capture

When the user asks to take a screenshot or capture the screen:

1. **First check** the surface manager service — it handles compositor/display output capture:
   ```bash
   ls-monitor -i com.webos.surfacemanager
   ```
   Look for a method related to `capture`, `compositor`, or `screenshot` in the output.

2. **Also check** the dedicated capture service as a fallback:
   ```bash
   ls-monitor -i com.webos.service.capture
   ```

3. After introspecting and finding the correct method, call it via `execute_device_command` with the user's requested output path.

4. The output parameter is typically named `"output"` or `"path"` depending on the method — check the introspection output carefully.

> **Key hint:** On webOS TV platforms, the surface manager (`com.webos.surfacemanager`) typically owns the compositor capture capability, not the generic capture service.

---

## Display Orientation

When the user asks to change screen orientation:

1. Check the settings service:
   ```bash
   ls-monitor -i com.webos.settingsservice
   ```
2. Look for `setSystemSettings` method. The `screenRotation` setting under `option` category controls orientation.

---

## Service Discovery (for unknown services)

When a service is NOT covered above:

1. Find the service: `ls-monitor -l | grep -i <keyword>`
2. Introspect methods: `ls-monitor -i <exact.service.name>`
3. Call using luna-send via `execute_device_command`
4. If the call fails: **STOP and report** — do NOT retry endlessly. Report the error and available methods to the user.
