# Luna Service 2 (LS2) Bus Governance

Governance rules for implementing and deploying Luna Service 2 (LS2) endpoints on webOS.

## Registration & Naming
- Use `LSRegisterPubSub()` for initialization.
- Service names must be unique and follow the namespace convention: `com.webos.service.<name>`.

## LSMethod Definitions
- Method tables must be defined as an array of `LSMethod` structs.
- Format: `{ "methodName", callbackFunction, LUNA_METHOD_FLAGS_NONE }`
- Always terminate the array with a NULL entry: `{ nullptr, nullptr, 0 }`.

## Service Invocations
- **Calling:** Use `LSCall` (asynchronous with callback) or `LSCallOneReply` (one-off request) for calling other services.
- **Subscriptions:** Use `LSSubscriptionReply` to iterate through subscribers and broadcast updates. Handle cancellation callbacks robustly.

## Mandatory Security Files
Four JSON configuration files are required for every service:
1. `services.d/com.webos.service.<name>.service` - Service description and executable mapping.
2. `roles.d/com.webos.service.<name>.role.json` - Defines role, types, and `allowedNames`.
3. `client-permissions.d/com.webos.service.<name>.perm.json` - Defines inbound permission rules.
4. `api-permissions.d/com.webos.service.<name>.api.json` - Outlines method-level access control (private vs. public API groups).

## CMakeLists.txt Integration
- Use `webos_build_daemon()` to define the executable target.
- Use `webos_build_system_bus_files()` to correctly install the JSON security files to the system bus directories.
