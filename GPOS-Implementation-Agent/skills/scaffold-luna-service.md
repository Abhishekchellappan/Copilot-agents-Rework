# Scaffold Luna Service Workflow

This skill defines the step-by-step workflow for creating a new Luna C++ service/daemon.

## 1. Requirement Gathering
- Ask the user for the service name (e.g., `com.example.service`).
- Ask for the desired API methods (e.g., `getSystemStatus`, `setVolume`).
- Ask for any external dependencies or libraries required.

## 2. Reference Lookup
- Execute the `find_reference_components` tool with `component_type='luna_service'`.
- Review the results to find a similar service to model the new one after.

## 3. Analyze Reference
- Execute the `workspace_code_analyzer` tool on the reference service.
- Extract the structure for:
  - `LSMethod` tables.
  - Signal handling configuration.
  - `GLib` main loop patterns.

## 4. Generate C++ Source Files
Generate the core C++ implementation files:
- `src/<service>.cpp`: The main entry point containing the `GMainLoop`, signal handlers, and the `LSRegisterPubSub` call.
- `src/<service>.h`: The service class header definition.
- `src/<service>_methods.cpp`: Implementations for the `LSMethod` callbacks.

## 5. Generate CMakeLists.txt
Generate the CMake build configuration. Ensure it includes:
- `include(webOS/webOS)`, `webos_modules_init`, and `webos_component`.
- `pkg_check_modules` for necessary dependencies, specifically: `glib-2.0`, `luna-service2`, `PmLogLib`, and `pbnjson_cpp`.
- Build macros: `webos_build_daemon` and `webos_build_system_bus_files`.

## 6. Generate Luna Security Files
Generate the requisite role and permission files for the Luna bus:
- `services.d/<service>.service`
- `roles.d/<service>.role.json`
- `client-permissions.d/<service>.perm.json`
- `api-permissions.d/<service>.api.json`

## 7. Generate Yocto Recipe
- Execute `scan_yocto_layers` to identify the appropriate target layer for the new service.
- Generate the `.bb` recipe file with the correct `DEPENDS` and inherited classes (e.g., `inherit webos_cmake`, `inherit webos_daemon`).

## 8. Validate
- Execute the `bitbake_layer_validator` tool on the generated recipe to ensure compliance and correctness.

## 9. Review
- Present all generated files (source, CMake, security, Yocto) to the user for review.
