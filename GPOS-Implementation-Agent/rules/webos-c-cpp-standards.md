# LG webOS C/C++ Coding Standards

## LG License Header
All source files must begin with the standard LG copyright header:
```c
/* @@@LICENSE
*
* Copyright (c) 2026 LG Electronics, Inc.
*
* Confidential computer software. Valid license from LG required for
* possession, use or copying. Consistent with FAR 12.211 and 12.212,
* Commercial Computer Software, Computer Software Documentation, and
* Technical Data for Commercial Items are licensed to the U.S. Government
* under vendor's standard commercial license.
*
* LICENSE@@@ */
```

## Logging: PmLogLib
Use `PmLogLib` for all logging instead of `printf` or `std::cout`.
- **Context:** Retrieve context using `PmLogGetContext("MyContext", &context)`.
- **Message IDs:** Required for Errors and Warnings. Must be max 8 uppercase characters (e.g., `INIT_FAIL`, `MEM_ERR`).
- **Macros:** `PmLogError`, `PmLogWarning`, `PmLogInfo`, `PmLogDebug`.
- **Format:** Key-value pairs using `{}` JSON-like structure within logs are standard for structured logging.

## GLib Event Loop
- Integrate deeply with GLib. Use `GMainLoop` as the core event loop.
- Register signal handlers for graceful termination (`SIGINT`, `SIGTERM`) attaching them to the main context using `g_unix_signal_add()`.

## JSON Parsing
- Use `pbnjson` library (`JValue`, `JSchema`, `JParser`) instead of raw string manipulation for robust parsing and serialization.
- Validate inputs against schema via `JSchema::fromFile()` or inline strings.

## Naming Conventions
- **Methods/Functions:** `camelCase()`
- **Classes/Structs:** `PascalCase`
- **Enums/Macros/Constants:** `UPPER_CASE_WITH_UNDERSCORES`

## Error Handling
- Always check return values for system and API calls.
- Use `errno` and `strerror()` for native OS interactions.
- Avoid swallowing errors; propagate them gracefully and log extensively.

## Header Guards
Format header guards with the component name:
```cpp
#ifndef COMPONENT_NAME_H
#define COMPONENT_NAME_H
// ...
#endif // COMPONENT_NAME_H
```

## Doxygen Documentation
Document all public APIs using Doxygen standards. Use `@brief`, `@param`, and `@return`.

## Memory Management
- **C++:** Prefer RAII (Resource Acquisition Is Initialization) and smart pointers (`std::unique_ptr`, `std::shared_ptr`).
- **C:** Explicitly match `malloc()`/`calloc()` with `free()`. Validate pointers before dereferencing.
