# Scaffold Flutter webOS Plugin Workflow

This skill defines the step-by-step workflow for creating a new Flutter webOS plugin.

## 1. Requirement Gathering
- Ask the user for the plugin name.
- Ask the user for the plugin's purpose.
- Ask the user which Luna services the plugin needs to call.

## 2. Reference Lookup
- Execute the `find_reference_components` tool with `component_type='flutter_plugin'`.
- Review the results to find similar existing plugins to use as a reference.

## 3. Analyze Reference
- Execute the `workspace_code_analyzer` tool on the selected reference plugin.
- Extract its architectural structure, specifically focusing on:
  - Dart platform interface design.
  - MethodChannel names and usage.
  - C++ `HandleMethodCall` dispatch logic.

## 4. Generate Dart Layer
Generate the following Dart files and present them for review:
- `lib/<plugin>.dart`: The public API class containing static methods that developers will interact with.
- `lib/<plugin>_platform_interface.dart`: The abstract platform interface defining the MethodChannel.
- `lib/<plugin>_method_channel.dart`: The concrete MethodChannel implementation that calls `invokeMethod`.

## 5. Generate Native C++ Layer
Generate the corresponding C++ source files:
- `webos/<plugin>_plugin.cc`: The main plugin logic, including `RegisterWithRegistrar`, `HandleMethodCall`, and returning `MethodResult`.
- `webos/include/<plugin>/<plugin>_plugin.h`: The plugin class header file.
- `webos/CMakeLists.txt`: Ensure it contains the correct `include_directories` and `target_link_libraries`.

## 6. Generate Metadata
Generate the metadata required by Flutter:
- `pubspec.yaml`: Ensure it includes `flutter.plugin.platforms.webos.pluginClass` configured with the correct C++ class name.

## 7. Generate Example App
Generate a sample application demonstrating plugin usage:
- `example/lib/main.dart`: A simple application utilizing the plugin's public API.
- `example/pubspec.yaml`: Must declare a path dependency on the newly created plugin.

## 8. Review
- Present all generated code and metadata files to the user for final review and approval.
