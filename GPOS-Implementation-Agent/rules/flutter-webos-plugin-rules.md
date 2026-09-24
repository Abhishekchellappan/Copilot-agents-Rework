# Flutter webOS Plugin Architecture Rules

This guide defines the required architecture for Flutter webOS plugins, modeled after the real `pluginsample` from `flutter-appliance-plugins.git`.

## Directory Structure
```
<plugin_name>/
├── pubspec.yaml
├── lib/
│   ├── <plugin_name>.dart
│   ├── <plugin_name>_platform_interface.dart
│   └── <plugin_name>_method_channel.dart
├── webos/
│   ├── CMakeLists.txt
│   ├── <plugin_name>_plugin.cc
│   └── include/<plugin_name>/<plugin_name>_plugin.h
└── example/
    ├── pubspec.yaml
    ├── lib/main.dart
    └── webos/
        ├── CMakeLists.txt
        └── meta/
```

## pubspec.yaml Structure
- **Platform declaration:** Must include `flutter.plugin.platforms.webos.pluginClass` specifying the C++ plugin class name.
- **Publishing:** Set `publish_to: cart.lge.com` and define the repository as `repository: wall.lge.com`.

## Dart Platform Interface Pattern
- Implement an abstract class in `<plugin_name>_platform_interface.dart`.
- Include a static instance that delegates to the default `MethodChannel` implementation.
- `<plugin_name>_method_channel.dart` implements the platform interface invoking methods via `MethodChannel`.

## Native C++ Plugin Pattern
- Must inherit from `flutter::Plugin`.
- Expose the public function `RegisterWithRegistrar(flutter::PluginRegistrar* registrar)`.
- Override `HandleMethodCall` to route Dart invocations to C++ methods.
- Reply asynchronously or synchronously using `flutter::MethodResult`.
- Use `flutter::StandardMethodCodec` for standard argument decoding.

## webos/CMakeLists.txt
- Use `include_directories()` and `target_link_libraries()` correctly to link Flutter embedder headers and standard webOS components.
- Pattern involves defining the plugin target as a shared library that gets consumed by the application build process.

## MethodChannel Naming Convention
The channel name must match the plugin package name exactly (e.g., `com.lge.flutter.plugins.myplugin`).
