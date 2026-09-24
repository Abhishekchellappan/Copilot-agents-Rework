# GPOS Code Implementation Agent

## Overview

The GPOS Code Implementation Agent is a specialized MCP (Model Context Protocol) server designed for **webOS platform code generation, analysis, and build diagnostics**. It provides AI-assisted tooling for developers working on the webOS GPOS (General Purpose Operating System) platform, covering everything from generating new source files and analyzing existing codebases to diagnosing BitBake build failures and enforcing coding standards.

The agent understands C, C++, Dart, Java, and BitBake recipe files, making it a comprehensive companion for the full webOS development workflow.

## Architecture

This agent follows the **generic MCP agent pattern** where the system is cleanly separated into two layers:

```
┌─────────────────────────────────────────────────────────┐
│                    MCP Client (IDE)                      │
│              (VS Code, Copilot, etc.)                    │
└────────────────────────┬────────────────────────────────┘
                         │ SSE / HTTP
┌────────────────────────▼────────────────────────────────┐
│              Python MCP Server (Black Box)               │
│                                                          │
│  server.py ─── Tool routing, SSE transport               │
│  config.py ─── Environment & settings                    │
│  ast_parser.py ─── C/C++/Dart/Java code analysis         │
│  bitbake_parser.py ─── BitBake recipe parsing            │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │         Markdown Knowledge Layer                    │  │
│  │                                                     │  │
│  │  .github/   → Agent instructions & persona          │  │
│  │  rules/     → Coding standards & conventions        │  │
│  │  skills/    → How-to guides & implementation tips   │  │
│  │                                                     │  │
│  │  (Auto-scanned at startup — drop a .md to extend)   │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

- **Python = Black Box**: The Python server (`server.py`, `config.py`, `ast_parser.py`, `bitbake_parser.py`) handles MCP protocol mechanics, tool dispatch, code parsing, and SSE transport. You rarely need to modify these files.
- **Markdown = Customization**: All domain knowledge — coding rules, implementation skills, agent persona — lives in Markdown files under `.github/`, `rules/`, and `skills/`. To teach the agent something new, simply drop a `.md` file into the appropriate folder.

## Quick Start

### Step 1: Generate a Jira Token

If your workflow involves Jira integration, generate a personal access token:

1. Navigate to your Jira instance → **Profile** → **Personal Access Tokens**
2. Click **Create token** and give it a descriptive name (e.g., `gpos-impl-agent`)
3. Copy the token and store it securely

### Step 2: Connect the MCP Server

Add the following to your IDE's MCP configuration file (e.g., `.vscode/mcp.json` or `~/.copilot/mcp.json`):

```json
{
  "mcpServers": {
    "gpos-implementation-agent": {
      "type": "sse",
      "url": "http://10.221.31.97:31988/sse"
    }
  }
}
```

> [!NOTE]
> Replace the IP address with the actual Kubernetes node IP if your cluster endpoint differs.

### Step 3: Test with a Query

Open your IDE's AI chat and try:

```
@gpos-implementation-agent Analyze the function signature in /app/workspace/src/main.cpp
```

or:

```
@gpos-implementation-agent Generate a C++ luna-service2 client for the com.webos.settingsservice API
```

If the server is running, you should receive a structured response with code analysis or generated source files.

## Available Tools

| Tool | Description |
|------|-------------|
| `generate_code` | Generates new source files (C, C++, Dart, Java, BitBake recipes) following webOS platform conventions and coding standards. Produces complete, buildable code with proper headers, includes, and license blocks. |
| `analyze_code` | Performs static analysis on existing source files — extracts function signatures, class hierarchies, include dependencies, and potential issues. Supports C/C++ AST parsing and Dart/Java structural analysis. |
| `diagnose_build` | Parses BitBake build logs to identify root causes of compilation failures, missing dependencies, recipe errors, and packaging issues. Returns structured diagnostics with suggested fixes. |
| `search_codebase` | Searches across the workspace for symbols, patterns, or file types. Supports regex and glob patterns with results ranked by relevance to the query context. |
| `apply_patch` | Applies a structured code patch to an existing file. Validates the patch against the current file content, ensures no conflicts, and produces a clean diff summary of changes made. |
| `explain_component` | Provides detailed explanations of webOS platform components, services, and APIs. Draws from the Markdown knowledge base to give context-aware descriptions with usage examples. |

## Adding Custom Rules

The agent's knowledge is fully extensible through Markdown files. No Python changes are required.

### Adding a Coding Rule

Create a new `.md` file in the `rules/` directory:

```markdown
# Rule: Always Use Smart Pointers

## Scope
C++ source files (.cpp, .h)

## Description
All dynamically allocated objects must use `std::unique_ptr` or `std::shared_ptr`.
Raw `new`/`delete` calls are prohibited except in low-level allocator implementations.

## Examples

### Correct
```cpp
auto device = std::make_unique<DeviceManager>();
```

### Incorrect
```cpp
DeviceManager* device = new DeviceManager(); // Raw new — prohibited
```
```

### Adding a Skill

Create a new `.md` file in the `skills/` directory:

```markdown
# Skill: Creating a webOS System Service

## When to Use
When the user asks to create a new native system service for webOS.

## Steps
1. Generate the service main entry point with `GMainLoop`
2. Register the service on the luna-bus with `LSRegister()`
3. Define method handlers for each API endpoint
4. Create the CMakeLists.txt with `webos_add_system_bus_service()`
5. Write the service configuration files (.service, .role.json)

## Template
(Include a complete code template here)
```

> [!TIP]
> The server auto-scans `rules/` and `skills/` at startup. After adding a new file, restart the pod for the changes to take effect.

## Deployment

### Build the Docker Image

```bash
docker build -t abhishek15c/gpos-implementation-agent:latest .
```

### Push to Registry

```bash
docker push abhishek15c/gpos-implementation-agent:latest
```

### Deploy to Kubernetes

```bash
kubectl apply -f gpos-implementation-mcp-k8s.yaml
```

### Verify the Deployment

```bash
# Check pod status
kubectl get pods -n ai-user2 -l app=gpos-implementation-agent

# Check service endpoint
kubectl get svc -n ai-user2 muralidhar-impl-mcp-svc

# Test health endpoint
curl http://10.221.31.97:31987/health

# View logs
kubectl logs -n ai-user2 -l app=gpos-implementation-agent -f
```

### Restart After Knowledge Updates

```bash
kubectl rollout restart deployment/muralidhar-impl-mcp -n ai-user2
```

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `WORKSPACE_ROOT` | `/app/workspace` | Root directory for code analysis and generation operations. All file paths are resolved relative to this directory. |
| `SERVER_PORT` | `8000` | HTTP port the MCP server listens on for SSE connections and health checks. |
| `LOG_LEVEL` | `INFO` | Logging verbosity. Set to `DEBUG` for detailed request/response tracing during development. |
| `RULES_DIR` | `/app/rules` | Directory containing Markdown coding rule files. Scanned recursively at startup. |
| `SKILLS_DIR` | `/app/skills` | Directory containing Markdown skill/how-to files. Scanned recursively at startup. |
| `MAX_FILE_SIZE_KB` | `512` | Maximum file size (in KB) that the agent will process for analysis. Larger files are skipped with a warning. |

## Supported Languages

| Language | File Extensions | Capabilities |
|----------|----------------|-------------|
| **C** | `.c`, `.h` | Code generation, AST analysis, header dependency tracking, build diagnostics |
| **C++** | `.cpp`, `.hpp`, `.cc`, `.hh`, `.cxx` | Full AST parsing, class hierarchy extraction, template analysis, luna-service2 integration |
| **Dart** | `.dart` | Code generation, structural analysis, Flutter/webOS widget patterns |
| **Java** | `.java` | Code generation, class/interface analysis, Android-style service patterns |
| **BitBake** | `.bb`, `.bbappend`, `.inc`, `.conf` | Recipe parsing, dependency resolution, build failure diagnostics, variable expansion tracking |
