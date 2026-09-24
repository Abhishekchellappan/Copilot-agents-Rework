# Cross-Component API Discovery Workflow

This skill defines how to discover and present APIs and Luna methods from existing services within the workspace.

## 1. Trigger
This workflow begins when the user asks questions like:
- "I need to call the audio volume service"
- "How does the settings service work?"

## 2. Component Lookup
- Execute the `find_reference_components` tool using a query that matches the user's requested service name or domain.

## 3. Code Analysis
- Once the service component is located, execute `workspace_code_analyzer` on it.
- Extract the following details:
  - **Luna method names**: Parse these from the `LSMethod` array definitions.
  - **Method parameters**: Extract these from the associated JSON schemas or `pbnjson` parsing logic within the method implementation.
  - **Service registration name**: Extract the fully qualified service name (e.g., `com.webos.service.audio`) from the `LSRegisterPubSub` or `LSRegister` calls.

## 4. Presentation
Present the discovered API information to the user in a formatted Markdown table:
| Method | Parameters | Return | Description |
|---|---|---|---|
| (Method Name) | (Required/Optional Parameters) | (Expected Return Payload) | (Brief Description inferred from code) |

## 5. Example Code Generation
- Provide a concise C++ or Dart (depending on context) code snippet demonstrating how the user's new or current service can use `LSCall` or a Luna client library to invoke one of the discovered methods.
