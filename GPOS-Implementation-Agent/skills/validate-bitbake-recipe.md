# Validate BitBake Recipe Workflow

This skill outlines the process for validating newly generated or existing BitBake recipes against Yocto and webOS standards.

## 1. Input
- The user provides the path to a recipe `.bb` file.

## 2. Validation Execution
- Execute the `bitbake_layer_validator` tool, passing the provided recipe path.

## 3. Reporting
- Compile the results and present all errors and warnings in a clear, categorized Markdown table.

## 4. Remediation Explanation
For every reported error:
- Explain **WHY** the fix is required (e.g., "LIC_FILES_CHKSUM is mandatory for legal compliance and license tracking").
- Provide the **EXACT** fix required (e.g., "Add: `LIC_FILES_CHKSUM = \"file://LICENSE;md5=...\"`").

## 5. Layer Verification
- Execute the `scan_yocto_layers` tool to verify that the recipe is situated within the correct target layer and directory structure.

## 6. Dependency Checking
- Execute `bitbake_layer_validator` with the `scan_deps_dir` argument to check the layer or recipe for potential circular dependencies.

## 7. Final Summary
- Conclude the workflow by presenting a summary statement in the format:
  > "Recipe is [VALID/INVALID] with [X] errors and [Y] warnings."
