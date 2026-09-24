# Diagnose and Fix Build Error Workflow

This skill provides a structured approach to diagnosing and resolving compiler and BitBake build errors.

## 1. Input Processing
- The user provides or pastes a raw build error log.

## 2. Error Diagnosis
- Execute the `diagnose_build_error` tool, passing the raw error text as input.

## 3. Categorization and Strategy
Based on the `error_type` returned by the tool, execute the corresponding strategy:

- **undefined_reference** (Linker error):
  - Identify the missing library from the symbol.
  - Use `workspace_code_analyzer` to search the workspace for the corresponding header or implementation.
  - Recommend adding the identified library to `DEPENDS` in the recipe `.bb` and to `target_link_libraries` in the `CMakeLists.txt`.

- **missing_header** (Compiler error):
  - Identify the package that provides the missing header.
  - Recommend adding the package to `pkg_check_modules` in `CMakeLists.txt` and `DEPENDS` in the `.bb` recipe.

- **installed_not_shipped** (QA Issue):
  - Identify the files that were compiled but not packaged.
  - Formulate and recommend the exact `FILES:${PN} += "/path/to/files"` line needed in the recipe.

- **solibs_issue** (Packaging error):
  - Explain the difference between `SOLIBS` and `SOLIBSDEV` to the user.
  - Recommend the proper `.so` versioning strategy in the CMake or Autotools configuration.

- **nothing_provides** (BitBake dependency error):
  - Identify the missing required recipe.
  - Execute `scan_yocto_layers` to search available layers for the missing dependency, or suggest how to create it.

- **compilation_error** (Syntax error):
  - Analyze the provided C/C++/Dart syntax error snippet.
  - Suggest the specific code modification to fix the logic or syntax.

## 4. Code Generation
- Generate the precise required fix (a `CMakeLists.txt` patch, a `.bb` recipe patch, or the exact source code fix).

## 5. User Confirmation
- Prompt the user: "Would you like me to apply this fix?"
