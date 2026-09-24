# Yocto/BitBake Recipe Standards

Standards for defining BitBake recipes (.bb) for webOS components.

## Recipe Naming
- Must end in `_git.bb` for source control checkouts, or `_<version>.bb` for tarball releases.
- Ensure the component name is lowercase with hyphens instead of spaces/underscores.

## Mandatory Fields
Every recipe must define:
- `SUMMARY`: Short single-line description.
- `DESCRIPTION`: A more detailed explanation.
- `LICENSE`: Valid SPDX license identifier (e.g., `Apache-2.0` or `Proprietary`).
- `LIC_FILES_CHKSUM`: Correct checksum of the license file from the source repository.
- `SRC_URI`: Upstream source location.

## Classes & Inheritance
- Standard webOS components should inherit: `webos_component`, `webos_cmake`, `webos_daemon`, `cmake`.

## Dependencies
- **Build time:** `DEPENDS = "glib-2.0 luna-service2 pmloglib pbnjson-cpp"`
- **Run time:** `RDEPENDS:${PN} = "..."`

## Service Installation
- For services that require explicit installation steps, append to `do_install`:
```bitbake
do_install:append() {
    # Custom installation logic here for luna-service2 files if webos_system_bus isn't handling it natively
}
```

## Packaging
Explicitly include webOS specific directories in the package:
```bitbake
FILES:${PN} += "${webos_servicesdir} ${webos_sysbus_rolesdir} ${webos_sysbus_pubservicesdir} ${webos_sysbus_prvservicesdir}"
```

## Common QA Fixes
- `installed-vs-shipped`: Ensure all files in `${D}` are packaged in `FILES:${PN}`.
- `SOLIBS`: Use correct regex for shared library parsing if providing `.so` modules.
- Ensure symlink `.so` files are correctly packaged in `-dev` packages, not the main package.
