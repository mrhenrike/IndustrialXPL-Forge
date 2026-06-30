# Public research vendor corpus (IndustrialXPL-Forge)

This directory contains **verbatim upstream sources** incorporated for cybersecurity
education, detection engineering, and authorized red-team research.

## Shipped in this repository (public)

| Prefix | Families |
|--------|----------|
| `submodules__malwares__*` | 12 IoT/ICS malware research trees (Mirai, TRISIS/TRITON, Bashlite, …) |
| `submodules__ics-tools__*` | 7 ICS tooling references (SCADAPASS, Redpoint, isf-w3h, …) |

Native IXF modules under `industrialxpl/modules/cve/malware/`, `scanners/malware_research/`,
and `core/malware/` wrap these trees — they do **not** execute weaponized payloads by default.

## Legal notice

By cloning or using this material you accept full responsibility for compliance with
applicable laws and for obtaining **written authorization** before testing any system
you do not own. See [TERMS_OF_USE.md](../../../TERMS_OF_USE.md), [DISCLAIMER.md](../../../DISCLAIMER.md),
and [SECURITY.md](../../../SECURITY.md) at the repository root.

Upstream projects retain their original licenses and attribution.

## PyPI vs GitHub

The PyPI package (`pip install industrialxpl-forge`) ships the framework and native modules.
The **full vendor corpus** is versioned in this Git repository (~2 GB). Clone with:

```bash
git clone https://github.com/mrhenrike/IndustrialXPL-Forge.git
cd IndustrialXPL-Forge
```

Other `submodules__ot__*` trees may exist locally for development and are not part of the
public research corpus unless explicitly added in a future release.
