# Security Policy — IndustrialXPL-Forge

## Scope

IndustrialXPL-Forge (IXF) is an offensive and defensive security research framework for OT/ICS/SCADA. This policy covers:

- Vulnerabilities in the IXF codebase itself
- Misuse of IXF modules against unauthorized targets
- Malware research modules and incorporated vendor sources

## Authorized Use Only

IXF modules — including malware analysis, compilation, and botnet research tools — must **only** be used on:

- Systems you own
- Isolated lab environments with no production connectivity
- Engagements with **explicit written authorization**

Unauthorized use may violate computer crime laws in your jurisdiction.

## Malware and Botnet Modules (public corpus)

IXF **publicly distributes** incorporated malware family sources and ICS-tool references
for **defensive research** (TTP mapping, IOC extraction, blue-team detection). These modules:

- Default to analysis/simulate modes where applicable
- Require operator confirmation for compile or live probe actions
- Must never be deployed against third-party networks without authorization

**Cloning this repository constitutes acceptance** that you are solely responsible for
lawful use. See [TERMS_OF_USE.md](TERMS_OF_USE.md) and [DISCLAIMER.md](DISCLAIMER.md).

## Reporting a Vulnerability in IXF

If you find a security issue in the IXF framework (RCE in the CLI, credential leak, sandbox escape in module loader, etc.):

1. **Do not** open a public GitHub issue for exploitable findings
2. Email: **henrique.santos@uniaogeek.com.br**
3. Include: affected version, reproduction steps, impact assessment
4. Allow **90 days** for remediation before public disclosure

We follow coordinated disclosure for OT/ICS-adjacent tooling.

## Reporting OT/ICS Equipment Vulnerabilities

If IXF helps you discover a vulnerability in deployed OT equipment:

1. Document in an isolated lab
2. Notify the vendor through their PSIRT/disclosure channel
3. Allow minimum **90 days** for critical issues
4. After disclosure, consider contributing a module via pull request

## Safe Defaults

- `simulate=false` by default — modules may send read probes on `check()` / `run()`
- Use `set simulate true` or `setg simulate true` for SafeMode (no live payloads)
- Destructive writes require `destructive=true` plus impact-level confirmation
- All destructive operations are logged under `.log/destructive_ops_*.log`

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.45  | Yes       |
| 1.0.44  | Yes       |
| 1.0.x   | Best effort |
| < 1.0   | No        |

---

Maintainer: André Henrique ([@mrhenrike](https://github.com/mrhenrike))
