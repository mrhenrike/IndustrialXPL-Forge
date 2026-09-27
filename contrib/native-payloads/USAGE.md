# IXF Native Payloads — Authorized Use Only

This directory contains native implementations of ICS/OT malware techniques
for use in authorized security assessments and penetration tests.

## Legal Requirements

By using any file in this directory, you confirm:

1. **Written authorization**: You have explicit written authorization from the
   owner of the target system and network.
2. **Scope compliance**: Your use is limited to the systems and IP ranges
   explicitly authorized in the engagement letter.
3. **Jurisdiction**: Your use complies with all applicable laws in your
   jurisdiction, including but not limited to:
   - Brazil: Lei 12.737/2012 (Lei Carolina Dieckmann)
   - Brazil: Marco Civil da Internet (Lei 12.965/2014)
   - USA: Computer Fraud and Abuse Act (CFAA)
   - EU: Directive on Attacks Against Information Systems (2013/40/EU)
4. **Controlled environment**: You understand these implementations can cause
   irreversible damage to industrial equipment, safety systems, and processes.
5. **Not for distribution**: You will not redistribute these files or derived
   works to unauthorized parties.

## How These Are Used

IXF detects this directory at runtime. When `destructive=true` AND a native
implementation exists, IXF offers to use it instead of the TTP-only simulator.

The default pip install (`pip install industrialxpl-forge`) does NOT include
this directory. To access native payloads, you must clone the repository:

```bash
git clone https://github.com/mrhenrike/IndustrialXPL-Forge.git
cd IndustrialXPL-Forge
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Contents

| Directory | Malware Family | Target | Impact Level |
|-----------|---------------|--------|--------------|
| `triton/` | TRITON/TRISIS (Xenotime/CPS) | Schneider Triconex SIS | CATASTROPHIC |
| `industroyer/` | Industroyer/Crashoverride (Sandworm) | IEC-104 RTUs / substations | CATASTROPHIC |
| `frostygoop/` | FrostyGoop (GRU-attributed) | Modbus TCP heating controllers | CRITICAL |
| `crashoverride/` | Crashoverride v2 | IEC-104 / IEC-101 substations | CATASTROPHIC |

## In-Memory Compilation

C and Rust payloads are compiled in-memory at execution time using:
- `gcc` / `cc` via subprocess (Linux)
- `cl.exe` via subprocess (Windows, requires MSVC)
- `rustc` via subprocess (Rust payloads)

The compiled binary is loaded into memory via `ctypes.CDLL` from a temporary
file that is deleted immediately after loading. No compiled artifacts persist
on disk after execution.

## Incident Response

If you accidentally deploy a payload against an unauthorized target:
1. Immediately disconnect the target network from all other segments
2. Preserve all logs before powering down
3. Contact the system vendor emergency line
4. File an incident report with your legal team
5. For safety systems: call relevant emergency services

---

**Author**: Andre Henrique (@mrhenrike) | Uniao Geek
**Repository**: https://github.com/mrhenrike/IndustrialXPL-Forge
