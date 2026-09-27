# IndustrialXPL-Forge — Architecture

Official repository: https://github.com/mrhenrike/IndustrialXPL-Forge

## Component diagram

```mermaid
flowchart TB
  subgraph cli [CLI Layer]
    ixf[ixf / industrialxpl]
    serve[ixf serve API]
  end
  subgraph core [Core Engines]
    interp[IXFInterpreter]
    modidx[Module Index]
    mitre[MITRE Index]
    nse[NSE Manager]
    comp[Malware Compiler]
  end
  subgraph exec [Execution]
    exploit[Exploit Modules]
    gate[DestructiveGate / SafeMode]
    printer[Rich Printer]
  end
  subgraph data [Resources]
    cveDB[CVE Database]
    nseScripts[NSE Scripts]
    ioc[IOC / YARA]
  end
  ixf --> interp
  serve --> modidx
  interp --> modidx
  interp --> exploit
  modidx --> mitre
  exploit --> gate
  exploit --> printer
  modidx --> cveDB
  nse --> nseScripts
```

## Data flow

```mermaid
sequenceDiagram
  participant U as Operator
  participant I as Interpreter
  participant G as DestructiveGate
  participant M as Module
  U->>I: use scanners/ics/modbus_scanner
  U->>I: set target 10.0.0.5
  U->>I: run
  I->>G: simulate default?
  G->>M: check() / run()
  M-->>I: results
  I-->>U: table / report
```

## Module hierarchy

```
industrialxpl/modules/
├── scanners/     discovery & fingerprinting
├── exploits/     protocol / vendor abuse
├── cve/          CVE-specific modules
├── creds/        default credential testing
├── assessment/   MITRE, compliance, SAST, detection
└── encoders/     payload encoders
```

## MITRE ATT&CK for ICS

Run `ixf mitre-coverage` or `use assessment/mitre_ics/coverage_report` for Navigator JSON export.

Gap techniques (issue #1) are covered by `assessment/mitre_ics/gap_technique_coverage`.
