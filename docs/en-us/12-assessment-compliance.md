# Assessment & Compliance

IXF includes 18 dedicated assessment modules covering IEC 62443, NIST SP 800-82r3, risk scoring, ICS Kill Chain, IR playbooks, protocol security audits, and network assessments. Additionally, 28 MITRE ATT&CK for ICS technique-specific assessment modules are available under `assessment/mitre_ics/`. All assessment modules run in simulate mode by default and never modify target state.

---

## Table of Contents

1. [Running Assessment Modules](#running-assessment-modules)
2. [All 18 Assessment Modules Listed](#all-18-assessment-modules-listed)
3. [IEC 62443 — Zone and Conduit Audit](#iec-62443--zone-and-conduit-audit)
4. [NIST SP 800-82r3 — ICS Security Checklist](#nist-sp-800-82r3--ics-security-checklist)
5. [Risk Scoring — Full Output with Score Breakdown](#risk-scoring--full-output-with-score-breakdown)
6. [ICS Kill Chain — All 8 Stages](#ics-kill-chain--all-8-stages)
7. [IR Playbook — All Phases with Actions](#ir-playbook--all-phases-with-actions)
8. [OPC UA Security Audit — Full Output](#opc-ua-security-audit--full-output)
9. [DNP3 Security Audit — Full Output](#dnp3-security-audit--full-output)
10. [IEC 61850 Security Audit — Full Output](#iec-61850-security-audit--full-output)
11. [ICS Firewall Audit — Full Output](#ics-firewall-audit--full-output)
12. [Industrial Network Assessment — Full Output](#industrial-network-assessment--full-output)
13. [All 28 MITRE Technique Assessment Modules](#all-28-mitre-technique-assessment-modules)
14. [Complete Assessment Session — Full Terminal Transcript](#complete-assessment-session--full-terminal-transcript)

---

## Running Assessment Modules

Assessment modules are loaded using the `assess` shortcut or the standard `use` → `set` → `run` workflow.

```bash
# Shortcut: assess
ixf > assess iec62443/zone_conduit_audit

# Standard workflow
ixf > use assessment/iec62443/zone_conduit_audit
ixf > set target 192.168.1.0/24
ixf > run

# Non-interactive (CLI)
ixf assess iec62443/zone_conduit_audit
ixf assess nist_sp800_82/control_checklist
ixf assess risk/ics_risk_scorer
```

**Assessment modules do not require a target.** They provide methodology, checklists, and structured analysis that apply to any ICS environment. When a `target` is set, the `check()` method probes connectivity for enhanced context.

---

## All 18 Assessment Modules Listed

| # | Module Path | Category | Description |
|---|------------|----------|-------------|
| 1 | `assessment/iec62443/zone_conduit_audit` | Compliance | IEC 62443 Zone and Conduit boundary audit |
| 2 | `assessment/iec62443/security_level_assessment` | Compliance | IEC 62443 Security Level (SL1-SL4) determination |
| 3 | `assessment/iec62443/foundational_requirements` | Compliance | IEC 62443-3-3 Foundational Requirements checklist |
| 4 | `assessment/nist_sp800_82/control_checklist` | Compliance | NIST SP 800-82r3 ICS control family checklist |
| 5 | `assessment/nist_sp800_82/network_architecture` | Compliance | NIST 800-82r3 network architecture review |
| 6 | `assessment/risk/ics_risk_scorer` | Risk | ICS risk scoring methodology with weighted factors |
| 7 | `assessment/risk/consequence_analysis` | Risk | Physical consequence analysis (SIL-based) |
| 8 | `assessment/threat_intel/ics_kill_chain` | Threat Intel | ICS Cyber Kill Chain — all 8 stages |
| 9 | `assessment/threat_intel/apt_ics_actors` | Threat Intel | Known APT groups targeting ICS/OT (Sandworm, APT33, Lazarus...) |
| 10 | `assessment/ir/iacs_ir_playbook` | Incident Response | ICS/OT IR playbook — all phases |
| 11 | `assessment/ir/recovery_guidance` | Incident Response | PLC and historian recovery procedures |
| 12 | `assessment/protocols/opcua_security_audit` | Protocol | OPC UA server security assessment |
| 13 | `assessment/protocols/dnp3_security_audit` | Protocol | DNP3 Secure Authentication v5 assessment |
| 14 | `assessment/protocols/iec61850_security_audit` | Protocol | IEC 61850 substation security assessment |
| 15 | `assessment/protocols/modbus_security_audit` | Protocol | Modbus TCP security and authentication assessment |
| 16 | `assessment/protocols/ethernetip_security_audit` | Protocol | EtherNet/IP CIP security assessment |
| 17 | `assessment/network/ics_firewall_audit` | Network | ICS/OT firewall and segmentation audit |
| 18 | `assessment/network/industrial_network_assessment` | Network | Industrial network infrastructure assessment |

---

## IEC 62443 — Zone and Conduit Audit

### IEC 62443 Security Levels Explained

| Level | Code | Definition | Threat Actor |
|-------|------|-----------|-------------|
| SL 1 | `SL1` | Protection against unintentional or coincidental violation | Untrained insider, random malware |
| SL 2 | `SL2` | Protection against intentional violation using simple means | Low-skill attacker, script kiddie |
| SL 3 | `SL3` | Protection against intentional violation using sophisticated means | Skilled attacker, organized crime |
| SL 4 | `SL4` | Protection against intentional violation by state-sponsored means | Nation-state APT, Sandworm-level |

**IEC 62443 Zone Model:**

```
  ┌──────────────────────────────────────────────────────┐
  │  Enterprise Zone (Level 4-5 — IT)                   │
  │  ERP, email, internet, business systems             │
  └─────────────────┬────────────────────────────────────┘
                    │  Demilitarized Zone (DMZ)
                    │  Firewall L2 ↔ L3
  ┌─────────────────▼────────────────────────────────────┐
  │  Site Operations Zone (Level 3)                     │
  │  Historian, Scheduling, HMI supervisory             │
  └─────────────────┬────────────────────────────────────┘
                    │  Firewall L2 ↔ L3 (strict)
  ┌─────────────────▼────────────────────────────────────┐
  │  Control Zone (Level 2)                             │
  │  SCADA servers, Engineering workstations, HMIs      │
  └─────────────────┬────────────────────────────────────┘
                    │  Conduit (protocol-filtered)
  ┌─────────────────▼────────────────────────────────────┐
  │  Field Device Zone (Level 1)                        │
  │  PLCs, RTUs, DCS controllers                        │
  └─────────────────┬────────────────────────────────────┘
                    │  Field bus / process bus
  ┌─────────────────▼────────────────────────────────────┐
  │  Field Network (Level 0)                            │
  │  Sensors, actuators, instruments, field devices     │
  └──────────────────────────────────────────────────────┘
```

### Full Terminal Output

```
ixf > assess iec62443/zone_conduit_audit
[*] Loading assessment/iec62443/zone_conduit_audit...
[*] Running IEC 62443 Zone and Conduit Audit...

  IEC 62443 Zone and Conduit Security Audit
  ══════════════════════════════════════════════════════════════════════
  Standard: ISA/IEC 62443-3-3 (System Security Requirements and SLs)
  ══════════════════════════════════════════════════════════════════════

  [Zone Architecture — SR 5.1]
  ──────────────────────────────────────────────────────────────────────
  Check                               Result    Priority  Notes
  IT/OT zone separation               MANUAL    HIGH      Verify Level 3→2 firewall rules
  Protocol whitelisting (Purdue)      MANUAL    HIGH      Only OT protocols in ICS zone
  Remote access authentication        MANUAL    HIGH      VPN MFA required for OT zones
  Jump server / DMZ presence          MANUAL    HIGH      Historian in DMZ, not directly in OT
  Zone/conduit documentation          MANUAL    MEDIUM    Zones defined in approved security plan
  Redundant control path              MANUAL    MEDIUM    Primary/secondary network separation
  Level-0 to Level-2 isolation        MANUAL    HIGH      No direct IT→PLC connectivity
  Wireless network isolation          MANUAL    HIGH      OT wireless on separate SSID/VLAN

  [Conduit Controls — SR 5.2]
  ──────────────────────────────────────────────────────────────────────
  Check                               Result    Priority  Notes
  Conduit data flow documentation     MANUAL    MEDIUM    Permitted flows documented
  Protocol filtering on conduits      MANUAL    HIGH      DPI for OT protocols at conduit
  Conduit monitoring                  MANUAL    HIGH      Anomaly detection on conduit traffic
  Unidirectional gateway use          MANUAL    MEDIUM    Consider data diodes for L3→L2

  [Security Level Targets]
  ──────────────────────────────────────────────────────────────────────
  Zone                    Recommended SL  Rationale
  Enterprise (L4-L5)      SL 2            Standard IT controls
  Site Operations (L3)    SL 2            Historian + scheduling — medium risk
  Control Zone (L2)       SL 3            SCADA/HMI — sophisticated adversaries possible
  Field Device Zone (L1)  SL 2            PLCs/RTUs — vendor constraints may limit SL3
  Safety System (SIS)     SL 3–SL 4       Safety systems require highest protection

  ══════════════════════════════════════════════════════════════════════
  [i] IEC 62443-3-3: Security Level target SL2 baseline requirements
  [i] SL3 required for critical infrastructure (energy, water, oil & gas)
  [i] Reference: https://www.isa.org/standards-publications/isa-standards/isa-62443

  [Foundational Requirements Summary — IEC 62443-3-3]
  ──────────────────────────────────────────────────────────────────────
  FR 1  Identification and Authentication Control (IAC)    7 requirements
  FR 2  Use Control (UC)                                   8 requirements
  FR 3  System Integrity (SI)                              6 requirements
  FR 4  Data Confidentiality (DC)                          4 requirements
  FR 5  Restricted Data Flow (RDF)                         5 requirements
  FR 6  Timely Response to Events (TRE)                    5 requirements
  FR 7  Resource Availability (RA)                         5 requirements
  ──────────────────────────────────────────────────────────────────────
  Total: 40 System Requirements (SR) across 7 Foundational Requirements
```

---

## NIST SP 800-82r3 — ICS Security Checklist

### All Control Domains

NIST SP 800-82r3 (Guide to OT Security, Rev. 3, 2023) organizes ICS security controls by NIST SP 800-53r5 control families adapted for OT environments.

```
ixf > assess nist_sp800_82/control_checklist
[*] Running NIST SP 800-82r3 Industrial Control System Security Checklist...

  NIST SP 800-82r3 — OT Security Control Checklist
  ══════════════════════════════════════════════════════════════════════
  Publication: NIST SP 800-82 Rev. 3 (September 2023)
  Scope: Industrial Control Systems (ICS) including SCADA, DCS, PLC
  ══════════════════════════════════════════════════════════════════════

  [AC — Access Control]
  ──────────────────────────────────────────────────────────────────────
  Control    Check                                    Priority  Notes
  AC-2       Account Management                        HIGH      Verify OT account lifecycle — no shared accounts
  AC-3       Access Enforcement                        HIGH      Deny-by-default in OT network
  AC-6       Least Privilege                           HIGH      Operators cannot modify PLC logic
  AC-7       Unsuccessful Logon Attempts               MEDIUM    Lockout after 5 failed attempts
  AC-17      Remote Access                             CRITICAL  MFA for ALL remote OT access
  AC-18      Wireless Access                           HIGH      WPA3-Enterprise for OT wireless
  AC-20      External Information System Connections   HIGH      Third-party remote access controlled

  [AU — Audit and Accountability]
  ──────────────────────────────────────────────────────────────────────
  Control    Check                                    Priority  Notes
  AU-2       Audit Events                              HIGH      PLC connect, program change, alarm
  AU-3       Content of Audit Records                  HIGH      Include: who, what, when, where
  AU-6       Audit Review                              HIGH      OT logs reviewed — not just collected
  AU-9       Protection of Audit Information           MEDIUM    Logs write-protected, forwarded to SIEM
  AU-12      Audit Record Generation                   HIGH      All OT systems generate logs

  [CM — Configuration Management]
  ──────────────────────────────────────────────────────────────────────
  Control    Check                                    Priority  Notes
  CM-2       Baseline Configuration                    HIGH      Known-good PLC program hashes stored
  CM-6       Configuration Settings                    HIGH      Disable unused protocols and ports
  CM-7       Least Functionality                       CRITICAL  Remove Telnet, HTTP, unused services
  CM-8       Information System Inventory              MEDIUM    All OT assets inventoried (Purdue level)
  CM-10      Software Usage Restrictions               HIGH      No unauthorized software on HMIs

  [IA — Identification and Authentication]
  ──────────────────────────────────────────────────────────────────────
  Control    Check                                    Priority  Notes
  IA-2       Identification and Authentication (Users) HIGH      No anonymous OT access
  IA-3       Device Authentication                     HIGH      Mutual auth for HMI-PLC communications
  IA-5       Authenticator Management                  HIGH      Rotate default credentials immediately
  IA-8       Authentication (Non-Org Users)            MEDIUM    Third-party contractors: time-limited accounts

  [IR — Incident Response]
  ──────────────────────────────────────────────────────────────────────
  Control    Check                                    Priority  Notes
  IR-3       Incident Response Testing                 HIGH      OT-specific IR exercises annually
  IR-4       Incident Handling                         CRITICAL  OT-specific IR procedure documented
  IR-6       Incident Reporting                        HIGH      CISA reporting within 72 hours (CI)
  IR-8       Incident Response Plan                    HIGH      ICS-specific plan, not just IT plan
  IR-10      Integrated IR Planning                    MEDIUM    Safety and cyber IR coordinated

  [MA — Maintenance]
  ──────────────────────────────────────────────────────────────────────
  Control    Check                                    Priority  Notes
  MA-2       Controlled Maintenance                    HIGH      PLC maintenance logged with work orders
  MA-3       Maintenance Tools                         HIGH      Scan maintenance laptops before OT use
  MA-4       Remote Maintenance                        CRITICAL  Jump server required for all remote maint
  MA-6       Timely Maintenance                        MEDIUM    Patch cycle defined for ICS components

  [MP — Media Protection]
  ──────────────────────────────────────────────────────────────────────
  Control    Check                                    Priority  Notes
  MP-2       Media Access                              MEDIUM    USB/removable media controlled in OT
  MP-7       Media Use                                 HIGH      USB whitelist enforced (device control)
  MP-8       Media Sanitization                        MEDIUM    Secure erase before media reuse

  [RA — Risk Assessment]
  ──────────────────────────────────────────────────────────────────────
  Control    Check                                    Priority  Notes
  RA-3       Risk Assessment                           HIGH      Annual OT-specific risk assessment
  RA-5       Vulnerability Scanning                    HIGH      ICS-safe vulnerability scanning
  RA-9       Criticality Analysis                      HIGH      Safety-critical assets identified

  [SC — System and Communications Protection]
  ──────────────────────────────────────────────────────────────────────
  Control    Check                                    Priority  Notes
  SC-7       Boundary Protection                       CRITICAL  OT network segmentation enforced
  SC-8       Transmission Integrity                    HIGH      Protocol integrity where supported
  SC-10      Network Disconnect                        MEDIUM    Idle session timeout on HMIs
  SC-23      Session Authenticity                      HIGH      No protocol replay attacks possible
  SC-28      Protection at Rest                        MEDIUM    Encrypt sensitive historian data

  [SI — System and Information Integrity]
  ──────────────────────────────────────────────────────────────────────
  Control    Check                                    Priority  Notes
  SI-2       Flaw Remediation                          HIGH      ICS patch management program exists
  SI-3       Malicious Code Protection                 HIGH      AV/EDR on HMIs (OT-safe vendor)
  SI-4       Information System Monitoring             HIGH      OT traffic baseline + anomaly detect
  SI-7       Software, Firmware, Integrity             CRITICAL  PLC firmware integrity verified
  SI-10      Information Input Validation              MEDIUM    HMI input validation against injection

  ══════════════════════════════════════════════════════════════════════
  [i] Reference: https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final
  [i] Map to IEC 62443: NIST 800-53r5 ↔ ISA/IEC 62443-2-1 (Security Program)
```

---

## Risk Scoring — Full Output with Score Breakdown

```
ixf > assess risk/ics_risk_scorer
[*] ICS Risk Scoring Assessment...

  ICS Risk Scoring Methodology
  ══════════════════════════════════════════════════════════════════════
  Framework: CISA ICS Risk Assessment + IEC 62443 Security Level baseline
  Scoring:   Weighted factor model (0–100 scale, higher = higher risk)
  ══════════════════════════════════════════════════════════════════════

  [Risk Factor Assessment]
  ──────────────────────────────────────────────────────────────────────
  Factor                   Weight  Score  Weighted  Assessment
  ─────────────────────────────────────────────────────────────────────
  Network exposure           30%    90     27.0     Internet-facing ICS assets: CRITICAL
  Authentication strength    25%    80     20.0     No auth on Modbus/DNP3: HIGH
  Safety system separation   25%    75     18.75    SIS on same network as SCADA: HIGH
  Patch level                15%    70     10.5     Firmware > 3 years unpatched: HIGH
  Logging and monitoring      5%    40     2.0      No OT-specific SOC/SIEM: MEDIUM
  ─────────────────────────────────────────────────────────────────────
  TOTAL RISK SCORE:                        78.25 / 100

  [Score Interpretation]
  ──────────────────────────────────────────────────────────────────────
  Score Range   Level       Recommended Action
  0–25          LOW         Maintain current controls, annual review
  26–50         MEDIUM      Remediation plan within 6 months
  51–75         HIGH        Remediation plan within 90 days, executive notification
  76–90         CRITICAL    Immediate remediation, CISO and operations leadership
  91–100        CATASTROPHIC Immediate shutdown consideration, emergency response

  Current score 78.25 → CRITICAL: Immediate remediation required.

  [Top Risk Findings]
  ──────────────────────────────────────────────────────────────────────
  Rank  Finding                                          Impact    Effort
  1     Internet-exposed ICS services (Shodan-visible)   CRITICAL  HIGH
  2     Modbus/DNP3 without authentication               CRITICAL  MEDIUM
  3     SIS on same network segment as SCADA             CRITICAL  HIGH
  4     PLC firmware unpatched for 3+ years              HIGH      MEDIUM
  5     No OT-specific anomaly detection (NDR/SOC)       HIGH      HIGH
  6     Default credentials on field devices             HIGH      LOW
  7     Flat OT network (no micro-segmentation)          HIGH      HIGH
  8     No PLC program integrity baseline                MEDIUM    LOW
  9     USB removable media not controlled               MEDIUM    LOW
  10    No OT-specific incident response procedure       MEDIUM    LOW

  [Remediation Priority Matrix]
  ──────────────────────────────────────────────────────────────────────
  Priority  Action                                       Timeline
  CRITICAL  Remove internet exposure (firewall rule)     Immediate
  CRITICAL  Isolate SIS network from SCADA              Immediate (downtime required)
  HIGH      Deploy jump server for remote OT access      30 days
  HIGH      Change all default credentials               30 days
  HIGH      Enable OT network monitoring (NDR)           60 days
  MEDIUM    ICS patch management program                 90 days
  MEDIUM    PLC program hash baseline                    60 days
  LOW       USB device control policy                    90 days

  ══════════════════════════════════════════════════════════════════════
  [i] CISA ICS-CERT scoring: https://www.cisa.gov/ics-cert
  [i] Run with target set to score a specific host's connectivity risk
```

---

## ICS Kill Chain — All 8 Stages

```
ixf > assess threat_intel/ics_kill_chain
[*] ICS Kill Chain Analysis...

  ICS Cyber Kill Chain — Incident Response Framework
  ══════════════════════════════════════════════════════════════════════
  Reference: Dragos ICS Incident Response Framework
             CISA Advisory AA22-103A (INCONTROLLER/PIPEDREAM)
             SANS ICS515 — ICS Active Defense and Incident Response
  ══════════════════════════════════════════════════════════════════════

  Stage 1: Target Identification
  ──────────────────────────────────────────────────────────────────────
  Description: Adversary identifies targets through open-source intelligence,
               Shodan searches, ICS vendor advisories, and supply chain research.
  Techniques:  OSINT (vendor docs, P&IDs, permits), Shodan/Censys searches,
               ICS honeypots, strategic intelligence from prior intrusions.
  MITRE:       T0840 (Network Connection Enumeration), T0888 (Remote System Info)
  Indicators:  Shodan scans to ICS ports, scanning from unusual geographies,
               vendor portal enumeration, job posting scraping for technology stack.
  Defenders:   Monitor Shodan for your assets. Use CISA CHIRP. Reduce internet exposure.

  Stage 2: Initial Access
  ──────────────────────────────────────────────────────────────────────
  Description: Adversary gains entry into enterprise or OT environment.
  Techniques:  Spearphishing (T0865), VPN abuse (T0822), IT→OT pivot via historian,
               supply chain compromise (T0862), watering hole (T0817),
               exploit public-facing application (T0819, e.g., Citect RCE).
  MITRE:       T0817, T0819, T0822, T0862, T0865
  Indicators:  Phishing emails targeting OT engineers, VPN login anomalies,
               new remote access from unexpected countries, supply chain update anomalies.
  Real-world:  Industroyer — initial access via phishing to energy utility.
               Colonial Pipeline — VPN credentials from dark web.
               SolarWinds Orion — supply chain, reached OT via IT integration.

  Stage 3: Establish Persistence
  ──────────────────────────────────────────────────────────────────────
  Description: Adversary installs backdoors and maintains long-term access.
  Techniques:  PLC backdoor rung injection (T0839), historian compromise,
               web shell on SCADA server, legitimate remote access tools (T0822),
               scheduled tasks, boot persistence on HMI workstations.
  MITRE:       T0839 (Module Firmware), T0843 (Program Upload), T0822
  Indicators:  Unexpected PLC program modifications, new scheduled tasks on HMIs,
               historian database queries from non-engineering IPs.
  Real-world:  FrostyGoop — persistent Modbus client installed on compromised host.
               TRITON — staged on historian VM with persistence via cron.

  Stage 4: Discovery
  ──────────────────────────────────────────────────────────────────────
  Description: Adversary maps the OT environment to understand the process.
  Techniques:  Modbus scan (T0888), S7 enumeration, tag read (T0802),
               P&ID review, historian database query, HMI screenshot collection,
               network topology mapping, engineering station access.
  MITRE:       T0802 (Automated Collection), T0840, T0888
  Indicators:  FC03/FC04 broadcast scans, S7 SZL reads from unexpected hosts,
               bulk historian tag downloads, HMI process screenshots exfiltrated.
  Real-world:  Sandworm: enumerated Ukrainian power grid topology via ICS protocols.
               APT33: read historian to understand Saudi Aramco process parameters.

  Stage 5: Lateral Movement
  ──────────────────────────────────────────────────────────────────────
  Description: Adversary moves from initial foothold to OT-adjacent systems.
  Techniques:  Engineering workstation compromise (T0886), jump server bypass,
               RDP to HMI from IT network, USB propagation (Stuxnet technique),
               S7comm remote session from engineering workstation.
  MITRE:       T0812 (Default Credentials), T0866 (Exploitation of Remote Services),
               T0886 (Remote Services)
  Indicators:  RDP from IT workstations to OT systems, USB media insertion on HMIs,
               new S7comm sessions from non-engineering-station IPs.
  Real-world:  Stuxnet — USB propagation into air-gapped Natanz centrifuge network.
               NotPetya — WMIC/EternalBlue lateral movement reached HMI workstations.

  Stage 6: Privilege Escalation
  ──────────────────────────────────────────────────────────────────────
  Description: Adversary obtains engineering software and PLC administrator access.
  Techniques:  Engineering software credential theft (T0859), PLC admin access via
               default credentials (T0812), HMI privilege escalation via CVE,
               Kerberoasting on OT Windows domain, bypass of PLC write protection.
  MITRE:       T0812, T0859 (Valid Accounts)
  Indicators:  New TIA Portal / RSLogix license activations, PLC write-protect
               switch state changes, engineering password spray attempts.
  Real-world:  TRITON — obtained Schneider SIS engineering credentials to deploy
               implant directly to safety controllers.

  Stage 7: Condition (Pre-Attack Preparation)
  ──────────────────────────────────────────────────────────────────────
  Description: Adversary modifies setpoints, suppresses alarms, and stages
               the environment for maximum impact without triggering early detection.
  Techniques:  Setpoint modification (T0836), alarm suppression (T0880),
               sensor spoofing (T0856), PLC logic injection (T0857),
               safety system bypass (T0878).
  MITRE:       T0836, T0856, T0878, T0880
  Indicators:  PLC setpoint changes outside maintenance windows, alarm
               acknowledgements without operator action, process historian
               showing values outside normal operating bands.
  Real-world:  FrostyGoop — continuously wrote 0x0000 setpoints to prevent
               operator recovery. TRITON — raised SIS trip limits before attack.

  Stage 8: Execute ICS Attack
  ──────────────────────────────────────────────────────────────────────
  Description: Adversary delivers the final payload to cause physical consequence.
  Techniques:  Modbus write (T0855), IEC 104 EXEC command (T0855),
               firmware flash (T0839), MBR wipe of engineering station (T0809),
               PLC logic bomb activation (T0857), device restart/bricking (T0816).
  MITRE:       T0809 (Data Destruction), T0814 (Denial of Control),
               T0816 (Device Restart/Shutdown), T0855 (Unauthorized Command)
  Indicators:  Unexpected FC16 writes, IEC 104 EXEC commands outside maintenance,
               mass device restart events, safety system trip on all channels.
  Real-world:  Industroyer — IEC 104 EXEC commands opened all substation breakers.
               FrostyGoop — FC16 writes killed 600 apartments heating in -10°C.
               CosmicEnergy — circuit breaker manipulation via LIGHTWORK module.

  ══════════════════════════════════════════════════════════════════════
  [i] Reference: https://www.dragos.com/ics-incident-response/
  [i] Reference: https://www.cisa.gov/uscert/ics/advisories/aa22-103a
  [i] Reference: https://attack.mitre.org/matrices/ics/
```

---

## IR Playbook — All Phases with Actions

```
ixf > assess ir/iacs_ir_playbook
[*] ICS/OT Incident Response Playbook...

  ICS/OT Incident Response Playbook
  ══════════════════════════════════════════════════════════════════════
  Framework: NIST SP 800-61r2 + ICS-specific adaptations
             CISA IACS Cyber Incident Response guidance
             Dragos ICS Incident Response Playbook
  ══════════════════════════════════════════════════════════════════════

  Phase 1: DETECTION
  ──────────────────────────────────────────────────────────────────────
  Priority     Action                                        Owner
  IMMEDIATE    Monitor OT network for Modbus FC anomalies    SOC/ICS analyst
  IMMEDIATE    Check for unexpected PLC program changes       OT engineer
  IMMEDIATE    Review historian for out-of-band tag writes    Process engineer
  IMMEDIATE    Check for unexpected remote access sessions    IT/OT security
  IMMEDIATE    Review active alarm states — suppression?      Operations
  HIGH         Correlate OT events with IT security alerts    SIEM analyst
  HIGH         Check for HMI process screenshot exfiltration  DLP/SIEM
  HIGH         Verify engineering workstation integrity        IT security
  HIGH         Check field device logs (S7, Modbus, DNP3)     OT engineer
  Indicators:  Unexplained setpoint changes, mass alarm silence,
               bulk FC03 reads from non-engineering IPs, PLC CPU errors.

  Phase 2: CONTAINMENT
  ──────────────────────────────────────────────────────────────────────
  Priority     Action                                        Owner        Timeline
  IMMEDIATE    Isolate compromised network segment            Network ops   <1 hour
  IMMEDIATE    Block confirmed attacker IP at perimeter       IT security   <30 min
  IMMEDIATE    Disable compromised user accounts              IT/OT admin   <30 min
  HIGH         Enable manual control mode for affected PLCs   Operations    <2 hours
  HIGH         Verify safety system is operating correctly    Safety Eng    <1 hour
  HIGH         Disconnect affected engineering workstations   IT security   <1 hour
  HIGH         Revoke active VPN/remote sessions              IT security   <30 min
  MEDIUM       Alert control room operators to manual mode    Operations    <2 hours
  MEDIUM       Notify management and legal                    CISO/Legal    <4 hours
  MEDIUM       Notify CISA/relevant regulatory body           CISO          <24 hours
  Caution:     Do NOT power off PLCs without operations approval.
               Always coordinate with process engineers before isolation.
               Consider safety impact of containment actions.

  Phase 3: EVIDENCE PRESERVATION
  ──────────────────────────────────────────────────────────────────────
  Priority     Action                                        Owner        Timeline
  IMMEDIATE    Upload and hash PLC programs (before restore)  OT engineer   <2 hours
  IMMEDIATE    Capture historian data (before overwrite)      OT engineer   <2 hours
  HIGH         Image engineering workstation disks            Forensics     <4 hours
  HIGH         Preserve firewall and switch logs              Network ops   <2 hours
  HIGH         Preserve SIEM/SOC logs (extend retention)      SOC analyst   <2 hours
  HIGH         Photograph physical device states              OT engineer   <2 hours
  HIGH         Document all observable indicators             Incident lead <4 hours
  MEDIUM       Capture network traffic (if not already pcap)  Network ops   <2 hours
  MEDIUM       Preserve memory dumps from compromised hosts   Forensics     <4 hours

  Phase 4: ERADICATION AND RECOVERY
  ──────────────────────────────────────────────────────────────────────
  Priority     Action                                        Owner        Timeline
  CRITICAL     Compare PLC program to known-good backup hash  OT engineer   <4 hours
  CRITICAL     Restore PLC programs from verified backup      OT engineer   <4 hours
  CRITICAL     Reset all OT credentials (rotate all)          IT/OT admin   <4 hours
  HIGH         Rebuild compromised engineering workstations   IT support    <8 hours
  HIGH         Patch exploited vulnerabilities (if known)     IT/OT eng    <1 week
  HIGH         Verify historian integrity vs backup           OT engineer   <8 hours
  MEDIUM       Reset network switch configurations            Network ops   <8 hours
  MEDIUM       Verify all remote access paths (deactivate)    IT security   <8 hours
  MEDIUM       Deploy enhanced monitoring (temporary NDR)     SOC analyst   <24 hours

  Phase 5: POST-INCIDENT ACTIVITIES
  ──────────────────────────────────────────────────────────────────────
  Priority     Action                                        Owner        Timeline
  HIGH         Update firewall rules based on attack path     Network ops   <1 week
  HIGH         Review and revoke unnecessary OT credentials   IT/OT admin   <1 week
  HIGH         Complete ICS-specific incident report          Incident lead <2 weeks
  HIGH         Notify affected parties / regulatory bodies    Legal/CISO   <1 week
  MEDIUM       Conduct IR tabletop with operations team       CISO         <1 month
  MEDIUM       Update ICS IR procedures based on lessons      Incident lead <1 month
  MEDIUM       Brief ICS vendor(s) on vulnerability           OT engineer   <2 weeks
  LOW          Share indicators with ISAC (sector-specific)   CISO         <1 month
  LOW          Update threat model with new TTPs observed      Security arch <1 month

  [Sector-Specific Guidance]
  ──────────────────────────────────────────────────────────────────────
  Energy Sector:    Protect protection relays and EMS/SCADA first.
                    IEC 61850 GOOSE suppression can cause cascading failures.
                    Coordinate with grid operator before any system isolation.

  Water/Wastewater: Protect dosing controls (chlorine, chemical feed) above all.
                    Isolation may impact public health — coordinate with authority.

  Oil and Gas:      Protect RTUs, pipeline compressor controllers, LACT units.
                    Pressure safety: verify SIS independence before isolation.

  Manufacturing:    Protect PLCs, MES, historian, robot controllers.
                    Coordinate downtime windows — unplanned stops have cost impact.

  ══════════════════════════════════════════════════════════════════════
  [i] Reference: https://www.cisa.gov/sites/default/files/publications/CISA_MS-ISAC_Ransomware_Guide.pdf
  [i] Reference: https://www.dragos.com/ics-incident-response/
```

---

## OPC UA Security Audit — Full Output

```
ixf > use assessment/protocols/opcua_security_audit
ixf > set target 192.168.1.100
ixf > run

  OPC UA Server Security Assessment — 192.168.1.100:4840
  ══════════════════════════════════════════════════════════════════════
  Protocol:  OPC Unified Architecture (OPC UA)
  Reference: OPC Foundation Security Model Part 2
             IEC 62541 (OPC UA specification)
  ══════════════════════════════════════════════════════════════════════

  [Authentication and Encryption — OPC UA Security Mode]
  ──────────────────────────────────────────────────────────────────────
  Check                              Result    Priority  Notes
  SecurityMode=None endpoints        MANUAL    CRITICAL  Check if server exposes None-mode endpoint
  Anonymous user identity            MANUAL    CRITICAL  Test: opc.tcp://host:4840 with no token
  Certificate validation (client)    MANUAL    HIGH      Verify server rejects untrusted certs
  Certificate expiry check           MANUAL    HIGH      Server cert must not be expired or self-signed
  Message security policy            MANUAL    HIGH      Must be Basic256Sha256 or Aes256_Sha256_RsaPss
  Endpoint encryption                MANUAL    HIGH      SignAndEncrypt required for prod environments
  Password in UserToken              MANUAL    HIGH      UserNameIdentityToken: passwords hashed?
  X.509 certificate authentication   MANUAL    MEDIUM    Prefer cert-based auth over username/password

  [Access Control — OPC UA Role Model]
  ──────────────────────────────────────────────────────────────────────
  Check                              Result    Priority  Notes
  Anonymous browse restriction       MANUAL    HIGH      Browse namespace only with auth
  Write without authentication       MANUAL    CRITICAL  Test: unauthenticated variable write
  Role-based access control          MANUAL    HIGH      OPC UA 1.05 WellKnownRole implemented
  Method call authorization          MANUAL    HIGH      Method calls require Operator role+
  Subscription to sensitive tags     MANUAL    MEDIUM    Limit who can subscribe to process values
  History read authorization         MANUAL    MEDIUM    Historian access requires separate role

  [Discovery and Information Disclosure]
  ──────────────────────────────────────────────────────────────────────
  Check                              Result    Priority  Notes
  Discovery endpoint exposure        MANUAL    MEDIUM    Restrict GetEndpoints to authorized clients
  Server namespace information       MANUAL    LOW       Namespace URIs reveal vendor/product
  Server diagnostic data             MANUAL    MEDIUM    Disable ServerDiagnostics in production
  Application name disclosure        MANUAL    LOW       Application name may reveal software stack

  [Transport and Network]
  ──────────────────────────────────────────────────────────────────────
  Check                              Result    Priority  Notes
  OPC UA over WebSocket (OPC UA/WS)  MANUAL    HIGH      Verify TLS required for WS transport
  Session timeout configuration      MANUAL    MEDIUM    Short session timeout (< 30 minutes)
  Secure channel lifetime            MANUAL    MEDIUM    Renew secure channel before expiry
  DOS protection (session limit)     MANUAL    MEDIUM    Max concurrent sessions configured

  [Known OPC UA Vulnerabilities]
  ──────────────────────────────────────────────────────────────────────
  CVE               CVSS  Check
  CVE-2023-27321    9.8   OPC UA .NET Classic stack heap overflow
  CVE-2022-2476     7.5   OPC UA open62541 infinite loop DoS
  CVE-2021-40142    7.5   OPC UA .NET Standard NULL dereference
  CVE-2019-13555    9.1   Unified Automation OPC UA C++ stack RCE
  ──────────────────────────────────────────────────────────────────────
  [i] Run ixf search OPC-UA to see available exploit modules

  ══════════════════════════════════════════════════════════════════════
  [i] Reference: https://opcfoundation.org/developer-tools/specifications-unified-architecture/part-2-security-model/
  [i] Tool: Wireshark OPC UA dissector, UAExpert (OPC Foundation client)
```

---

## DNP3 Security Audit — Full Output

```
ixf > assess protocols/dnp3_security_audit

  DNP3 Secure Authentication v5 Assessment
  ══════════════════════════════════════════════════════════════════════
  Protocol:  DNP3 (Distributed Network Protocol 3) — ANSI/IEEE Std 1815-2012
  Reference: IEC 62351-5 (Security for DNP3 over TCP/IP)
             IEEE Std 1815-2012 DNP3 specification
  ══════════════════════════════════════════════════════════════════════

  [DNP3 Secure Authentication (SAv5)]
  ──────────────────────────────────────────────────────────────────────
  Check                              Result    Priority  Notes
  SAv5 challenge-response enabled    MANUAL    CRITICAL  Per IEC 62351-5 requirement
  Replay protection (seq numbers)    MANUAL    CRITICAL  Unique session keys prevent replay
  Application seq number validation  MANUAL    HIGH      Application layer seq enforced
  HMAC algorithm                     MANUAL    HIGH      Must be HMAC-SHA-256 (not MD5)
  Key change interval                MANUAL    HIGH      Session keys rotated < 15 min
  Unauthorized control commands      MANUAL    CRITICAL  Test control without valid SAv5
  User role-based authorization      MANUAL    HIGH      SAv6 user roles: Viewer/Operator/Engineer

  [DNP3 Data Link and Application Layer]
  ──────────────────────────────────────────────────────────────────────
  Check                              Result    Priority  Notes
  Data link CRC validation           MANUAL    MEDIUM    CRC errors detect frame tampering
  Application layer timeout          MANUAL    MEDIUM    Enforce response timeout for controls
  Broadcast message acceptance       MANUAL    HIGH      Disable broadcast control acceptance
  Direct operate without confirm     MANUAL    HIGH      Require confirm for critical controls
  Unsolicited response flooding      MANUAL    MEDIUM    Rate-limit unsolicited responses
  Time synchronization (IIN bit 4)   MANUAL    LOW       RTU requests time sync when needed

  [DNP3 Known Vulnerabilities]
  ──────────────────────────────────────────────────────────────────────
  CVE               CVSS  Check
  CVE-2019-10979    9.8   Triangle Microworks DNP3 master stack overflow
  CVE-2022-1385     8.1   Schneider EcoStruxure DNP3 auth bypass
  CVE-2021-33012    8.6   Wireshark DNP3 dissector crash (DoS)
  ──────────────────────────────────────────────────────────────────────
  [i] ICS-ALERT-14-281-01B: DNP3 implementations without authentication
  [i] Run ixf search DNP3 to see available exploit modules

  ══════════════════════════════════════════════════════════════════════
  [i] Reference: https://ieeexplore.ieee.org/document/6327898 (IEEE 1815-2012)
  [i] Reference: https://ics-cert.us-cert.gov/alerts/ICS-ALERT-14-281-01B
  [i] Tool: ixf use exploits/protocols/dnp3/dnp3_auth_bypass for test modules
```

---

## IEC 61850 Security Audit — Full Output

```
ixf > assess protocols/iec61850_security_audit

  IEC 61850 Substation Automation Security Assessment
  ══════════════════════════════════════════════════════════════════════
  Protocol:  IEC 61850 — Communication Networks and Systems in Substations
  Reference: IEC 62351-6 (Security for IEC 61850)
             IEC 62351-8 (RBAC for power systems management)
  ══════════════════════════════════════════════════════════════════════

  [GOOSE — Generic Object Oriented Substation Events]
  ──────────────────────────────────────────────────────────────────────
  Check                              Result    Priority  Notes
  GOOSE authentication (62351-6)     MANUAL    CRITICAL  HMAC-SHA-256 on all GOOSE frames
  GOOSE multicast spoofing           MANUAL    CRITICAL  Unsigned GOOSE can be replayed/spoofed
  GOOSE replay attack protection     MANUAL    CRITICAL  StNum + SqNum must be validated
  GOOSE subscription authorization   MANUAL    HIGH      IEDs filter by AppID + VLAN
  GOOSE VLANs (IEC 61850-8-1)       MANUAL    HIGH      Process bus VLAN isolated from corp

  [MMS — Manufacturing Message Specification]
  ──────────────────────────────────────────────────────────────────────
  Check                              Result    Priority  Notes
  MMS authentication                 MANUAL    CRITICAL  ISO 9506: Association required
  TLS for MMS-over-TCP               MANUAL    HIGH      IEC 62351-3: TLS 1.2+ for MMS
  Certificate-based MMS auth        MANUAL    HIGH      Replace password with cert auth
  MMS write authorization            MANUAL    CRITICAL  RBAC enforced for control writes
  Anonymous MMS browse               MANUAL    HIGH      IED namespace not world-readable
  MMS logging                        MANUAL    MEDIUM    All MMS writes logged to SIEM

  [SAMPLED VALUES — SV]
  ──────────────────────────────────────────────────────────────────────
  Check                              Result    Priority  Notes
  SV integrity protection            MANUAL    HIGH      IEC 62351-6 HMAC for SV frames
  SV replay detection                MANUAL    HIGH      SmpCnt validation prevents replay
  Process bus segmentation           MANUAL    HIGH      SV traffic isolated to process bus

  [IED and Station Network]
  ──────────────────────────────────────────────────────────────────────
  Check                              Result    Priority  Notes
  Station bus / bay bus / process bus MANUAL   HIGH      Three-level network hierarchy enforced
  IED firmware integrity             MANUAL    HIGH      Firmware hash verification before deploy
  Configuration file signing (SCD)   MANUAL    HIGH      SCL file signed before distribution
  SCL configuration access control   MANUAL    MEDIUM    SCD/CID files write-protected

  [Known IEC 61850 Vulnerabilities]
  ──────────────────────────────────────────────────────────────────────
  CVE               CVSS  Check
  CVE-2021-26266    9.8   ABB MMS server buffer overflow
  CVE-2019-13556    9.1   Siemens SICAM A8000 MMS auth bypass
  CVE-2018-10963    7.5   Siemens SINAUT spectrum GOOSE injection
  ──────────────────────────────────────────────────────────────────────
  [i] Industroyer/Crashoverride used IEC 61850 MMS for substation attack (2016)
  [i] Run ixf search IEC-61850 to see available exploit modules

  ══════════════════════════════════════════════════════════════════════
  [i] Reference: https://www.iec.ch/iec61850
  [i] Reference: IEC 62351-6: Security for IEC 61850 profile
```

---

## ICS Firewall Audit — Full Output

```
ixf > assess network/ics_firewall_audit

  ICS/OT Firewall and Network Segmentation Audit
  ══════════════════════════════════════════════════════════════════════
  Framework: NIST SP 800-82r3 (SC-7), IEC 62443-3-3 (SR 5.1, SR 5.2)
             CISA ICS Recommended Practices
  ══════════════════════════════════════════════════════════════════════

  [IT/OT Boundary Firewall]
  ──────────────────────────────────────────────────────────────────────
  Check                   Result    Priority  Remediation
  IT/OT segmentation      MANUAL    CRITICAL  Verify stateful firewall at Purdue L3→L2
  Default deny policy     MANUAL    CRITICAL  All traffic denied by default, explicit allow
  Protocol whitelisting   MANUAL    HIGH      Only industrial protocols (Modbus, S7, DNP3) in OT
  Source IP restrictions  MANUAL    HIGH      Only engineering workstation IPs reach PLCs
  Internet to OT block    MANUAL    CRITICAL  No direct internet to OT systems
  Historian DMZ placement MANUAL    HIGH      Historian in DMZ, not directly in OT network
  Remote access VPN       MANUAL    CRITICAL  VPN MFA for all OT remote access
  Jump server enforcement MANUAL    HIGH      All remote sessions via jump server
  Firewall logging        MANUAL    HIGH      All firewall events logged to SIEM

  [OT Internal Segmentation]
  ──────────────────────────────────────────────────────────────────────
  Check                   Result    Priority  Notes
  SCADA/HMI isolation     MANUAL    HIGH      SCADA on separate VLAN from PLCs
  Safety system isolation MANUAL    CRITICAL  SIS on dedicated isolated network
  Engineering VLAN        MANUAL    HIGH      Engineering workstations on dedicated VLAN
  Inter-PLC communication MANUAL    MEDIUM    PLC-to-PLC traffic controlled and logged
  Wireless OT network     MANUAL    HIGH      OT wireless SSID isolated (WPA3-Enterprise)

  [Protocol-Specific Rules]
  ──────────────────────────────────────────────────────────────────────
  Protocol        Port    Rule Required                     Notes
  Modbus TCP      502     Only EWS and SCADA → PLCs         Block port 502 on IT
  S7comm          102     Only TIA Portal hosts → S7 PLCs   Block from internet
  EtherNet/IP     44818   Only RSLogix hosts → AB PLCs      Block on perimeter
  DNP3            20000   SCADA → RTUs only                 No direct internet
  IEC 104         2404    SCADA/EMS → RTUs only             Critical: EXEC controls
  OPC UA          4840    SCADA-only → OPC servers          TLS required
  BACnet/IP       47808   BAS controllers only              Isolate from OT
  Telnet          23      BLOCK everywhere in OT            Replace with SSH
  HTTP            80      Block on HMI/PLC interfaces       HTTPS only if needed

  [Firewall Rule Review Indicators]
  ──────────────────────────────────────────────────────────────────────
  Finding                          Risk       Recommendation
  "ANY ANY" rules in OT segment    CRITICAL   Enumerate and replace with explicit rules
  Bi-directional Modbus rules      HIGH       OT→IT Modbus traffic unnecessary
  No logging on allow rules        HIGH       Log all permitted OT traffic
  Overlapping allow rules          MEDIUM     Audit and deduplicate
  Expired rules (>2 years)         MEDIUM     Review and remove stale rules
  No change control on rules       MEDIUM     Implement firewall change management

  ══════════════════════════════════════════════════════════════════════
  [i] CISA: https://www.cisa.gov/uscert/ics/recommended-practices
  [i] NSA/CISA: Stop Bad Practices guide for ICS
  [i] Tool: Review firewall ACLs manually or with firewall analysis tool
```

---

## Industrial Network Assessment — Full Output

```
ixf > assess network/industrial_network_assessment

  Industrial Network Infrastructure Assessment
  ══════════════════════════════════════════════════════════════════════
  Framework: NIST SP 800-82r3, IEC 62443-3-3, ISA-99
             SANS ICS Network Security Architecture guidelines
  ══════════════════════════════════════════════════════════════════════

  [Network Architecture]
  ──────────────────────────────────────────────────────────────────────
  Check                    Result    Priority  Notes
  Purdue model compliance  MANUAL    HIGH      Network matches Purdue/ISA-99 hierarchy
  Flat network topology    MANUAL    CRITICAL  Detect flat network — enables east-west pivot
  Network diagrams current MANUAL    MEDIUM    Network diagrams updated < 6 months ago
  Asset inventory          MANUAL    HIGH      All OT assets in inventory (Purdue level noted)
  IP address management    MANUAL    MEDIUM    Static IPs for critical OT devices

  [Network Devices]
  ──────────────────────────────────────────────────────────────────────
  Check                    Result    Priority  Notes
  Unmanaged switches       MANUAL    HIGH      No unmanaged switches in OT — no visibility
  Switch firmware patches  MANUAL    HIGH      Switch firmware patched within 1 year
  Port security            MANUAL    HIGH      MAC address filtering on OT switch ports
  SNMP community strings   MANUAL    HIGH      Check: not "public" or "private"
  SNMP version             MANUAL    HIGH      SNMPv3 with auth/priv (no v1/v2c in OT)
  Telnet/HTTP management   MANUAL    CRITICAL  Disable insecure management on all switches
  SSH for switch access    MANUAL    HIGH      SSHv2 with key auth for switch management
  VLANs configured         MANUAL    HIGH      Separate VLANs: OT, engineering, safety, mgmt
  Spanning tree attacks    MANUAL    MEDIUM    BPDU Guard on access ports

  [Routing and WAN]
  ──────────────────────────────────────────────────────────────────────
  Check                    Result    Priority  Notes
  Routing protocol auth    MANUAL    HIGH      OSPF/BGP MD5/SHA authentication
  Static routes for OT     MANUAL    MEDIUM    Prefer static routes in OT (no dynamic routing)
  WAN encryption           MANUAL    HIGH      MPLS VPN or IPSec for OT WAN links
  Remote site OT access    MANUAL    HIGH      Jump server at each remote OT site

  [Monitoring and Visibility]
  ──────────────────────────────────────────────────────────────────────
  Check                    Result    Priority  Notes
  OT network monitoring    MANUAL    HIGH      NDR deployed (Dragos, Claroty, Nozomi, etc.)
  ICS traffic baseline     MANUAL    HIGH      Normal Modbus/S7 communication pattern known
  Anomaly alerting         MANUAL    HIGH      Alerts on new ICS devices or protocols
  SIEM OT log ingestion    MANUAL    HIGH      OT device logs forwarded to SIEM
  SPAN/TAP for monitoring  MANUAL    MEDIUM    Passive monitoring preferred for ICS traffic
  OT SOC coverage          MANUAL    HIGH      24x7 monitoring or escalation to OT-capable team

  [Wireless Networks]
  ──────────────────────────────────────────────────────────────────────
  Check                    Result    Priority  Notes
  OT wireless isolation    MANUAL    HIGH      Dedicated SSID, VLAN-isolated from IT
  WPA3-Enterprise required MANUAL    HIGH      WPA2-Personal not acceptable for OT
  Rogue AP detection       MANUAL    HIGH      WIDS configured for OT wireless zone
  Bluetooth/Zigbee audit   MANUAL    MEDIUM    Field device wireless protocols audited

  ══════════════════════════════════════════════════════════════════════
  [i] Reference: https://www.sans.org/reading-room/whitepapers/ICS/ics-network-architecture-38424
  [i] Tool: Nmap OT discovery (see IXF NSE scripts), Claroty/Nozomi for NDR
```

---

## All 28 MITRE Technique Assessment Modules

All modules are under `assessment/mitre_ics/`. They run in simulate mode by default and provide structured analysis with detection and prevention controls.

| # | Module Path | Technique | Tactic | Description |
|---|------------|-----------|--------|-------------|
| 1 | `t0800_activate_firmware_update_mode` | T0800 | Persistence | Firmware update mode activation analysis |
| 2 | `t0801_monitor_process_state` | T0801 | Collection | Process state monitoring for attack staging |
| 3 | `t0802_automated_collection` | T0802 | Collection | Automated historian and tag data collection |
| 4 | `t0803_block_command_message` | T0803 | Inhibit Response | Command message blocking analysis |
| 5 | `t0804_block_reporting_message` | T0804 | Inhibit Response | Reporting message blocking assessment |
| 6 | `t0805_block_serial_com` | T0805 | Inhibit Response | Serial communication blocking assessment |
| 7 | `t0806_brute_force_io` | T0806 | Impair Process Control | Brute force I/O forcing assessment |
| 8 | `t0809_data_destruction` | T0809 | Impact | Data destruction (KillDisk/NotPetya) assessment |
| 9 | `t0812_default_credentials` | T0812 | Initial Access | Default credential exposure assessment |
| 10 | `t0813_denial_of_control` | T0813 | Inhibit Response | Denial of control assessment |
| 11 | `t0814_denial_of_service` | T0814 | Impact | Denial of service against ICS components |
| 12 | `t0816_device_restart_shutdown` | T0816 | Impact | Device restart and shutdown assessment |
| 13 | `t0817_drive_by_compromise` | T0817 | Initial Access | Drive-by compromise via ICS vendor portals |
| 14 | `t0822_external_remote_services` | T0822 | Initial Access | Remote access without MFA assessment |
| 15 | `t0827_loss_of_control` | T0827 | Impact | Loss of control analysis |
| 16 | `t0828_loss_of_productivity` | T0828 | Impact | Productivity and revenue loss assessment |
| 17 | `t0831_manipulation_of_control` | T0831 | Impact | Control manipulation techniques |
| 18 | `t0836_modify_parameter` | T0836 | Impair Process Control | Setpoint and parameter modification |
| 19 | `t0839_module_firmware` | T0839 | Persistence | Firmware modification persistence |
| 20 | `t0840_network_connection_enum` | T0840 | Discovery | Network connection enumeration |
| 21 | `t0843_program_upload` | T0843 | Collection | PLC program upload exfiltration |
| 22 | `t0851_rootkit` | T0851 | Evasion | ICS rootkit and evasion techniques |
| 23 | `t0855_unauthorized_command` | T0855 | Impair Process Control | Unauthorized command injection |
| 24 | `t0856_spoof_reporting_message` | T0856 | Impair Process Control | Sensor spoofing and data falsification |
| 25 | `t0857_modify_control_logic` | T0857 | Persistence | PLC control logic modification |
| 26 | `t0859_valid_accounts` | T0859 | Credential Access | Valid account abuse assessment |
| 27 | `t0878_alarm_suppression` | T0878 | Inhibit Response | Alarm suppression technique analysis |
| 28 | `t0880_modify_alarm_settings` | T0880 | Inhibit Response | Alarm setting modification assessment |

**Run any MITRE assessment module:**

```bash
ixf use assessment/mitre_ics/t0836_modify_parameter
ixf > set target 192.168.1.100
ixf > run
```

**Run all MITRE assessment modules in sequence:**

```bash
for technique in t0800 t0801 t0802 t0803 t0804 t0805 t0806 t0809 t0812 t0813 \
                 t0814 t0816 t0817 t0822 t0827 t0828 t0831 t0836 t0839 t0840 \
                 t0843 t0851 t0855 t0856 t0857 t0859 t0878 t0880; do
  ixf assess "mitre_ics/${technique}_*" 2>/dev/null || true
done
```

---

## Complete Assessment Session — Full Terminal Transcript

This is a complete run of a full IXF compliance and threat assessment session against a target network:

```
$ ixf

[*] Indexing modules…
[+] 976 modules indexed.

ixf > assess iec62443/zone_conduit_audit

[*] Loading assessment/iec62443/zone_conduit_audit...
[*] Running IEC 62443 Zone and Conduit Audit...

  IEC 62443 Zone and Conduit Security Audit
  ══════════════════════════════════════════════════════════════════════
  [Zone Architecture — SR 5.1]
  Check                               Result    Priority  Notes
  IT/OT zone separation               MANUAL    HIGH      Verify Level 3→2 firewall rules
  Protocol whitelisting (Purdue)      MANUAL    HIGH      Only OT protocols in ICS zone
  Remote access authentication        MANUAL    HIGH      VPN MFA required for OT zones
  Jump server / DMZ presence          MANUAL    HIGH      Historian in DMZ, not directly in OT
  Zone/conduit documentation          MANUAL    MEDIUM    Zones defined in security plan
  Redundant control path              MANUAL    MEDIUM    Primary/secondary network separation
  [i] Reference: https://www.isa.org/standards-publications/isa-standards/isa-62443
  ══════════════════════════════════════════════════════════════════════

ixf > assess nist_sp800_82/control_checklist

[*] Running NIST SP 800-82r3 ICS Security Checklist...
  [output as shown in NIST section above...]

ixf > assess risk/ics_risk_scorer

[*] ICS Risk Scoring Assessment...
  [output as shown in Risk Scoring section above...]
  TOTAL RISK SCORE: 78.25 / 100 → CRITICAL

ixf > assess threat_intel/ics_kill_chain

[*] ICS Kill Chain Analysis...
  [output as shown in ICS Kill Chain section above...]

ixf > assess ir/iacs_ir_playbook

[*] ICS/OT Incident Response Playbook...
  [output as shown in IR Playbook section above...]

ixf > use assessment/protocols/opcua_security_audit
[*] Module loaded: OPC UA Security Audit

ixf > set target 192.168.1.100
[*] target => 192.168.1.100

ixf > run
  [output as shown in OPC UA section above...]

ixf > assess protocols/dnp3_security_audit
  [output as shown in DNP3 section above...]

ixf > assess protocols/iec61850_security_audit
  [output as shown in IEC 61850 section above...]

ixf > assess network/ics_firewall_audit
  [output as shown in ICS Firewall section above...]

ixf > assess network/industrial_network_assessment
  [output as shown in Industrial Network section above...]

ixf > use assessment/mitre_ics/t0843_program_upload
[*] Module loaded: MITRE T0843 Program Upload — PLC Logic Exfiltration Assessment

ixf > set target 192.168.1.100
[*] target => 192.168.1.100

ixf > run

  [SIMULATE MODE — no packets sent]
  ─────────────────────────────────────────────────────────────────────
  [i] What would happen:

      T0843 Program Upload — Attack Scenario

      Stage 1: Discovery — enumerate S7comm/EIP/Modbus PLCs
      Stage 2: Access — connect to PLC programming interface
      Stage 3: Upload — request complete PLC ladder logic program
      Stage 4: Analysis — identify safety bypass opportunities

  [i] Detection and Prevention Controls:
  Check                               Control                    Framework
  Engineering station access control  Require auth for S7comm    IEC 62443 CR 1.1
  PLC write protection switch         Enable hardware key         NIST AC-3
  Network segmentation                Engineering VLAN separate   IEC 62443 SR 5.1
  Protocol whitelisting               Block S7comm non-eng IPs    NIST SC-7
  Audit logging                       Log all PLC operations      NIST AU-12
  [i] MITRE ATT&CK for ICS: T0843 (Program Upload)
  ─────────────────────────────────────────────────────────────────────

ixf > use assessment/mitre_ics/t0836_modify_parameter
[*] Module loaded: MITRE T0836 Modify Parameter Assessment
ixf > set target 192.168.1.100
ixf > run
  [Simulate output — setpoint manipulation controls...]

ixf > use assessment/mitre_ics/t0880_modify_alarm_settings
ixf > set target 192.168.1.100
ixf > run
  [Simulate output — alarm suppression controls...]

ixf > mitre-coverage

[*] Indexing modules…
  MITRE ATT&CK for ICS Coverage
  Overall: 82/85 techniques (96.5%)
  Tactic                    Total  Covered  %
  Initial Access            9      9        100%
  Execution                 12     11       91.7%
  [... full coverage table ...]

ixf > report json
[*] Generating JSON report...
[+] Report saved: .tmp/ixf_report_20240601_182500.json

ixf > report html
[*] Generating HTML report...
[+] Report saved: .tmp/ixf_report_20240601_182501.html

ixf > mitre-report layer
[*] Generating MITRE ATT&CK Navigator layer...
[+] Layer saved: .tmp/ixf_navigator_layer_20240601.json
[i] Import at: https://mitre-attack.github.io/attack-navigator/

ixf > exit
[*] Goodbye.
```

**Non-interactive equivalent (single command):**

```bash
ixf \
  assess iec62443/zone_conduit_audit \
  assess nist_sp800_82/control_checklist \
  assess risk/ics_risk_scorer \
  assess threat_intel/ics_kill_chain \
  assess ir/iacs_ir_playbook \
  assess network/ics_firewall_audit \
  assess network/industrial_network_assessment \
  assess protocols/opcua_security_audit \
  assess protocols/dnp3_security_audit \
  assess protocols/iec61850_security_audit \
  mitre-coverage \
  report json \
  report html \
  mitre-report layer
```

---

*Previous: [PolyExploit Runner](11-poly-exploit-runner.md) | Next: [Module Catalog](13-module-catalog.md)*
