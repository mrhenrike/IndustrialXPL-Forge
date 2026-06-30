# Assessment & Compliance

IXF includes 18 assessment modules covering IEC 62443, NIST SP 800-82r3, MITRE ATT&CK for ICS coverage, risk scoring, threat intelligence (ICS Kill Chain), incident response playbooks, protocol security audits, and network assessment — all with detailed checklists and actionable guidance.

---

## All 18 Assessment Modules

| Module Path | Category | Description | Impact |
|-------------|----------|-------------|--------|
| `assessment/iec62443/zone_conduit_audit` | Framework | IEC 62443-3-3 zone and conduit compliance audit | INFO |
| `assessment/nist_sp800_82/control_checklist` | Framework | NIST SP 800-82r3 ICS security control checklist | INFO |
| `assessment/risk/ics_risk_scorer` | Risk | Composite ICS risk score based on 5 weighted factors | INFO |
| `assessment/threat_intel/ics_kill_chain` | Threat | ICS kill chain 8-phase analysis | INFO |
| `assessment/ir/iacs_ir_playbook` | IR | 5-phase ICS incident response playbook | INFO |
| `assessment/protocols/opcua_security_audit` | Protocol | OPC UA security configuration audit (IEC 62541) | INFO |
| `assessment/protocols/dnp3_security_audit` | Protocol | DNP3 SAv5 security authentication audit | INFO |
| `assessment/protocols/iec61850_security_audit` | Protocol | IEC 61850 / IEC 62351 security audit | INFO |
| `assessment/network/ics_firewall_audit` | Network | ICS network firewall rule set audit | INFO |
| `assessment/network/industrial_network_assessment` | Network | Full industrial network security assessment | INFO |
| `assessment/mitre_ics/coverage_report` | MITRE | MITRE ATT&CK for ICS coverage report | INFO |
| `assessment/mitre_ics/full_mitre_sweep` | MITRE | Full MITRE technique sweep (simulation) | INFO |
| `assessment/mitre_ics/t0801_monitor_process_state` | MITRE TTP | T0801 Monitor Process State simulation | INFO |
| `assessment/mitre_ics/t0806_brute_force_io` | MITRE TTP | T0806 Brute Force I/O simulation | INFO |
| `assessment/mitre_ics/t0807_remote_services` | MITRE TTP | T0807 Command-Line Interface | INFO |
| `assessment/mitre_ics/t0820_exploitation_remote` | MITRE TTP | T0820 Exploitation of Remote Services | INFO |
| `assessment/sast/plc_source_analyzer` | SAST | PLC source code analysis wrapper (calls SAST engine) | INFO |
| `assessment/mitre_ics/t0836_modify_parameter` | MITRE TTP | T0836 Modify Parameter assessment | INFO |

---

## Running Assessment Modules

Use the `assess` command to load and immediately execute:

```
ixf > assess <module_path>
```

Or use the standard `use` → `set target` → `run` workflow:

```
ixf > use assessment/iec62443/zone_conduit_audit
ixf > set target 192.168.1.0/24
ixf > run
```

---

## IEC 62443 — Zone and Conduit Audit

### Security Levels (SL1–SL4)

IEC 62443-3-3 defines four Security Levels based on attacker capability and required protection:

| Level | Definition | Attacker Profile | Example Requirements |
|-------|-----------|-----------------|---------------------|
| **SL 1** | Protection against unintentional or coincidental violation | Casual, no specific skill | Basic access control, no anonymous access |
| **SL 2** | Protection against intentional violation using simple means | Motivated attacker, basic ICS knowledge | Authentication, encrypted management, event logging |
| **SL 3** | Protection against intentional violation using sophisticated means | Skilled attacker with ICS expertise | MFA, strict zone segmentation, anomaly detection |
| **SL 4** | Protection against intentional violation using state-sponsored means | Nation-state, unlimited resources | Air gap, supply chain controls, hardware security modules |

Most critical infrastructure should target **SL 2 as minimum** and **SL 3 for safety systems**.

### Zone/Conduit Model

The IEC 62443 zone/conduit model divides the network into security zones and conduits:

- **Zone:** A grouping of logical or physical assets that share the same security requirements
- **Conduit:** A communication path between zones (with controls)
- **Purdue Model Zones:** Level 4 (Enterprise) → Level 3 (Operations) → Level 2 (Control) → Level 1 (Field Devices)

### Full Audit Output

```
ixf > assess iec62443/zone_conduit_audit
[*] Loading assessment/iec62443/zone_conduit_audit...
[*] Running IEC 62443 Zone and Conduit Audit...

  ══════════════════════════════════════════════════════════════════════
  IEC 62443 Zone and Conduit Compliance Audit
  Framework: IEC 62443-2-1, IEC 62443-3-3 | Target SL: 2 (baseline)
  ══════════════════════════════════════════════════════════════════════

  [Zone Model]
  ──────────────────────────────────────────────────────────────────────
  Purdue Level 4 (Enterprise Network — Business)
    Zone:    Corporate network — ERP, email, internet access
    Target:  No direct OT access | Separate from Level 3

  Purdue Level 3 (Operations/Site Network — MES/Historian)
    Zone:    Site operations — historians, engineering workstations
    Target:  DMZ between Level 4 and Level 2 | No direct PLC access

  Purdue Level 2 (Control Network — SCADA/HMI)
    Zone:    SCADA servers, HMI stations, control room
    Target:  Isolated — only approved traffic to Level 1

  Purdue Level 1 (Field Control Network — PLCs/RTUs)
    Zone:    PLCs, RTUs, field controllers
    Target:  Minimal external connectivity; serial preferred

  Purdue Level 0 (Process — Physical Sensors/Actuators)
    Zone:    Field instruments — temperature, pressure, valves
    Target:  No IP connectivity at this level

  ──────────────────────────────────────────────────────────────────────
  IEC 62443-3-3 Control Requirements (SL2 Baseline)
  ──────────────────────────────────────────────────────────────────────
  Requirement                              Status    SL2 Reference
  SR 1.1: Human user identification       REVIEW    Unique accounts per user, no shared
  SR 1.2: Software process identification REVIEW    Service accounts documented
  SR 1.3: Use control enforcement          REVIEW    RBAC implemented per zone
  SR 1.4: Identifier management           REVIEW    Account lifecycle process exists
  SR 1.5: Authenticator management        REVIEW    Password policy + rotation
  SR 1.6: Wireless access management      REVIEW    No unauthorized wireless in OT zones
  SR 2.1: Authorization enforcement       REVIEW    Need-to-know access model
  SR 3.3: Security functionality check    REVIEW    Startup integrity check
  SR 3.4: Software and info integrity     REVIEW    File integrity monitoring on HMIs
  SR 3.5: Input validation                REVIEW    PLC programs validate all inputs
  SR 3.6: Deterministic output            REVIEW    No state machine bypass possible
  SR 4.1: Info confidentiality            REVIEW    OPC UA with security mode=Basic256
  SR 4.2: Use of cryptography             REVIEW    No cleartext management protocols
  SR 5.1: Network segmentation            REVIEW    Purdue model zones implemented
  SR 5.2: Zone boundary protection        REVIEW    Firewall between all Purdue levels
  SR 5.3: General purpose person-to-person comm REVIEW  No general internet in OT zones
  SR 5.4: Application partitioning        REVIEW    OT apps on dedicated systems
  SR 7.1: DoS protection                  REVIEW    Rate limiting on OT network interfaces
  SR 7.2: Resource management             REVIEW    PLC scan cycle monitored
  SR 7.3: Control system backup           REVIEW    PLC program backup documented
  SR 7.4: Control system recovery         REVIEW    Recovery time <4h objective
  SR 7.5: Emergency power                 REVIEW    UPS on critical control systems
  SR 7.6: Network and security config mgmt REVIEW   Config management system
  SR 7.7: Least functionality             REVIEW    Unused ports/services disabled
  ──────────────────────────────────────────────────────────────────────
  [i] Status REVIEW = requires manual verification in the target environment
  [i] Reference: ISA/IEC 62443 standards suite
  [i] Assessment tool: https://www.isa.org/store/isa-62443
  ══════════════════════════════════════════════════════════════════════
```

---

## NIST SP 800-82r3 — ICS Security Checklist

### All 8 Control Domains with Full Checklist Output

```
ixf > assess nist_sp800_82/control_checklist
[*] Running NIST SP 800-82r3 Industrial Control System Security Checklist...

  ══════════════════════════════════════════════════════════════════════
  NIST SP 800-82 Rev. 3 — ICS Security Control Checklist
  Reference: https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final
  ══════════════════════════════════════════════════════════════════════

  Domain 1: Access Control (AC)
  ──────────────────────────────────────────────────────────────────────
  AC-2  Account Management           REVIEW   ICS accounts documented, reviewed quarterly
  AC-3  Access Enforcement            REVIEW   RBAC enforced on all OT systems
  AC-6  Least Privilege               REVIEW   Operator accounts cannot modify PLC programs
  AC-7  Unsuccessful Logon Attempts   REVIEW   Lockout after 5 failed attempts
  AC-17 Remote Access                 REVIEW   VPN + MFA for all OT remote access
  AC-18 Wireless Access               REVIEW   Wireless prohibited in OT zones or isolated
  AC-19 Access Control for Mobile     REVIEW   No mobile devices in control rooms
  AC-20 Use of External Systems       REVIEW   No direct external system connectivity

  Domain 2: Audit and Accountability (AU)
  ──────────────────────────────────────────────────────────────────────
  AU-2  Event Logging                 REVIEW   All OT events logged (logins, program changes)
  AU-3  Content of Audit Records      REVIEW   Records include who, what, when, where
  AU-6  Audit Review Analysis         REVIEW   OT logs reviewed (automated SIEM preferred)
  AU-9  Protection of Audit Info      REVIEW   Logs write-protected, sent to central SIEM
  AU-12 Audit Record Generation       REVIEW   PLC audit events logged (not all PLCs support)

  Domain 3: Configuration Management (CM)
  ──────────────────────────────────────────────────────────────────────
  CM-2  Baseline Configuration        REVIEW   PLC program baseline documented and stored
  CM-6  Configuration Settings        REVIEW   Hardened configs for all OT systems
  CM-7  Least Functionality           REVIEW   Unused protocols/ports disabled
  CM-8  Component Inventory           REVIEW   OT asset inventory current and complete
  CM-10 Software Usage Restrictions   REVIEW   Only approved software on OT systems
  CM-11 User-Installed Software       REVIEW   Users cannot install unapproved software

  Domain 4: Incident Response (IR)
  ──────────────────────────────────────────────────────────────────────
  IR-1  Incident Response Policy      REVIEW   OT-specific IR policy documented
  IR-4  Incident Handling             REVIEW   ICS IR procedures tested annually (tabletop)
  IR-5  Incident Monitoring           REVIEW   OT network monitored for anomalies (SIEM/IDS)
  IR-6  Incident Reporting            REVIEW   CISA/ICS-CERT notification procedure defined
  IR-8  Incident Response Plan        REVIEW   IR plan includes OT-specific scenarios

  Domain 5: Risk Assessment (RA)
  ──────────────────────────────────────────────────────────────────────
  RA-3  Risk Assessment               REVIEW   Annual ICS-specific risk assessment
  RA-5  Vulnerability Scanning        REVIEW   Passive OT vulnerability scanning (no active)
  RA-9  Criticality Analysis          REVIEW   BES/CIP criticality determined

  Domain 6: System and Communications Protection (SC)
  ──────────────────────────────────────────────────────────────────────
  SC-7  Boundary Protection           REVIEW   Firewalls between all network zones
  SC-8  Transmission Confidentiality  REVIEW   Encrypted management protocols (SSH, HTTPS)
  SC-10 Network Disconnect            REVIEW   Idle sessions timeout (< 15 min for HMI)
  SC-12 Cryptographic Key Mgmt        REVIEW   PKI for OPC UA certificates managed
  SC-17 Public Key Certificates       REVIEW   Self-signed certs replaced with org CA
  SC-28 Protection of Data at Rest    REVIEW   HMI workstation drives encrypted
  SC-29 Heterogeneity                 REVIEW   Diversity in OT components/vendors

  Domain 7: System and Information Integrity (SI)
  ──────────────────────────────────────────────────────────────────────
  SI-2  Flaw Remediation              REVIEW   OT patch management process (vendor-approved)
  SI-3  Malicious Code Protection     REVIEW   AV on Windows HMIs (ICS-aware, whitelist)
  SI-7  Software Integrity            REVIEW   PLC program integrity verified (hashes)
  SI-10 Information Input Validation  REVIEW   PLC programs validate all operator inputs

  Domain 8: Program Management (PM)
  ──────────────────────────────────────────────────────────────────────
  PM-1  Information Security Program  REVIEW   OT security program formally documented
  PM-6  Information Security Measures REVIEW   OT security metrics tracked and reported
  PM-14 Testing Training Monitoring   REVIEW   OT security exercises conducted annually
  PM-16 Threat Awareness Program      REVIEW   ICS threat intelligence received and used

  ══════════════════════════════════════════════════════════════════════
  [i] All items marked REVIEW require manual verification
  [i] Reference: NIST SP 800-82 Rev. 3 (May 2023)
  [i] ICS-CERT: https://www.cisa.gov/ics
  ══════════════════════════════════════════════════════════════════════
```

---

## Risk Scorer — Full Output with Score Calculation

```
ixf > assess risk/ics_risk_scorer
[*] ICS Risk Scoring...

  ══════════════════════════════════════════════════════════════════════
  ICS Risk Score — Composite Methodology
  Reference: CISA ICS Risk Assessment Methodology
  ══════════════════════════════════════════════════════════════════════

  Factor 1: Network Exposure (30% weight)
  ──────────────────────────────────────────────────────────────────────
  Question: Is the ICS/SCADA directly accessible from the internet or DMZ?
  Indicators:
    CRITICAL (score 10.0): ICS ports (502, 102, 44818, 4840) internet-facing
    HIGH     (score 7.5):  ICS in DMZ with insufficient controls
    MEDIUM   (score 5.0):  ICS behind firewall but remote access without MFA
    LOW      (score 2.5):  Air-gapped or strict network segmentation
  Assessment: Set target to internet-facing IP or 'none' for air-gapped
  Default assumption for methodology: HIGH (7.5) — typical enterprise OT

  Factor 2: Authentication Strength (25% weight)
  ──────────────────────────────────────────────────────────────────────
  Question: Is authentication required for all OT system access?
  Indicators:
    CRITICAL (10.0): Modbus/DNP3 — no authentication by design; all access open
    HIGH      (7.5): Default credentials unchanged; shared passwords
    MEDIUM    (5.0): Unique passwords but no MFA; basic auth only
    LOW       (2.5): MFA enforced for all remote access; certificate-based auth
  Assessment: HIGH (7.5) — Modbus unauthenticated, SSH default creds present

  Factor 3: Safety System Separation (25% weight)
  ──────────────────────────────────────────────────────────────────────
  Question: Are Safety Instrumented Systems (SIS) isolated from control network?
  Indicators:
    CRITICAL (10.0): SIS on same VLAN as basic process control or internet
    HIGH      (7.5): SIS has OT network access (should be one-way/air-gapped)
    MEDIUM    (5.0): SIS behind firewall but on OT network
    LOW       (2.5): SIS fully isolated — independent power, network, HMI
  Assessment: HIGH (7.5) — SIS on same OT network as SCADA

  Factor 4: Patch Level (15% weight)
  ──────────────────────────────────────────────────────────────────────
  Question: How current is OT firmware and software?
  Indicators:
    CRITICAL (10.0): Firmware > 5 years old; no patch process; EOL systems
    HIGH      (7.5): Firmware 2-5 years old; irregular patching
    MEDIUM    (5.0): Firmware < 2 years old; semi-annual patching
    LOW       (2.5): Current firmware; monthly patching window; vendor alerts
  Assessment: HIGH (7.5) — firmware typically 3+ years; long change windows

  Factor 5: Logging and Monitoring (5% weight)
  ──────────────────────────────────────────────────────────────────────
  Question: Is OT network traffic monitored for anomalies?
  Indicators:
    CRITICAL (10.0): No logging; no monitoring; no SIEM
    HIGH      (7.5): Syslog only; no OT-specific anomaly detection
    MEDIUM    (5.0): OT-aware IDS (Claroty, Nozomi, Dragos) without fine-tuning
    LOW       (2.5): OT-aware IDS + SOC with OT expertise + regular review
  Assessment: MEDIUM (5.0) — Syslog to SIEM; no OT-specific IDS

  ──────────────────────────────────────────────────────────────────────
  Score Calculation
  ──────────────────────────────────────────────────────────────────────
  Factor                         Score  Weight   Weighted
  Network Exposure               7.5    30%      2.25
  Authentication Strength        7.5    25%      1.875
  Safety System Separation       7.5    25%      1.875
  Patch Level                    7.5    15%      1.125
  Logging and Monitoring         5.0     5%      0.25
  ──────────────────────────────────────────────────────────────────────
  COMPOSITE RISK SCORE: 7.375 / 10.0
  RISK LEVEL: HIGH (7.0-8.9) — Significant risk requiring immediate action

  Priority Recommendations:
  1. [CRITICAL ACTION] Implement Modbus/ICS authentication (DMZ + authentication proxy)
  2. [CRITICAL ACTION] Segment SIS from SCADA on separate network with one-way gateway
  3. [HIGH ACTION]     Deploy OT-aware IDS/NDR (Claroty, Nozomi Networks, Dragos)
  4. [HIGH ACTION]     Establish OT patching program with vendor-approved schedule
  5. [MEDIUM ACTION]   Enable MFA for all remote OT access
  ══════════════════════════════════════════════════════════════════════
```

---

## ICS Kill Chain — All 8 Stages

```
ixf > assess threat_intel/ics_kill_chain
[*] Running ICS Kill Chain Assessment...

  ══════════════════════════════════════════════════════════════════════
  ICS Kill Chain (Dragos / Assante-Lee 2015)
  Reference: https://dragos.com/resource/ics-kill-chain/
  ══════════════════════════════════════════════════════════════════════

  Stage 1: Recon
  ──────────────────────────────────────────────────────────────────────
  Description: External reconnaissance of exposed OT assets and targeting
  Attacker Actions:
    - OSINT on utility/industrial company (LinkedIn, job postings)
    - Shodan/Censys scan for internet-facing OT ports (502, 102, 4840, etc.)
    - ICS-CERT advisory review for unpatched vulnerabilities
    - Social engineering for employee information
    - Vendor supply chain mapping
  IXF Coverage: scanners/ics/*, discover command, cve-scan workflow
  MITRE ICS: T0883 (Internet Accessible Device), T0808 (Control Device Identification)
  Defensive: Remove OT assets from internet; implement network scanning alerts

  Stage 2: Weaponization
  ──────────────────────────────────────────────────────────────────────
  Description: Development or acquisition of ICS-specific attack capability
  Attacker Actions:
    - Develop or purchase ICS protocol exploits (Modbus, DNP3, S7comm)
    - Acquire OT malware (Industroyer, Triton framework components)
    - Develop custom payload for specific vendor/device
    - Build or acquire supply chain injection capability
    - Prepare spear-phishing documents with ICS themes
  IXF Coverage: cve/* modules, exploits/protocols/* (simulate), malware TTP replicas
  MITRE ICS: T0854 (Spearphishing), T0862 (Supply Chain Compromise)
  Defensive: Threat intelligence sharing; vendor security partnerships

  Stage 3: Delivery
  ──────────────────────────────────────────────────────────────────────
  Description: Delivery of weaponized payload to target environment
  Attacker Actions:
    - Spearphishing email to engineering/operations staff
    - Compromised VPN credentials for remote access (T0822)
    - Supply chain compromise (vendor update, hardware implant)
    - USB/removable media (T0847) — especially in air-gapped environments
    - Watering hole attack on ICS vendor/conference websites
  IXF Coverage: assessment/threat_intel/ics_kill_chain; ttp T0854
  MITRE ICS: T0822 (External Remote Services), T0847 (Replication via Removable Media)
  Defensive: Email filtering; MFA for VPN; USB policy enforcement; supply chain vetting

  Stage 4: Exploitation
  ──────────────────────────────────────────────────────────────────────
  Description: Exploit vulnerabilities to gain initial IT/OT foothold
  Attacker Actions:
    - Exploit unpatched vulnerability in internet-facing system (T0819)
    - Leverage exposed OPC DA/UA endpoint for initial access
    - Use default or brute-forced credentials (T0812, T0859)
    - Exploit OT-specific CVE (Siemens S7, Rockwell ControlLogix, etc.)
  IXF Coverage: cve/* (350+ CVE modules), creds/*, exploits/protocols/*
  MITRE ICS: T0819 (Exploit Public-Facing), T0812 (Default Credentials)
  Defensive: Patch management; remove default credentials; network monitoring

  Stage 5: Installation (Lateral Movement to OT)
  ──────────────────────────────────────────────────────────────────────
  Description: Move from IT environment into OT/ICS network
  Attacker Actions:
    - Move from compromised IT workstation to engineering workstation
    - Exploit Purdue Level 3→2 segmentation gaps
    - Use legitimate remote access tools (MSTSC, RDP to HMI)
    - Install persistence on OT jump server/historian
    - Abuse OPC DA tunnel between Level 3 and Level 2
  IXF Coverage: assessment/network/ics_firewall_audit; ttp T0843
  MITRE ICS: T0820 (Exploitation Remote Services), T0867 (Lateral Tool Transfer)
  Defensive: Strict firewall rules; monitor lateral movement; OT jump server logging

  Stage 6: C2 Installation (OT Command and Control)
  ──────────────────────────────────────────────────────────────────────
  Description: Establish persistent OT-side command and control
  Attacker Actions:
    - Deploy Industroyer-style C2 module on OT server
    - Establish covert channel via ICMP tunneling through firewall
    - Use legitimate ICS protocol (OPC UA, Modbus) as C2 carrier
    - Install rootkit on HMI workstation (T0851)
    - Establish scheduled task for persistence on OT workstation
  IXF Coverage: cve/malware/* (Industroyer modules), ttp T0851, T0869
  MITRE ICS: T0884 (Connection Proxy), T0885 (Commonly Used Port), T0851 (Rootkit)
  Defensive: Application whitelisting on HMIs; outbound OT traffic monitoring

  Stage 7: Execution (ICS Payload Delivery)
  ──────────────────────────────────────────────────────────────────────
  Description: Delivery of ICS-specific attack payload to field devices
  Attacker Actions:
    - Use Industroyer/CrashOverride IEC 104 module to send TRIP commands
    - Upload modified PLC program (T0843) to overwrite safety logic
    - Use FrostyGoop-style Modbus attack to modify setpoints
    - Disable safety systems via Triton/TRISIS-style attack
    - Trigger PLC logic bomb (pre-planted in earlier phase)
    - Use EKANS-style process killer to disable HMI/historian first
  IXF Coverage: cve/malware/* (all malware modules), exploits/protocols/*
  MITRE ICS: T0836 (Modify Parameter), T0855 (Unauthorized Command), T0838, T0836
  Defensive: OT anomaly detection; PLC logic integrity monitoring; safety system isolation

  Stage 8: Impact
  ──────────────────────────────────────────────────────────────────────
  Description: Achieve physical disruption, damage, or sustained control
  Attacker Actions:
    - Trigger physical process disruption (power outage, heating failure, water contamination)
    - Cause physical equipment damage (centrifuge destruction — Stuxnet model)
    - Wipe SCADA workstations (KillDisk) to delay recovery
    - Suppress alarms to extend impact duration (T0838, T0878)
    - Deny view to operators — spoof sensor readings (T0832, T0856)
  IXF Coverage: cve/malware/*, assessment modules, full TTP sweep
  MITRE ICS: T0837 (Loss of Safety), T0879 (Damage to Property), T0826-T0829 (Loss of...)
  Defensive: Segmentation; backup/recovery; independent safety monitoring; incident response

  ══════════════════════════════════════════════════════════════════════
```

---

## IR Playbook — All 5 Phases

```
ixf > assess ir/iacs_ir_playbook
[*] Running ICS Incident Response Playbook...

  ══════════════════════════════════════════════════════════════════════
  IACS Incident Response Playbook (NIST 800-61 + ICS CERT)
  ══════════════════════════════════════════════════════════════════════

  Phase 1: Preparation
    Actions:
      - Establish OT-specific IR team (operations, IT security, vendor support contacts)
      - Pre-position forensic tools (Wireshark, network tap, USB forensic kits)
      - Document baseline PLC programs and firmware checksums
      - Establish out-of-band communication (satellite phone, radio if needed)
      - Pre-define escalation path: CISO → CISA ICS-CERT → FBI Cyber Division
      - Conduct quarterly tabletop exercises with OT scenario (e.g., ransomware on HMI)

  Phase 2: Detection and Analysis
    Actions:
      - Identify anomalies in OT network traffic (protocol deviation, unusual timing)
      - Collect PLC audit logs (program download events, CPU mode changes)
      - Compare current PLC program hash to baseline (detect logic modifications)
      - Capture network traffic for forensic analysis (full packet capture, 7-day retention)
      - Correlate OT events with IT security events (EDR, SIEM)
      - Classify incident severity: Information Event | Operational Disruption | Safety Event
      - IXF: Run mitre-scan discovery on affected segments to map attacker techniques

  Phase 3: Containment
    Actions:
      - Isolate affected OT segments (physically disconnect compromised controllers if safe)
      - Switch to manual operations where possible (prevent further automated damage)
      - Preserve forensic evidence BEFORE remediation (memory dumps, disk images)
      - Block attacker C2 channels (DNS sinkholes, firewall blocks on identified IPs)
      - Notify operations manager: do NOT shut down process without safety review
      - Activate out-of-band monitoring (bypass compromised SCADA for visibility)
      - Physical inspection of field devices if CATASTROPHIC impact suspected

  Phase 4: Eradication and Recovery
    Actions:
      - Restore PLC programs from verified offline backup
      - Reset all credentials (PLC, HMI, historian, VPN, OT admin accounts)
      - Rebuild compromised HMI/SCADA workstations from known-good images
      - Apply all available patches and firmware updates (vendor-approved)
      - Verify physical process parameters before restoring automated control
      - Conduct independent safety review before startup (SIS functional test)
      - Staged restoration: field devices → controllers → SCADA → integration
      - Document root cause and attack timeline

  Phase 5: Post-Incident Activity
    Actions:
      - Complete incident report (CISA ICS-CERT notification within 1 hour of discovery)
      - Lessons learned meeting within 2 weeks
      - Update OT asset inventory based on findings
      - Implement detection improvements (new SIEM rules, IDS signatures)
      - Conduct vendor notification if supply chain suspected
      - Executive brief with board/C-suite if operational impact significant
      - Update IR playbook with lessons learned
      - IXF: Document MITRE techniques used; update mitre-report layer for SOC

  ══════════════════════════════════════════════════════════════════════
```

---

## OPC UA Security Audit — Full Output

```
ixf > assess protocols/opcua_security_audit
[*] Loading assessment/protocols/opcua_security_audit...

  ══════════════════════════════════════════════════════════════════════
  OPC UA Security Audit (IEC 62541 / OPC Foundation)
  ══════════════════════════════════════════════════════════════════════

  [OPC UA Security Architecture Checks]
  ──────────────────────────────────────────────────────────────────────
  Check                                        Status    Notes
  SecurityMode=None prohibited                  REVIEW   Check all endpoints
  SecurityMode=Sign enforced (minimum)          REVIEW   Requires valid certificates
  SecurityMode=SignAndEncrypt preferred          REVIEW   For sensitive process data
  Certificate validation (trust list)           REVIEW   No self-signed in production
  Anonymous user policy disabled                REVIEW   Require username+password at min
  Certificate-based authentication preferred    REVIEW   Better than username+password
  UserToken: X509 certificate (not just username) REVIEW Implement PKI for OPC UA clients
  Session timeout configured                    REVIEW   Idle sessions expire (< 1 hour)
  Audit event logging (SecurityAuditEvent)      REVIEW   AuditEventType logged to SIEM
  OPC UA reverse connect (server-initiates)     REVIEW   Avoid if possible (C2 risk)
  OPC UA Pub/Sub authentication                 REVIEW   UADP with signing enabled
  Firewall restricts port 4840                  REVIEW   Only approved OPC UA clients
  ──────────────────────────────────────────────────────────────────────
  Reference: OPC UA Security Part 2 (IEC 62541-2)
  Test commands:
    nmap -sV -p 4840 --script opcua-info <target>
    python -m opcua.tools.cmd discover opc.tcp://<target>:4840
  ══════════════════════════════════════════════════════════════════════
```

---

## DNP3 Security Audit — Full Output

```
ixf > assess protocols/dnp3_security_audit
[*] Loading assessment/protocols/dnp3_security_audit...

  ══════════════════════════════════════════════════════════════════════
  DNP3 Security Authentication v5 (SAv5) Audit
  Reference: IEEE 1815 Annex D (DNP3 Security Authentication)
  ══════════════════════════════════════════════════════════════════════

  [DNP3 Protocol Security Checks]
  ──────────────────────────────────────────────────────────────────────
  Check                                        Status    Notes
  DNP3 without SAv5 in use                     REVIEW   DNP3 has NO auth by default
  SAv5 enabled on master and outstation        REVIEW   Both endpoints must support SAv5
  Pre-shared key management (Update Key)       REVIEW   Keys rotated per NIST 800-133
  HMAC algorithm: SHA-256 (not SHA-1)          REVIEW   SHA-1 deprecated in SAv5
  Challenge-response replay protection         REVIEW   Timestamps + sequence numbers
  Critical ASDU authentication enforced        REVIEW   All DIRECT OPERATE commands auth'd
  Aggressive mode configured (performance)     REVIEW   For trusted links only
  Port 20000 access restricted                 REVIEW   Firewall permits only masters
  DNP3 secure authentication in SCADA          REVIEW   HMI/master supports SAv5
  Routable DNP3 (TCP) preferred over serial    REVIEW   Serial harder to intercept
  ──────────────────────────────────────────────────────────────────────
  Key Facts:
  - DNP3 without SAv5 has NO authentication — any device on the network can send commands
  - CosmicEnergy (2023) exploited unauthenticated DNP3 for grid switching
  - SAv5 provides HMAC-based message authentication; requires key pre-provisioning
  Reference: IEEE 1815, NERC CIP-005, NERC CIP-007
  ══════════════════════════════════════════════════════════════════════
```

---

## IEC 61850 Security Audit — Full Output

```
ixf > assess protocols/iec61850_security_audit
[*] Loading assessment/protocols/iec61850_security_audit...

  ══════════════════════════════════════════════════════════════════════
  IEC 61850 Security Audit (IEC 62351 Extensions)
  ══════════════════════════════════════════════════════════════════════

  [GOOSE Security (IEC 62351-6)]
  ──────────────────────────────────────────────────────────────────────
  Check                                        Status    Notes
  GOOSE authentication (HMAC-SHA256)           REVIEW   IEC 62351-6 GOOSE auth
  GOOSE multicast VLAN isolation               REVIEW   Switch-level filtering
  GOOSE StNum replay protection                REVIEW   Monitor StNum sequence
  GOOSE publisher authentication               REVIEW   Source IED authenticated
  Rogue GOOSE detection                        REVIEW   Network tap + IDS rule

  [MMS Security (IEC 62351-3/4)]
  ──────────────────────────────────────────────────────────────────────
  Check                                        Status    Notes
  MMS over TLS (IEC 62351-3)                   REVIEW   Port 102 with TLS negotiation
  Client certificate authentication            REVIEW   X.509 certs for MMS clients
  RBAC for MMS (IEC 62351-8)                   REVIEW   Role-Based Access Control
  MMS read restriction                         REVIEW   Non-operator restricted from reads
  MMS write restriction                        REVIEW   Only authorized engineering clients

  [Station Bus]
  ──────────────────────────────────────────────────────────────────────
  SCL file (SCD/CID) access control           REVIEW   IED config files protected
  IED management access                        REVIEW   SSH with cert auth; no Telnet
  Sampled Values (SVs) authentication          REVIEW   IEC 62351-6 SV auth
  Station bus VLAN isolation                   REVIEW   Separate VLAN from process bus
  ──────────────────────────────────────────────────────────────────────
  Reference: IEC 61850 / IEC 62351 | NERC CIP for substations
  ══════════════════════════════════════════════════════════════════════
```

---

## ICS Firewall Audit — Full Output

```
ixf > assess network/ics_firewall_audit
[*] Running ICS Firewall Audit...

  ══════════════════════════════════════════════════════════════════════
  ICS Network Firewall Audit
  Reference: NIST SP 800-82 Rev. 3, IEC 62443
  ══════════════════════════════════════════════════════════════════════

  [Firewall Rules — Inbound to OT Network]
  ──────────────────────────────────────────────────────────────────────
  Rule Check                                   Verdict   Notes
  Block all from Internet to OT               REVIEW    No OT ports directly internet-facing
  Block Modbus (502) from IT                   REVIEW    IT should not access OT Modbus
  Block S7comm (102) from IT                   REVIEW    Only engineering workstations
  Block EtherNet/IP (44818) from IT            REVIEW    Only approved SCADA clients
  Block DNP3 (20000) from untrusted masters    REVIEW    Master whitelist enforced
  Block OPC UA (4840) from internet            REVIEW    Never internet-exposed
  Block telnet (23) completely                 REVIEW    No Telnet in OT zones
  Block SNMP public (161) from IT/internet     REVIEW    SNMP community = private/SNMPv3
  Allow historian read from Level 3→Level 2    REVIEW    One-way data flow preferred
  Allow engineering WS (specific IP) to PLCs  REVIEW    Source IP whitelist only
  Block RDP (3389) to OT from all             REVIEW    Use OT jump server instead
  Log ALL denied traffic                       REVIEW    Firewall deny = alert to SIEM

  [North-South Rules (OT to Internet)]
  ──────────────────────────────────────────────────────────────────────
  Rule Check                                   Verdict   Notes
  Block outbound from PLCs/RTUs                REVIEW    Field devices should not egress
  Block outbound from SCADA to internet        REVIEW    SCADA has no legitimate internet need
  Allow SIEM log forwarding (syslog/514)       REVIEW    Outbound syslog to central SIEM
  Allow NTP (123) to approved NTP servers      REVIEW    OT NTP server preferred
  Block SMB (445) outbound from OT             REVIEW    NotPetya spread prevention
  Block DNS from OT to internet                REVIEW    Use internal DNS resolver only

  [Anomalous Protocol Checks]
  ──────────────────────────────────────────────────────────────────────
  ICMP restricted (no ICMP flood)              REVIEW    Echo request/reply limited
  GRE tunnels blocked                          REVIEW    C2 tunnel prevention
  HTTP/HTTPS from PLCs/RTUs blocked            REVIEW    No cloud connectivity from field
  ══════════════════════════════════════════════════════════════════════
```

---

## Industrial Network Assessment — Full Output

```
ixf > assess network/industrial_network_assessment
[*] Running Industrial Network Assessment...

  ══════════════════════════════════════════════════════════════════════
  Industrial Network Security Assessment
  ══════════════════════════════════════════════════════════════════════

  [Network Architecture Review]
  ──────────────────────────────────────────────────────────────────────
  Check                                        Status    Score
  Purdue model implemented                     REVIEW    Architecture documented?
  IT/OT network separation                     REVIEW    Physical or VLAN separation?
  DMZ between IT and OT                        REVIEW    Historian/jump server in DMZ?
  OT VLAN per process area                     REVIEW    Production/safety/management VLANs?
  Unmanaged switches in OT                     REVIEW    All switches managed + VLAN capable?
  Wireless networks in OT zones                REVIEW    Industrial wireless with WPA3?
  OT network monitoring/NDR                    REVIEW    Claroty/Nozomi/Dragos deployed?
  OT asset inventory                           REVIEW    Automated discovery in use?

  [Protocol Security]
  ──────────────────────────────────────────────────────────────────────
  Check                                        Status
  Clear-text OT protocols (Modbus, DNP3)       REVIEW   Accept inherent risk with compensating controls
  Encrypted OT protocols (OPC UA TLS)          REVIEW   Prefer encrypted where supported
  Legacy protocols (Telnet, FTP on OT devices) REVIEW   Replace or isolate
  Protocol-aware firewall rules                REVIEW   DPI for OT protocols (not just ports)

  [Remote Access]
  ──────────────────────────────────────────────────────────────────────
  Check                                        Status
  VPN for all remote OT access                 REVIEW   No direct RDP/SSH from internet
  MFA enforced for OT VPN                      REVIEW   Hardware token or authenticator app
  Jump server / bastion for OT access          REVIEW   All sessions via recorded jump server
  Vendor remote access policy                  REVIEW   Time-limited, monitored, MFA required
  Session recording (privileged access)        REVIEW   CyberArk/BeyondTrust PAM logging

  [Resilience]
  ──────────────────────────────────────────────────────────────────────
  Check                                        Status
  Redundant network paths for critical PLCs    REVIEW   Ring topology or dual NIC
  UPS on OT network equipment                  REVIEW   Switches, routers, firewalls
  Network device configuration backup          REVIEW   Weekly config backup to offline store
  OT network redundancy test                   REVIEW   Annual failover test performed?
  ══════════════════════════════════════════════════════════════════════
```

---

## All 28 MITRE Technique Assessment Modules

The following assessment modules implement individual MITRE ATT&CK for ICS techniques as simulation/detection assessment:

| Module | TID | Technique Name | Tactic |
|--------|-----|----------------|--------|
| `assessment/mitre_ics/t0801_monitor_process_state` | T0801 | Monitor Process State | Collection |
| `assessment/mitre_ics/t0806_brute_force_io` | T0806 | Brute Force I/O | Impair Process Control |
| `assessment/mitre_ics/t0807_remote_services` | T0807 | Command-Line Interface | Execution |
| `assessment/mitre_ics/t0820_exploitation_remote` | T0820 | Exploitation of Remote Services | Lateral Movement |
| `assessment/mitre_ics/t0823_graphical_user` | T0823 | Graphical User Interface | Execution |
| `assessment/mitre_ics/t0828_loss_of_productivity` | T0828 | Loss of Productivity and Revenue | Impact |
| `assessment/mitre_ics/t0830_aitm_modbus` | T0830 | Adversary-in-the-Middle | Collection |
| `assessment/mitre_ics/t0835_manipulate_io` | T0835 | Manipulate I/O Image | Impair Process Control |
| `assessment/mitre_ics/t0840_network_connection` | T0840 | Network Connection Enumeration | Discovery |
| `assessment/mitre_ics/t0842_network_sniff` | T0842 | Network Sniffing | Discovery |
| `assessment/mitre_ics/t0845_program_upload` | T0845 | Program Upload | Collection |
| `assessment/mitre_ics/t0847_replication_via` | T0847 | Replication via Removable Media | Persistence |
| `assessment/mitre_ics/t0848_rogue_master` | T0848 | Rogue Master | Impair Process Control |
| `assessment/mitre_ics/t0851_rootkit` | T0851 | Rootkit | Evasion |
| `assessment/mitre_ics/t0852_screen_capture` | T0852 | Screen Capture | Collection |
| `assessment/mitre_ics/t0861_point_and_tag` | T0861 | Point and Tag Identification | Discovery |
| `assessment/mitre_ics/t0863_user_exec_mali` | T0863 | User Execution Malicious Content | Execution |
| `assessment/mitre_ics/t0864_transient_cyber` | T0864 | Transient Cyber Asset | Initial Access |
| `assessment/mitre_ics/t0867_lateral_tool_t` | T0867 | Lateral Tool Transfer | Lateral Movement |
| `assessment/mitre_ics/t0869_standard_appli` | T0869 | Standard Application Layer Protocol | C2 |
| `assessment/mitre_ics/t0870_network_sniffi` | T0870 | Network Sniffing | Discovery |
| `assessment/mitre_ics/t0871_execution_via` | T0871 | Execution via Interpreter | Execution |
| `assessment/mitre_ics/t0874_hooking` | T0874 | Hooking | Evasion |
| `assessment/mitre_ics/t0877_io_module_disc` | T0877 | I/O Module Discovery | Discovery |
| `assessment/mitre_ics/t0878_alarm_suppress` | T0878 | Alarm Suppression | Inhibit Response Function |
| `assessment/mitre_ics/t0879_damage_to_prop` | T0879 | Damage to Property | Impact |
| `assessment/mitre_ics/t0881_service_stop` | T0881 | Service Stop | Impact |
| `assessment/mitre_ics/t0890_exploitation_f` | T0890 | Exploitation for Privilege Escalation | Privilege Escalation |

---

## Complete Assessment Session Transcript

A full session using 30+ commands across all assessment areas:

```
$ ixf

  ___           _           _       _  __  ______  _       ______
 |_ _|_ __   __| |_   _ ___| |_ _ __(_) \ \/ / _ \| |     |  ___|__  _ __ __ _  ___
  | || '_ \ / _` | | | / __| __| '__| |  \  /|  __/| |     | |_ / _ \| '__/ _` |/ _ \
  | || | | | (_| | |_| \__ \ |_| |  | |  /  \| |   | |___  |  _| (_) | | | (_| |  __/
 |___|_| |_|\__,_|\__,_|___/\__|_|  |_| /_/\_\_|   |_____| |_|  \___/|_|  \__, |\___|
                                                                              |___/
  IndustrialXPL-Forge v1.0.13
  Type 'help' for commands.  simulate=True by default.

ixf > setg simulate true
[*] Global: simulate => True

ixf > stats
[i] Total: 1193 | Vendors: 150 | MITRE: 96/103 (93%)

ixf > mitre-coverage
  TOTAL: 96/103 (93%)

ixf > discover 192.168.1.0/24
[*] Module loaded: Modbus TCP Device Detect
[*] target => 192.168.1.0/24
  [SIMULATE] Would scan 192.168.1.0/24:502 for Modbus...

ixf > back
ixf > mitre-scan discovery 192.168.1.0/24
[*] Sweeping Discovery (TA0102) on 192.168.1.0/24...
  [SIMULATE] 11 techniques, 28 modules...
[+] Discovery sweep complete.

ixf > ttp T0843 192.168.1.100
[*] T0843 (Program Download) — 5 modules — simulate
[+] T0843 complete.

ixf > ttp T0812 192.168.1.0/24
[*] T0812 (Default Credentials) — 34 modules — simulate
[+] T0812 complete.

ixf > ttp-check T0846 192.168.1.100
[*] T0846 check-only on 192.168.1.100...
[+] Potential: scanners/ics/modbus_detect — port 502 open
[+] Potential: scanners/ics/s7_comm_scanner — port 102 open

ixf > cve CVE-2021-22681
[*] Module loaded: CVE-2021-22681 Siemens S7-1200/1500 PLC (CRITICAL)

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > set target 192.168.1.50
[*] target => 192.168.1.50

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > show info
  cvss: 9.8 | impact: CRITICAL | MITRE: T0830, T0855

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > check
[*] Checking 192.168.1.50:102...
[+] POTENTIAL — Port 102 open, S7comm+ detected

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > run
  [SIMULATE] CVE-2021-22681 S7 TLS Key exploit chain...

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > back

ixf > assess iec62443/zone_conduit_audit
  [IEC 62443 audit output — 24 SR checks REVIEW]

ixf > assess nist_sp800_82/control_checklist
  [NIST 800-82r3 — 8 domains, 35 controls REVIEW]

ixf > assess risk/ics_risk_scorer
  COMPOSITE SCORE: 7.375 / 10.0 — HIGH

ixf > assess threat_intel/ics_kill_chain
  [8-stage kill chain analysis]

ixf > assess ir/iacs_ir_playbook
  [5-phase IR playbook]

ixf > assess protocols/opcua_security_audit
  [OPC UA security checks]

ixf > assess protocols/dnp3_security_audit
  [DNP3 SAv5 checks]

ixf > assess network/ics_firewall_audit
  [Firewall rule audit]

ixf > assess network/industrial_network_assessment
  [Full network assessment]

ixf > mitre-report layer
[+] Navigator layer saved: ixf_mitre_layer_20260601.json

ixf > report html
[+] Report saved: ixf_report_20260601_164500.html

ixf > report json
[+] Report saved: ixf_report_20260601_164502.json

ixf > exit
[*] Exiting IndustrialXPL-Forge. Stay safe.
```

---

## Compliance Reporting — Generating Reports for Each Framework

### IEC 62443 Report

```bash
ixf assess iec62443/zone_conduit_audit report markdown
# Saves: ixf_report_*.md (include IEC 62443 checklist section)
```

### NIST SP 800-82r3 Report

```bash
ixf assess nist_sp800_82/control_checklist report html
# Generates HTML with NIST control checklist
```

### MITRE ATT&CK for ICS Navigator Layer

```bash
ixf mitre-report layer
# Generates: ixf_mitre_layer_YYYYMMDD.json
# Open at: https://mitre-attack.github.io/attack-navigator/
```

### Combined Assessment Report

```bash
# Run all assessments then generate comprehensive report
ixf \
  assess iec62443/zone_conduit_audit \
  assess nist_sp800_82/control_checklist \
  assess risk/ics_risk_scorer \
  mitre-coverage \
  mitre-report layer \
  report html \
  report json
```

### NERC CIP Mapping

IXF assessment modules map to NERC CIP standards for bulk electric systems:

| IXF Module | NERC CIP Standard | Description |
|------------|------------------|-------------|
| `network/ics_firewall_audit` | CIP-005 (Electronic Security Perimeter) | Verify ESP boundary, access points |
| `network/industrial_network_assessment` | CIP-007 (System Security Management) | Port management, security patches |
| `ir/iacs_ir_playbook` | CIP-008 (Incident Reporting and Response) | IR plan, reporting timelines |
| `nist_sp800_82/control_checklist` | CIP-010 (Configuration Management) | Baseline configs, change management |
| `iec62443/zone_conduit_audit` | CIP-005, CIP-006 (Physical Security) | Zone model, physical access controls |
| `protocols/opcua_security_audit` | CIP-007 (Ports and Services) | OPC UA security configuration |
| `protocols/dnp3_security_audit` | CIP-005 (Interactive Remote Access) | DNP3 SAv5 for remote access |
| `risk/ics_risk_scorer` | CIP-011 (Information Protection) | Risk-based classification |

---

## IEC 62443 Security Levels — Complete Reference

### SL1: Protection against Unintentional Violation

**Target scenario:** Casual or unintentional violations by authorized users or by accidental system misconfiguration.

**Minimum controls required at SL1:**
- Asset inventory maintained
- Documented network topology
- Basic account management (unique accounts, no shared admin)
- Quarterly patch review process
- Basic incident response procedure
- Physical access restrictions to control room

**IXF assessment:** `assess iec62443/zone_conduit_audit` with `set sl_target 1`

### SL2: Protection against Intentional Violation Using Simple Means

**Target scenario:** Motivated attacker using simple attack methods, publicly available tools, and limited resources. This is the baseline target for most industrial sites.

**Controls added at SL2 (above SL1):**
- Network segmentation (zone and conduit model)
- Firewall at IT/OT boundary with default-deny policy
- MFA for all remote access to OT zones
- Jump server for all remote access (no direct OT VPN)
- Security event logging and review
- Defined incident response with OT-specific procedures
- Patch management process with risk-based prioritization
- OT-safe endpoint protection on EWS and HMI

**IXF assessment:** `assess iec62443/zone_conduit_audit` (default target: SL2)

### SL3: Protection against Intentional Violation Using Sophisticated Means

**Target scenario:** Motivated attacker with sophisticated skills, custom attack tools, moderate resources, and OT-specific knowledge. Includes organized crime and advanced cybercriminals.

**Controls added at SL3 (above SL2):**
- Defense-in-depth across all Purdue levels
- Advanced threat detection and OT-specific monitoring (Claroty, Dragos, Nozomi)
- Physical security controls for OT assets (tamper seals, CCTV, access logs)
- Comprehensive audit logging with tamper-evident storage
- Strict change management with dual approval for OT changes
- Regular penetration testing and red team exercises (using IXF)
- Cryptographic authentication for protocol-level access where supported
- PLC firmware integrity verification

### SL4: Protection against State-Sponsored Attack (Nation-State APT)

**Target scenario:** Highly capable nation-state attacker with advanced custom tooling, unlimited resources, insider knowledge, and long-term persistent access campaigns. Applicable to nuclear, critical power infrastructure, water treatment serving millions.

**Controls added at SL4 (above SL3):**
- Physical security hardening equivalent to government classified facilities
- All OT communication channels cryptographically authenticated
- Continuous real-time threat hunting with dedicated ICS SOC
- Annual red team exercises against nation-state TTPs
- Air-gapped or unidirectional data diodes for critical data flows
- Hardware security modules for cryptographic key management
- Multi-party authorization for safety-critical operations
- Formal security architecture review by qualified ICS security experts

### Zone and Conduit Model

The IEC 62443 zone and conduit model organizes OT assets into security zones, with conduits defining the allowed communication paths between zones.

| Zone | Purdue Level | Typical Assets | Recommended SL |
|------|-------------|----------------|----------------|
| Enterprise Zone | Level 4-5 | ERP, email, internet | Not in scope |
| Site Business Zone | Level 3 | Historian (DMZ), data aggregation | SL2 |
| Control Zone | Level 2 | SCADA servers, EWS, HMI | SL2-SL3 |
| Field Zone | Level 1 | PLCs, DCS controllers | SL2-SL3 |
| Process Zone | Level 0 | Sensors, actuators, field devices | SL1-SL2 |
| Safety Zone | Separate | SIS, ESD, F&G systems | SL3-SL4 |

**Conduit security requirements:**
- Each conduit must document: allowed protocols, data flow direction, authentication requirements
- Firewall or data diode must enforce conduit rules
- All conduit crossing events must be logged

---

## Additional MITRE Technique Assessment Modules

### T0843 — Program Download

```
ixf > use assessment/mitre_ics/t0843_program_upload
ixf > set target 192.168.1.55
ixf > run

  MITRE T0843 — Program Download Assessment
  ═══════════════════════════════════════════════════════════════════════════
  Checks:
  PD-001  S7comm program block write accessible       MANUAL  Port 102 reachable
  PD-002  EtherNet/IP CIP firmware download possible  MANUAL  Port 44818 reachable
  PD-003  Program download requires auth              MANUAL  Check TIA Portal security
  PD-004  Firmware integrity verification enabled     MANUAL  Check hash verification

  Attack scenario: Modified PLC program downloaded (e.g., STUXNET pattern)
  MITRE: T0843 (Program Download), T0889 (Modify Program)
  Remediation: Enable access protection; sign PLC programs; monitor for downloads
  ═══════════════════════════════════════════════════════════════════════════
```

### T0851 — Rootkit

```
ixf > use assessment/mitre_ics/t0851_rootkit
ixf > run

  MITRE T0851 — Rootkit Assessment
  ═══════════════════════════════════════════════════════════════════════════
  Checks:
  RK-001  PLC firmware hash verification enabled      MANUAL  Compare against baseline
  RK-002  EWS process list monitoring                 MANUAL  Detect hidden processes
  RK-003  SCADA application integrity monitoring      MANUAL  File hash comparison

  Known ICS rootkit patterns: STUXNET (S7 rootkit), TRITON (SIS firmware patch)
  MITRE: T0851 (Rootkit), T0857 (System Firmware)
  ═══════════════════════════════════════════════════════════════════════════
```

---

*Previous: [PolyExploit Runner](11-poly-exploit-runner.md) | Next: [Module Catalog](13-module-catalog.md)*
