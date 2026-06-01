# Assessment & Compliance

IXF includes 18+ assessment modules covering IEC 62443, NIST SP 800-82r3, MITRE ATT&CK for ICS, risk scoring, and incident response playbooks.

---

## Running Assessment Modules

Use the `assess` command to load and immediately execute an assessment:

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

```
ixf > assess iec62443/zone_conduit_audit
[*] Loading assessment/iec62443/zone_conduit_audit...
[*] Running IEC 62443 Zone and Conduit Audit...

  IEC 62443 Zone and Conduit Audit
  ──────────────────────────────────────────────────────────────────
  Check                               Result    Notes
  IT/OT zone separation               MANUAL    Verify Level 3→2 firewall rules
  Protocol whitelisting (Purdue)      MANUAL    Check only OT protocols in ICS zone
  Remote access authentication        MANUAL    VPN MFA required for OT zones
  Jump server / DMZ presence          MANUAL    Historian in DMZ, not directly in OT
  Zone/conduit documentation          MANUAL    Zones defined in security plan
  Redundant control path              MANUAL    Primary/secondary network separation
  ──────────────────────────────────────────────────────────────────
  [i] IEC 62443-3-3: Security Level target SL2 baseline requirements
  [i] Reference: https://www.isa.org/standards-publications/isa-standards/isa-62443
```

**IEC 62443 Security Levels:**

| Level | Definition |
|-------|-----------|
| SL 1 | Protection against unintentional or coincidental violation |
| SL 2 | Protection against intentional violation using simple means |
| SL 3 | Protection against intentional violation using sophisticated means |
| SL 4 | Protection against intentional violation using state-sponsored means |

---

## NIST SP 800-82r3 — ICS Security Checklist

```
ixf > assess nist_sp800_82/control_checklist
[*] Running NIST SP 800-82r3 Industrial Control System Security Checklist...

  NIST SP 800-82r3 Control Checklist
  ──────────────────────────────────────────────────────────────────
  Control Domain           Check                              Notes
  Access Control           AC-2: Account management           Verify OT account lifecycle
  Access Control           AC-17: Remote access               MFA for all remote access
  Audit and Accountability AU-6: Audit review                 OT logs collected and reviewed
  Configuration Mgmt       CM-7: Least functionality          Disable unused protocols/ports
  Incident Response        IR-4: Incident handling            OT-specific IR procedures
  Risk Assessment          RA-3: Risk assessment              Annual ICS risk assessment
  System Protection        SC-7: Boundary protection          OT network segmentation
  System Integrity         SI-2: Flaw remediation             Patch management for ICS
  ──────────────────────────────────────────────────────────────────
  [i] Reference: https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final
```

---

## Risk Scoring

```
ixf > assess risk/ics_risk_scorer
[*] ICS Risk Scoring...
[*] Set 'target' to analyze a specific host, or run without target for methodology.

  ICS Risk Score Methodology
  ──────────────────────────────────────────────────────────────────
  Factor                   Weight   Assessment
  Network exposure          30%     Internet-facing ICS: CRITICAL
  Authentication strength   25%     No auth on Modbus: HIGH
  Safety system separation  25%     SIS on same network: HIGH
  Patch level               15%     Firmware > 3 years: HIGH
  Logging/monitoring         5%     No OT-specific SOC: MEDIUM
  ──────────────────────────────────────────────────────────────────
  [i] Use CISA ICS-CERT scoring: https://www.cisa.gov/ics-cert
```

---

## ICS Kill Chain / Threat Intelligence

```
ixf > assess threat_intel/ics_kill_chain
[*] ICS Kill Chain Analysis...

  ICS Cyber Kill Chain — Incident Response Framework
  ──────────────────────────────────────────────────────────────────
  Stage 1: Target Identification    OSINT, Shodan, ICS honeypots
  Stage 2: Initial Access           Spearphishing, VPN abuse, IT→OT pivot
  Stage 3: Establish Persistence    PLC backdoor, historian compromise
  Stage 4: Discovery                Modbus scan, S7 enumeration, tag read
  Stage 5: Lateral Movement         Engineering workstation, jump server
  Stage 6: Privilege Escalation     PLC admin access, engineering software
  Stage 7: Condition                Setpoint modification, safety bypass
  Stage 8: Execute ICS Attack       Modbus write, IEC 104 EXEC, firmware flash
  ──────────────────────────────────────────────────────────────────
  [i] Reference: Dragos ICS Incident Response framework
  [i] Reference: CISA Advisory AA22-103A (INCONTROLLER/PIPEDREAM)
```

---

## IR Playbook

```
ixf > assess ir/iacs_ir_playbook
[*] ICS/OT Incident Response Playbook...

  ICS/OT Incident Response Playbook
  ──────────────────────────────────────────────────────────────────
  Phase        Action                                    Priority
  Detection    Monitor OT network anomalies (Modbus FC)  Immediate
  Containment  Isolate compromised network segment        <1 hour
  Evidence     Preserve PLC programs + historian logs     <2 hours
  Recovery     Restore from known-good program backup     <4 hours
  Post-IR      Update firewall rules, review credentials  <1 week
  ──────────────────────────────────────────────────────────────────
  Vertical-specific playbooks:
    Energy: protect protection relays, EMS/SCADA
    Water: protect dosing controls, SCADA HMIs
    Oil & Gas: protect RTUs, compressor controllers
    Manufacturing: protect PLCs, MES, historian
```

---

## Protocol Security Audits

### OPC UA Security Audit

```
ixf > use assessment/protocols/opcua_security_audit
ixf > set target 192.168.1.100
ixf > run

  OPC UA Server Security Assessment — 192.168.1.100:4840
  ──────────────────────────────────────────────────────────────────
  Check                              Result    Notes
  SecurityMode=None                  MANUAL    Check if server accepts anonymous
  Certificate validation             MANUAL    Verify client cert check enabled
  Anonymous browse                   MANUAL    Test anonymous namespace browse
  Write without auth                 MANUAL    Test unauthenticated tag write
  Discovery endpoint exposure        MANUAL    Verify endpoint info not leaked
```

### DNP3 Secure Authentication Audit

```
ixf > assess protocols/dnp3_security_audit
  DNP3 Secure Authentication v5 Assessment
  ──────────────────────────────────────────────────────────────────
  SAv5 challenge-response            MANUAL    Verify per IEC 62351-5
  Replay protection                  MANUAL    Unique session keys enforced
  Sequence number check              MANUAL    Application seq numbers validated
  Unauthorized control               MANUAL    Test control without SAv5
```

### IEC 61850 Security Audit

```
ixf > assess protocols/iec61850_security_audit
  IEC 61850 Substation Security Assessment
  ──────────────────────────────────────────────────────────────────
  GOOSE authentication               MANUAL    IEC 62351-6 HMAC enabled
  MMS access control                 MANUAL    MMS auth required for controls
  SAMPLED VALUES integrity           MANUAL    SV integrity protection
  Substation network segmentation    MANUAL    Station/bay/process bus segmented
```

---

## MITRE ATT&CK Assessment Modules

Individual technique assessment modules are under `assessment/mitre_ics/`:

```
ixf > use assessment/mitre_ics/t0843_program_upload
ixf > set target 192.168.1.100
ixf > run

ixf > use assessment/mitre_ics/t0836_modify_parameter
ixf > use assessment/mitre_ics/t0880_modify_alarm_settings
ixf > use assessment/mitre_ics/t0878_alarm_suppression
ixf > use assessment/mitre_ics/t0851_rootkit
ixf > use assessment/mitre_ics/t0879_damage_to_property
```

All 28 technique-specific assessment modules run in simulate mode by default and provide structured analysis outputs with step-by-step attack scenarios and detection recommendations.

---

## Network Security Assessments

### ICS Firewall Audit

```
ixf > assess network/ics_firewall_audit
  ICS/OT Firewall and Network Segmentation Audit
  ──────────────────────────────────────────────────────────────────
  Check                   Result    Notes
  IT/OT segmentation      MANUAL    Level 3→2 firewall rules present
  Protocol whitelisting   MANUAL    Only industrial protocols in OT
  Remote access VPN       MANUAL    VPN MFA for all OT remote access
  Internet exposure       MANUAL    No direct internet to OT systems
  Historian DMZ           MANUAL    Historian in DMZ, not in OT network
```

### Industrial Network Assessment

```
ixf > assess network/industrial_network_assessment
  Industrial Network Infrastructure Assessment
  ──────────────────────────────────────────────────────────────────
  Check                    Result    Notes
  SNMP community strings   MANUAL    Check for default public/private
  Unmanaged switches       MANUAL    Identify unmanaged switches in OT
  Flat network topology    MANUAL    Detect flat network allowing pivot
  Telnet/HTTP management   MANUAL    Insecure mgmt protocols present
  Routing protocol auth    MANUAL    OSPF/BGP authentication verified
```

---

## Running a Full Assessment Session

```bash
# Full compliance assessment workflow
ixf assess iec62443/zone_conduit_audit
ixf assess nist_sp800_82/control_checklist
ixf assess risk/ics_risk_scorer
ixf assess threat_intel/ics_kill_chain
ixf assess ir/iacs_ir_playbook
ixf assess network/ics_firewall_audit
ixf assess protocols/opcua_security_audit
ixf mitre-coverage
ixf report json
```

---

*Previous: [PolyExploit Runner](11-poly-exploit-runner.md) | Back to [Index](_index.md)*
