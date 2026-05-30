"""IACS Cyber Security Incident Response Playbook.

Interactive OT-specific IR checklist based on the IACS Cyber Security
Incident Response Playbook. Guides through 4 IR phases for OT environments.
"""

from industrialxpl.core.exploit import (
    Exploit,
    OptBool,
    mute,
    print_info,
    print_status,
    print_success,
    print_table,
    print_warning,
)

_PHASES = {
    "1. Detection": [
        "Identify source of alert (IDS, SIEM, operator report, anomalous process behavior)",
        "Verify if event is OT-specific (unusual Modbus commands, PLC mode change, HMI anomaly)",
        "Establish incident severity: Safety impact? Process impact? Data exfiltration?",
        "Activate OT incident response team (OT security, operations, plant manager)",
        "Preserve evidence: capture network traffic, log snapshots, HMI screenshots",
    ],
    "2. Containment": [
        "Determine containment strategy: isolate without stopping critical processes",
        "Identify affected zones — isolate infected zone/conduit from rest of OT network",
        "Block external communications from compromised systems (block at firewall)",
        "Disable compromised remote access accounts (VPN, vendor accounts)",
        "Notify safety/operations teams — maintain safe process state during containment",
    ],
    "3. Eradication": [
        "Identify all affected systems: engineering workstations, HMIs, SCADA servers, PLCs",
        "Verify PLC program integrity: compare current logic to known-good backup",
        "Check firmware integrity of affected PLCs, RTUs, protection relays",
        "Remove malware/backdoors from engineering workstations and SCADA servers",
        "Re-credential: change all OT passwords (especially any default/shared accounts)",
    ],
    "4. Recovery": [
        "Restore OT systems from verified clean backups (validate before restoring)",
        "Re-validate PLC programs against last known-good backup before restarting process",
        "Restart processes in controlled, phased manner — monitor for anomalies",
        "Verify all safety system functions are operational before full production restart",
        "Confirm with operations that process is running within expected parameters",
    ],
}


class Exploit(Exploit):
    __info__ = {
        "name":         "IACS Cyber Security Incident Response Playbook (OT-Specific)",
        "description":  "Interactive OT incident response checklist based on the "
                        "IACS Cyber Security Incident Response Playbook. "
                        "Guides through Detection, Containment, Eradication, and Recovery "
                        "phases with OT-specific considerations (process safety, PLC validation, "
                        "zone isolation).",
        "authors":      ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":   (
            "IACS Cyber Security Incident Response Playbook",
            "NIST SP 800-82r3 — Incident Response for OT",
        ),
        "devices":      ("IR tool — no network target",),
        "impact":       "INFO",
        "exploit_type": "Incident Response",
        "source_poc":   "IXF native",
        "cve":          "N/A", "cvss": "N/A", "severity": "INFO",
        "mitre_techniques": [],
    }

    simulate    = OptBool(True, "Simulate mode")
    destructive = OptBool(False, "N/A")

    @mute
    def check(self) -> bool:
        return True

    def run(self) -> None:
        print_status("IACS Cyber Security Incident Response Playbook")
        print_warning("For each item: press Enter when completed, 'skip' to skip, 'q' to quit.")
        print_info("")

        completed = skipped = total = 0

        for phase, items in _PHASES.items():
            print_info("══ {} ══".format(phase))
            for item in items:
                total += 1
                print_info("  [ ] {}".format(item[:80]))
                try:
                    inp = input("      Status [Enter=done/skip/q]: ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    break
                if inp == "q":
                    break
                elif inp == "skip":
                    skipped += 1
                else:
                    completed += 1
                    print_success("      [✓] Done")
            print_info("")

        print_success("IR Playbook Progress: {}/{} completed, {} skipped.".format(
            completed, total, skipped))
        if completed < total - skipped:
            print_warning("{} items still outstanding. Complete before closing incident.".format(
                total - completed - skipped))
        else:
            print_success("All IR steps completed. Document incident report and conduct lessons learned.")
