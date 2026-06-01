# SafeMode / DestructiveMode

IXF is designed to be **safe by default**. Every module starts in simulate mode and requires explicit multi-step opt-in before any live exploit payload is transmitted.

---

## The Two Modes

### SafeMode (Default)

Every module defaults to `simulate=True`. In this mode:

- No packets are sent to the target
- `run()` calls `DestructiveGate.print_simulation()` which prints what *would* happen
- The output shows the exact payload, MITRE techniques, and step-by-step attack flow
- Safe for use in SIEM/IDS detection testing without impacting production systems

```
ixf (FrostyGoop Modbus Heating Attack) > run

  [SIMULATE MODE — no packets sent]
  ─────────────────────────────────────────────────────────────
  [i] What would happen:
      FrostyGoop TTP (2024) — Sandworm/GRU (Russia)

      Phase 1 [Modbus Discovery]: Would scan for Modbus TCP port 502 on target
      Phase 2 [FC16 Write]: Would write 0x0000 to holding registers (disable heating)
      Phase 3 [Loop]: Repeat every 30s to prevent recovery
      Physical Impact: Heating system offline — 600 apartments lose heat (Ukraine 2024)

  [i] Payload (hex): 00 01 00 00 00 0B 01 10 00 00 00 02 04 00 00 00 00
  [i] MITRE ATT&CK for ICS: T0836 (Modify Parameter), T0814 (Denial of Control)
  [i] To run live: set simulate false + set destructive true
```

### DestructiveMode

Requires both:
1. `set simulate false`
2. `set destructive true`

Then `run` triggers the `DestructiveGate` confirmation flow.

---

## Impact Levels

Every module declares an impact level in `__info__["impact"]`. The level determines what confirmation is required before live execution.

| Level | Description | Confirmation Required |
|-------|-------------|----------------------|
| `INFO` | Passive observation only. No packets sent. | Automatic |
| `READ` | Read-only queries. No state change on target. | Automatic |
| `LOW` | Non-destructive write. Reversible. | Simple warning displayed |
| `MEDIUM` | Process parameter modification. May affect operation. Reversible. | Press Enter |
| `HIGH` | Device restart / process stop. Requires operator intervention. | Type confirmation string |
| `CRITICAL` | Firmware modification / safety bypass / PLC logic overwrite. MAY BE IRREVERSIBLE. | Type confirmation string |
| `CATASTROPHIC` | Physical equipment damage / safety system disabling. IRREVERSIBLE. | Type confirmation string + 10-second wait |

---

## DestructiveGate Confirmation Flow

### Step 1: Set Flags

```
ixf (FrostyGoop Modbus Heating Attack) > set simulate false
[*] simulate => False

ixf (FrostyGoop Modbus Heating Attack) > set destructive true
[*] destructive => True
```

### Step 2: Run

```
ixf (FrostyGoop Modbus Heating Attack) > run
```

### Step 3: See the Banner

For `CATASTROPHIC` impact, a 10-second wait occurs before the prompt:

```
  ██████████████████████████████████████████████████████████████████████
  ██  DESTRUCTIVE MODE — CATASTROPHIC IMPACT                          ██
  ██  THIS ACTION IS IRREVERSIBLE                                      ██
  ██████████████████████████████████████████████████████████████████████

  Module:  FrostyGoop Modbus Heating Attack (Go) — Extended
  Target:  192.168.1.100:502
  Impact:  CATASTROPHIC — Physical equipment damage / safety system disabling. IRREVERSIBLE.
  Action:  Sends Modbus FC16 write commands to disable heating controllers.
           Historical impact: 600 apartments in Lviv, Ukraine lost heat for 2 days.

  [!] WAITING 10 SECONDS BEFORE PROMPT — press Ctrl+C to abort

  Type the following string EXACTLY to confirm (case-sensitive):
  I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION

  Confirmation>
```

### Step 4: Confirm or Abort

**To proceed:**
```
  Confirmation> I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION
[*] Confirmed. Audit entry written. Executing...
[*] [FrostyGoop] Connecting to 192.168.1.100:502...
```

**Any other input aborts:**
```
  Confirmation> yes
[-] ABORTED. Audit entry written. Type the exact confirmation string to proceed.
```

**Ctrl+C also aborts:**
```
  Confirmation> ^C
[-] ABORTED by user.
```

---

## The Confirmation String

The exact string required for `HIGH`, `CRITICAL`, and `CATASTROPHIC` impacts:

```
I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION
```

This string must be typed **exactly** — any variation (extra spaces, wrong case, partial text) will abort the operation.

---

## Audit Logging

Every destructive operation (whether confirmed or aborted) is appended to:

```
.log/destructive_ops_YYYY-MM-DD.log
```

The log file is created in the directory where IXF is run. Example entry:

```
2026-06-01T20:15:43Z | CONFIRMED | module=cve.malware.frostygoop_modbus_heating | target=192.168.1.100:502 | impact=CATASTROPHIC
2026-06-01T20:16:01Z | ABORTED   | module=cve.malware.crashoverride_industroyer | target=192.168.1.200:2404 | impact=CATASTROPHIC
```

The log path can be changed at the `safety.py` module level (for custom deployments).

---

## `print_simulation()` Output Explained

When `simulate=True`, `run()` calls `DestructiveGate.print_simulation()`:

```
  [SIMULATE MODE — no packets sent]
  ─────────────────────────────────────────────────────────────
  [i] What would happen:              ← description parameter
      <step-by-step attack description>

  [i] Payload (human):  <human readable payload>    ← payload_human (optional)
  [i] Payload (hex):    00 01 00 00 ... [truncated]  ← payload_hex (optional, 120 char limit)
  [i] MITRE ATT&CK for ICS: T0836, T0814            ← mitre_techniques (optional)
  [i] To run live: set simulate false
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `description` | string | yes | Multi-line description of what would happen |
| `payload_hex` | string | no | Hex dump of the exploit payload (truncated to 120 chars) |
| `payload_human` | string | no | Human-readable payload description |
| `mitre_techniques` | list[str] | no | MITRE technique IDs to display |

---

## Full Workflow Diagram

```
ixf > use <module>
ixf > set target <ip>
ixf > run
     │
     ├─► simulate=True  ─────────► print_simulation() ──► [no packets]
     │
     └─► simulate=False
              │
              ├─► destructive=False ──► check() only ──► [no exploit]
              │
              └─► destructive=True
                        │
                        ├─► impact INFO/READ/LOW/MEDIUM ──► run() directly
                        │
                        └─► impact HIGH/CRITICAL/CATASTROPHIC
                                  │
                                  ├─► CATASTROPHIC: sleep(10s)
                                  ├─► Display destructive banner
                                  ├─► Prompt for confirmation string
                                  ├─► Write audit entry (CONFIRMED or ABORTED)
                                  └─► Confirmed: run() ──► [live exploit]
```

---

## Best Practices

1. **Never disable simulate mode in production environments**
2. **Always run `check()` before `run()` in live mode**
3. **Use `setg simulate true` at session start to enforce safe mode globally**
4. **Review audit logs after every authorized test session**
5. **For training/SIEM detection: use simulate mode to trigger detection without impact**

---

*Previous: [Module System](04-module-system.md) | Next: [MITRE ATT&CK for ICS](06-mitre-attack-ics.md)*
