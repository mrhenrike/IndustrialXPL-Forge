# Legal Disclaimer — IndustrialXPL-Forge

**READ BEFORE USE**

IndustrialXPL-Forge (IXF) is provided for **authorized security research, penetration testing, red/blue team exercises, and defensive preparation** in Operational Technology (OT), Industrial Control Systems (ICS), SCADA, and IIoT environments.

## No Warranty

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

## Operator Responsibility

By using IXF you accept full legal and ethical responsibility for your actions. The authors and maintainers:

- Do **not** authorize attacks against systems you do not own or have written permission to test
- Do **not** condone disruption of critical infrastructure, utilities, healthcare, or safety systems
- Are **not** liable for damages arising from misuse of this software

## Malware and Incorporated Sources

IXF includes modules and vendor trees referencing historical IoT/ICS malware (Mirai, TRISIS/TRITON, Bashlite, Akaja, and others) for **research and detection engineering only**.

- Compiled artifacts must remain in isolated lab environments
- Distribution of weaponized binaries to third parties is prohibited
- Upstream malware sources retain their original licenses and attribution

## Simulations vs Live Actions

- **SafeMode**: `set simulate true` — describes actions without sending exploit payloads
- **Live mode**: default `simulate=false` — may perform network reads and protocol probes
- **Destructive mode**: requires explicit `destructive=true` and confirmation gates

Always verify authorization and scope before disabling simulate mode.

## Export and Compliance

Some modules implement techniques that may be subject to export control or local cybercrime statutes. Ensure compliance with applicable laws in your country before use, especially across international engagements.

## Contact

Questions about authorized use: **henrique.santos@uniaogeek.com.br**

---

Copyright © André Henrique / União Geek. Licensed under MIT — see [LICENSE](LICENSE).
