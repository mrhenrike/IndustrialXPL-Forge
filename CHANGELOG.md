# Changelog — IndustrialXPL-Forge

## [1.3.0] — 2026-09-26

### Added — Protocol Layer
- GHSA-5jvp-3p2v-5qgf: Aedes MQTT broker QoS 2 memory exhaustion DoS (CVSS 7.5, fixed in 1.2.0)
- CVE-2024-33889: OPC Foundation UA C++ SDK NULL pointer deref DoS (CVSS 7.5)

### Merged
- feat/ixf-protocol-stack: Modbus TCP, S7comm, EtherNet/IP/CIP, PROFINET DCP native stacks
- feat/ixf-remaining-exploits: Gridwolf import layer, Schneider ComBox, QNX/VxWorks DoS, ICS brute

## [1.2.0] — 2026-09-24

### Added — 14 New CVE Modules
- CVE-2023-3595 (enhanced): Rockwell ControlLogix CIP OOB write (Sandworm TTP, CVSS 10.0)
- CVE-2023-3596: Rockwell ControlLogix companion stack overflow (CVSS 9.8)
- CVE-2024-6242: Rockwell ControlLogix auth bypass → RCE (CVSS 9.8)
- CVE-2025-0977: CODESYS SysDrv3S kernel driver RCE (CVSS 9.8)
- CVE-2023-24474: Honeywell Experion PKS pre-auth RCE (CVSS 10.0, Armis Scarecrow)
- CVE-2024-29966: AVEVA System Platform deserialization RCE (CVSS 9.8)
- CVE-2024-49775: Siemens UMC heap overflow (CVSS 9.8)
- CVE-2025-27452: Siemens SINEMA Remote Connect pre-auth RCE (CVSS 9.8)
- CVE-2025-24868: Siemens WinCC OA SQLi → RCE (CVSS 9.8)
- CVE-2024-10273: Emerson DeltaV DCS code injection (CVSS 9.8)
- CVE-2024-9570: Moxa EDR-810 pre-auth RCE (CVSS 9.8) [new vendor]
- CVE-2024-3397: HMS Networks eWon Cosy+ OS cmd injection (CVSS 9.8) [new vendor]
- CVE-2024-35558: libmodbus stack overflow (CVSS 9.8)
- CVE-2023-27321: OPC Foundation UA .NET heap overflow (CVSS 9.8)
- CVE-2024-38480: OpenDNP3 stack buffer overflow (CVSS 9.8)
- CVE-2025-3140: Prosys OPC UA Simulation Server pre-auth RCE (CVSS 9.8)
- CVE-2024-8935: Schneider Electric Modicon M340 auth bypass (CVSS 9.8)
- CVE-2025-40765: Siemens S7-1200/1500 S7comm-plus arbitrary write (CVSS 9.8)

## [1.1.1] — 2026-09-19 (previous release)