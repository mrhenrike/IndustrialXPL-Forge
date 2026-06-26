# Changelog

All notable changes to IndustrialXPL-Forge are documented here.

Format: [Semantic Versioning](https://semver.org) -- `MAJOR.MINOR.PATCH`.

---

## [1.0.40] - 2026-06-25

### Added
- Global CLI flags via `tools/xpl_cli.py`: `-h`/`--help`, `-V`/`--version`, `-i`/`--interactive`, `--doctor`/`--check`

---

## [1.0.39] - 2026-06-16

### Added - Rockwell Automation ICS Wave (ICSA-26-167-01 through 05)

Sync from EmbedXPL-Forge. Five new modules covering June 2026 CISA Rockwell Automation advisories:

- `cve/rockwell/factorytalk_analytics_pavilionx_icsa_26_167_01.py`
  ICSA-26-167-01: Redis exposure (CVE-2025-9364), privilege escalation (CVE-2024-6435 CVSS 8.8),
  and path traversal RCE (CVE-2024-7961 CVSS 7.2) in FactoryTalk Analytics PavilionX.

- `cve/rockwell/rslinx_classic_dos_icsa_26_167_02.py`
  ICSA-26-167-02: EtherNet/IP DoS against RSLinx Classic <= 4.50.00 (CVE-2020-13573 CVSS 7.5).
  Crashes the RSLinx Classic service disrupting SCADA/HMI communications.

- `cve/rockwell/logix_5370_5570_cip_dos_icsa_26_167_03.py`
  ICSA-26-167-03: CIP malformed ForwardOpen MNRF on CompactLogix 5370 / ControlLogix 5570
  (CVE-2022-3157 CVSS 8.6, CVE-2025-11743 CVSS 6.5, CVE-2020-6998).

- `cve/rockwell/compactlogix_icsa_26_167_04.py`
  ICSA-26-167-04: Unauthenticated CIP tag write, web info disclosure, FTP project
  exfiltration on CompactLogix 5370/5380/5480 (June 2026 surface).

- `cve/rockwell/flex_io_ethernetip_dos_icsa_26_167_05.py`
  ICSA-26-167-05: Improper input validation (CVE-2026-0646) and resource exhaustion
  (CVE-2026-0647) DoS on Rockwell 1794-AENTR FLEX I/O EtherNet/IP Adapter V2.012.

---

## [1.0.38] - 2026-06-15

### Changed
- Sync from EmbedXPL-Forge v3.7.1: ICS/OT/BMS/IIoT modules
- Removed 31 duplicate protocol/ICS modules
- Added check() to 6 BLE/WiFi modules
- Destructive writers: Modbus FC5/6/8/15/16/21/22/23, S7comm CPU Stop/Write, IEC-104 C_SC/DC/RC/SE
