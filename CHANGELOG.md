# Changelog

All notable changes to IndustrialXPL-Forge are documented here.

Format: [Semantic Versioning](https://semver.org) -- `MAJOR.MINOR.PATCH`.

---

## [1.0.46] - 2026-06-30

### Added
- `core/ics_tools/` — catalog, orchestrator, runner for 7 incorporated ics-tools families
- CLI `ics_tools list|analyze|plan|run|compile`
- `scanners/ics_tools_research/ics_tools_ops` — unified ICS-tools module
- `scanners/malware_research/malware_full_pipeline` — C2 build, exec, deploy, shell, firmware
- `core/malware/build_profile.py`, `c2_patch.py`, `obfuscator.py`, `lab_ops.py`
- CLI `malware build|exec|deploy|shell|firmware` with `setg LHOST` / `LPORT` / `OBFUSCATE` / `STEALTH`

### Changed
- `MalwareCompiler.compile()` accepts `BuildProfile` for Mirai C2 lab patching

---

## [1.0.45] - 2026-06-30

### Added
- **Public research vendor corpus** — 12 malware families + 7 ics-tools trees versioned in
  `industrialxpl/resources/vendor/submodules__malwares__*` and `submodules__ics-tools__*`
- [TERMS_OF_USE.md](TERMS_OF_USE.md) — user responsibility for public clone/use
- `industrialxpl/resources/vendor/README.md` — corpus inventory and PyPI vs GitHub note

### Changed
- DISCLAIMER, SECURITY, CODE_OF_CONDUCT, README — reinforced authorized-use and sole user liability
- `.gitignore` — incorporated malware/ics-tools vendor no longer excluded from Git
- PyPI package remains framework-only (~100 MB limit); full corpus via `git clone`

---

## [1.0.44] - 2026-06-29

### Added
- Full EmbedXPL utility port (83 files):
  - `core/ics/` — native S7, S7+, CIP, Modbus, WDB2 clients
  - `core/shells/` — covert shell handlers
  - `core/session.py`, `core/pool.py` — session and connection pool
  - `core/exploit/{shell,shell_stager,payloads,encoders,char_by_char}.py`
  - `modules/payloads/` (42) and `modules/encoders/` (17) — multi-arch payloads
- Malware family TTP modules (12 families) under `cve/malware/families/`
- `core/malware/family_ttp.py` — shared base for native malware research modules
- Root `SECURITY.md` and `DISCLAIMER.md`

### Changed
- Module catalog: 1160+ indexed modules
- Documentation aligned: `simulate=false` default; use `set simulate true` or `setg simulate true` for SafeMode
- README/wiki updated with malware CLI, payloads, encoders, and network globals (`setg PORT/TRANSPORT/UNIT_ID`)

---

## [1.0.43] - 2026-06-29

### Added
- Native malware framework expansion:
  - `core/malware/compiler.py` — cross-compile IXF native + vendor (Mirai, Akaja, Bashlite)
  - `core/malware/tristation.py` — TriStation/TCM client ported from TRISIS decompiled sources
  - `core/malware/botnet_network.py` — telnet/ICS port scan and credential probe helpers
- New modules:
  - `assessment/malware/malware_native_compiler`
  - `scanners/malware_research/mirai_telnet_ics_scanner`
  - `scanners/malware_research/botnet_network_mapper`
  - `cve/malware/triton_tristation_native`
- CLI command `malware` — list, analyze, plan, compile families

### Changed
- Malware orchestrator routes families to new native IXF modules
- Gap analysis vs EmbedXPL: payloads/shells/GPU remain future work; references/ is empty

---

## [1.0.42] - 2026-06-29

### Added
- Global `setg PORT`, `setg TRANSPORT`, `setg UNIT_ID` — applied automatically when loading modules
- `OptTransport` and `OptPortExpr` option types in core
- `industrialxpl/core/network/` — shared TCP/UDP probe helpers and default OT ports
- New scanner `scanners/ics/ot_multi_probe` — multi-protocol discovery (modbus, dnp3, bacnet, s7, enip, opcua)

### Changed
- `dnp3_scanner`: respects `transport` option (tcp | udp | both)
- `ModbusBaseExploit`: explicit `transport` option (tcp-only for Modbus/TCP)
- SIMULATE default remains `false` — execution follows module options without global override

---

## [1.0.41] - 2026-06-29

### Fixed
- `modbus_detect`: respect `FC` and `REGISTERS`/`COILS` options instead of always sending FC04
- Modbus scanners: honor `SIMULATE` mode (TCP check only, no Modbus PDU on the wire)

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
