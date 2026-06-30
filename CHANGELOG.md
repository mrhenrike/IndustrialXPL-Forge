# Changelog

All notable changes to IndustrialXPL-Forge are documented here.

Format: [Semantic Versioning](https://semver.org) -- `MAJOR.MINOR.PATCH`.

---

---

## [1.0.56] - 2026-06-28

### Added
- **F01 fuzzing nativo** — `_native/fuzzing/` (mutator C + modbus/s7 smoke)
- `core/ics/fuzz_engine.py` — 8 estratégias de mutação MIT
- `scanners/ics/fuzz_native.py` — módulo IXF com simulate default
- PyPI extra `fuzzing` (gcc externo)
- Gate **F01** com step `fuzz_compile`

## [1.0.55] - 2026-06-28

### Added
- **F-AIM2 gap modules** (awesome-ics-malware 20/20 families):
  - `fast16_simulation_sabotage.py`, `chaya_003_siemens_eng_kill.py`
  - `dynowiper_hmi_wiper.py`, `zionsiphon_water_lab.py`
- `aim2_helpers.py` — TTP helpers + `aim2_family_status()`
- Gate **F-AIM2** em `incorporation_gates.json`

### Changed
- `score_incorporation.py` — gaps zerados (stuxnet parcial)
- `test_e2e_lab.py` — modo `aim2`

## [1.0.54] - 2026-06-28

### Added
- **Incorporation gates** — `tools/verify_incorporation_gate.py`, `tools/incorporation_gates.json`
- **E2E lab runner** — `tools/test_e2e_lab.py` (c2, bashlite, aim-manifest, forensics-ioc)
- **awesome-ics-malware pipeline** — `ingest_awesome_ics_malware.py`, `deep_study_external.py`, `score_incorporation.py`
- Research corpus — `resources/research/awesome-ics-malware/manifest.json` + per-URL studies
- **IOC forensics** — `resources/ioc/awesome-ics-malware-hashes.json` (221 hashes, 20 families)
- `forensics_engine` — `ioc_inventory()`, `match_ioc_hash()`, `scan_file_hashes()`
- `docs/INCORPORATION_PLAYBOOK.md` — gate protocol + licença MIT-first

### Changed
- `env_doctor.py` — docker, pdftotext, tesseract, nmap, paho-mqtt, incorporation gate status
- `verify_family_matrix.py` — `check_phase_registrations()` hook for gates

## [1.0.52] - 2026-06-30

### Added
- **Sample lab DBs** (`resources/sql/samples/`) — `botnet.db`, `mirai.db`, `c2_state.json`
- `malware db bootstrap|init` — cada usuário gera `.tmp/ixf_c2/` a partir dos samples
- `botnet_registry_schema.sqlite.sql` — schema versionado do registry IXF
- **IXF native Bashlite/Gafgyt bot** (`_native/bashlite/`) — telnet scan, wget deploy, IXF C2 arch=8
- `bashlite_patch.py` — vendor creds embed + table patch
- `forensics_engine.py` — S7 probe + OB mapping (stdlib, no pandas/snap7)
- `docker_stack.py` — Lisa `malware docker lisa up|down|status`
- `maliot_lookup.py` — Maliot JSON corpus inventory
- PyPI extras: `forensics`, `malware-lab`, `docker-lab` (granular install)

### Changed
- **TriStationClient** — TsBase ops (upload/allocate/cancel/exploit)
- TRITON module — `upload_probe` option
- HTTP C2 syncs `bashlite.dbg` + `mirai.dbg` into payload root

### Fixed
- `bashlite_bot_debug` compile — removed broken `release_dir` reference
- **Bashlite creds parser** — vendor C-array wordlists parsed correctly (was embedding C syntax as strings)
- **Bashlite build staging** — patches go to `.tmp/staging/`; source tree no longer dirtied on compile
- Lisa overlay — radare2 built from source; nginx Node 18 + OpenSSL legacy provider
- `docker_stack` — auto `sudo docker` when socket permission denied

### Verified
- `tools/verify_family_matrix.py` — includes bashlite compile smoke
- Lisa stack E2E — `http://127.0.0.1:4242` returns 200

## [1.0.51] - 2026-06-30

### Added
- **`family_capabilities.py`** — per-family matrix (mode, compile targets, IXF route)
- **`native_actions.py`** — ELF/YARA/schema inventory without vendor execution
- **`ics_tools/native_handlers.py`** — IXF-native runtime for all 7 ics-tools (no py2neo/pandas/python2)
- CLI `malware matrix` / `ics_tools matrix`
- `tools/verify_family_matrix.py` — smoke test 12+7 families

### Fixed
- Mirai **`mirai_bot_debug`** via `MiraiCrossCompiler` (i586-gcc path)
- **`iot_pnscan`** / **`iot_randomware`** compile targets
- ICS-tools **`run`** uses native handlers first; vendor only as fallback
- Bashlite snippet false compile targets removed (ELF corpus mode)

---

## [1.0.50] - 2026-06-30

### Added
- **Linux-only** runtime gate (`core/platform.py`) — IXF aborts on Windows/macOS
- Persistent **HTTP payload daemon** (`http_payload_daemon.py`, `http_payload_manager.py`)
- Go CNC **bot registry** → sync live bots to `botnet.db` (`bot_registry.go`)
- `C2Config.release_dir` persisted in `c2_state.json`

### Fixed
- Mirai **handshake Python** aligned with Go (4-byte + optional source length)
- **`hybrid`** = Go CNC + HTTP persistent (no port conflict with Python listener)
- **`resume_on_startup`** passes full config (backend, DSN, release_dir, api_port)
- **`c2_daemon`** supervisor without recursive spawn; health-check restarts HTTP/Go
- Stale **PID files** auto-cleared (`go_cnc`, `http`, `python` daemon)
- **`deploy_via_wget`** duplicate upsert removed
- **`botnet_c2_ops`** / **`malware_full_pipeline`** parity with CLI
- MySQL schema init statement splitting
- Go CNC **`ensure_built`** rebuilds when `*.go` sources are newer than binary (stale handshake fix)

---

## [1.0.49] - 2026-06-30

### Added
- `tools/install-mirai-toolchains.sh` — download uClibc cross-compilers (Hexoral mirror)
- `malware crosscompile install` — instala toolchains via IXF
- `ensure_cross_path_in_env()` — PATH automático para mips-gcc, armv4l-gcc, etc.

### Fixed
- Go CNC build (`netshift` em `database_ixf.go`)
- `c2_patch.py` regex escape para patch `table.c`
- Host debug build via `i586-gcc` quando gcc nativo falha

---

## [1.0.48] - 2026-06-28

### Added
- **Go Mirai CNC** (`native/go/ixf-mirai-cnc/`) — admin telnet, bot handler, API de ataques
- **Multi-DB** via `IXF_C2_DSN`: `sqlite://`, `mysql://`, `postgres://` + schemas SQL
- `core/malware/go_cnc_manager.py`, `db_init.py`, `crosscompile.py`
- `malware c2 build-go` — compila CNC Go + inicializa schema
- `malware crosscompile list|all|mips|arm|...` — bots Mirai multi-arch
- Propagação **arch-aware** (`uname` → mirai.mips/arm/x86...)
- `setg C2_BACKEND auto|go|python` e `setg C2_DSN`
- Extra PyPI `[c2]` — pymysql, psycopg2-binary

### Changed
- `malware c2 start` — auto cross-compile + Go CNC full stack (fallback Python)
- IXF multilanguage: Python shell + backends Go/C conforme módulo

---

## [1.0.47] - 2026-06-28

### Added
- `core/malware/c2_server.py` — listener Mirai-compatible (handshake 0x00 0x00 0x00 + ping echo)
- `core/malware/c2_persistence.py` — SQLite `.tmp/ixf_c2/botnet.db` + estado entre sessões IXF
- `core/malware/c2_daemon.py` — daemon detached (C2 sobrevive ao fechar IXF)
- `core/malware/propagator.py` — scan telnet IoT/OT, deploy wget/beacon para LHOST/LPORT
- CLI `malware c2 start|stop|status` e `malware propagate <target>`
- Módulo `scanners/malware_research/botnet_c2_ops`
- Retomada automática no startup: bots reportando ao C2 após reabrir IXF (`setg C2_PERSIST true`)

### Changed
- `malware_full_pipeline` — ações `c2_start`, `c2_status`, `propagate`, `full`

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
