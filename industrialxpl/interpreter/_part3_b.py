    def _help_option_timing(self) -> None:
        from industrialxpl.core.modbus.timing import ModbusTiming
        profile_table = ModbusTiming.describe_all()
        msg = (
            "\nOption: TIMING"
            "\n--------------"
            "\nType     : T-level string (T0-T5) or slug name"
            "\nDefault  : T3 (Normal)"
            "\nScope    : global (setg) + per-module (set)"
            "\nApplies  : all Modbus/OT scanner and exploit modules"
            "\n\n" + profile_table +
            "\n\nBoth T<n> number AND slug name are accepted everywhere:"
            "\n  set TIMING T0   =   set TIMING paranoid"
            "\n  set TIMING T2   =   set TIMING polite"
            "\n  set TIMING T3   =   set TIMING normal      [default]"
            "\n  set TIMING T4   =   set TIMING aggressive"
            "\n  set TIMING T5   =   set TIMING insane"
            "\n  setg timing T2       -- applies to ALL modules"
            "\n  set TIMING T4        -- applies only to current module"
            "\n  setg timing 0        -- numeric form (no T prefix) also accepted"
            "\n\nRelated:"
            "\n  set TIMEOUT 5        -- override socket timeout (keeps delays/retries)"
            "\n  setg timeout 0       -- 0 = use timing profile default\n"
        )
        print_info(msg)

    def _help_option_registers(self) -> None:
        print_info("""
Option: registers
-----------------
Type     : address expression string
Default  : (module-specific, e.g. 0-9)
Scope    : per-module (set)
Applies  : all Modbus scanner/read modules

Accepted notations:
  Decimal offset (0-based):
    10               -- single address, offset 10
    14-20            -- range: offsets 14,15,...,20
    10,14-20,100     -- mixed list

  Schneider/Modicon 5-digit (implied FC):
    00001            -- coil 1  (implies FC1)
    00001-00100      -- coils 1-100 (implies FC1)
    10001            -- discrete input 1 (implies FC2)
    30001-30010      -- input registers 1-10 (implies FC4)
    40001            -- holding register 1 (implies FC3)
    40001-40010      -- holding registers 1-10
    40001,40005,41000 -- specific holding registers

  Modicon 6-digit:
    000001-065536    -- coils (FC1)
    400001-465536    -- holding registers (FC3)

Notes:
  - Schneider/Modicon notation automatically sets the FC unless overridden by 'fc'
  - Empty = use module default range
  - Max range per single read: 125 words (FC3/4) or 2000 bits (FC1/2)

Examples:
  set registers 40001-40010         -- holding registers 1-10 (FC3)
  set registers 0-9                 -- first 10 addresses with module default FC
  set registers 10,14-20,100        -- sparse list, 3 groups
  set registers 00001-00100         -- 100 coils starting at 1 (FC1)
""")

    def _help_option_coils(self) -> None:
        print_info("""
Option: COILS
-------------
Type     : address expression string
Default  : (empty -- not used)
Scope    : per-module (set)
Priority : COILS takes precedence over REGISTERS when both are set

Use COILS for coil (FC1) and discrete input (FC2) reads.
Use REGISTERS for holding (FC3) and input register (FC4) reads.

Accepted notations:
  Decimal offset (0-based):
    0                -- single coil at offset 0
    0-7              -- 8 coils starting at 0
    0-100            -- 101 coils
    10,20-30,100     -- sparse list

  Modicon 5-digit (auto-implies FC):
    00001            -- coil 1 (implies FC1)
    00001-00100      -- coils 1-100 (implies FC1)
    10001            -- discrete input 1 (implies FC2)
    10001-10100      -- discrete inputs 1-100 (implies FC2)

Notes:
  - When COILS is set, FC is automatically 1 unless overridden by the FC option
  - Decimal offsets with COILS are treated as coil addresses (FC1)
  - Max 2000 coils per single Modbus request

Examples:
  set COILS 0-7                     -- read 8 coils starting at 0 (FC1)
  set COILS 0-100                   -- read 101 coils
  set COILS 10,20-30,50             -- sparse coil list
  set COILS 00001-00100             -- Modicon notation, 100 coils
  set COILS 10001-10020             -- 20 discrete inputs (FC2)
  set COILS 0-7                     -- then set FC 2 to read as discrete inputs
""")

    def _help_option_port(self) -> None:
        print_info("""
Option: port
------------
Type     : port expression string
Default  : 502 (standard Modbus/TCP)
Scope    : per-module (set) or global (setg)

Accepted values:
  Single:      502
  List:        502,510,5020
  Range:       500-510         (max 1000 ports per range for safety)
  Mixed:       502,1000-1010

Common Modbus/OT ports:
  502    -- Modbus/TCP (standard)
  4840   -- OPC-UA
  44818  -- EtherNet/IP
  20000  -- DNP3
  2404   -- IEC 60870-5-104
  102    -- S7comm / ISO-on-TCP
  47808  -- BACnet/IP
  5094   -- HART-IP
  18245  -- GE-SRTP

Examples:
  set port 502               -- standard Modbus
  set port 502,510           -- two ports
  set port 500-510           -- scan range of 11 ports
  setg port 502              -- global default port
""")

    def _help_option_transport(self) -> None:
        print_info("""
Option: transport
-----------------
Type     : string
Default  : module-specific (tcp for Modbus, both for DNP3)
Scope    : per-module (set) or global (setg)

Accepted values:
  tcp   -- TCP only
  udp   -- UDP only
  both  -- try TCP then UDP (where protocol supports both)

Protocol notes:
  Modbus/TCP  -- tcp only
  DNP3        -- tcp and/or udp (default port 20000)
  BACnet/IP   -- udp only (47808)
  S7comm      -- tcp only (102)

Examples:
  set transport tcp
  setg transport both
""")

    def _help_option_fc(self) -> None:
        print_info("""
Option: fc
----------
Type     : integer (0-127)
Default  : 0 (use module default or implied by register notation)
Scope    : per-module (set)

Function Codes:
  0    -- auto (module default or inferred from 'registers' notation)
  1    -- Read Coils               (bits, max 2000 per request)
  2    -- Read Discrete Inputs     (bits, max 2000 per request)
  3    -- Read Holding Registers   (16-bit words, max 125 per request)
  4    -- Read Input Registers     (16-bit words, max 125 per request)
  5    -- Write Single Coil        (requires destructive=true)
  6    -- Write Single Register    (requires destructive=true)
  15   -- Write Multiple Coils     (requires destructive=true)
  16   -- Write Multiple Registers (requires destructive=true)
  17   -- Report Server ID         (device fingerprint)
  43   -- Read Device Identification (MEI, vendor/product info)

Priority:
  explicit fc > fc implied by register notation > module default

Examples:
  set fc 0             -- auto (default)
  set fc 3             -- force FC3 regardless of register notation
  set fc 4             -- force FC4 Input Registers
  set registers 40001  -- automatically implies fc=3 (unless overridden)
""")

    def _help_option_unit_id(self) -> None:
        print_info("""
Option: unit_id
---------------
Type     : integer (0-247)
Default  : 1
Scope    : per-module (set) or global (setg)

Modbus Unit ID (also called Slave ID or Slave Address) identifies
the target device on a Modbus network.

  0      -- broadcast (no response expected, not all devices support)
  1      -- standard single-device default
  1-247  -- serial Modbus slave addresses
  255    -- reserved for gateway/host use in some implementations

When to change:
  - Modbus-to-TCP gateways bridge multiple serial devices; each has a different unit_id
  - Use 'modbus_id_fuzzer' to discover active unit_ids on a gateway
  - RTU serial chains: each device has a unique ID (1-247)

Examples:
  set unit_id 1              -- default
  set unit_id 10             -- specific slave
  setg unit_id 1             -- global default
  use scanners/ics/modbus_id_fuzzer  -- discover all active IDs
""")

    def _help_option_timeout(self) -> None:
        print_info("""
Option: timeout
---------------
Type     : integer (seconds, 0 = use timing profile default)
Default  : 0
Scope    : per-module (set) or global (setg)

Overrides the socket timeout from the timing profile.
When 0, the timeout from the selected 'timing' profile is used.

Relationship with timing:
  timing=T3  -> socket_timeout=1s   (normal)
  timeout=5  -> overrides to 5s     (explicit value wins)
  timeout=0  -> use timing default  (no override)

Examples:
  set timeout 0              -- use timing profile default (recommended)
  set timeout 5              -- 5-second socket timeout
  set timeout 30             -- for slow serial-to-TCP gateways
  setg timeout 3             -- global override for all modules
""")

    def _help_option_target(self) -> None:
        print_info("""
Option: target
--------------
Type     : IPv4 address, IPv6 address, or hostname
Default  : (empty -- required)
Scope    : per-module (set) or global (setg)

Accepted values:
  IPv4:       192.168.1.100
  IPv6:       2001:db8::1
  Hostname:   plc.corp.local
  CIDR:       (not accepted here -- use 'discover' for subnet sweep)

Examples:
  set target 192.168.1.100
  set target 10.0.0.50
  setg target 192.168.1.100  -- apply to all subsequent modules
  unsetg target              -- clear global target
""")

    def _help_option_destructive(self) -> None:
        print_info("""
Option: destructive
-------------------
Type     : bool (true/false/yes/no/1/0)
Default  : false
Scope    : per-module (set)

Enables write/exploit operations that may cause irreversible changes:
  false  -- read-only operations only (safe for production)
  true   -- enables writes, firmware changes, coil manipulation, DoS

For INFO/READ modules (assessment, scanners): destructive has no effect.
For HIGH/CRITICAL modules: requires typed confirmation before execution.

Never set destructive=true on production systems without authorization.

Examples:
  set destructive false      -- default, safe
  set destructive true       -- enables exploit -- use with extreme caution
""")

    def _help_option_threads(self) -> None:
        print_info("""
Option: threads (global only)
-----------------------------
Type     : integer >= 1
Default  : 10
Scope    : global (setg only)

Number of parallel threads for multi-host or multi-port operations.
Affects: subnet sweeps, CIDR scans, TTP runs, MITRE full sweeps.

Recommended values:
  1-5    -- conservative (T0/T1 timing)
  10     -- default (T3 Normal)
  20-50  -- fast networks (T4 Aggressive)
  100+   -- not recommended; may cause TCP exhaustion

Examples:
  setg threads 5             -- conservative
  setg threads 20            -- fast scan
  setg threads 1             -- single-threaded (max stealth)
""")

    def _help_option_host_timeout(self) -> None:
        print_info("""
Option: HOST_TIMEOUT  (global only -- setg)
-----------------------------------------
Type     : integer (seconds)
Default  : 30
Nmap eq. : --host-timeout 30s

Maximum time in seconds IXF will spend on a single host.
When the limit is reached, the host is skipped and marked as timed-out.

Recommended values by environment:
  Fast LAN          : 10-15
  Corporate WAN     : 30-60   (default)
  Serial/slow RTUs  : 60-120
  0                 : no limit (not recommended for large networks)

Examples:
  setg HOST_TIMEOUT 30       -- 30-second cap per host (default)
  setg HOST_TIMEOUT 60       -- slower/distant OT devices
  setg HOST_TIMEOUT 0        -- no cap (use with care)
""")

    def _help_option_retries(self) -> None:
        print_info("""
Options: MAX_RETRIES / MIN_RETRIES  (global only -- setg)
-------------------------------------------------------
Type     : integer >= 0
Defaults : MAX_RETRIES=2, MIN_RETRIES=0
Nmap eq. : --max-retries 2

MAX_RETRIES: how many times to retry a probe before giving up.
MIN_RETRIES: minimum attempts regardless of response.

Tuning for OT environments:
  Max=0: single attempt only -- fastest, but misses intermittent devices
  Max=1: one retry -- good for stable networks
  Max=2: two retries -- default, balances reliability and speed
  Max=3: three retries -- for noisy serial links or slow PLCs

Caution: high retries may hammer fragile OT devices or trigger alarms.

Examples:
  setg MAX_RETRIES 2         -- default (safe)
  setg MAX_RETRIES 1         -- lean scans on stable networks
  setg MIN_RETRIES 0         -- always at least 1 attempt
""")

    def _help_option_scan_delay(self) -> None:
        print_info("""
Option: SCAN_DELAY  (global only -- setg)
----------------------------------------
Type     : integer (milliseconds)
Default  : 300
Nmap eq. : --scan-delay 300ms

Minimum delay between consecutive probes to the same host.
This is the primary control to reduce scan aggression on OT devices.

PLCs and RTUs are often single-threaded -- rapid back-to-back requests
can cause buffer overflows, CPU spikes, or communication hangs.

Guidance:
  0-100 ms  : only for lab environments with modern equipment
  300 ms    : default -- conservative for most OT environments
  500-1000  : for slow serial bridges, energy meters, older PLCs
  1000+     : for very sensitive RTUs (water/gas treatment plants)

Examples:
  setg SCAN_DELAY 300        -- default
  setg SCAN_DELAY 1000       -- 1 second between probes (very gentle)
  setg SCAN_DELAY 0          -- no delay (not recommended for OT)
""")

    def _help_option_max_rate(self) -> None:
        print_info("""
Option: MAX_RATE  (global only -- setg)
--------------------------------------
Type     : integer (probes per second, >= 1)
Default  : 10
Nmap eq. : --max-rate 10

Global cap on how many probes IXF sends per second across all threads.
Prevents flooding the network segment even with high THREADS settings.

Safe values for OT:
  1-5    : critical infrastructure, nuclear, water treatment
  5-10   : industrial automation, building management (default)
  10-20  : IT-managed OT segments with modern firewalls
  50+    : lab environments only

Examples:
  setg MAX_RATE 10           -- default (safe for most OT)
  setg MAX_RATE 2            -- very gentle, for critical systems
  setg MAX_RATE 50           -- lab/fast network only
""")

