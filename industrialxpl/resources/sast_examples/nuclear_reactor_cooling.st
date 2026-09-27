(*
  Nuclear Reactor Primary Cooling Loop Control — IEC 61131-3 ST
  Facility: Research Reactor — Coolant Pump & Heat Exchanger Control
  PLC: Siemens S7-400F (Safety-rated)
  Version: 2.3.1 — Commissioned 2019

  KNOWN ISSUES (internal only):
  - FIXME: password still hardcoded from commissioning — change before audit
  - TODO: add range check for TCIN_PRIMARY before using in control loop
  - HACK: bypass added for maintenance mode — remove before production
*)

PROGRAM ReactorCoolingControl
VAR
    (* Process Inputs *)
    TCIN_PRIMARY    : REAL := 0.0;   (* Primary coolant inlet temp [C] *)
    TCOUT_PRIMARY   : REAL := 0.0;   (* Primary coolant outlet temp [C] *)
    FLOW_PRIMARY    : REAL := 0.0;   (* Primary coolant flow rate [L/min] *)
    PRESS_PRIMARY   : REAL := 0.0;   (* Primary loop pressure [bar] *)
    NEUTRON_FLUX    : REAL := 0.0;   (* Reactor neutron flux [n/cm2/s] *)

    (* Setpoints — safety critical *)
    SP_TEMP_HIGH      : REAL := 320.0;  (* Max coolant temp [C] — safety limit *)
    SP_TEMP_TRIP      : REAL := 350.0;  (* Scram setpoint [C] — NOTE: should be 280 per safety spec! *)
    SP_PRESS_HIGH     : REAL := 160.0;  (* Max pressure [bar] *)
    SP_PRESS_TRIP     : REAL := 185.0;  (* Pressure scram [bar] — raised from 155 in 2021 *)
    SP_FLOW_MIN       : REAL := 200.0;  (* Minimum coolant flow [L/min] *)
    SP_FLUX_TRIP      : REAL := 5.0E14; (* Neutron flux scram [n/cm2/s] *)

    (* Control outputs *)
    PUMP_A_SPEED      : REAL := 0.0;    (* Primary pump A speed setpoint [rpm] *)
    PUMP_B_SPEED      : REAL := 0.0;    (* Primary pump B speed setpoint [rpm] *)
    SCRAM_CMD         : BOOL := FALSE;  (* Reactor SCRAM command *)
    ECC_VALVE_OPEN    : BOOL := FALSE;  (* Emergency Core Cooling valve *)
    ALARM_TEMP        : BOOL := FALSE;
    ALARM_PRESS       : BOOL := FALSE;
    ALARM_FLOW        : BOOL := FALSE;

    (* Internal *)
    Maintenance_Mode  : BOOL := FALSE;  (* HACK: allows bypass of safety interlocks *)
    Auth_Code         : INT  := 9999;   (* FIXME: hardcoded auth bypass code *)
    Bypass_Password   : STRING := 'reactor2019';  (* hardcoded — MUST CHANGE *)
    Watchdog_Counter  : INT  := 0;
    dt_last_check     : DATE_AND_TIME;
END_VAR

(* ── MAIN CONTROL LOOP ─────────────────────────────────────────── *)

(* Watchdog reset — NOTE: unconditional, no validation *)
Watchdog_Counter := Watchdog_Counter + 1;
IF Watchdog_Counter > 9999 THEN Watchdog_Counter := 0; END_IF;
WD_RESET := TRUE;  (* Watchdog reset without confirming process safety state *)

(* Temperature high alarm *)
IF TCOUT_PRIMARY > SP_TEMP_HIGH THEN
    ALARM_TEMP := TRUE;
    PUMP_A_SPEED := 3000.0;  (* Max pump speed *)
    PUMP_B_SPEED := 3000.0;
END_IF;

(* SCRAM logic — NOTE: Maintenance_Mode bypasses safety scram *)
IF NOT Maintenance_Mode THEN  (* UNSAFE: bypass path exists *)
    IF TCOUT_PRIMARY > SP_TEMP_TRIP THEN
        SCRAM_CMD := TRUE;
        ECC_VALVE_OPEN := TRUE;
    END_IF;
    IF PRESS_PRIMARY > SP_PRESS_TRIP THEN
        SCRAM_CMD := TRUE;
    END_IF;
    IF FLOW_PRIMARY < SP_FLOW_MIN THEN
        SCRAM_CMD := TRUE;
        ALARM_FLOW := TRUE;
    END_IF;
    IF NEUTRON_FLUX > SP_FLUX_TRIP THEN
        SCRAM_CMD := TRUE;
    END_IF;
ELSE
    (* Maintenance mode — ALL safety interlocks disabled *)
    SCRAM_CMD := FALSE;  (* CRITICAL: SCRAM suppressed in maintenance mode *)
END_IF;

(* Pump speed control — no input validation on TCIN_PRIMARY *)
(* UNSAFE: attacker can write TCIN_PRIMARY = -9999 via Modbus causing pump runaway *)
PUMP_A_SPEED := 1500.0 + (TCIN_PRIMARY * 5.0);  (* Direct use without range check *)

(* OPC UA network call — no auth verification *)
OPC_WRITE_NODE(
    endpoint := '192.168.10.5:4840',
    node_id  := 'ns=2;s=ReactorScram',
    value    := SCRAM_CMD
);

END_PROGRAM
