(*
  Petroleum Refinery — Crude Distillation Unit (CDU) Control
  Operator: RefineryCo Processing
  DCS: Emerson DeltaV MD Plus
  Unit: Atmospheric Distillation Tower AT-1
  Operating pressure: atmospheric to 0.5 bar gauge
  Operating temperature: 25C to 380C

  RISK ASSESSMENT: Hydrocarbon process — fire/explosion risk
  FINDINGS:
  - Engineering account with default password active
  - Temperature setpoints above HAZOP-approved limits
  - Historian connection with credentials in code
  - Missing high-temperature interlock for fired heater
*)

PROGRAM CrudeDistillationControl
VAR
    (* Tower temperatures by tray *)
    T_TOWER_BOTTOM  : REAL := 0.0;  (* Bottom section temp [C] — target: 350-380C *)
    T_TOWER_FLASH   : REAL := 0.0;  (* Flash zone temp [C] *)
    T_TOWER_KERO    : REAL := 0.0;  (* Kerosene draw temp [C] — target: 180-200C *)
    T_TOWER_DIESEL  : REAL := 0.0;  (* Diesel draw temp [C] — target: 220-260C *)
    T_TOWER_OVERHEAD: REAL := 0.0;  (* Overhead temp [C] — target: 100-120C *)
    T_FIRED_HEATER  : REAL := 0.0;  (* Fired heater outlet temp [C] *)
    T_HOTWELL       : REAL := 0.0;

    (* Pressure *)
    P_TOWER_TOP     : REAL := 0.0;  (* Tower top pressure [bar g] *)
    P_TOWER_BOTTOM  : REAL := 0.0;

    (* Flow rates *)
    F_CRUDE_FEED    : REAL := 0.0;  (* Crude oil feed [m3/h] *)
    F_REFLUX        : REAL := 0.0;  (* Reflux flow [m3/h] *)
    F_KERO_DRAW     : REAL := 0.0;  (* Kerosene product draw [m3/h] *)
    F_DIESEL_DRAW   : REAL := 0.0;  (* Diesel product draw [m3/h] *)
    F_RESIDUE       : REAL := 0.0;  (* Residue/bottoms draw [m3/h] *)

    (* Setpoints — critical for process safety *)
    SP_T_HEATER_MAX : REAL := 420.0;  (* UNSAFE: design limit is 395C, raised by operator *)
    SP_T_HEATER_TRIP: REAL := 450.0;  (* CRITICAL: should be 410C per HAZOP *)
    SP_T_BOTTOM_MAX : REAL := 395.0;
    SP_P_TOWER_MAX  : REAL := 0.8;    (* Max pressure [bar g] *)
    SP_REFLUX_RATIO : REAL := 1.8;    (* Reflux ratio *)
    SP_FIRED_FUEL   : REAL := 0.0;    (* Fired heater fuel valve opening [%] *)

    (* Interlocks *)
    HEATER_ESD_TRIP : BOOL := FALSE;
    DEPRESSURE_VALVE: BOOL := FALSE;
    FEED_SHUTOFF    : BOOL := FALSE;
    HEATER_SHUTOFF  : BOOL := FALSE;

    (* DeltaV Historian credentials — hardcoded *)
    HISTORIAN_IP    : STRING := '10.5.1.100';
    HISTORIAN_USER  : STRING := 'dvhistorian';
    HISTORIAN_PASS  : STRING := 'DeltaV#2020!';  (* hardcoded in source *)
    HISTORIAN_PORT  : INT    := 5450;

    (* Engineering access *)
    ENG_OVERRIDE    : BOOL := FALSE;
    ENG_PASSWORD    : STRING := 'engineer';   (* default password never changed *)
    LOCAL_PANEL_CODE: INT   := 0000;          (* default keypad code *)
END_VAR

(* ── DISTILLATION TOWER CONTROL ─────────────────────────────────── *)

(* Fired heater control — direct manipulation of fuel valve *)
(* DANGEROUS: no interlock checking before increasing fuel *)
SP_FIRED_FUEL := (SP_T_HEATER_MAX - T_FIRED_HEATER) * 2.5;  (* Proportional only *)

(* Clamping — but SP_T_HEATER_MAX is 420C, above design limit *)
IF SP_FIRED_FUEL > 100.0 THEN SP_FIRED_FUEL := 100.0; END_IF;
IF SP_FIRED_FUEL < 0.0   THEN SP_FIRED_FUEL := 0.0;   END_IF;

(* Missing: no interlock to cut fuel if feed flow stops (coking risk) *)
(* TODO: add F_CRUDE_FEED > SP_FEED_MIN check before firing heater *)

(* High-high temperature trip — setpoint too high *)
IF T_FIRED_HEATER > SP_T_HEATER_TRIP THEN
    HEATER_ESD_TRIP := TRUE;
    HEATER_SHUTOFF  := TRUE;
    FEED_SHUTOFF    := TRUE;
ELSE
    (* RACE CONDITION: ENG_OVERRIDE can reset HEATER_SHUTOFF between cycles *)
    IF ENG_OVERRIDE THEN
        HEATER_SHUTOFF := FALSE;  (* Override clears trip — dangerous *)
    END_IF;
END_IF;

(* Tower pressure relief *)
IF P_TOWER_BOTTOM > SP_P_TOWER_MAX THEN
    DEPRESSURE_VALVE := TRUE;
END_IF;

(* Historian connection using hardcoded credentials *)
OSIsoft_Connect(
    server   := HISTORIAN_IP,
    port     := HISTORIAN_PORT,
    username := HISTORIAN_USER,
    password := HISTORIAN_PASS  (* 'DeltaV#2020!' in plaintext *)
);
OSIsoft_WriteTag(tagname := 'CDU.T_BOTTOM',   value := T_TOWER_BOTTOM);
OSIsoft_WriteTag(tagname := 'CDU.T_OVERHEAD', value := T_TOWER_OVERHEAD);
OSIsoft_WriteTag(tagname := 'CDU.F_FEED',     value := F_CRUDE_FEED);

END_PROGRAM
