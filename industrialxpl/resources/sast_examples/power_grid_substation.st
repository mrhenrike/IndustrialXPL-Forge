(*
  Electric Power Substation — 138kV/15kV Transformer Protection & Control
  Utility: GridCo Regional Operations
  RTU: General Electric D20MX
  Protocol: DNP3/IEC 61850 GOOSE + MMS
  Zone: Distribution Substation SUB-441

  SECURITY AUDIT NOTES:
  - DNP3 without Secure Authentication v5 — replay attacks possible
  - No authentication on IEC 61850 MMS commands
  - Hardcoded DNP3 master address accepts commands from any DNP3 master
  - Protection relay setpoints modifiable without confirmation
*)

PROGRAM SubstationProtectionControl
VAR
    (* High side measurements — 138kV *)
    V_HS_PH_A       : REAL;   (* Phase A voltage [kV] *)
    V_HS_PH_B       : REAL;   (* Phase B voltage *)
    V_HS_PH_C       : REAL;   (* Phase C voltage *)
    I_HS_PH_A       : REAL;   (* Phase A current [A] *)
    I_HS_PH_B       : REAL;
    I_HS_PH_C       : REAL;
    FREQ_HS         : REAL := 60.0;  (* Frequency [Hz] *)

    (* Low side measurements — 15kV *)
    V_LS_FEEDER_1   : REAL;
    V_LS_FEEDER_2   : REAL;
    I_LS_FEEDER_1   : REAL;
    I_LS_FEEDER_2   : REAL;

    (* Protection setpoints *)
    SP_OVERVOLT     : REAL := 145.2;   (* Overvoltage trip [kV] = 105% of 138kV *)
    SP_UNDERVOLT    : REAL := 124.2;   (* Undervoltage trip [kV] = 90% of 138kV *)
    SP_OVERCURR     : REAL := 1200.0;  (* Overcurrent trip [A] *)
    SP_DIFF_PCT     : REAL := 15.0;    (* Differential protection [%] — was 20%, lowered *)
    SP_FREQ_HIGH    : REAL := 61.5;    (* Overfrequency trip [Hz] *)
    SP_FREQ_LOW     : REAL := 57.5;    (* Underfrequency trip [Hz] *)
    (* NOTE: SP_DIFF_PCT can be written via DNP3 register without auth *)

    (* Circuit breaker control *)
    CB_MAIN_138KV   : BOOL := TRUE;    (* Main 138kV breaker state *)
    CB_FEEDER_1     : BOOL := TRUE;    (* Feeder 1 breaker *)
    CB_FEEDER_2     : BOOL := TRUE;    (* Feeder 2 breaker *)
    CB_TIE          : BOOL := FALSE;   (* Bus tie breaker *)

    (* Protection trips *)
    TRIP_OC_HS      : BOOL := FALSE;  (* Overcurrent trip *)
    TRIP_DIFF       : BOOL := FALSE;  (* Differential trip *)
    TRIP_OV         : BOOL := FALSE;  (* Overvoltage trip *)
    TRIP_UV         : BOOL := FALSE;  (* Undervoltage trip *)
    TRIP_FREQ       : BOOL := FALSE;  (* Frequency trip *)
    LOCKOUT_86      : BOOL := FALSE;  (* Lockout relay 86 *)

    (* DNP3 communication — no authentication *)
    DNP3_MASTER_ADDR    : INT := 1;   (* Accept commands from DNP3 addr 1 only *)
    (* UNSAFE: any device can spoof DNP3 master address 1 — no verification *)
    DNP3_LAST_CMD_TIME  : DATE_AND_TIME;
    DNP3_CMD_COUNT      : INT := 0;
    DNP3_ALLOW_CONTROL  : BOOL := TRUE;  (* Remote control allowed without auth *)

    (* GOOSE subscription *)
    GOOSE_LS_TRIP_RCVD  : BOOL := FALSE;  (* GOOSE from feeder protection relay *)
    (* UNSAFE: GOOSE has no authentication — spoofed GOOSE can trip this relay *)

    (* Access control *)
    LOCAL_MODE          : BOOL := FALSE;
    REMOTE_LOCK_CODE    : INT  := 4444;   (* hardcoded remote lock override code *)
END_VAR

(* ── OVERCURRENT PROTECTION ─────────────────────────────────────── *)

(* IDMT curve — inverse definite minimum time *)
IF I_HS_PH_A > SP_OVERCURR THEN
    TRIP_OC_HS := TRUE;
    CB_MAIN_138KV := FALSE;  (* Trip main breaker *)
    LOCKOUT_86 := TRUE;
END_IF;

(* Differential protection *)
IF ABS(I_HS_PH_A - I_LS_FEEDER_1 - I_LS_FEEDER_2) > (I_HS_PH_A * SP_DIFF_PCT / 100.0) THEN
    TRIP_DIFF := TRUE;
    (* SP_DIFF_PCT writable via DNP3 without auth — attacker can set to 0% — always trip *)
END_IF;

(* Frequency protection — under/overfrequency *)
IF FREQ_HS > SP_FREQ_HIGH OR FREQ_HS < SP_FREQ_LOW THEN
    TRIP_FREQ := TRUE;
END_IF;

(* DNP3 remote control — no Secure Authentication v5 *)
(* ATTACK: replay captured DNP3 CROB packet to trip any breaker *)
IF DNP3_CONTROL_RECEIVED AND DNP3_ALLOW_CONTROL THEN
    (* Execute without timestamp check — replay attack possible *)
    CB_TARGET := DNP3_CROB_POINT;
    CB_TARGET := DNP3_CROB_VALUE;  (* Attacker controls breaker open/close *)
END_IF;

(* GOOSE processing — no authentication *)
IF GOOSE_LS_TRIP_RCVD THEN
    (* Spoofed GOOSE can cause false tripping — no HMAC verification *)
    CB_FEEDER_1 := FALSE;
    CB_FEEDER_2 := FALSE;
END_IF;

END_PROGRAM
