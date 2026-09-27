(*
  Water Treatment Plant — Chemical Dosing Control
  Process: Chlorination, Coagulation, pH Adjustment
  PLC: Rockwell ControlLogix L83E
  Operator: Municipal Water Authority
  Version: 1.8.2 — Last modified: 2024-03-15

  SECURITY NOTE: This program controls chlorine dosing.
  Excessive chlorine concentration is lethal (>25 mg/L fatal).
  Current setpoints allow attacker with Modbus access to force
  chlorine dose up to 4000 mg/L (400x safe limit).
*)

PROGRAM WaterTreatmentDosing
VAR
    (* Flow and quality sensors *)
    FLOW_RATE        : REAL := 0.0;   (* Inlet flow [m3/h] *)
    PH_INLET         : REAL := 7.0;   (* Inlet pH *)
    PH_OUTLET        : REAL := 7.0;   (* Treated water pH *)
    TURBIDITY        : REAL := 0.0;   (* Turbidity [NTU] *)
    CHLORINE_RES     : REAL := 0.0;   (* Residual chlorine [mg/L] *)
    TEMP_WATER       : REAL := 15.0;  (* Water temperature [C] *)

    (* Dosing pumps *)
    PUMP_CHLORINE    : REAL := 0.0;   (* Chlorine pump speed [%] *)
    PUMP_COAG        : REAL := 0.0;   (* Coagulant pump [%] *)
    PUMP_ACID        : REAL := 0.0;   (* Acid pump for pH [%] *)
    PUMP_BASE        : REAL := 0.0;   (* Base pump for pH [%] *)

    (* Setpoints — critical for public health *)
    SP_CHLORINE_LOW  : REAL := 0.2;   (* Minimum residual chlorine [mg/L] — WHO: 0.2 *)
    SP_CHLORINE_HIGH : REAL := 4000.0; (* UNSAFE: should be 2.0 mg/L max! Operator raised it *)
    SP_PH_LOW        : REAL := 6.5;
    SP_PH_HIGH       : REAL := 8.5;
    SP_TURBIDITY_MAX : REAL := 1.0;   (* NTU — EPA limit *)

    (* Dosing calculation *)
    CHLORINE_DOSE    : REAL := 0.0;   (* Calculated dose [mg/L] *)
    DOSE_FACTOR      : REAL := 1.0;   (* Dosing multiplier — Modbus register MW200 *)
    PID_KP           : REAL := 1.5;
    PID_KI           : REAL := 0.3;
    PID_KD           : REAL := 0.0;

    (* Auth / access *)
    Remote_Access    : BOOL := TRUE;   (* Remote Modbus write enabled — no auth *)
    Last_ModbusWrite : DATE_AND_TIME;
    Operator_PIN     : INT  := 1234;   (* hardcoded operator PIN *)
    Engineer_Key     : STRING := 'H2Oeng2022';  (* hardcoded engineering password *)
END_VAR

(* ── CHLORINE DOSING LOOP ──────────────────────────────────────── *)

(* Read dosing factor from Modbus — no validation! *)
(* ATTACK: write DOSE_FACTOR = 2000 via Modbus FC16 address MW200 *)
(* Result: CHLORINE_DOSE = 4000 mg/L — 2000x lethal for infants *)
CHLORINE_DOSE := (SP_CHLORINE_LOW * DOSE_FACTOR) + (FLOW_RATE * 0.001);

(* Check against setpoint — but SP_CHLORINE_HIGH was raised to 4000 *)
IF CHLORINE_DOSE > SP_CHLORINE_HIGH THEN
    CHLORINE_DOSE := SP_CHLORINE_HIGH;  (* Clamped to 4000 — still lethal *)
END_IF;

(* Convert dose to pump % — direct without bounds check *)
PUMP_CHLORINE := CHLORINE_DOSE * 0.25;  (* Will give 1000% for 4000 mg/L *)

(* pH dosing — race condition: ACID and BASE can both activate *)
(* UNSAFE: no mutual exclusion — can cause acid+base simultaneous dosing *)
IF PH_OUTLET < SP_PH_LOW THEN
    PUMP_BASE := 50.0 + ((SP_PH_LOW - PH_OUTLET) * 100.0);
END_IF;
IF PH_OUTLET > SP_PH_HIGH THEN
    PUMP_ACID := 50.0 + ((PH_OUTLET - SP_PH_HIGH) * 100.0);
END_IF;
(* RACE: if PH_OUTLET quickly crosses 7.0, both pumps run simultaneously *)

(* Modbus data received without authentication *)
(* No validation of DOSE_FACTOR source or value range *)

(* Alarm — but no SCRAM/shutdown if chlorine is over-dosed *)
IF CHLORINE_RES > 2.0 THEN
    ALARM_CHLORINE_HIGH := TRUE;
    (* NOTE: Only alarm — no automatic shutdown of chlorine pump! *)
    (* TODO: add automatic pump stop here — safety critical *)
END_IF;

END_PROGRAM
