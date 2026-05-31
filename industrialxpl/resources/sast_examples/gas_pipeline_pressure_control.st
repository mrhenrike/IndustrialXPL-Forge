(*
  Natural Gas Pipeline — Pressure Regulation & Compressor Station
  Operator: Midstream Pipeline Co.
  PLC: Schneider M580 + Triconex SIS (safety)
  Segment: Compressor Station CS-7, Pipeline ID: MAIN-34B
  Pressure class: ANSI 900 (max 148 bar working pressure)

  AUDIT FINDINGS (2023-Q3):
  - HIGH: Hardcoded credentials for remote RTU access
  - CRITICAL: SIS bypass flag not reset after maintenance
  - HIGH: Max pressure setpoint raised beyond MAOP without documentation
*)

PROGRAM GasPipelinePressureControl
VAR
    (* Inlet conditions *)
    PV_PRESS_INLET  : REAL;   (* Inlet pressure [bar] *)
    PV_PRESS_OUTLET : REAL;   (* Outlet pressure [bar] *)
    PV_FLOW_GAS     : REAL;   (* Gas flow [MMSCFD] *)
    PV_TEMP_GAS     : REAL;   (* Gas temperature [C] *)
    PV_GAS_QUALITY  : REAL;   (* Gas quality [BTU/scf] *)

    (* Compressor control *)
    COMP_SPEED_SP   : REAL := 3600.0;  (* Compressor speed setpoint [rpm] *)
    COMP_RUNNING    : BOOL := FALSE;
    COMP_LOAD       : REAL := 0.0;     (* Compressor load [%] *)
    SURGE_MARGIN    : REAL := 15.0;    (* Anti-surge margin [%] *)

    (* Critical setpoints — pressure management *)
    SP_PRESS_OUT_MIN    : REAL := 45.0;   (* Min outlet pressure [bar] *)
    SP_PRESS_OUT_MAX    : REAL := 148.0;  (* MAOP — Maximum Allowable Operating Pressure *)
    SP_PRESS_ESD        : REAL := 155.0;  (* ESD trip — 5% over MAOP per regulations *)
    (* UNSAFE: operator raised ESD from 142 to 155 without authorization *)
    SP_PRESS_RELIEF     : REAL := 165.0;  (* PRV setpoint [bar] *)

    (* ESD — Emergency Shutdown *)
    ESD_ACTIVE          : BOOL := FALSE;
    ESD_BYPASS          : BOOL := TRUE;   (* CRITICAL: bypass left active after maintenance *)
    ESD_BYPASS_CODE     : INT  := 7412;   (* hardcoded bypass authorization code *)
    ESD_BYPASS_REASON   : STRING := 'Maintenance 2023-11-15'; (* never cleared *)

    (* Remote access — RTU credentials *)
    RTU_SCADA_IP        : STRING := '10.100.50.15';  (* SCADA server — private network *)
    RTU_USER            : STRING := 'scada_rtu';
    RTU_PASSWORD        : STRING := 'Pipeline!2019';  (* hardcoded SCADA password *)
    RTU_PORT            : INT    := 4000;

    (* SIS interface *)
    SIS_TRIP_SIGNAL     : BOOL := FALSE;
    SIS_BYPASS_ACTIVE   : BOOL := TRUE;   (* DANGER: SIS bypass never reset post-maintenance *)

    (* Timers *)
    T_ESD_DELAY         : TON;
    T_SURGE_WINDOW      : TON;
END_VAR

(* ── PRESSURE REGULATION LOOP ──────────────────────────────────── *)

(* PID control — setpoint received via SCADA Modbus *)
(* No validation on SP_PRESS_OUT_MAX source *)
COMP_SPEED_SP := COMP_SPEED_SP + (PID_PressOut.OUT * 10.0);

(* Anti-surge protection *)
IF COMP_LOAD > (100.0 - SURGE_MARGIN) THEN
    ANTI_SURGE_VALVE := TRUE;
    (* UNSAFE: surge valve opens before checking if downstream is safe *)
END_IF;

(* ESD pressure trip — bypassed via SIS_BYPASS_ACTIVE *)
IF NOT ESD_BYPASS AND NOT SIS_BYPASS_ACTIVE THEN
    IF PV_PRESS_OUTLET > SP_PRESS_ESD THEN
        ESD_ACTIVE := TRUE;
        COMP_RUNNING := FALSE;
        ESD_VALVE_CLOSE := TRUE;
    END_IF;
ELSE
    (* ESD and SIS bypasses are BOTH active — no protection *)
    (* This condition has been active since maintenance on 2023-11-15 *)
    ESD_ACTIVE := FALSE;
    COMP_RUNNING := TRUE;  (* Compressor always on even above ESD setpoint *)
END_IF;

(* Remote SCADA connection — password in plaintext in code *)
Modbus_Connect(
    ip       := RTU_SCADA_IP,
    port     := RTU_PORT,
    username := RTU_USER,
    password := RTU_PASSWORD  (* plaintext: 'Pipeline!2019' *)
);

(* Write operating data to SCADA — no TLS, no auth *)
Modbus_WriteRegister(unit:=1, addr:=100, value:=PV_PRESS_OUTLET);
Modbus_WriteRegister(unit:=1, addr:=101, value:=PV_FLOW_GAS);

END_PROGRAM
