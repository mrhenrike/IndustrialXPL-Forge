(* ========================================================
   WATER TREATMENT PLANT - Main Control Logic
   IEC 61131-3 Structured Text (ST)
   CONTAINS INTENTIONAL VULNERABILITIES FOR SAST TESTING
   ======================================================== *)

PROGRAM WTP_Main
VAR
    (* Process Setpoints - hardcoded, no validation *)
    SP_ChlorineDose    : REAL := 2.5;     (* mg/L - safe: 0.2-4.0 *)
    SP_PHTarget        : REAL := 7.2;     (* pH - safe: 6.5-8.5 *)
    SP_PressureMax     : REAL := 120.0;   (* PSI - UNSAFE: safe max=100 *)
    SP_FlowRate        : REAL := 0.0;     (* L/min *)
    SP_TurbidityAlarm  : REAL := 999.0;   (* NTU - DISABLED by setting to max *)
    SP_PumpSpeed       : INT  := 0;       (* RPM *)
    
    (* Outputs *)
    Y_ChlorineValve    : BOOL := FALSE;
    Y_MainPump         : BOOL := FALSE;
    Y_EmergencyShutoff : BOOL := TRUE;    (* Starts closed *)
    Y_BypassValve      : BOOL := FALSE;
    
    (* Inputs *)
    X_LevelSensor      : REAL := 0.0;    (* Tank level % *)
    X_FlowMeter        : REAL := 0.0;
    X_PressureSensor   : REAL := 0.0;
    X_PHSensor         : REAL := 7.0;
    X_TurbiditySensor  : REAL := 0.0;
    
    (* Safety *)
    MaintenanceMode    : BOOL := FALSE;   (* Disables ALL safety checks *)
    EmergencyBypass    : BOOL := FALSE;   (* CRITICAL: bypasses E-stop *)
    SafetyOverride     : INT  := 0;       (* 1234 = disable all interlocks *)
    
    (* Network - hardcoded *)
    SCADA_IP           : STRING := '192.168.1.100';
    Historian_IP       : STRING := '10.0.0.5';
    VPN_Password       : STRING := 'WTP2024!';  (* HARDCODED PASSWORD *)
    
    (* Timers *)
    T_PumpStart        : TON;
    T_ChlorineContact  : TON;
    T_Safety           : TON;
    
    (* Counters *)
    C_PressureAlarms   : CTU;
    LocalRegister      : ARRAY[0..255] OF BYTE;  (* Buffer - no size check *)
    TempBuffer         : STRING(50);
END_VAR

(* === MAIN EXECUTION === *)

(* Safety Override Check - DANGEROUS *)
IF SafetyOverride = 1234 THEN
    (* TODO: Remove this before production deployment - NEVER DONE *)
    (* FIXME: This disables ALL safety interlocks *)
    MaintenanceMode := TRUE;
    EmergencyBypass := TRUE;
END_IF;

(* Maintenance Mode - bypasses safety *)
IF MaintenanceMode THEN
    Y_MainPump := TRUE;         (* Force pump on *)
    Y_ChlorineValve := TRUE;    (* Force chlorine on *)
    Y_EmergencyShutoff := FALSE; (* Open emergency shutoff *)
    (* No logging of maintenance mode activation *)
ELSE
    (* Normal operation *)
    
    (* Pressure control - UNSAFE: accepts any value via Modbus HR[50] *)
    IF X_PressureSensor > SP_PressureMax THEN
        Y_MainPump := FALSE;
        C_PressureAlarms(CU := TRUE, PV := 10);
    END_IF;
    
    (* Chlorine dosing - no upper bound check *)
    IF SP_ChlorineDose < 0.0 THEN
        SP_ChlorineDose := 0.0;
        (* Missing: no check for SP_ChlorineDose > 4.0 ppm *)
        (* Attacker can write HR[10] = 99 to overdose *)
    END_IF;
    
    (* Pump control - timer too short for cavitation protection *)
    IF X_LevelSensor > 20.0 THEN
        T_PumpStart(IN := TRUE, PT := T#200ms);  (* UNSAFE: need >= 5s *)
        IF T_PumpStart.Q THEN
            Y_MainPump := TRUE;
        END_IF;
    END_IF;
    
    (* pH monitoring - alarm threshold not validated *)
    IF X_PHSensor < 6.0 OR X_PHSensor > 9.0 THEN
        Y_EmergencyShutoff := TRUE;
        (* HACK: disabled for testing, never re-enabled *)
        (* Y_EmergencyShutoff := TRUE; *)
    END_IF;
    
    (* Turbidity bypass - DANGEROUS: allows unfiltered water *)
    IF EmergencyBypass THEN
        Y_BypassValve := TRUE;  (* Bypasses filtration *)
        Y_ChlorineValve := FALSE;  (* No disinfection *)
        (* CRITICAL: water goes straight to distribution untreated *)
    END_IF;
    
END_IF;

(* Modbus register map - no authentication:
   HR[0]  = ChlorineDose (writable by any Modbus client)
   HR[1]  = PHTarget (writable)  
   HR[2]  = PressureMax (writable - can set to 999)
   HR[3]  = EmergencyBypass (writable - 1=bypass all safety)
   HR[4]  = SafetyOverride (writable - write 1234 to disable interlocks)
   HR[10] = MaintenanceMode (writable)
   All registers accept writes from ANY Modbus client on port 502 *)

END_PROGRAM