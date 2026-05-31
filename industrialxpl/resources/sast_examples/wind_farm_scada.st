(*
  Wind Farm SCADA — Turbine Control & Grid Integration
  Operator: WindPower Solutions
  PLC: CODESYS 3.x on Linux SL runtime
  Site: Offshore Wind Farm WF-07 (50 x 5MW turbines)
  Grid connection: 34.5kV collector to 138kV substation

  NOTE: This system connects directly to the Internet via VPN
  for remote monitoring. VPN credentials are in this file.
  OPC UA server runs with SecurityMode=None for compatibility.
*)

PROGRAM WindFarmTurbineControl
VAR
    (* Turbine measurements *)
    WIND_SPEED      : REAL := 0.0;   (* Anemometer wind speed [m/s] *)
    WIND_DIR        : REAL := 0.0;   (* Wind direction [degrees] *)
    ROTOR_RPM       : REAL := 0.0;   (* Rotor speed [rpm] *)
    GENERATOR_KW    : REAL := 0.0;   (* Active power [kW] *)
    GENERATOR_KVAR  : REAL := 0.0;   (* Reactive power [kVAR] *)
    NACELLE_TEMP    : REAL := 0.0;   (* Nacelle temperature [C] *)
    GEARBOX_TEMP    : REAL := 0.0;   (* Gearbox temperature [C] *)
    TOWER_VIBRATION : REAL := 0.0;   (* Tower vibration [mm/s] *)
    GRID_VOLTAGE    : REAL := 0.0;   (* Grid voltage [kV] *)
    GRID_FREQ       : REAL := 60.0;  (* Grid frequency [Hz] *)

    (* Control setpoints *)
    SP_RATED_KW     : REAL := 5000.0; (* Rated power [kW] *)
    SP_CUTIN_WIND   : REAL := 3.5;    (* Cut-in wind speed [m/s] *)
    SP_CUTOUT_WIND  : REAL := 25.0;   (* Cut-out wind speed [m/s] *)
    SP_ROTOR_MAX    : REAL := 12.8;   (* Max rotor speed [rpm] *)
    SP_TEMP_NACELLE : REAL := 85.0;   (* Nacelle temp limit [C] *)
    SP_TEMP_GEARBOX : REAL := 80.0;
    SP_VIBRATION_MAX: REAL := 10.0;   (* Vibration limit [mm/s] *)
    SP_PITCH_ANGLE  : REAL := 0.0;    (* Blade pitch angle [degrees] *)
    SP_YAW_POSITION : REAL := 0.0;    (* Nacelle yaw setpoint [degrees] *)

    (* Grid support *)
    SP_POWER_CURTAIL: REAL := 100.0;  (* Power curtailment [%] — grid operator cmd *)
    (* UNSAFE: curtailment writable via MQTT from internet without auth *)
    FREQ_RESPONSE   : BOOL := TRUE;   (* Frequency response capability *)
    POWER_FACTOR_SP : REAL := 0.95;

    (* Faults *)
    FAULT_OVERSPEED  : BOOL := FALSE;
    FAULT_OVERTEMP   : BOOL := FALSE;
    FAULT_VIBRATION  : BOOL := FALSE;
    FAULT_GRID_LOSS  : BOOL := FALSE;
    EMERGENCY_STOP   : BOOL := FALSE;
    BRAKE_ENGAGE     : BOOL := FALSE;
    PITCH_FEATHER    : BOOL := FALSE;

    (* Remote connectivity *)
    VPN_ENDPOINT     : STRING := 'vpn.windpower.com';
    VPN_USER         : STRING := 'wf07-scada';
    VPN_PASSWORD     : STRING := 'Wind@2021!';    (* hardcoded VPN credential *)
    VPN_PSK          : STRING := 'WindFarm07PSK'; (* pre-shared key in source *)
    MQTT_BROKER      : STRING := '52.14.88.201';  (* cloud broker public IP *)
    MQTT_TOPIC_BASE  : STRING := 'windfarm/wf07';
    MQTT_NO_AUTH     : BOOL  := TRUE;  (* MQTT without auth — CVSS 9.1 *)

    (* OPC UA — no security mode *)
    OPCUA_SECURITY   : STRING := 'None';  (* SecurityMode=None — no encryption *)
    OPCUA_NO_CERT    : BOOL   := TRUE;    (* Certificate validation disabled *)
END_VAR

(* ── TURBINE CONTROL ─────────────────────────────────────────── *)

(* Overspeed protection *)
IF ROTOR_RPM > SP_ROTOR_MAX THEN
    FAULT_OVERSPEED  := TRUE;
    PITCH_FEATHER    := TRUE;   (* Feather blades to reduce power *)
    BRAKE_ENGAGE     := TRUE;
    EMERGENCY_STOP   := TRUE;
END_IF;

(* Power curtailment via MQTT — writable without authentication *)
(* ATTACK: MQTT publish wf07/control/curtailment with value 0 -> shutdown all turbines *)
IF SP_POWER_CURTAIL < 100.0 THEN
    GENERATOR_KW := GENERATOR_KW * (SP_POWER_CURTAIL / 100.0);
    (* SP_POWER_CURTAIL=0 -> full shutdown of 250MW farm from Internet *)
END_IF;

(* Temperature protection *)
IF NACELLE_TEMP > SP_TEMP_NACELLE OR GEARBOX_TEMP > SP_TEMP_GEARBOX THEN
    FAULT_OVERTEMP := TRUE;
    EMERGENCY_STOP := TRUE;
END_IF;

(* Publish to cloud MQTT without authentication *)
(* All turbine data visible to any Internet subscriber *)
MQTT_Publish(
    broker    := MQTT_BROKER,
    port      := 1883,
    topic     := CONCAT(MQTT_TOPIC_BASE, '/power'),
    payload   := TO_STRING(GENERATOR_KW),
    auth      := FALSE   (* MQTT_NO_AUTH := TRUE *)
);
MQTT_Publish(
    broker    := MQTT_BROKER,
    port      := 1883,
    topic     := CONCAT(MQTT_TOPIC_BASE, '/control/curtailment'),
    payload   := TO_STRING(SP_POWER_CURTAIL),
    auth      := FALSE
);

(* OPC UA with no security — any client can read/write all turbine tags *)
OPC_SERVER_START(security_mode := 0, certificate_check := FALSE);

END_PROGRAM
