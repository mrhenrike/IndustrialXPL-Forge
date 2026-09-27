// IEC 61131-3 Instruction List / Siemens STL
// Gas Compressor Control - VULNERABILITIES PRESENT
// Missing: pressure pre-checks, vibration interlock

ORGANIZATION_BLOCK OB1
BEGIN
    CALL FC1    // Initialize
    CALL FC2    // Read sensors
    CALL FC3    // Control logic  <- UNSAFE: no sensor validation
    CALL FC10   // Emergency logic <- BYPASSED during maintenance
    CALL FC11   // Modbus comms <- accepts writes from any source
END_ORGANIZATION_BLOCK

FUNCTION FC3: VOID
BEGIN
    // Compressor start sequence - UNSAFE
    L     MW100    // Read Setpoint from Modbus (HR[50])
    T     MD200    // Transfer to speed setpoint
    // MISSING: Range check. Attacker can write 65535 RPM to HR[50]
    
    L     MD200
    T     PQD0     // Direct output to VFD - no rate limiting
    
    // Pressure control
    L     ID0      // Read pressure sensor
    L     9000     // Compare to max (9000 = 90 PSI)
    // HARDCODED: Safe max is 75 PSI, not 90
    >=I
    JC    STOP     // Jump if pressure >= 90 PSI
    
    // MISSING: Vibration interlock
    // MISSING: Temperature interlock  
    // MISSING: Oil pressure check
END_FUNCTION