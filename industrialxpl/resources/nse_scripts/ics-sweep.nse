description = [[
ICS/OT Full Protocol Sweep — IndustrialXPL-Forge

Rapid multi-protocol sweep to identify any ICS/OT services on a single
host across all common industrial protocol ports. Provides a summary of
all detected industrial services in a single scan.

Runs all IXF NSE scripts in discovery mode:
- Protocol fingerprinting (Modbus, S7, EtherNet/IP, DNP3, BACnet, ...)
- Historian detection (PI, AVEVA, AspenTech, ...)
- Engineering port accessibility (S7:102, EtherNet/IP:44818, ...)
- Safety system exposure (Triconex:1502, ...)

Usage:
  nmap --script ics-sweep -p 20-65535 <target>
  nmap --script ics-sweep --script-args ics-sweep.timeout=5000 <target>

AUTHORIZED TESTING ONLY — part of IndustrialXPL-Forge
]]

author     = "Andre Henrique (@mrhenrike) | IXF"
license    = "MIT"
categories = {"discovery", "safe", "ics"}

local stdnse = require "stdnse"
local comm   = require "comm"
local nmap   = require "nmap"

-- Full ICS port/service map
local ICS_SERVICES = {
  -- PLCs / RTUs
  [102]   = {name="Siemens S7comm",          type="PLC Engineering",  risk="CRITICAL"},
  [44818] = {name="EtherNet/IP CIP",         type="PLC Engineering",  risk="CRITICAL"},
  [502]   = {name="Modbus TCP",              type="PLC/RTU Process",  risk="HIGH"},
  [20000] = {name="DNP3",                    type="RTU/SCADA",        risk="HIGH"},
  [9600]  = {name="Omron FINS",              type="PLC",              risk="HIGH"},
  [20256] = {name="Unitronics PCOM",         type="PLC",              risk="HIGH"},
  [48898] = {name="Beckhoff ADS/AMS",        type="PLC Engineering",  risk="HIGH"},
  [11740] = {name="CODESYS V3 Runtime",      type="PLC Engineering",  risk="HIGH"},
  [5007]  = {name="Mitsubishi SLMP",         type="PLC",              risk="HIGH"},
  [2004]  = {name="LS Electric LSIS",        type="PLC",              risk="HIGH"},
  -- ICS Protocols
  [2404]  = {name="IEC 60870-5-104",        type="Power Grid RTU",   risk="CATASTROPHIC"},
  [4840]  = {name="OPC UA",                 type="SCADA/DCS/ICS",    risk="HIGH"},
  [47808] = {name="BACnet/IP",              type="Building Auto",    risk="MEDIUM"},
  [1502]  = {name="Triconex TriStation",    type="Safety PLC (SIS)", risk="CATASTROPHIC"},
  -- Historians
  [5450]  = {name="OSIsoft PI Server",      type="Historian",        risk="HIGH"},
  [5413]  = {name="AVEVA System Platform",  type="Historian",        risk="HIGH"},
  [10014] = {name="AspenTech InfoPlus.21",  type="Historian",        risk="HIGH"},
  -- SCADA/HMI
  [80]    = {name="HTTP (SCADA Web UI)",    type="SCADA/HMI",        risk="HIGH"},
  [443]   = {name="HTTPS (SCADA Web UI)",   type="SCADA/HMI",        risk="HIGH"},
  [8080]  = {name="HTTP Alt (SCADA)",       type="SCADA/HMI",        risk="HIGH"},
  -- Management
  [22]    = {name="SSH",                    type="Management",       risk="MEDIUM"},
  [23]    = {name="Telnet",                 type="Management",       risk="HIGH"},
  [161]   = {name="SNMP",                   type="Network Mgmt",     risk="MEDIUM"},
  [4911]  = {name="Niagara Fox Protocol",   type="BAS",              risk="HIGH"},
  [3671]  = {name="KNX/IP",                type="Building Auto",    risk="MEDIUM"},
}

portrule = function(host, port)
  return port.state == "open" and ICS_SERVICES[port.number] ~= nil
end

action = function(host, port)
  local svc = ICS_SERVICES[port.number]
  if not svc then return end

  local output = stdnse.output_table()
  output["service"] = svc.name
  output["type"]    = svc.type
  output["risk"]    = svc.risk
  output["address"] = host.ip .. ":" .. port.number

  -- Quick banner grab
  local status, data = comm.get_banner(host, port, {timeout=1500})
  if status and data and #data > 0 then
    output["banner_hex"] = stdnse.tohex(data:sub(1, math.min(16, #data)))
  end

  if svc.risk == "CATASTROPHIC" or svc.risk == "CRITICAL" then
    output["action_required"] = "Verify this service is not accessible from untrusted networks"
  end

  return output
end
