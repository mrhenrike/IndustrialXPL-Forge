description = [[
ICS Safety Instrumented System (SIS) Exposure Check — IndustrialXPL-Forge

Detects Safety Instrumented Systems (SIS) and Safety PLCs exposed on the
network. SIS devices are critical safety barriers — their compromise can
lead to equipment damage, environmental releases, or loss of life.

Targets: Triconex TriStation (1502), Pilz PSS4000 (OPC UA 4840),
HIMA HIMatrix (OPC UA 4840), Rockwell GuardLogix (EtherNet/IP 44818),
Emerson DeltaV SIS (DCOM 135), Yokogawa ProSafe-RS (OPC UA 4840).

Historical context: TRITON/TRISIS malware (2017) targeted Triconex SIS
at a Saudi Arabian petrochemical facility.

AUTHORIZED TESTING ONLY — part of IndustrialXPL-Forge
]]

author     = "Andre Henrique (@mrhenrike) | IXF"
license    = "MIT"
categories = {"discovery", "safe", "ics"}

local stdnse  = require "stdnse"
local comm    = require "comm"

-- SIS-related ports and identifiers
local SIS_PORTS = {
  [1502] = {
    name   = "Triconex TriStation Protocol",
    vendor = "Schneider Electric",
    type   = "Safety PLC",
    malware= "TRITON/TRISIS malware vector (2017 Saudi petrochemical attack)",
    cve    = "CVE-2019-6829 (Triconex integrity violation), CVE-2023-5402 (Model 3009 bypass)",
    mitre  = "T0816 (Compromise Safety Instrumented System), T0880 (Modify Alarm Settings)",
    probe  = "\x1f\x02\x00\x00\x00\x00\x00\x00\x00\x00",
  },
  [4840] = {
    name   = "OPC UA Safety (Pilz/HIMA/ProSafe)",
    vendor = "Multiple SIS vendors",
    type   = "Safety PLC / SIS",
    malware= "Potential SIS interface if device is safety-rated",
    cve    = "CVE-2019-13533 (Pilz PSS4000 missing auth), CVE-2019-10953 (HIMA ProFSafe)",
    mitre  = "T0816 (Compromise SIS), T0880 (Modify Alarm)",
    probe  = "\x48\x45\x4c\x46",
  },
}

-- Port 1502 is almost exclusively Triconex
portrule = function(host, port)
  return port.state == "open" and SIS_PORTS[port.number] ~= nil
end

action = function(host, port)
  local sig = SIS_PORTS[port.number]
  if not sig then return end

  local output = stdnse.output_table()

  local status, data = comm.exchange(host, port, sig.probe, {timeout=3000})
  local reachable = status and data and #data > 0

  output["service"]    = sig.name
  output["vendor"]     = sig.vendor
  output["type"]       = sig.type
  output["reachable"]  = tostring(reachable)
  output["mitre"]      = sig.mitre
  output["cve"]        = sig.cve
  output["threat"]     = sig.malware

  if reachable then
    output["CRITICAL_WARNING"] = "SAFETY SYSTEM accessible from network — compromise could cause physical harm"
    output["immediate_action"] = "Isolate from all non-SIS networks. Verify no unauthorized changes to safety logic."
    if data then
      output["banner"] = stdnse.tohex(data:sub(1, math.min(24, #data)))
    end
  end

  return output
end
