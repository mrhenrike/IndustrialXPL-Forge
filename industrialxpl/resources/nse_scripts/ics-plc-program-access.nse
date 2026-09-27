description = [[
ICS PLC Program Upload/Download Accessibility Check — IndustrialXPL-Forge

Checks if PLC engineering ports are accessible from the network without
authentication. Unauthorized program access allows an attacker to read
(upload) the PLC logic or overwrite (download) it with malicious code.

Checks: Siemens S7 (102), Rockwell EtherNet/IP (44818), CODESYS (11740),
Unitronics PCOM (20256), Beckhoff ADS (48898), Omron FINS (9600).

Does NOT attempt to upload/download programs — only checks reachability
and performs a safe handshake to confirm the service is accessible.

AUTHORIZED TESTING ONLY — part of IndustrialXPL-Forge
]]

author     = "Andre Henrique (@mrhenrike) | IXF"
license    = "MIT"
categories = {"discovery", "safe", "ics"}

local stdnse  = require "stdnse"
local comm    = require "comm"
local bin     = require "bin"

-- Engineering port fingerprints
local ENG_PORTS = {
  [102]   = {
    name   = "Siemens S7 Engineering (ISO-TSAP)",
    vendor = "Siemens",
    probe  = "\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x03",
    mitre  = "T0845 (Program Upload), T0843 (Program Download)",
    cve    = "CVE-2021-22681 (S7 hardcoded TLS key), CVE-2022-38465 (global RSA key)",
  },
  [44818] = {
    name   = "Rockwell EtherNet/IP CIP Engineering",
    vendor = "Rockwell Automation",
    probe  = "\x65\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    mitre  = "T0845 (Program Upload), T0839 (Modify Program)",
    cve    = "CVE-2022-1161 (firmware modification), CVE-2023-3595 (1756-EN2x RCE)",
  },
  [11740] = {
    name   = "CODESYS V3 Runtime Engineering",
    vendor = "CODESYS",
    probe  = "\x12\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    mitre  = "T0839 (Modify Program), T0843 (Program Download)",
    cve    = "CVE-2022-47379 (heap overflow RCE), CVE-2022-31806 (default creds)",
  },
  [20256] = {
    name   = "Unitronics PCOM Engineering",
    vendor = "Unitronics",
    probe  = "\x5f\x00\xfe",
    mitre  = "T0845 (Program Upload)",
    cve    = "CVE-2023-6448 (default creds — CISA 2023 water utility alert)",
  },
  [48898] = {
    name   = "Beckhoff ADS/AMS TwinCAT Engineering",
    vendor = "Beckhoff",
    probe  = "\x03\x66\x14\x71\x00\x00\x00\x00\x00\x00\x00\x00",
    mitre  = "T0836 (Modify Parameter), T0843 (Program Download)",
    cve    = "CVE-2019-5637 (UPnP missing auth), CVE-2023-21640 (ADS DoS)",
  },
  [9600]  = {
    name   = "Omron FINS Network Engineering",
    vendor = "Omron",
    probe  = "\x46\x49\x4e\x53\x00\x00\x00\x0c\x00\x00\x00\x02\x00\x00\x00\x00",
    mitre  = "T0845 (Program Upload), T0821 (Modify Controller Tasking)",
    cve    = "CVE-2023-27396 (CJ2M FINS missing auth)",
  },
}

portrule = function(host, port)
  return port.state == "open" and ENG_PORTS[port.number] ~= nil
end

action = function(host, port)
  local sig = ENG_PORTS[port.number]
  if not sig then return end

  local output  = stdnse.output_table()
  local reachable = false

  -- Safe probe — just handshake, no program operations
  local status, data = comm.exchange(host, port, sig.probe, {timeout=3000})
  if status and data and #data > 0 then
    reachable = true
    output["banner_hex"] = stdnse.tohex(data:sub(1, math.min(24, #data)))
  end

  output["service"]     = sig.name
  output["vendor"]      = sig.vendor
  output["reachable"]   = tostring(reachable)
  output["mitre"]       = sig.mitre
  output["related_cve"] = sig.cve

  if reachable then
    output["WARNING"] = "Engineering port ACCESSIBLE from network — program upload/download may be possible without authentication"
    output["risk"]    = "CRITICAL — unauthorized PLC logic modification"
  else
    output["status"]  = "Engineering port not responding to probe"
  end

  return output
end
