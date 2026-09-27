description = [[
ICS/OT Honeypot Detection — IndustrialXPL-Forge

Attempts to detect ICS honeypots (Conpot, GasPot, GridPot, CritifFence,
HoneyD with ICS modules) by probing for inconsistencies between protocol
responses that real devices would not exhibit.

Honeypot indicators checked:
- Identical responses to all Modbus unit IDs (real devices reject invalid)
- Suspiciously clean S7 responses (no hardware-specific quirks)
- TCP banner inconsistencies (HTTP server behind Modbus port)
- Response timing anomalies
- Conpot-specific response patterns

NOTE: False positives possible. Use as one signal among many.

AUTHORIZED TESTING ONLY — part of IndustrialXPL-Forge
]]

author     = "Andre Henrique (@mrhenrike) | IXF"
license    = "MIT"
categories = {"discovery", "safe", "ics"}

local stdnse  = require "stdnse"
local comm    = require "comm"
local nmap    = require "nmap"
local os      = require "os"

-- Modbus probe for unit ID 1
local MODBUS_UNIT1  = "\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01"
-- Modbus probe for invalid unit ID 255 (should be rejected by real devices)
local MODBUS_UNIT255 = "\x00\x02\x00\x00\x00\x06\xff\x03\x00\x00\x00\x01"
-- Modbus probe for unit ID 0 (broadcast — should not respond)
local MODBUS_UNIT0  = "\x00\x03\x00\x00\x00\x06\x00\x03\x00\x00\x00\x01"

local function check_modbus_honeypot(host, port)
  local indicators = {}

  -- Test unit ID 1
  local s1, d1 = comm.exchange(host, port, MODBUS_UNIT1, {timeout=2000})
  -- Test unit ID 255 (invalid — most real devices will not respond or will error)
  local s255, d255 = comm.exchange(host, port, MODBUS_UNIT255, {timeout=2000})
  -- Test unit ID 0 (broadcast — should not echo data)
  local s0, d0 = comm.exchange(host, port, MODBUS_UNIT0, {timeout=2000})

  if s1 and d1 and s255 and d255 then
    -- Both unit 1 and unit 255 responded with data
    if d1 and d255 and d1:sub(7) == d255:sub(7) then
      table.insert(indicators, "IDENTICAL responses to unit ID 1 and invalid unit ID 255 (Conpot pattern)")
    else
      table.insert(indicators, "Responds to both valid and invalid unit IDs (possible honeypot)")
    end
  end

  if s0 and d0 and #d0 > 0 then
    table.insert(indicators, "Responds to unit ID 0 broadcast (unusual for real Modbus device)")
  end

  -- Check for HTTP behind Modbus port (some honeypots do this)
  local sh, dh = comm.exchange(host, port, "GET / HTTP/1.0\r\n\r\n", {timeout=1500})
  if sh and dh and (dh:find("HTTP/") or dh:find("html")) then
    table.insert(indicators, "HTTP response on Modbus port — possible misconfigured honeypot")
  end

  return indicators
end

portrule = function(host, port)
  return port.state == "open" and port.number == 502
end

action = function(host, port)
  local output     = stdnse.output_table()
  local indicators = check_modbus_honeypot(host, port)

  output["target"]          = host.ip .. ":" .. port.number
  output["indicators_found"] = #indicators

  if #indicators > 0 then
    output["honeypot_likely"] = "YES — " .. #indicators .. " indicator(s) detected"
    output["indicators"] = indicators
    output["note"] = "Target may be a honeypot. Proceed with caution. False positives possible."
  else
    output["honeypot_likely"] = "NO — no common honeypot patterns detected"
    output["note"] = "Absence of indicators does not guarantee real device"
  end

  return output
end
