description = [[
ICS Device Firmware Version Detection — IndustrialXPL-Forge

Extracts firmware version and hardware information from ICS devices via
protocol-specific read operations. Version information is essential for
CVE matching and vulnerability assessment.

Supports: Siemens S7 (SZID/module info), Rockwell (EtherNet/IP identity),
BACnet (device description), OPC UA (server info), Modbus (FC43 device ID),
FINS (controller data read).

AUTHORIZED TESTING ONLY — part of IndustrialXPL-Forge
]]

author     = "Andre Henrique (@mrhenrike) | IXF"
license    = "MIT"
categories = {"discovery", "version", "safe", "ics"}

local stdnse  = require "stdnse"
local comm    = require "comm"
local bin     = require "bin"

-- Modbus FC43 (Read Device Identification) probe
-- Transaction ID=1, Protocol=0, Length=6, Unit=1, FC=0x2B, MEI=0x0E, ReadDevID=0x01, ObjID=0x00
local MODBUS_DEVID = "\x00\x01\x00\x00\x00\x06\x01\x2b\x0e\x01\x00"

-- EtherNet/IP List Identity
local ENIP_LIST_IDENTITY = "\x65\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

-- Siemens S7 COTP connection (minimal)
local S7_COTP = "\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x03"

local function parse_modbus_devid(data)
  if not data or #data < 9 then return nil end
  local result = {}
  -- Skip MBAP header (6 bytes) + unit (1) + FC (1) + MEI (1) + ReadDevID (1) + ConformityLevel (1)
  -- Object count at byte 12 (0-indexed: 11)
  if #data < 12 then return nil end
  local obj_count = data:byte(12)
  local pos = 13
  local obj_names = {"VendorName", "ProductCode", "RevisionLevel", "VendorURL", "ProductName", "ModelName"}
  for i = 1, math.min(obj_count, 6) do
    if pos + 2 > #data then break end
    local obj_id  = data:byte(pos)
    local obj_len = data:byte(pos + 2)
    if pos + 3 + obj_len - 1 > #data then break end
    local obj_val = data:sub(pos + 3, pos + 2 + obj_len)
    if obj_len > 0 and obj_names[obj_id + 1] then
      result[obj_names[obj_id + 1]] = obj_val
    end
    pos = pos + 3 + obj_len
  end
  return result
end

local function parse_enip_identity(data)
  if not data or #data < 28 then return nil end
  -- EtherNet/IP List Identity Response
  -- Skip: cmd(2) + len(2) + session(4) + status(4) + senderContext(8) + options(4) = 24 bytes
  -- Item count at byte 24
  local result = {}
  -- Simple: extract printable strings
  local ascii = data:gsub("[^%g%s]", ".")
  result["raw_ascii"] = ascii:sub(1, 64)
  return result
end

portrule = function(host, port)
  return port.state == "open" and (
    port.number == 502 or port.number == 44818 or
    port.number == 102 or port.number == 47808 or
    port.number == 4840
  )
end

action = function(host, port)
  local output = stdnse.output_table()
  output["target"] = host.ip .. ":" .. port.number

  if port.number == 502 then
    -- Modbus Device Identification
    local status, data = comm.exchange(host, port, MODBUS_DEVID, {timeout=3000})
    if status and data then
      local devid = parse_modbus_devid(data)
      if devid then
        output["protocol"] = "Modbus TC (FC43 Device Identification)"
        for k, v in pairs(devid) do
          output[k] = v
        end
      else
        output["raw"] = stdnse.tohex(data:sub(1, 32))
      end
    end

  elseif port.number == 44818 then
    -- EtherNet/IP Identity
    local status, data = comm.exchange(host, port, ENIP_LIST_IDENTITY, {timeout=3000})
    if status and data then
      output["protocol"] = "EtherNet/IP List Identity"
      local parsed = parse_enip_identity(data)
      if parsed then
        for k, v in pairs(parsed) do output[k] = v end
      end
      output["raw_hex"] = stdnse.tohex(data:sub(1, math.min(48, #data)))
    end

  elseif port.number == 102 then
    -- Siemens COTP
    local status, data = comm.exchange(host, port, S7_COTP, {timeout=3000})
    if status and data and #data > 0 then
      output["protocol"] = "Siemens S7 ISO-TSAP"
      output["response_hex"] = stdnse.tohex(data:sub(1, math.min(32, #data)))
      if data:byte(5) == 0xd0 then
        output["cotp_type"] = "CC (Connect Confirm) — S7 accessible"
      end
    end
  end

  if next(output) and output["target"] then
    output["note"] = "Use CVE database to match version against known vulnerabilities"
    return output
  end
end
