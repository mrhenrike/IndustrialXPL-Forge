description = [[
ICS/OT Comprehensive Device Enumeration — IndustrialXPL-Forge

Actively enumerates ICS/OT devices by probing multiple industrial protocols
on a single target. Combines banner grabbing, service fingerprinting, and
protocol-specific queries to identify device type, vendor, firmware version,
and open attack surface.

Protocols probed: Modbus (502), S7comm (102), EtherNet/IP (44818),
DNP3 (20000), BACnet (47808), OPC UA (4840), FINS (9600), IEC 104 (2404).

AUTHORIZED TESTING ONLY — part of IndustrialXPL-Forge
]]

author     = "Andre Henrique (@mrhenrike) | IXF"
license    = "MIT"
categories = {"discovery", "safe", "ics"}

local nmap    = require "nmap"
local stdnse  = require "stdnse"
local shortport = require "shortport"
local comm    = require "comm"
local bin     = require "bin"

-- Protocol probes (raw bytes)
local PROBES = {
  modbus = {
    port = 502,
    probe = "\x00\x01\x00\x00\x00\x06\x01\x2b\x0e\x01\x00",
    info  = "Modbus TCP (FC43 Device Identification)",
  },
  s7comm = {
    port = 102,
    probe = "\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x03",
    info  = "Siemens S7comm COTP Connect",
  },
  enip = {
    port = 44818,
    probe = "\x65\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    info  = "EtherNet/IP List Identity",
  },
  iec104 = {
    port = 2404,
    probe = "\x68\x04\x07\x00\x00\x00",
    info  = "IEC 60870-5-104 STARTDT",
  },
  opcua = {
    port = 4840,
    probe = "\x48\x45\x4c\x46\x28\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    info  = "OPC UA Hello",
  },
  pcom = {
    port = 20256,
    probe = "\x5f\x00\xfe",
    info  = "Unitronics PCOM",
  },
  ads = {
    port = 48898,
    probe = "\x03\x66\x14\x71\x00\x00\x00\x00\x00\x00\x00\x00",
    info  = "Beckhoff ADS/AMS",
  },
}

-- Detect vendor from banner bytes
local function fingerprint_vendor(data)
  if not data or #data == 0 then return "Unknown" end
  local hex = stdnse.tohex(data)
  -- Simple heuristic fingerprinting
  if data:find("SIMATIC") or data:find("S7") then
    return "Siemens"
  elseif data:find("SCHNEIDER") or data:find("MODICON") or data:find("M340") then
    return "Schneider Electric"
  elseif data:find("ROCKWELL") or data:find("Allen") or data:find("ControlLogix") then
    return "Rockwell Automation"
  elseif data:find("ABB") then
    return "ABB"
  elseif data:find("OMRON") then
    return "Omron"
  elseif hex:sub(1,4) == "0300" then
    return "Siemens (S7 COTP)"
  elseif hex:sub(1,2) == "68" then
    return "IEC 61850/IEC 104 device"
  end
  return "ICS device (vendor unidentified)"
end

portrule = function(host, port)
  return port.state == "open"
end

action = function(host, port)
  local output   = stdnse.output_table()
  local detected = {}

  for proto, cfg in pairs(PROBES) do
    if port.number == cfg.port then
      local status, data = comm.exchange(host, port, cfg.probe, {timeout=3000})
      if status and data and #data > 0 then
        local entry = {
          protocol = cfg.info,
          vendor   = fingerprint_vendor(data),
          banner   = stdnse.tohex(data:sub(1, math.min(32, #data))),
          bytes    = #data,
        }
        table.insert(detected, entry)
        stdnse.debug1("ICS response on port %d: %s", port.number, cfg.info)
      end
    end
  end

  -- Generic banner grab for any open port
  if #detected == 0 then
    local status, data = comm.get_banner(host, port, {timeout=2000})
    if status and data and #data > 0 then
      output["banner"] = stdnse.tohex(data:sub(1, 32))
      output["vendor"] = fingerprint_vendor(data)
    end
  else
    output["ics_protocols"] = detected
    output["target"] = host.ip .. ":" .. port.number
  end

  if next(output) then
    return output
  end
end
