description = [[
ICS Process Historian Discovery — IndustrialXPL-Forge

Discovers process historian servers used in industrial environments:
OSIsoft PI Server, AVEVA System Platform, AspenTech InfoPlus.21,
Canary Labs, GE Proficy Historian, Emerson DeltaV Historian.

Historians store years of plant process data and are high-value targets
for operational intelligence and sabotage.

Probes: PI SDK (5450), AVEVA Galaxy (5413), AspenTech (10014),
MSSQL (1433), OPC HDA (135).

AUTHORIZED TESTING ONLY — part of IndustrialXPL-Forge
]]

author     = "Andre Henrique (@mrhenrike) | IXF"
license    = "MIT"
categories = {"discovery", "safe", "ics"}

local stdnse  = require "stdnse"
local shortport = require "shortport"
local comm    = require "comm"

-- Historian service signatures
local HISTORIAN_PORTS = {
  [5450]  = {name="OSIsoft PI Data Archive",          vendor="OSIsoft/AVEVA"},
  [5413]  = {name="AVEVA System Platform Galaxy",     vendor="AVEVA"},
  [10014] = {name="AspenTech Aspen InfoPlus.21",      vendor="AspenTech"},
  [1433]  = {name="SQL Server (possibly historian)",  vendor="Microsoft/GE/Emerson"},
  [135]   = {name="OPC HDA/Classic (DCOM)",           vendor="Multiple"},
  [49320] = {name="Kepware/PTC KEPServerEX OPC",      vendor="PTC/Kepware"},
  [57412] = {name="PTC ThingWorx/Kepware",            vendor="PTC"},
  [4840]  = {name="OPC UA Server (historian)",        vendor="Multiple"},
  [22350] = {name="GE Proficy Historian",             vendor="GE Vernova"},
  [11234] = {name="Canary Labs Historian",            vendor="Canary Labs"},
  [55555] = {name="Honeywell Experion PKS",           vendor="Honeywell"},
}

portrule = function(host, port)
  return port.state == "open" and HISTORIAN_PORTS[port.number] ~= nil
end

action = function(host, port)
  local sig = HISTORIAN_PORTS[port.number]
  if not sig then return end

  local output = stdnse.output_table()
  output["service"]  = sig.name
  output["vendor"]   = sig.vendor
  output["address"]  = host.ip .. ":" .. port.number

  -- Probe for banner
  local status, data = comm.get_banner(host, port, {timeout=2000})
  if status and data and #data > 0 then
    output["banner"] = stdnse.tohex(data:sub(1, 32))
  end

  output["risk"] = "Historian servers store all process data — high-value target"
  output["mitigation"] = "Ensure historian is in DMZ; restrict access to engineering VLANs"

  return output
end
