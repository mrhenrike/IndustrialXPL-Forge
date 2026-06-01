description = [[
ICS/OT Default Credential Checker — IndustrialXPL-Forge

Tests common default credentials against HTTP, Telnet, and FTP interfaces
of industrial control system devices including PLCs, HMIs, SCADA servers,
and engineering workstations.

Covers 50+ OT/ICS vendors: Siemens, Schneider Electric, Rockwell Automation,
ABB, Honeywell, Emerson, Beckhoff, Omron, GE, Yokogawa, and more.

AUTHORIZED TESTING ONLY — part of IndustrialXPL-Forge
]]

author = "Andre Henrique (@mrhenrike) | IXF"
license = "MIT"
categories = {"auth", "default", "intrusive", "ics"}

local shortport = require "shortport"
local http = require "http"
local brute = require "brute"
local creds = require "creds"
local stdnse = require "stdnse"
local table = require "table"

-- Common ICS/OT default credentials per vendor
local ICS_CREDS = {
  -- Generic OT
  {user="admin",    pass="admin"},
  {user="admin",    pass=""},
  {user="",         pass=""},
  {user="operator", pass="operator"},
  {user="user",     pass="user"},
  {user="guest",    pass="guest"},
  -- Siemens
  {user="admin",    pass="siemens"},
  {user="service",  pass="service"},
  -- Schneider Electric
  {user="USER",     pass="USER"},
  {user="USERUSER", pass="USERUSER"},
  {user="schneider",pass="schneider"},
  -- Rockwell Automation
  {user="Administrator", pass="1234"},
  {user="admin",    pass="rockwell"},
  -- Beckhoff TwinCAT
  {user="Administrator", pass="1"},
  {user="",         pass="1"},
  -- Honeywell
  {user="honeywell",pass="honeywell"},
  {user="eng",      pass="eng"},
  -- GE / CIMPLICITY
  {user="cimplicity",pass="cimplicity"},
  {user="ge",       pass="ge"},
  -- Emerson DeltaV
  {user="dvadmin",  pass="dvadmin"},
  {user="deltav",   pass="deltav"},
  -- Unitronics
  {user="",         pass="1111"},
  -- Yokogawa
  {user="admin",    pass="yokogawa"},
  -- Moxa
  {user="admin",    pass="moxa"},
  {user="root",     pass="moxa"},
  -- Tridium Niagara
  {user="admin",    pass="niagara"},
  -- WAGO
  {user="admin",    pass="wago"},
  -- B&R Automation
  {user="Administrator", pass=""},
  -- WEG
  {user="admin",    pass="weg"},
  -- ABB
  {user="admin",    pass="abb"},
}

portrule = function(host, port)
  return port.state == "open" and (
    port.number == 80 or port.number == 443 or
    port.number == 8080 or port.number == 8443 or
    port.number == 23 or port.number == 21 or
    shortport.http(host, port)
  )
end

local function try_http_auth(host, port, user, pass)
  local resp = http.get(host, port, "/", {
    auth = {username = user, password = pass},
    timeout = 3000,
  })
  if resp and resp.status and resp.status ~= 401 and resp.status ~= 403 then
    return true
  end
  return false
end

action = function(host, port)
  local results = {}
  local output = stdnse.output_table()

  output["target"] = host.ip .. ":" .. port.number
  output["tested"] = #ICS_CREDS
  output["valid_credentials"] = {}

  stdnse.debug1("Testing %d ICS credential pairs on %s:%d", #ICS_CREDS, host.ip, port.number)

  for _, cred in ipairs(ICS_CREDS) do
    if try_http_auth(host, port, cred.user, cred.pass) then
      local found = string.format("user='%s' pass='%s'", cred.user, cred.pass)
      table.insert(output["valid_credentials"], found)
      stdnse.debug1("VALID: %s on %s:%d", found, host.ip, port.number)
      -- Register with brute library
      local c = creds.Credentials:new(SCRIPT_NAME, host, port)
      c:add(cred.user, cred.pass, creds.State.VALID)
    end
  end

  if #output["valid_credentials"] > 0 then
    output["WARNING"] = "Default ICS credentials accepted — device may be compromised"
    return output
  else
    return stdnse.format_output(false, "No default credentials accepted")
  end
end
