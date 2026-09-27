description = [[
SCADA/HMI HTTP fingerprint — IXF issue #3
]]
author = "Andre Henrique (@mrhenrike) | IXF"
license = "MIT"
categories = {"discovery", "safe", "ics"}
portrule = "shortport.port_or_service(80, 'http')"
action = function(host, port)
  local http = require "http"
  local resp, err = http.get(host, port, "/")
  if resp and resp.status then
    portstate.set_port_state(host, port, "open", "HTTP " .. tostring(resp.status))
  end
end
