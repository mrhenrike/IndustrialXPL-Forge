description = [[
OPC UA namespace browser smoke — IXF issue #3
]]
author = "Andre Henrique (@mrhenrike) | IXF"
license = "MIT"
categories = {"discovery", "safe", "ics"}
portrule = "shortport.port_or_service(4840, 'opcua')"
action = function(host, port)
  local s = nmap.new_socket()
  s:set_timeout(3000)
  if s:connect(host, port) then
    portstate.set_port_state(host, port, "open", "OPC UA TCP")
    s:close()
  end
end
