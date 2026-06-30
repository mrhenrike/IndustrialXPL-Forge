description = [[
DNP3 outstation enumeration — IXF issue #3
]]
author = "Andre Henrique (@mrhenrike) | IXF"
license = "MIT"
categories = {"discovery", "safe", "ics"}
portrule = "shortport.port_or_service(20000, 'dnp3')"
action = function(host, port)
  local s = nmap.new_socket()
  s:set_timeout(3000)
  if s:connect(host, port) then
    portstate.set_port_state(host, port, "open", "DNP3 TCP open")
    s:close()
  end
end
