description = [[
Modbus coil/register read — IXF issue #3
]]
author = "Andre Henrique (@mrhenrike) | IXF"
license = "MIT"
categories = {"discovery", "safe", "ics"}
portrule = "shortport.port_or_service(502, 'modbus-tcp')"
action = function(host, port)
  local status, result = comm.exchange(host, port, "\x00\x01\x00\x00\x00\x06\x01\x01\x00\x00\x00\x01", {timeout=3000})
  if status then
    portstate.set_port_state(host, port, "open", "Modbus FC01 response")
  end
end
