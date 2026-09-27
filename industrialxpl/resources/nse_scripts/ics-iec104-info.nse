description = [[
IEC 60870-5-104 substation info — IXF issue #3
]]
author = "Andre Henrique (@mrhenrike) | IXF"
license = "MIT"
categories = {"discovery", "safe", "ics"}
portrule = "shortport.port_or_service(2404, 'iec104')"
action = function(host, port)
  local status, result = comm.exchange(host, port, "\x68\x04\x07\x00\x00\x00", {timeout=3000})
  if status then
    portstate.set_port_state(host, port, "open", "IEC-104 STARTDT")
  end
end
