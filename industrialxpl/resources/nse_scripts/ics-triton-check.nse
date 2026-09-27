description = [[
Triconex SIS accessible check (TRITON vector) — IXF issue #3
]]
author = "Andre Henrique (@mrhenrike) | IXF"
license = "MIT"
categories = {"discovery", "safe", "ics"}
portrule = "shortport.port_or_service(1502, 'tristation') or shortport.port_or_service(1502)"
action = function(host, port)
  local s = nmap.new_socket()
  s:set_timeout(3000)
  if s:connect(host, port) then
    portstate.set_port_state(host, port, "open", "TriStation TCP probe")
    s:close()
  end
end
