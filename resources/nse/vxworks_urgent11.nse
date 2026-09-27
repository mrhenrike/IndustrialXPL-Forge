local ftp = require "ftp"
local shortport = require "shortport"
local stdnse = require "stdnse"
local vulns = require "vulns"

description = [[
VxWorks OS is affected by 11 vulnerabilities (6 Remote Code Execution - 5 Information Leaks, Denial of Service, Logical Flaws) 
due to an issue in the TCP/IP Stack implementation (IPnet). 
All versions between 6.5 (included) and 7 (excluded) are affected.

CVE--2019-12255: TCP Urgent Pointer = 0 leads to integer underflow
CVE--2019-12256: Stack overflow in the parsing of IPv4 packets’ IP options
CVE--2019-12257: Heap overflow in DHCP Offer/ACK parsing inside ipdhcpc
CVE--2019-12258: Denial of Service (DoS) of TCP connection via malformed TCP options
CVE--2019-12259: DoS via NULL dereference in IGMP parsing
CVE--2019-12260: TCP Urgent Pointer state confusion caused by malformed TCP AO option
CVE--2019-12261: TCP Urgent Pointer state confusion during connect() to a remote host
CVE--2019-12262: Handling of unsolicited Reverse Address Resolution Protocol (ARP) replies
CVE--2019-12263: TCP Urgent Pointer state confusion due to race condition
CVE--2019-12264: Logical flaw in IPv4 assignment by the ipdhcpc DHCP client
CVE--2019-12265: IGMP information leak via IGMPv3 specific membership report

Reference:
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE--2019-12255
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE--2019-12256
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE--2019-12257
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE--2019-12258
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE--2019-12259
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE--2019-12260
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE--2019-12261
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE--2019-12262
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE--2019-12263
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE--2019-12264
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE--2019-12265

]]

---
-- @usage
-- nmap --script vxworks_urgent11.nse -p 21 <host>
--
-- @output
-- PORT   STATE SERVICE
-- 21/tcp open  ftp
-- | vxworks_urgent11:
-- |   VULNERABLE:
-- |   VxWorks OS TCP/IP stack (IPnet) multiple vulnerabilities
-- |     State: VULNERABLE
-- |     IDs:  CVEs: CVE-2019-122(55-65) -  CWE-IDs: 88|119|384|399|476
-- |     Risk factor: High  CVSSv3: 9.8 (HIGH)
-- |     Description:
-- |       VxWorks OS is affected by 11 vulnerabilities (6 Remote Code Execution - 5 Information Leaks, Denial of Service, Logical Flaws) 
-- |       due to an issue in the TCP/IP Stack implementation (IPnet). All versions between 6.5 (included) and 7 (excluded) are affected.
-- |     Disclosure date: 2019-07-30
-- |     References:
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE--2019-12255
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE--2019-12256
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE--2019-12257
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE--2019-12258
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE--2019-12259
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE--2019-12260
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE--2019-12261
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE--2019-12262
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE--2019-12263
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE--2019-12264
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE--2019-12265
-- |       
--

author = "Younes Dragoni - Security Researcher @(Nozomi Networks Labs)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "vuln"}

portrule = function (host, port)
  if port.version.product ~= nil and port.version.product ~= "VxWorks" then
    return false
  end
  return shortport.port_or_service(21, "ftp")(host, port)
end

local function get_vxworks_banner(banner)
  local version
  local v1
  local v2
  if banner then
    v1, v2 = banner:match("VxWorks%s(%d+).(%d+)")
  end
  stdnse.debug2(version)
  return banner, v1, v2
end

local function ftp_finish(socket, status, message)
  if socket then
    socket:close()
  end
  return status, message
end

-- Returns true if the provided version is vulnerable - source: https://www.windriver.com/security/announcements/tcp-ip-network-stack-ipnet-urgent11/security-advisory-ipnet/
-- advisories are going to be added based on the VxWorks OS version
local function is_version_vulnerable(v1, v2, description)
  CVEs = {
    [12255] = 'CVE--2019-12255: TCP Urgent Pointer = 0 leads to integer underflow',
    [12256] = 'CVE--2019-12256: Stack overflow in the parsing of IPv4 packets’ IP options',
    [12257] = 'CVE--2019-12257: Heap overflow in DHCP Offer/ACK parsing inside ipdhcpc',
    [12258] = 'CVE--2019-12258: Denial of Service (DoS) of TCP connection via malformed TCP options',
    [12259] = 'CVE--2019-12259: DoS via NULL dereference in IGMP parsing',
    [12260] = 'CVE--2019-12260: TCP Urgent Pointer state confusion caused by malformed TCP AO option',
    [12261] = 'CVE--2019-12261: TCP Urgent Pointer state confusion during connect() to a remote host',
    [12262] = 'CVE--2019-12262: Handling of unsolicited Reverse Address Resolution Protocol (ARP) replies',
    [12263] = 'CVE--2019-12263: TCP Urgent Pointer state confusion due to race condition',
    [12264] = 'CVE--2019-12264: Logical flaw in IPv4 assignment by the ipdhcpc DHCP client',
    [12265] = 'CVE--2019-12265: IGMP information leak via IGMPv3 specific membership report',
  }
  if tonumber(v1) == 7 or (tonumber(v1) < 7 and tonumber(v2) < 6)  then
    return false
  else
    if (tonumber(v1) == 6 and tonumber(v2) == 5) or (tonumber(v1) == 9  and tonumber(v2) == 4) then
      CVEs[12255] = nil
    end
    if (tonumber(v1) < 7 and tonumber(v2) < 9) then
      CVEs[12256] = nil
    end
    if (tonumber(v1) == 6 and tonumber(v2) == 5) or (tonumber(v1) == 9  and tonumber(v2) == 4) then
      CVEs[12257] = nil
    end
    if (tonumber(v1) == 6 and tonumber(v2) == 5) then
      CVEs[12258] = nil
      CVEs[12259] = nil
      CVEs[12262] = nil
      CVEs[12264] = nil
      CVEs[12265] = nil
    end
    if (tonumber(v1) < 7 and tonumber(v2) < 9) or (tonumber(v1) == 9 and tonumber(v2) == 3) then
      CVEs[12260] = nil
    end
    if (tonumber(v1) < 7 and tonumber(v2) < 7)  then
      CVEs[12261] = nil
    end
    if (tonumber(v1) < 7 and tonumber(v2) < 6) then
      CVEs[12263] = nil
    end
    return true, CVEs
  end

end

local function check_vxworks(ftp_opts)
  local ftp_server = {}
  local socket, code, message = ftp.connect(ftp_opts.host, ftp_opts.port)
  if not socket then
    return socket, code
  end
  
  ftp_server.banner, ftp_server.v1, ftp_server.v2 = get_vxworks_banner(message)
  if not ftp_server.banner then
    return ftp_finish(socket, false, "failed to get FTP banner.")
  elseif not ftp_server.banner:match("VxWorks") then
    return ftp_finish(socket, false, "not a VxWorks server.")
  end
  local vuln = ftp_opts.vuln
  if ftp_server.v1 and ftp_server.v2 then
    local check, CVEs = is_version_vulnerable(ftp_server.v1, ftp_server.v2, ftp_opts.vuln.description)
    if not check then
      vuln.state = vulns.STATE.NOT_VULN
      return ftp_finish(socket, true), nil, ftp_server.banner
    end
    vuln.state = vulns.STATE.LIKELY_VULN
  end
  return ftp_finish(socket, true), CVEs, ftp_server.banner
end


action = function(host, port)
  local ftp_opts = {
    host = host,
    port = port,
    vuln = {
      title = 'VxWorks Urgent/11 vulnerabilities',
      IDS = {CVE = 'CVE-2019-122(55-65)' , CWEs = '88|119|384|399|476'},
      risk_factor = "High",
      scores = {
        CVSSv2 = "10.0 (HIGH) (AV:N/AC:L/Au:N/C:C/I:C/A:C)",
      },
      description = [[
        VxWorks OS is affected by 11 vulnerabilities (6 Remote Code Execution - 5 Information Leaks, Denial of Service, Logical Flaws) 
        due to an issue in the TCP/IP Stack implementation (IPnet). 
        All versions between 6.5 (included) and 7 (excluded) are likely exploitable.
        Affected vulnerabilities:

      ]],
      references = {
        'https://www.us-cert.gov/ics/advisories/icsa-19-211-01',
        'https://www.windriver.com/security/announcements/tcp-ip-network-stack-ipnet-urgent11/security-advisory-ipnet/',
      },
      dates = {
        disclosure = {year = 2019, month = 07, day = 30},
      },
      extra_info = {
      },
    }
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)

  -- local state = check_vxworks(ftp_opts)
  local status, err, banner = check_vxworks(ftp_opts)
  if not status then
    stdnse.debug1("%s", err)
    return nil
  end
  if err ~= nil then
    for _,v in pairs(err) do 
      ftp_opts.vuln.description = ftp_opts.vuln.description .. '\t' .. v .. '\n'
    end
  end
  ftp_opts.vuln.extra_info = "Banner Grabbing: " .. banner

  return report:make_output(ftp_opts.vuln)
end
