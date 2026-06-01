# Scripts NSE para ICS/OT

O IXF inclui um conjunto de scripts NSE (Nmap Scripting Engine) específicos para reconhecimento e fingerprinting de dispositivos ICS/OT. Esses scripts estendem as capacidades do Nmap para protocolos industriais que não são cobertos pelos scripts NSE padrão.

---

## Índice

1. [Visão Geral](#visão-geral)
2. [Instalação: `nse install` com Saída Completa](#instalação-nse-install-com-saída-completa)
3. [Os 8 Scripts NSE Detalhados](#os-8-scripts-nse-detalhados)
   - [modbus-enum.nse](#1-modbus-enumnse)
   - [s7-enumerate.nse](#2-s7-enumeratensenão)
   - [enip-list.nse](#3-enip-listnse)
   - [bacnet-info.nse](#4-bacnet-infonse)
   - [dnp3-info.nse](#5-dnp3-infonse)
   - [opcua-enum.nse](#6-opcua-enumnse)
   - [profinet-dcp.nse](#7-profinet-dcpnse)
   - [ics-detect.nse](#8-ics-detectnse)
4. [Exemplos Combinados](#exemplos-combinados)
5. [Escrevendo Scripts NSE Personalizados](#escrevendo-scripts-nse-personalizados)

---

## Visão Geral

Os scripts NSE do IXF são desenvolvidos para:

- **Fingerprinting de protocolos ICS** — identificar devices Modbus, S7, EtherNet/IP, BACnet, DNP3, OPC UA e PROFINET
- **Enumeração de ativos** — extrair informações detalhadas (fabricante, modelo, versão de firmware)
- **Detecção multi-protocolo** — varredura única que detecta qualquer protocolo ICS presente
- **Integração com pipeline Nmap** — saída compatível com formatos -oN, -oX, -oJ do Nmap

### Pré-requisitos

```bash
# Nmap 7.80 ou superior
nmap --version

# Python 3.10+ (para geração de scripts IXF)
python3 --version

# Instalar scripts via IXF
ixf -c "nse install"
```

---

## Instalação: `nse install` com Saída Completa

```bash
$ ixf -c "nse install"
[*] Instalando scripts NSE ICS do IXF...

  Detectando diretório de scripts Nmap...
  [+] Encontrado: /usr/share/nmap/scripts/

  Copiando scripts:
  [+] modbus-enum.nse      → /usr/share/nmap/scripts/modbus-enum.nse
  [+] s7-enumerate.nse     → /usr/share/nmap/scripts/s7-enumerate.nse
  [+] enip-list.nse        → /usr/share/nmap/scripts/enip-list.nse
  [+] bacnet-info.nse      → /usr/share/nmap/scripts/bacnet-info.nse
  [+] dnp3-info.nse        → /usr/share/nmap/scripts/dnp3-info.nse
  [+] opcua-enum.nse       → /usr/share/nmap/scripts/opcua-enum.nse
  [+] profinet-dcp.nse     → /usr/share/nmap/scripts/profinet-dcp.nse
  [+] ics-detect.nse       → /usr/share/nmap/scripts/ics-detect.nse

  Atualizando banco de dados de scripts Nmap...
  [*] Executando: nmap --script-updatedb
      Starting Nmap 7.94...
      NSE: Updating rule database.
      NSE: Script Database updated successfully.
  [+] Banco de dados de scripts atualizado.

  Verificando instalação...
  [+] modbus-enum.nse: OK
  [+] s7-enumerate.nse: OK
  [+] enip-list.nse: OK
  [+] bacnet-info.nse: OK
  [+] dnp3-info.nse: OK
  [+] opcua-enum.nse: OK
  [+] profinet-dcp.nse: OK
  [+] ics-detect.nse: OK

  [+] 8 scripts NSE instalados com sucesso.
  [i] Para listar: ixf -c "nse list"
  [i] Para executar: nmap --script modbus-enum -p 502 <alvo>
  [i] Ou via IXF: ixf -c "nse run modbus-enum <alvo>"
```

### Instalação Manual (alternativa)

```bash
# Copiar scripts manualmente
sudo cp industrialxpl/resources/nse_scripts/*.nse /usr/share/nmap/scripts/

# Atualizar banco de dados
sudo nmap --script-updatedb

# Verificar scripts disponíveis
nmap --script-help modbus-enum
```

### Instalação no Windows

```powershell
# Localizar diretório de scripts Nmap
$NmapScripts = "C:\Program Files (x86)\Nmap\scripts\"

# Copiar scripts
Copy-Item "industrialxpl\resources\nse_scripts\*.nse" $NmapScripts

# Atualizar banco de dados
& "C:\Program Files (x86)\Nmap\nmap.exe" --script-updatedb
```

---

## Os 8 Scripts NSE Detalhados

### 1. modbus-enum.nse

**Descrição:** Enumera dispositivos Modbus TCP, identifica o vendor/fabricante, obtém informações de device identification (FC43/MEI) e testa múltiplos unit IDs para descobrir dispositivos em sistemas multi-drop.

**Sintaxe:**
```bash
nmap --script modbus-enum [--script-args modbus-enum.unit_ids=<range>] -p 502 <alvo>
```

**Argumentos do script:**

| Argumento | Tipo | Padrão | Descrição |
|-----------|------|--------|-----------|
| `modbus-enum.unit_ids` | string | `"1-10"` | Range de unit IDs a testar (ex: "1-247" para completo) |
| `modbus-enum.registers` | bool | `false` | Se true, tenta ler registradores 0-10 |
| `modbus-enum.timeout` | int | `3` | Timeout em segundos |

**Exemplo 1 — scan básico:**
```bash
$ nmap --script modbus-enum -p 502 192.168.1.100

Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 192.168.1.100

PORT    STATE SERVICE
502/tcp open  modbus
| modbus-enum:
|   Unit ID 1:
|     Device Identification (FC43/MEI):
|       Vendor Name:     Schneider Electric
|       Product Code:    BMXP342020H
|       Major Firmware:  2
|       Minor Firmware:  50
|       Product Name:    Modicon M340 BMXP342020H
|       Hardware Serial: 00-00-42-F5-A8-11
|     Modbus Response:
|       Function Code:   FC3 (Read Holding Registers)
|       Response:        Valid (8 bytes received)
|_  1 unit ID(s) responded of 10 tested
```

**Exemplo 2 — scan com todos os unit IDs:**
```bash
$ nmap --script modbus-enum --script-args modbus-enum.unit_ids=1-247 -p 502 10.0.0.0/24

Starting Nmap 7.94...
Nmap scan report for 10.0.0.5

PORT    STATE SERVICE
502/tcp open  modbus
| modbus-enum:
|   Unit ID 1: Schneider Electric Modicon M340
|   Unit ID 10: Generic Modbus RTU (no identification)
|   Unit ID 100: ABB SREA-01 Ethernet Adapter
|_  3 unit ID(s) responded of 247 tested

Nmap scan report for 10.0.0.12

PORT    STATE SERVICE
502/tcp open  modbus
| modbus-enum:
|   Unit ID 1: Yokogawa STARDOM FCN/FCJ Controller
|_  1 unit ID(s) responded of 247 tested
```

**Exemplo 3 — com leitura de registradores:**
```bash
$ nmap --script modbus-enum --script-args modbus-enum.registers=true -p 502 192.168.1.100

PORT    STATE SERVICE
502/tcp open  modbus
| modbus-enum:
|   Unit ID 1:
|     Vendor: Schneider Electric
|     Sample Holding Registers (FC3, HR[0-9]):
|       HR[0]:  1234
|       HR[1]:  5678
|       HR[2]:  9012
|       HR[3]:  3456
|       HR[4]:  7890
|_  Caution: register values may be operational data
```

---

### 2. s7-enumerate.nse

**Descrição:** Enumera PLCs Siemens S7 via protocolo S7comm. Obtém informações detalhadas da CPU, versão de firmware, número de série, nível de proteção e lista de módulos instalados. Funciona com S7-300, S7-400, S7-1200 e S7-1500.

**Sintaxe:**
```bash
nmap --script s7-enumerate [--script-args s7-enumerate.slot=<slot>] -p 102 <alvo>
```

**Argumentos do script:**

| Argumento | Tipo | Padrão | Descrição |
|-----------|------|--------|-----------|
| `s7-enumerate.slot` | int | `2` | Slot do PLC CPU (0-31) |
| `s7-enumerate.timeout` | int | `5` | Timeout em segundos |
| `s7-enumerate.szl` | bool | `true` | Se true, tenta ler System Status List (SZL) |

**Exemplo 1 — enumeração completa:**
```bash
$ nmap --script s7-enumerate -p 102 192.168.1.50

Starting Nmap 7.94...
Nmap scan report for 192.168.1.50

PORT    STATE SERVICE
102/tcp open  iso-tsap
| s7-enumerate:
|   Module:
|     CPU Type:          CPU 1214C DC/DC/DC
|     AS Name:           S7-1200_STATION
|     Module Name:       PLC_1
|     Plant ID:          
|     Copyright:         Original Siemens Equipment
|     Serial Number:     S V-C20B01F4
|     Module Type:       CPU
|     Order Code:        6ES7 214-1AG40-0XB0
|     Hardware (Version): 4
|     Firmware (Version): V4.4
|   Status:
|     Mode:              RUN
|     Run Status:        Running
|     Startup Errors:    0
|   Protection:
|     Mode:              Protection Level 1 (no restriction)
|     Password Protected: No
|     Copy Protection:  No
|   Connection:
|     TSAP:              10.02
|     Protocol:          S7comm (S7-1200/S7-300 compatible)
|_  Scanned in 0.42s
```

**Exemplo 2 — slot específico:**
```bash
$ nmap --script s7-enumerate --script-args s7-enumerate.slot=0 -p 102 192.168.1.60

PORT    STATE SERVICE
102/tcp open  iso-tsap
| s7-enumerate:
|   CPU Type:     CPU 315-2 DP
|   Order Code:   6ES7 315-2AH14-0AB0
|   Firmware:     V3.3
|   Serial:       S7C2B4F3A1
|   Protection:   Level 2 (write-protected)
|_  Note: Password protection active
```

**Exemplo 3 — varredura de sub-rede:**
```bash
$ nmap --script s7-enumerate -p 102 192.168.1.0/24 -oX s7_scan.xml

[Output truncado — múltiplos PLCs encontrados]
Nmap scan report for 192.168.1.50 — S7-1200 CPU 1214C
Nmap scan report for 192.168.1.51 — S7-300 CPU 315-2 DP
Nmap scan report for 192.168.1.52 — S7-1500 CPU 1516-3 PN/DP
```

---

### 3. enip-list.nse

**Descrição:** Enumera dispositivos EtherNet/IP (Allen-Bradley/Rockwell) via protocolo CIP. Envia o comando List Identity para obter informações completas do dispositivo incluindo vendor, device type, product code e revisão.

**Sintaxe:**
```bash
nmap --script enip-list [--script-args enip-list.timeout=<secs>] -p 44818 <alvo>
```

**Exemplo 1 — ControlLogix:**
```bash
$ nmap --script enip-list -p 44818 192.168.1.20

PORT      STATE SERVICE
44818/tcp open  EtherNet/IP
| enip-list:
|   Identity Object (CIP Class 0x01):
|     Vendor ID:       1 (Rockwell Automation/Allen-Bradley)
|     Device Type:     14 (Programmable Logic Controller)
|     Product Code:    77
|     Revision:        16.011
|     Status:          0x0060 (Owned, Configured, Major Fault Occurred=False)
|     Serial Number:   0x00123456
|     Product Name:    1756-L72 LOGIX5572
|   TCP/IP Object (CIP Class 0xF5):
|     IP Address:      192.168.1.20
|     Hostname:        CONTROLLOGIX-01
|     Domain Name:     plant.local
|_  Scanned in 0.31s
```

**Exemplo 2 — CompactLogix:**
```bash
$ nmap --script enip-list -p 44818 192.168.1.25

PORT      STATE SERVICE
44818/tcp open  EtherNet/IP
| enip-list:
|   Vendor:       Rockwell Automation/Allen-Bradley
|   Device Type:  14 (PLC)
|   Product:      1769-L24ER-QB1B COMPACTLOGIX 5370 L24ER
|   Revision:     30.011
|   Serial:       0x00ABCDEF
|_  Status: Running
```

---

### 4. bacnet-info.nse

**Descrição:** Obtém informações de dispositivos BACnet/IP via UDP. Envia um Who-Is broadcast e coleta respostas I-Am, depois obtém informações detalhadas via Read-Property-Request (serviço 12).

**Sintaxe:**
```bash
nmap --script bacnet-info -sU -p 47808 <alvo>
```

**Exemplo 1 — controlador HVAC:**
```bash
$ nmap --script bacnet-info -sU -p 47808 192.168.1.200

PORT      STATE SERVICE
47808/udp open  BACnet Building Automation
| bacnet-info:
|   Device Identifier: 1234567
|   Vendor:
|     ID:          7 (Honeywell International)
|     Name:        Honeywell International Inc.
|   Model Name:    WEB-8000
|   Firmware:      3.8.2
|   Description:   Web-Based Building Controller
|   Location:      Building A, Floor 3, HVAC Room
|   Object Name:   WebController_03
|   Protocol Version: 1
|   BACnet Revision: 14
|   Segmentation:  No Segmentation
|   Max APDU Length: 1476 bytes
|_  Scanned in 1.23s
```

**Exemplo 2 — múltiplos dispositivos BACnet:**
```bash
$ nmap --script bacnet-info -sU -p 47808 192.168.1.0/24

Nmap scan report for 192.168.1.200 — Honeywell WEB-8000 (Device 1234567)
Nmap scan report for 192.168.1.201 — Johnson Controls FX-07 (Device 7654321)
Nmap scan report for 192.168.1.202 — Siemens APOGEE Insight (Device 9876543)
```

---

### 5. dnp3-info.nse

**Descrição:** Testa conectividade DNP3 e obtém informações básicas de outstations DNP3 via TCP ou UDP. Envia uma Request Link Status e verifica a resposta.

**Sintaxe:**
```bash
nmap --script dnp3-info -p 20000 <alvo>
```

**Exemplo 1 — RTU de subestação:**
```bash
$ nmap --script dnp3-info -p 20000 10.0.1.50

PORT      STATE SERVICE
20000/tcp open  dnp3
| dnp3-info:
|   DNP3 Link Layer:
|     Source Address:  3
|     Dest Address:    1 (Master confirmed)
|   Application Layer:
|     Function Code:   0x81 (Response)
|     Data Objects:    Internal Indications
|   Device Status:
|     Class 0 Data:    Available
|     Time Sync:       Required
|     Need Time:       Yes
|_  Note: Device requires time synchronization
```

**Exemplo 2 — UDP DNP3:**
```bash
$ nmap --script dnp3-info -sU -p 20000 10.0.1.100

PORT      STATE SERVICE
20000/udp open  dnp3
| dnp3-info:
|   Protocol: DNP3 over UDP
|   Outstation responding to Link Status requests
|   IIN (Internal Indication):
|     Local Control:  False
|     Need Time:      True
|_  Device: GE D60 Distance Relay
```

---

### 6. opcua-enum.nse

**Descrição:** Enumera servidores OPC UA sem autenticação. Obtém endpoints disponíveis, navega na árvore de nós do namespace 0 (padrão) e lista objetos, variáveis e seus valores quando acessíveis anonimamente.

**Sintaxe:**
```bash
nmap --script opcua-enum [--script-args opcua-enum.depth=<n>] -p 4840 <alvo>
```

**Argumentos:**

| Argumento | Tipo | Padrão | Descrição |
|-----------|------|--------|-----------|
| `opcua-enum.depth` | int | `2` | Profundidade de navegação na árvore |
| `opcua-enum.anon_only` | bool | `true` | Se false, tenta também credenciais padrão |

**Exemplo 1 — enumeração básica:**
```bash
$ nmap --script opcua-enum -p 4840 192.168.1.100

PORT     STATE SERVICE
4840/tcp open  OPC-UA
| opcua-enum:
|   Server Information:
|     Application URI:    urn:plant-server:PLCServer
|     Product URI:        urn:siemens.com:S7-1200
|     Application Name:   Siemens S7-1200 OPC UA Server
|     Application Type:   Server
|     Server Software:    1.04.0.0 (SIMATIC S7-1200 OPC-UA Server)
|   Security Modes:
|     None (SecurityMode: None, SecurityPolicy: None) — ANONYMOUS ACCESS!
|     Basic256Sha256 (SecurityMode: Sign, SecurityPolicy: Basic256Sha256)
|   Namespace Table:
|     0: http://opcfoundation.org/UA/
|     1: urn:Siemens:S7:GlobalDB
|     2: urn:plant-server:PLCServer
|   Browseable Objects (depth 2, anonymous):
|     /Objects/
|       /Server/ (OPC UA Server metadata)
|       /PLC_1/
|         /PLC_1/Temperature_Reactor_A  Float: 342.5
|         /PLC_1/Pressure_Reactor_A     Float: 8.4
|         /PLC_1/SETPOINT_TEMP          Float: 280.0
|         /PLC_1/Chlorine_Dosage        Float: 1.8
|_  WARNING: Anonymous access enabled — server exposes process data!
```

**Exemplo 2 — nenhum acesso anônimo:**
```bash
$ nmap --script opcua-enum -p 4840 192.168.1.101

PORT     STATE SERVICE
4840/tcp open  OPC-UA
| opcua-enum:
|   Application: Secure OPC UA Server
|   Security: SignAndEncrypt (Basic256Sha256) — properly secured
|   Anonymous Access: DISABLED
|_  Cannot enumerate without credentials
```

---

### 7. profinet-dcp.nse

**Descrição:** Identifica dispositivos PROFINET via DCP (Discovery and Configuration Protocol). Envia frames Layer 2 DCP Identify_All multicast e coleta respostas para descobrir dispositivos em segmentos de rede.

**Sintaxe:**
```bash
nmap --script profinet-dcp -e <interface> <alvo>
```

**Nota:** PROFINET DCP opera em Layer 2 (Ethernet), não TCP/IP. O script requer acesso à interface de rede.

**Exemplo 1 — identificação de dispositivo:**
```bash
$ nmap --script profinet-dcp -e eth0 192.168.1.150

Nmap scan report for 192.168.1.150

PORT   STATE SERVICE
|_ profinet-dcp: Scanning with raw Layer 2 (requires root)
| profinet-dcp:
|   DCP Identify Response:
|     MAC Address:         00:1B:1B:0A:00:01
|     Name of Station:     plc-siemens-01
|     IP Address:          192.168.1.150
|     Subnet Mask:         255.255.255.0
|     Default Gateway:     192.168.1.1
|     Device Family:       SIMATIC
|     Vendor:              Siemens AG
|     Device ID:           0x0001 / 0x0001
|     Device Role:         IO-Device
|     Device Options:
|       IP: Possible
|       Name of Station: Possible
|     Order Number:        6ES7 315-2EH14-0AB0
|_  Scanned in 0.15s
```

**Exemplo 2 — múltiplos dispositivos PROFINET:**
```bash
$ nmap --script profinet-dcp -e eth0 192.168.1.0/24

[*] PROFINET DCP requires Layer 2 — showing devices on local segment
Device at 00:1B:1B:0A:00:01 — plc-siemens-01 (SIMATIC S7-300)
Device at 00:1B:1B:0A:00:02 — et200-01 (ET 200S Distributed I/O)
Device at 00:1B:1B:0A:00:10 — scalance-x208 (SCALANCE X208 Switch)
```

---

### 8. ics-detect.nse

**Descrição:** Script de detecção multi-protocolo ICS. Detecta automaticamente qual protocolo ICS está presente em uma porta ou conjunto de portas. Usa sondas mínimas de cada protocolo e reporta o primeiro que responde com sucesso.

**Sintaxe:**
```bash
nmap --script ics-detect -p 502,102,44818,2404,4840,47808,20000 <alvo>
```

**Exemplo 1 — varredura de múltiplas portas ICS:**
```bash
$ nmap --script ics-detect -p 502,102,44818,2404,4840,47808,20000 192.168.1.100

Starting Nmap 7.94...
Nmap scan report for 192.168.1.100

PORT      STATE SERVICE
102/tcp   open  iso-tsap
| ics-detect:
|   Protocol: S7comm (Siemens S7 PLC)
|   Confidence: HIGH
|   Vendor: Siemens AG
|   Details: COTP CC received — S7 device confirmed
|_  Recommendation: use scanners/ics/s7_enumerate in IXF

502/tcp   open  modbus
| ics-detect:
|   Protocol: Modbus TCP
|   Confidence: HIGH
|   Details: Valid MBAP response (protocol ID = 0x0000)
|_  Recommendation: use scanners/ics/modbus_detect in IXF

4840/tcp  open  opc-ua
| ics-detect:
|   Protocol: OPC UA
|   Confidence: HIGH
|   Details: OPC UA Hello received successfully
|_  Recommendation: use scanners/ics/opcua_endpoints in IXF

44818/tcp closed
2404/tcp  closed
20000/tcp closed
47808/udp open
| ics-detect:
|   Protocol: BACnet/IP
|   Confidence: MEDIUM
|   Details: I-Am response to Who-Is broadcast
|_  Recommendation: use scanners/ics/bacnet_device_id in IXF
```

**Exemplo 2 — host sem protocolos ICS:**
```bash
$ nmap --script ics-detect -p 502,102,44818 192.168.1.200

PORT      STATE SERVICE
502/tcp   closed
102/tcp   closed
44818/tcp closed

| ics-detect:
|_  No ICS protocols detected on scanned ports
```

**Exemplo 3 — scan completo de infraestrutura:**
```bash
$ nmap --script ics-detect -p 502,102,44818,2404,4840,47808,20000,18245,5006,9600 \
  192.168.1.0/24 -oX ics_infrastructure.xml

[Output salvo em ics_infrastructure.xml — 15 dispositivos ICS encontrados]
Dispositivos encontrados:
  192.168.1.5   — Modbus TCP (Schneider Modicon M340)
  192.168.1.12  — Modbus TCP (Generic RTU)
  192.168.1.20  — EtherNet/IP (Rockwell ControlLogix)
  192.168.1.50  — S7comm (Siemens S7-1200)
  192.168.1.100 — OPC UA + S7comm (Siemens)
  192.168.1.150 — BACnet/IP (Honeywell WEB-8000)
```

---

## Exemplos Combinados

### Varredura Completa de Infraestrutura OT

```bash
# Varredura abrangente com todos os scripts ICS
nmap --script modbus-enum,s7-enumerate,enip-list,bacnet-info,dnp3-info,opcua-enum,ics-detect \
  -p T:502,102,44818,2404,4840,20000,U:47808 \
  --open -T3 \
  -oA ics_full_scan_$(date +%Y%m%d) \
  192.168.1.0/24

echo "Varredura concluída. Relatórios em: ics_full_scan_$(date +%Y%m%d).{nmap,xml,gnmap}"
```

### Integração com IXF

```bash
# Descobrir com Nmap, depois aprofundar com IXF
nmap --script ics-detect -p 502,102,44818 192.168.1.0/24 -oG - | \
  grep "Modbus TCP" | awk '{print $2}' | \
  while read ip; do
    echo "Analisando ${ip} com IXF..."
    ixf --simulate -c "use scanners/ics/modbus_detect; set target ${ip}; run"
  done
```

### NSE + IXF: Pipeline Completo

```bash
#!/usr/bin/env bash
# Pipeline: Nmap NSE → IXF CVE Check
SUBNET="192.168.1.0/24"

echo "[1/3] Descoberta com NSE..."
nmap --script ics-detect -p 502,102 "${SUBNET}" -oG - 2>/dev/null | \
  grep "S7comm" | awk '{print $2}' > /tmp/s7_hosts.txt

echo "[2/3] Verificação de CVE com IXF..."
while read ip; do
    ixf --simulate --no-color -c "
        cve CVE-2021-22681;
        set target ${ip};
        run;
        back;
        cve CVE-2022-38465;
        set target ${ip};
        run
    " >> /tmp/ixf_cve_results.txt 2>&1
done < /tmp/s7_hosts.txt

echo "[3/3] Relatório..."
grep -E "\[SIMULATE\]|POTENCIAL|\[+\]" /tmp/ixf_cve_results.txt
echo "Resultados completos: /tmp/ixf_cve_results.txt"
```

---

## Escrevendo Scripts NSE Personalizados

Scripts NSE são escritos em Lua 5.3. O IXF inclui bibliotecas auxiliares para protocolos ICS que podem ser reutilizadas.

### Template Básico de Script NSE

```lua
-- Nome: meu-protocolo-ics.nse
-- Descrição: Template para script NSE ICS personalizado
-- Versão: 1.0
-- Autor: Seu Nome

-- Cabeçalho obrigatório
description = [[
  Detecta e enumera dispositivos que usam <Protocolo ICS>.
  
  Este script envia uma requisição de identificação mínima
  e retorna informações de vendor, modelo e versão.
]]

-- Categorias: safe = não intrusivo, discovery = descoberta
categories = {"safe", "discovery"}

-- Dependências Nmap
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

-- Definir em quais portas o script executa
portrule = shortport.port_or_service(502, "modbus")

-- Função principal
action = function(host, port)
  local socket = nmap.new_socket()
  
  -- Configurar timeout
  socket:set_timeout(3000)  -- 3 segundos
  
  -- Conectar ao alvo
  local status, err = socket:connect(host, port)
  if not status then
    stdnse.debug1("Conexão falhou: %s", err)
    return nil
  end
  
  -- Enviar probe específico do protocolo
  -- Exemplo: Modbus FC3 Read Holding Registers
  local probe = string.char(
    0x00, 0x01,  -- Transaction ID
    0x00, 0x00,  -- Protocol ID (Modbus)
    0x00, 0x06,  -- Length
    0x01,        -- Unit ID
    0x03,        -- FC3
    0x00, 0x00,  -- Start register
    0x00, 0x01   -- Quantity
  )
  
  local send_status, send_err = socket:send(probe)
  if not send_status then
    socket:close()
    return nil
  end
  
  -- Receber resposta
  local recv_status, response = socket:receive_bytes(8)
  socket:close()
  
  -- Verificar se a resposta é válida
  if not recv_status or #response < 8 then
    return nil
  end
  
  -- Verificar Protocol ID Modbus (bytes 3-4 = 0x0000)
  local proto_id = string.byte(response, 3) * 256 + string.byte(response, 4)
  if proto_id ~= 0 then
    return nil  -- Não é Modbus
  end
  
  -- Construir resultado
  local result = stdnse.output_table()
  result["Protocol"] = "Modbus TCP"
  result["Unit ID"] = string.byte(response, 7)
  result["Function Code"] = string.byte(response, 8)
  result["Status"] = "Responding"
  
  return result
end
```

### Usando Biblioteca IXF para NSE

O IXF fornece módulos Lua auxiliares:

```lua
-- Carregar biblioteca IXF para NSE
local ixf_modbus = require "ixf-modbus"
local ixf_s7 = require "ixf-s7"

-- Exemplo: usar helper Modbus
local device_info = ixf_modbus.get_device_identification(host, port)
if device_info then
  local result = stdnse.output_table()
  result["Vendor"] = device_info.vendor_name
  result["Product"] = device_info.product_code
  result["Firmware"] = device_info.firmware_version
  return result
end
```

### Instalar Script Personalizado

```bash
# Copiar para diretório de scripts
sudo cp meu-protocolo-ics.nse /usr/share/nmap/scripts/

# Atualizar banco de dados
sudo nmap --script-updatedb

# Testar
nmap --script meu-protocolo-ics -p 502 192.168.1.100

# Registrar no IXF
ixf -c "nse list"  # Deve aparecer na lista após instalação
```

### Dicas para Desenvolvedores de Scripts NSE ICS

1. **Sempre use `categories = {"safe", "discovery"}`** para scripts que apenas leem dados
2. **Implemente timeout adequado** — dispositivos ICS podem ser lentos
3. **Trate erros graciosamente** — dispositivos OT nem sempre retornam erros padrão
4. **Documente os protocolos testados** — inclua versões e variantes do protocolo
5. **Evite enviar dados que modifiquem o estado** — scripts NSE devem ser passivos
6. **Teste em ambiente isolado** antes de usar em produção
7. **Use `stdnse.debug()` para debugging** — ativa com `--script-trace`

---

*Anterior: [Catálogo de Módulos](13-catalogo-modulos.md) | Início: [Índice](../index.md)*
