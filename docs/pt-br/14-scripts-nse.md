# Scripts NSE

O IXF inclui 8 scripts NSE (Nmap Scripting Engine) para descoberta e fingerprint de dispositivos ICS industriais. Eles integram as capacidades de varredura do IXF diretamente no ecossistema Nmap, permitindo workflows de reconhecimento combinados.

---

## Sumário

1. [Visão Geral e Pré-requisitos](#visão-geral-e-pré-requisitos)
2. [Instalação dos Scripts NSE](#instalação-dos-scripts-nse)
3. [ixf-modbus-info.nse](#ixf-modbus-infonse)
4. [ixf-s7-info.nse](#ixf-s7-infonse)
5. [ixf-enip-info.nse](#ixf-enip-infonse)
6. [ixf-bacnet-info.nse](#ixf-bacnet-infonse)
7. [ixf-dnp3-info.nse](#ixf-dnp3-infonse)
8. [ixf-opcua-info.nse](#ixf-opcua-infonse)
9. [ixf-iec104-info.nse](#ixf-iec104-infonse)
10. [ixf-fins-info.nse](#ixf-fins-infonse)
11. [Exemplos Combinados](#exemplos-combinados)
12. [Escrevendo Scripts NSE Personalizados](#escrevendo-scripts-nse-personalizados)
13. [Solução de Problemas](#solução-de-problemas)

---

## Visão Geral e Pré-requisitos

Os scripts NSE do IXF são scripts Lua compatíveis com o Nmap Scripting Engine. Eles realizam detecção, fingerprint e enumeração de dispositivos ICS nas portas industriais padrão.

### Pré-requisitos

| Requisito | Versão Mínima | Instalação |
|-----------|--------------|------------|
| Nmap | 7.80+ | `apt install nmap` / `brew install nmap` |
| IXF | 2.0+ | `
        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    ` |
| Python | 3.9+ | Pré-requisito do IXF |
| Lua | 5.3+ | Incluído no Nmap |
| Permissão root/admin | — | Necessária para pacotes raw (alguns scripts) |

### Tipos de Script NSE

| Categoria NSE | Scripts IXF | Quando Usar |
|---------------|-------------|-------------|
| `discovery` | Todos | Varreduras gerais de rede |
| `safe` | Todos | Marcados como seguros (sem modificação) |
| `version` | modbus, s7, enip | Fingerprint de versão de produto |
| `ics` | Todos | Categoria personalizada IXF |

---

## Instalação dos Scripts NSE

### Via Comando IXF

```
ixf > nse install
```

**Saída:**

```
[IXF NSE Installer]
════════════════════════════════════════════════════════════

Detectando instalação do Nmap...
[+] Nmap 7.94 encontrado em /usr/bin/nmap
[+] Diretório de scripts: /usr/share/nmap/scripts/

Copiando scripts IXF NSE:
  [+] ixf-modbus-info.nse    → /usr/share/nmap/scripts/ixf-modbus-info.nse
  [+] ixf-s7-info.nse        → /usr/share/nmap/scripts/ixf-s7-info.nse
  [+] ixf-enip-info.nse      → /usr/share/nmap/scripts/ixf-enip-info.nse
  [+] ixf-bacnet-info.nse    → /usr/share/nmap/scripts/ixf-bacnet-info.nse
  [+] ixf-dnp3-info.nse      → /usr/share/nmap/scripts/ixf-dnp3-info.nse
  [+] ixf-opcua-info.nse     → /usr/share/nmap/scripts/ixf-opcua-info.nse
  [+] ixf-iec104-info.nse    → /usr/share/nmap/scripts/ixf-iec104-info.nse
  [+] ixf-fins-info.nse      → /usr/share/nmap/scripts/ixf-fins-info.nse

Atualizando banco de dados de scripts Nmap...
[+] nmap --script-updatedb executado com sucesso.

[+] 8 scripts NSE instalados.

Para verificar:
  nmap --script-help ixf-modbus-info
  nmap -p 502 --script ixf-modbus-info 192.168.1.100
```

### Instalação Manual

```bash
# Localizar diretório de scripts do Nmap
nmap --version | head -3

# Copiar scripts manualmente
sudo cp $(pip show industrialxpl-forge | grep Location | awk '{print $2}')/industrialxpl/scripts/nse/*.nse \
  /usr/share/nmap/scripts/

# Atualizar banco de dados
sudo nmap --script-updatedb

# Verificar instalação
nmap --script-help ixf-modbus-info
```

---

## ixf-modbus-info.nse

Detecta e fingerprinta dispositivos Modbus TCP, extraindo informações de identificação MEI quando disponíveis.

**Porta padrão:** 502/tcp  
**Categoria NSE:** `discovery, safe, version, ics`  
**Impacto:** READ — somente leitura

### Descrição

O script envia uma requisição FC03 (Read Holding Registers) para verificar se o dispositivo responde ao Modbus TCP. Opcionalmente envia FC43/MEI para extrair informações de identificação do dispositivo (VendorName, ProductCode, MajorMinorRevision).

### Sintaxe

```bash
nmap -p 502 --script ixf-modbus-info [--script-args ixf-modbus.unit=1,ixf-modbus.identify=true] <alvo>
```

**Argumentos:**

| Argumento | Padrão | Descrição |
|-----------|--------|-----------|
| `ixf-modbus.unit` | `1` | ID de unidade Modbus a sondar (1-247) |
| `ixf-modbus.identify` | `true` | Tentar identificação MEI FC43 |
| `ixf-modbus.timeout` | `5` | Timeout de socket em segundos |

### Exemplo com Saída Nmap

```bash
nmap -p 502 --script ixf-modbus-info 192.168.1.0/24
```

**Saída:**

```
Nmap scan report for 192.168.1.10
Host is up (0.002s latency).
PORT    STATE SERVICE
502/tcp open  modbus
| ixf-modbus-info:
|   Protocol: Modbus TCP
|   Unit ID: 1
|   Responded to FC03: YES
|   Holding Register 0: 0x1A4F (6735 dec)
|   MEI Identification:
|     VendorName: Schneider Electric
|     ProductCode: Modicon M340
|     MajorMinorRevision: V2.30
|   IXF Assessment: Modbus sem autenticação — qualquer host pode ler/escrever
|_  MITRE Relevante: T0846, T0861, T0836 (se FC16 permitido)

Nmap scan report for 192.168.1.15
Host is up (0.003s latency).
PORT    STATE SERVICE
502/tcp open  modbus
| ixf-modbus-info:
|   Protocol: Modbus TCP
|   Unit ID: 1
|   Responded to FC03: YES
|   MEI Identification:
|     VendorName: Siemens AG
|     ProductCode: ET 200SP (IM155-6PN)
|     MajorMinorRevision: V4.2.1
|   IXF Assessment: Dispositivo Siemens ET200SP em porta Modbus
|_  MITRE Relevante: T0846, T0836

Nmap scan report for 192.168.1.20
Host is up (0.001s latency).
PORT    STATE SERVICE
502/tcp open  modbus
| ixf-modbus-info:
|   Protocol: Modbus TCP
|   Unit ID: 1
|   Responded to FC03: YES
|   Exception Response: FC03 Exception Code 02 (Illegal Data Address)
|   MEI Identification: FALHOU (FC43 não suportado)
|_  IXF Assessment: Dispositivo Modbus detectado (sem MEI)
```

---

## ixf-s7-info.nse

Enumera informações de CPU e firmware de PLCs Siemens S7 via protocolo S7comm.

**Porta padrão:** 102/tcp  
**Categoria NSE:** `discovery, safe, version, ics`  
**Impacto:** READ — somente leitura

### Descrição

Estabelece uma conexão COTP/S7comm e envia requisições SZL (System Status List) para extrair informações do módulo, nível de proteção e versão de firmware.

### Sintaxe

```bash
nmap -p 102 --script ixf-s7-info [--script-args ixf-s7.slot=2,ixf-s7.rack=0] <alvo>
```

**Argumentos:**

| Argumento | Padrão | Descrição |
|-----------|--------|-----------|
| `ixf-s7.rack` | `0` | Número do rack do chassis |
| `ixf-s7.slot` | `2` | Slot do CPU no chassis |
| `ixf-s7.timeout` | `5` | Timeout em segundos |

### Exemplo com Saída Nmap

```bash
nmap -p 102 --script ixf-s7-info 192.168.1.50
```

**Saída:**

```
Nmap scan report for 192.168.1.50
Host is up (0.002s latency).
PORT    STATE SERVICE
102/tcp open  iso-tsap
| ixf-s7-info:
|   Protocol: S7comm (ISO-TSAP)
|   COTP Connection: OK
|   S7 Setup Communication: OK
|   Order Number: 6ES7 315-2AH14-0AB0
|   Module Name: CPU 315-2 DP
|   Plant Identification: (vazio)
|   Copyright: Original Siemens Equipment
|   Serial Number: S7C1234567890
|   Module Type: CPU
|   Reserved: OK
|   Memory Size RAM: 256 KB
|   Memory Size Load: 8 MB
|   Firmware Version: V2.6.7
|   Hardware Version: 4.0
|   Module State: RUN
|   Protection Level: 0 (Sem proteção — acesso completo)
|   IXF Assessment: S7-300 sem proteção de senha — lógica PLC totalmente acessível
|_  MITRE Relevante: T0843, T0844, T0846 (T0816 via s7_stop_cpu)

Nmap scan report for 192.168.1.51
Host is up (0.003s latency).
PORT    STATE SERVICE
102/tcp open  iso-tsap
| ixf-s7-info:
|   Protocol: S7comm+ (TLS variant — S7-1200/1500)
|   COTP Connection: OK
|   S7 Setup Communication: OK
|   Order Number: 6ES7 511-1AK02-0AB0
|   Module Name: CPU 1511-1 PN
|   Firmware Version: V2.9.4
|   Module State: RUN
|   Protection Level: 3 (Proteção total — senha configurada)
|   IXF Assessment: S7-1500 com proteção. Verificar CVE-2021-22681 (hardcoded key)
|_  MITRE Relevante: T0843 (CVE-2021-22681), T0846
```

---

## ixf-enip-info.nse

Descobre e enumera dispositivos EtherNet/IP usando o serviço List Identity (CIP Command 0x63).

**Porta padrão:** 44818/tcp  
**Categoria NSE:** `discovery, safe, version, ics`  
**Impacto:** READ — somente leitura

### Sintaxe

```bash
nmap -p 44818 --script ixf-enip-info 192.168.1.0/24
```

### Exemplo com Saída Nmap

```bash
nmap -p 44818 --script ixf-enip-info 192.168.1.10
```

**Saída:**

```
Nmap scan report for 192.168.1.10
Host is up (0.002s latency).
PORT      STATE SERVICE
44818/tcp open  EtherNet/IP
| ixf-enip-info:
|   Protocol: EtherNet/IP (CIP)
|   List Identity (Command 0x63): OK
|   Vendor ID: 0x0001 (Rockwell Automation/Allen-Bradley)
|   Device Type: 0x000E (Programmable Logic Controller)
|   Product Code: 0x00B1 (1756-L71)
|   Revision: 32.011
|   Status: 0x0030 (Running, Configured)
|   Serial Number: 00C09200
|   Product Name: 1756-L71 ControlLogix5571
|   IP Address: 192.168.1.10
|   IXF Assessment: ControlLogix 1756 identificado. Verificar CVE-2022-1159, CVE-2022-1161
|   Vendor: Rockwell Automation
|_  MITRE Relevante: T0843, T0846, T0812
```

---

## ixf-bacnet-info.nse

Descobre dispositivos BACnet/IP via Who-Is broadcast e enumera suas propriedades.

**Porta padrão:** 47808/udp  
**Categoria NSE:** `discovery, safe, ics`  
**Impacto:** READ — somente leitura

### Sintaxe

```bash
nmap -p U:47808 --script ixf-bacnet-info 192.168.100.0/24
```

### Exemplo com Saída Nmap

```bash
nmap -sU -p 47808 --script ixf-bacnet-info 192.168.100.0/24
```

**Saída:**

```
Nmap scan report for 192.168.100.10
Host is up (0.003s latency).
PORT      STATE SERVICE
47808/udp open  BACnet
| ixf-bacnet-info:
|   Protocol: BACnet/IP
|   Who-Is Response: I-Am recebido
|   Device Instance: 1001
|   Max APDU: 1476 bytes
|   Segmentation: Both
|   Vendor ID: 7 (Siemens Building Technologies)
|   Vendor Name: Siemens Building Technologies
|   Model Name: PXC100-E
|   Description: Siemens PXC100-E BACnet Controller
|   Firmware Version: 10.5.0.4
|   Application Software Version: 10.5.0
|   Protocol Version: 1
|   Protocol Revision: 14
|   Objects Count: 47
|   IXF Assessment: Controlador BACnet sem autenticação
|_  MITRE Relevante: T0836 (BACnet write), T0814 (Who-Is flood)
```

---

## ixf-dnp3-info.nse

Detecta dispositivos DNP3 via Data Link Layer e obtém informações de endereçamento.

**Porta padrão:** 20000/tcp  
**Categoria NSE:** `discovery, safe, ics`  
**Impacto:** READ — somente leitura

### Sintaxe

```bash
nmap -p 20000 --script ixf-dnp3-info 10.0.0.0/24
```

### Exemplo com Saída Nmap

```bash
nmap -p 20000 --script ixf-dnp3-info 10.0.1.5
```

**Saída:**

```
Nmap scan report for 10.0.1.5
Host is up (0.001s latency).
PORT      STATE SERVICE
20000/tcp open  DNP3
| ixf-dnp3-info:
|   Protocol: DNP3 (IEEE 1815)
|   Data Link Layer: Respondeu
|   Source Address: 1 (RTU)
|   Destination: 1024 (Master)
|   Data Link Control: 0x84 (ACK, DIR, PRM)
|   Application Layer: Disponível
|   Class 0 Data Points:
|     Digital Inputs:  32
|     Digital Outputs: 16
|     Analog Inputs:   8
|     Analog Outputs:  4
|   SAv5 (Secure Auth v5): NÃO detectado — Sem autenticação!
|   IXF Assessment: RTU DNP3 sem autenticação SAv5 — comandos de controle sem auth possíveis
|_  MITRE Relevante: T0855 (Unauthorized Command), T0814 (DNP3 flood)
```

---

## ixf-opcua-info.nse

Enumera servidores OPC UA, detectando endpoints, modo de segurança e configurações de autenticação.

**Porta padrão:** 4840/tcp  
**Categoria NSE:** `discovery, safe, version, ics`  
**Impacto:** READ — somente leitura

### Sintaxe

```bash
nmap -p 4840 --script ixf-opcua-info [--script-args ixf-opcua.browse=true] <alvo>
```

**Argumentos:**

| Argumento | Padrão | Descrição |
|-----------|--------|-----------|
| `ixf-opcua.browse` | `false` | Tentar browse anônimo do namespace |
| `ixf-opcua.timeout` | `5` | Timeout em segundos |

### Exemplo com Saída Nmap

```bash
nmap -p 4840 --script ixf-opcua-info 192.168.1.100
```

**Saída — Servidor Inseguro:**

```
Nmap scan report for 192.168.1.100
Host is up (0.002s latency).
PORT     STATE SERVICE
4840/tcp open  OPC UA
| ixf-opcua-info:
|   Protocol: OPC UA (IEC 62541)
|   Server: Kepware KepServerEX v6.13
|   ProductURI: urn:KEPWARE-EX:UA:KepServerEX
|   ApplicationType: Server
|   Endpoints Discovered: 2
|   Endpoint 1:
|     URL: opc.tcp://192.168.1.100:4840/KEPServerEX
|     SecurityMode: None  [VULNERAVEL — sem segurança!]
|     SecurityPolicy: http://opcfoundation.org/UA/SecurityPolicy#None
|     UserTokenType: Anonymous  [VULNERAVEL — acesso anônimo!]
|   Endpoint 2:
|     URL: opc.tcp://192.168.1.100:49320/KEPServerEX
|     SecurityMode: None
|     SecurityPolicy: None
|   IXF Assessment: CRÍTICO — OPC UA com SecurityMode=None e acesso anônimo
|                   Qualquer host pode ler/escrever tags de processo sem autenticação
|_  MITRE Relevante: T0861, T0836 (OPC UA write), T0832

```

**Saída — Servidor Seguro:**

```
Nmap scan report for 192.168.1.200
Host is up (0.003s latency).
PORT     STATE SERVICE
4840/tcp open  OPC UA
| ixf-opcua-info:
|   Protocol: OPC UA (IEC 62541)
|   Server: Ignition OPC UA Server (Inductive Automation)
|   ProductURI: urn:Ignition:UA:Server
|   Endpoints Discovered: 3
|   Endpoint 1 (Seguro):
|     URL: opc.tcp://192.168.1.200:62541/discovery
|     SecurityMode: SignAndEncrypt  [OK]
|     SecurityPolicy: Basic256Sha256  [OK]
|     UserTokenType: Certificate  [OK]
|   IXF Assessment: OPC UA corretamente configurado com Basic256Sha256
|_  MITRE Relevante: T0861 (com auth necessária para T0836)
```

---

## ixf-iec104-info.nse

Detecta RTUs e dispositivos IEC 60870-5-104 e obtém informações básicas via STARTDT.

**Porta padrão:** 2404/tcp  
**Categoria NSE:** `discovery, safe, ics`  
**Impacto:** READ — somente leitura

### Sintaxe

```bash
nmap -p 2404 --script ixf-iec104-info 172.16.0.0/24
```

### Exemplo com Saída Nmap

```bash
nmap -p 2404 --script ixf-iec104-info 172.16.0.10
```

**Saída:**

```
Nmap scan report for 172.16.0.10
Host is up (0.002s latency).
PORT     STATE SERVICE
2404/tcp open  IEC 60870-5-104
| ixf-iec104-info:
|   Protocol: IEC 60870-5-104
|   STARTDT: Respondeu (STARTDT CON recebido)
|   I-Frame: Transmissão de dados disponível
|   W Parameter: 8 (frames não confirmados máx)
|   K Parameter: 12 (I-frames pendentes máx)
|   T0: 30s (timeout de conexão)
|   T1: 15s (timeout de send/receive)
|   T2: 10s (timeout de confirmação)
|   T3: 20s (teste de link)
|   Autenticação: Não detectada (IEC 62351-5 não ativo)
|   ASDU Address: Acessível (sem autenticação)
|   IXF Assessment: RTU IEC 104 sem autenticação — comandos de controle sem auth possíveis
|_  MITRE Relevante: T0855, T0813, T0814 (flood possível)
```

---

## ixf-fins-info.nse

Descobre e enumera PLCs Omron via protocolo FINS (Factory Interface Network Service).

**Porta padrão:** 9600/udp  
**Categoria NSE:** `discovery, safe, version, ics`  
**Impacto:** READ — somente leitura

### Sintaxe

```bash
nmap -sU -p 9600 --script ixf-fins-info 192.168.2.0/24
```

### Exemplo com Saída Nmap

```bash
nmap -sU -p 9600 --script ixf-fins-info 192.168.2.50
```

**Saída:**

```
Nmap scan report for 192.168.2.50
Host is up (0.003s latency).
PORT     STATE SERVICE
9600/udp open  Omron FINS
| ixf-fins-info:
|   Protocol: Omron FINS (UDP)
|   FINS Node Address: 1
|   Network: 0
|   FINS Response: OK
|   CPU Unit Info:
|     Model: CJ2M-CPU31
|     Version: Ver.2.00
|     System Version: Ver.9.01
|     CPU Unit Status: RUN (Executing)
|     Error Information: 0000 (Sem erros)
|   Memory Area:
|     DM (Data Memory): 32768 words disponíveis
|     HR (Holding Relay): 512 words disponíveis
|     EM0 (Extended Memory): 32768 words
|   Autenticação FINS: Não detectada
|   IXF Assessment: Omron CJ2M sem autenticação FINS — leitura/escrita de memória sem auth
|_  MITRE Relevante: T0836 (FINS memory write), T0846, T0861
```

---

## Exemplos Combinados

### Varredura completa de sub-rede com todos os scripts IXF

```bash
nmap -p 502,102,44818,47808,20000,2404,4840,9600 \
  --script ixf-modbus-info,ixf-s7-info,ixf-enip-info,ixf-bacnet-info,ixf-dnp3-info,ixf-opcua-info,ixf-iec104-info,ixf-fins-info \
  -sU -sT \
  192.168.1.0/24
```

**Saída consolidada:**

```
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 192.168.1.10
Host is up (0.002s latency).
PORT      STATE SERVICE
502/tcp   open  modbus
| ixf-modbus-info: Schneider Electric Modicon M340 V2.30 [SEM AUTH]
102/tcp   open  iso-tsap
| ixf-s7-info: Siemens CPU 315-2 DP V2.6.7 [Proteção: NENHUMA]
44818/tcp open  EtherNet/IP
| ixf-enip-info: Rockwell 1756-L71 ControlLogix5571 Rev32.011
47808/udp open  BACnet
| ixf-bacnet-info: Siemens PXC100-E BACnet [SEM AUTH]
4840/tcp  open  OPC UA
| ixf-opcua-info: Kepware KepServerEX [SecurityMode=None — VULNERAVEL]

Nmap scan report for 192.168.1.20
Host is up (0.003s latency).
PORT      STATE SERVICE
20000/tcp open  DNP3
| ixf-dnp3-info: RTU DNP3 ADDR=1 [SAv5: AUSENTE]
2404/tcp  open  IEC 60870-5-104
| ixf-iec104-info: RTU IEC 104 [Sem auth IEC 62351]

Nmap scan report for 192.168.1.50
Host is up (0.001s latency).
PORT     STATE SERVICE
9600/udp open  Omron FINS
| ixf-fins-info: Omron CJ2M-CPU31 V2.00 [SEM AUTH FINS]
```

---

### Varredura rápida apenas de ICS (sem versão)

```bash
nmap -p 502,102,44818,47808,20000,2404,4840 \
  --script "ixf-*" \
  192.168.1.0/24 \
  -T4 --open
```

---

### Varredura com saída XML para análise

```bash
nmap -p 502,102,44818,47808,20000,2404,4840 \
  --script "ixf-*" \
  192.168.1.0/24 \
  -oX ics_scan_$(date +%Y%m%d).xml
```

---

### Integração com IXF após varredura Nmap

```bash
# Passo 1: Varredura Nmap para descoberta
nmap -p 502 --script ixf-modbus-info 192.168.1.0/24 -oG modbus_scan.gnmap

# Passo 2: Extrair IPs com Modbus aberto
grep "open" modbus_scan.gnmap | awk '{print $2}' > alvos_modbus.txt

# Passo 3: Executar assessment IXF em alvos descobertos
while IFS= read -r ip; do
  echo "=== Avaliando $ip ==="
  ixf use exploits/protocols/modbus/modbus_fc16_write_registers set target "$ip" run
done < alvos_modbus.txt
```

---

## Escrevendo Scripts NSE Personalizados

Para criar scripts NSE personalizados para novos protocolos ICS:

### Template Básico (Lua)

```lua
-- ixf-custom-protocol-info.nse
-- Detecta e enumera dispositivos usando <protocolo>
-- Uso: nmap -p <porta> --script ixf-custom-protocol-info <alvo>

local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local comm = require "comm"

-- Metadados do script (obrigatório)
description = [[
Detecta dispositivos <Protocolo ICS> e extrai informações básicas.
IXF IndustrialXPL-Forge — https://github.com/SafeLabs/IndustrialXPL-Forge
]]

author = "IXF Team"
license = "Same as Nmap --  See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version", "ics"}

-- Porta padrão do protocolo
portrule = shortport.port_or_service(<PORTA>, "<NOME_SERVICO>", "tcp")

-- Função principal
action = function(host, port)
  -- Argumento de script opcionais
  local timeout = stdnse.get_script_args("ixf-custom.timeout") or 5
  timeout = tonumber(timeout) * 1000  -- converter para ms

  -- Conectar ao alvo
  local socket = nmap.new_socket()
  socket:set_timeout(timeout)
  local status, err = socket:connect(host.ip, port.number)
  if not status then
    return nil
  end

  -- Enviar payload de sonda (personalizar para o protocolo)
  local probe = string.char(0x00, 0x01, 0x00, 0x00)  -- exemplo
  local send_status, send_err = socket:send(probe)
  if not send_status then
    socket:close()
    return nil
  end

  -- Receber resposta
  local recv_status, response = socket:receive_bytes(32)
  socket:close()

  if not recv_status or #response < 4 then
    return nil
  end

  -- Parsear resposta e construir saída
  local output = stdnse.output_table()
  output["Protocol"] = "<Nome do Protocolo>"
  output["Status"] = "Respondeu"

  -- Extrair informações específicas do protocolo
  -- (implementar lógica de parsing aqui)
  output["Device Info"] = "Extraído do payload de resposta"
  output["IXF Assessment"] = "<Avaliação de segurança>"
  output["MITRE Relevante"] = "T0846, T0836"

  return output
end
```

### Testando o Script

```bash
# Teste local (sem execução real de rede)
nmap --script-help ixf-custom-protocol-info

# Teste contra alvo
nmap -p <PORTA> --script ixf-custom-protocol-info <IP_ALVO>

# Depuração
nmap -p <PORTA> --script ixf-custom-protocol-info --script-trace <IP_ALVO>
```

### Registrando no IXF

```bash
# Copiar script para diretório IXF
cp ixf-custom-protocol-info.nse \
  $(pip show industrialxpl-forge | grep Location | awk '{print $2}')/industrialxpl/scripts/nse/

# Reinstalar scripts
ixf > nse install

# Verificar
nmap --script-help ixf-custom-protocol-info
```

---

## Solução de Problemas

### Erro: Script não encontrado

```
Failed to find a script matching the given name or pattern
```

**Solução:** Reinstalar scripts e atualizar banco de dados:
```bash
ixf > nse install
# ou manualmente:
sudo nmap --script-updatedb
```

---

### Erro: Permissão negada

```
FAILED (Operation not permitted)
```

**Solução:** Alguns scripts exigem root para pacotes raw:
```bash
sudo nmap -p 502 --script ixf-modbus-info 192.168.1.100
```

---

### Erro: Timeout na varredura UDP

```
47808/udp filtered|open BACnet
```

**Solução:** UDP pode ser filtrado. Use `-sU` com `--min-rate` para melhorar detecção:
```bash
sudo nmap -sU -p 47808 --script ixf-bacnet-info --min-rate 100 192.168.1.0/24
```

---

### Erro: Script falha em firewalls modernos

**Problema:** Firewalls DPI bloqueiam payloads de protocolo ICS.

**Solução:** Verificar com scanners nativos do IXF:
```bash
ixf > use scanners/ics/modbus_detect
ixf > set target 192.168.1.100
ixf > run
```

---

### Verificar versão dos scripts instalados

```bash
nmap --script-help ixf-modbus-info | grep "IXF\|version\|Author"
```

---

### Atualizar scripts após atualização do IXF

```bash
pip install --upgrade industrialxpl-forge
ixf > nse install
```

---

*Anterior: [Catálogo de Módulos](13-catalogo-modulos.md) | Voltar ao [Índice](_index.md)*
