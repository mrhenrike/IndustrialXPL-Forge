![IndustrialXPL-Forge](docs/img/industrialxpl_forge-banner_16x9-en_us.png)

# IndustrialXPL-Forge (IXF)

> **O Maior Framework de Assessment e Exploração de Segurança OT/ICS/SCADA do Mundo**
> Parte da suite XPL-Forge | Autor: André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | [União Geek](https://uniaogeek.com.br/)

[![PyPI](https://img.shields.io/pypi/v/industrialxpl-forge?color=red&label=PyPI)](https://pypi.org/project/industrialxpl-forge/)
[![Python](https://img.shields.io/pypi/pyversions/industrialxpl-forge?color=blue&label=Python)](https://pypi.org/project/industrialxpl-forge/)
[![Licença: MIT](https://img.shields.io/badge/Licen%C3%A7a-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://img.shields.io/github/actions/workflow/status/mrhenrike/IndustrialXPL-Forge/ci.yml?branch=master&label=CI)](https://github.com/mrhenrike/IndustrialXPL-Forge/actions)
[![Módulos](https://img.shields.io/badge/M%C3%B3dulos-919%2B-brightgreen)](https://github.com/mrhenrike/IndustrialXPL-Forge)
[![Vendors](https://img.shields.io/badge/Vendors-151%2B-orange)](https://github.com/mrhenrike/IndustrialXPL-Forge)
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
