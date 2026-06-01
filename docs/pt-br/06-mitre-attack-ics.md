# MITRE ATT&CK para ICS

O IXF integra o MITRE ATT&CK para ICS v19, mapeando 976+ módulos para 74 das 90 técnicas (cobertura de 82%) em todas as 12 táticas. Toda técnica mapeada no IXF tem ao menos um módulo executável em `exploits/`, `cve/`, `assessment/mitre_ics/` ou `scanners/ics/`.

---

## Índice

1. [Visão Geral das Táticas](#visão-geral-das-táticas)
2. [Aliases de Tática](#aliases-de-tática)
3. [Exemplos Completos de Comandos](#exemplos-completos-de-comandos)
   - [mitre](#mitre--consultar-técnica)
   - [mitre-list](#mitre-list--índice-de-técnicas)
   - [mitre-scan](#mitre-scan--varredura-de-tática)
   - [mitre-all](#mitre-all--varredura-completa)
   - [mitre-coverage](#mitre-coverage--relatório-de-cobertura)
   - [mitre-report](#mitre-report--exportação)
4. [ttp T0843 — Saída Completa](#ttp-t0843--saída-completa)
5. [ttp-list — Saída Completa por Tática](#ttp-list--saída-completa-por-tática)
6. [Cobertura por Técnica — Tabela Completa](#cobertura-por-técnica--tabela-completa)
7. [Layer ATT&CK Navigator Explicado](#layer-attck-navigator-explicado)
8. [Módulos de Assessment por Técnica](#módulos-de-assessment-por-técnica)

---

## Visão Geral das Táticas

A tabela abaixo mostra todas as 12 táticas do MITRE ATT&CK para ICS v19 com a cobertura do IXF. As contagens de cobertura incluem módulos de exploits CVE, exploits a nível de protocolo, módulos baseados em credenciais e módulos de assessment dedicados.

| ID de Tática | Nome da Tática | Total de Técnicas (v19) | Cobertos IXF | Cobertura IXF | Qtd Módulos |
|-------------|----------------|------------------------|-------------|--------------|-------------|
| TA0108 | Initial Access | 9 | 9 | 100% | 93 |
| TA0104 | Execution | 9 | 8 | 88% | 74 |
| TA0110 | Persistence | 8 | 6 | 75% | 48 |
| TA0111 | Privilege Escalation | 2 | 2 | 100% | 11 |
| TA0103 | Evasion | 5 | 4 | 80% | 28 |
| TA0102 | Discovery | 13 | 11 | 84% | 134 |
| TA0109 | Lateral Movement | 3 | 3 | 100% | 52 |
| TA0100 | Collection | 9 | 8 | 88% | 97 |
| TA0101 | Command and Control | 3 | 3 | 100% | 19 |
| TA0107 | Inhibit Response Function | 18 | 14 | 77% | 218 |
| TA0106 | Impair Process Control | 11 | 9 | 81% | 143 |
| TA0105 | Impact | 11 | 8 | 72% | 59 |
| **TOTAL** | | **101** | **74** | **82%** | **976+** |

> **Nota:** MITRE ATT&CK para ICS v19 expandiu de 90 para 101 técnicas com a adição de sub-técnicas nas táticas Evasion e Impact. O IXF rastreia contra a linha de base original de 90 técnicas para estabilidade; a cifra de 82% referencia essa linha de base.

### Descrição Detalhada das 12 Táticas

**TA0108 — Initial Access (Acesso Inicial)**

Técnicas que os adversários usam para ganhar um ponto de apoio dentro de uma rede ICS. Inclui exploração de aplicações voltadas ao público, acesso remoto externo e comprometimento de ativos de infraestrutura. Cobertura IXF: **100%** (9/9 técnicas).

**TA0104 — Execution (Execução)**

Técnicas que resultam na execução de código controlado pelo adversário em um sistema local ou remoto. Em ambientes ICS, inclui execução via APIs nativas de PLC, interfaces GUI de SCADA e scripts automatizados. Cobertura IXF: **88%** (8/9 técnicas).

**TA0110 — Persistence (Persistência)**

Técnicas que os adversários usam para manter o acesso a sistemas através de reinicializações, credenciais alteradas e outras interrupções que podem cortar o acesso. Cobertura IXF: **75%** (6/8 técnicas).

**TA0111 — Privilege Escalation (Escalada de Privilégio)**

Técnicas que resultam em um adversário obtendo permissões de nível superior em um sistema ou rede. Cobertura IXF: **100%** (2/2 técnicas).

**TA0103 — Evasion (Evasão)**

Técnicas que os adversários usam para evitar detecção. Inclui mascaramento, manipulação de relatórios e exploração de serviços remotos de forma furtiva. Cobertura IXF: **80%** (4/5 técnicas).

**TA0102 — Discovery (Descoberta)**

Técnicas que os adversários usam para obter conhecimento sobre o sistema e a rede ICS interna. Inclui enumeração de rede, sniffing e identificação de dispositivos. Cobertura IXF: **84%** (11/13 técnicas).

**TA0109 — Lateral Movement (Movimento Lateral)**

Técnicas que os adversários usam para entrar e controlar sistemas remotos em uma rede ICS. Inclui download de programas PLC, transferência de ferramentas e exploração de serviços remotos. Cobertura IXF: **100%** (3/3 técnicas).

**TA0100 — Collection (Coleta)**

Técnicas que os adversários usam para coletar informações relevantes para os objetivos do adversário. Em ICS, inclui monitoramento de estado de processo, coleta de dados de historiadores e interceptação de comunicações. Cobertura IXF: **88%** (8/9 técnicas).

**TA0101 — Command and Control (C2)**

Técnicas que os adversários usam para se comunicar com sistemas sob seu controle dentro de uma rede de vítimas. Cobertura IXF: **100%** (3/3 técnicas).

**TA0107 — Inhibit Response Function (Inibir Função de Resposta)**

Técnicas que os adversários usam para impedir a resposta de segurança, proteção, controle de qualidade e outros operadores. Inclui supressão de alarmes, bloqueio de mensagens de comando e manipulação de sinais. Cobertura IXF: **77%** (14/18 técnicas).

**TA0106 — Impair Process Control (Prejudicar Controle de Processo)**

Técnicas que os adversários usam para manipular, desabilitar ou danificar o controle de processos físicos. Inclui modificação de parâmetros, manipulação de controladores e substituição de programas. Cobertura IXF: **81%** (9/11 técnicas).

**TA0105 — Impact (Impacto)**

Técnicas que os adversários usam para interromper, degradar, destruir ou manipular a integridade, disponibilidade ou segurança de um sistema de controle e seu ambiente operacional. Cobertura IXF: **72%** (8/11 técnicas).

---

## Aliases de Tática

O shell IXF aceita múltiplas formas ao especificar táticas em qualquer comando (`mitre-scan`, `ttp-list`, `mitre-list`):

| Nome Canônico | ID de Tática | Aliases Aceitos |
|---------------|-------------|-----------------|
| Initial Access | TA0108 | `initial-access`, `initial_access`, `ia`, `TA0108` |
| Execution | TA0104 | `execution`, `exec`, `TA0104` |
| Persistence | TA0110 | `persistence`, `persist`, `TA0110` |
| Privilege Escalation | TA0111 | `privilege-escalation`, `privesc`, `pe`, `TA0111` |
| Evasion | TA0103 | `evasion`, `defense-evasion`, `de`, `TA0103` |
| Discovery | TA0102 | `discovery`, `recon`, `TA0102` |
| Lateral Movement | TA0109 | `lateral-movement`, `lateral`, `lm`, `TA0109` |
| Collection | TA0100 | `collection`, `collect`, `TA0100` |
| Command and Control | TA0101 | `command-and-control`, `c2`, `c&c`, `cnc`, `TA0101` |
| Inhibit Response Function | TA0107 | `inhibit`, `inhibit-response`, `irf`, `TA0107` |
| Impair Process Control | TA0106 | `impair`, `impair-process`, `ipc`, `TA0106` |
| Impact | TA0105 | `impact`, `TA0105` |

---

## Exemplos Completos de Comandos

### `mitre` — Consultar Técnica

**Exemplo: consultar T0843 (Program Download):**

```
ixf > mitre T0843

  ╔══════════════════════════════════════════════════════════════════╗
  ║  MITRE ATT&CK para ICS — Detalhe da Técnica                      ║
  ╚══════════════════════════════════════════════════════════════════╝

  ID:          T0843
  Nome:        Program Download
  Tática:      Lateral Movement (TA0109)
  IXF Módulos: 12 módulos

  Descrição:
    Adversários podem fazer download de programas modificados para controladores
    industriais que foram comprometidos por meios de acesso. Isso pode incluir
    modificação de lógica de controle, firmware ou arquivos de configuração que
    alteram o processo físico controlado pelo sistema.

    No contexto do IXF, os módulos T0843 exploram protocolos de upload/download
    de programa específicos do vendor (S7comm, EtherNet/IP CIP, TriStation,
    Modbus) para substituir ou modificar programas de controle em PLCs.

  Módulos IXF:
    cve.siemens.cve_2021_22681_s7_1200_hardcoded_key
    cve.rockwell.cve_2022_1161_controllogix_modified_fw
    exploits.protocols.s7comm.s7_unauthorized_cpu_control
    assessment.mitre_ics.t0843_program_upload
    cve.malware.crashoverride_industroyer
    cve.apt.sandworm_industroyer_iec104
    exploits.plc.siemens.s7_1200_hardcoded_key
    exploits.plc.rockwell.logix5000_fw_download
    cve.schneider.cve_2018_7789_modicon_rce
    cve.mitsubishi.cve_2022_33139_melsec_fw
    assessment.mitre_ics.t0843_program_download_check
    cve.malware.pipedream_iocontrol

  Sub-técnicas: Nenhuma (técnica base apenas)

  Remediação:
    - Implementar autenticação forte para upload/download de programas PLC
    - Monitorar e alertar em conexões S7comm na porta 102
    - Usar recursos de proteção de acesso do PLC (senha, nível de proteção)
    - Habilitar auditoria de mudanças de programa e versionamento
    - Verificar integridade do programa PLC periodicamente (hash)
    - Segmentar acesso às portas de programação de PLCs
```

**Exemplo: consultar T0819 (Exploit Public-Facing Application):**

```
ixf > mitre T0819

  ID:          T0819
  Nome:        Exploit Public-Facing Application
  Tática:      Initial Access (TA0108)
  IXF Módulos: 47 módulos

  Descrição:
    Adversários podem tentar explorar fraquezas em aplicações ICS acessíveis à
    internet, incluindo interfaces web SCADA, portais de estação de engenharia
    e gateways de acesso remoto expostos diretamente à internet.

  Módulos IXF (amostra):
    exploits.scada.ignition.ignition_rce
    exploits.scada.wonderware.archestra_dcom_exec
    exploits.scada.ge_cimplicity.cimplicity_path_traversal
    exploits.scada.kepware.kepserverex_buffer_overflow
    cve.siemens.cve_2019_13945_simatic_s7_dos
    cve.rockwell.cve_2023_3595_controllogix_rce
    cve.schneider.cve_2022_45789_ecostruxure_rce
    ... (39 módulos adicionais)
```

### `mitre-list` — Índice de Técnicas

**Todas as técnicas:**

```
ixf > mitre-list
  MITRE ATT&CK para ICS — Índice de Técnicas
  ─────────────────────────────────────────────────────────────────
  ── Initial Access (TA0108) ─────────────────────────────────────
  T0817   Drive-by Compromise                        3 módulos
  T0819   Exploit Public-Facing Application         47 módulos
  T0822   External Remote Services                  12 módulos
  T0859   Valid Accounts                             8 módulos
  T0862   Supply Chain Compromise                    2 módulos
  T0863   User Execution                             3 módulos
  T0864   Transient Cyber Asset                      1 módulo
  T0865   Spearphishing Attachment                   4 módulos
  T0883   Internet Accessible Device                 7 módulos

  ── Execution (TA0104) ──────────────────────────────────────────
  T0800   Activate Firmware Update Mode              2 módulos
  T0807   Remote Services                            6 módulos
  T0821   Modify Controller Tasking                  8 módulos
  T0823   Graphical User Interface                   0 módulos (sem cobertura)
  T0834   Native API                                 4 módulos
  T0853   Scripting                                  3 módulos
  T0858   Change Credential                          4 módulos
  T0871   Execution through API                      3 módulos

  ── Persistence (TA0110) ────────────────────────────────────────
  T0837   Module Firmware                            5 módulos
  T0838   Modify Program                             9 módulos
  T0839   Change Credential                          4 módulos (alias de T0858)
  T0845   Program Organization Units                 4 módulos
  T0851   Rootkit                                    2 módulos
  T0873   Project File Infection                     3 módulos

  ── Privilege Escalation (TA0111) ───────────────────────────────
  T0874   Hooking                                    1 módulo
  T0890   Exploitation for Privilege Escalation      3 módulos

  ...

  [Total: 74 técnicas mapeadas | 976+ módulos]
```

**Filtrado por Discovery:**

```
ixf > mitre-list discovery
  MITRE ATT&CK para ICS — Técnicas de Discovery (TA0102)
  ─────────────────────────────────────────────────────────────────
  T0840   Network Connection Enumeration             2 módulos
  T0842   Network Sniffing                           3 módulos
  T0846   Remote System Discovery                    8 módulos
  T0854   Serial Connection Enumeration              1 módulo
  T0861   Point and Tag Identification               4 módulos
  T0868   Detect Program State                       2 módulos
  T0869   Standard Application Layer Protocol        5 módulos
  T0877   I/O Module Discovery                       3 módulos
  T0882   Theft of Operational Information           3 módulos
  T0887   Wireless Sniffing                          1 módulo
  T0888   Remote System Information Discovery        6 módulos
  ──────────────────────────────────────────────────────────────
  Cobertos: 11/13 técnicas (84%) | 38 módulos
```

**Filtrado por Inhibit Response Function:**

```
ixf > mitre-list inhibit
  MITRE ATT&CK para ICS — Técnicas de Inhibit Response Function (TA0107)
  ─────────────────────────────────────────────────────────────────
  T0803   Block Command Message                      4 módulos
  T0804   Block Reporting Message                    3 módulos
  T0805   Block Serial COM                           1 módulo
  T0814   Denial of Service                          7 módulos
  T0816   Device Restart/Shutdown                    5 módulos
  T0833   Modify Alarm Settings                      3 módulos
  T0856   Spoof Reporting Message                    2 módulos
  T0878   Alarm Suppression                          8 módulos
  T0881   Service Stop                               3 módulos
  T0815   Denial of View                             4 módulos
  T0829   Loss of Safety                             6 módulos
  T0813   Denial of Control                          8 módulos
  T0830   Loss of View                               3 módulos
  T0832   Manipulation of View                       4 módulos
  ──────────────────────────────────────────────────────────────
  Cobertos: 14/18 técnicas (77%) | 61 módulos
```

### `mitre-scan` — Varredura de Tática

**Varredura de Initial Access em sub-rede:**

```
ixf > mitre-scan initial-access 192.168.1.0/24
[*] Varrendo tática: Initial Access (TA0108) em 192.168.1.0/24
[*] simulate=True (modo seguro)
[*] Técnica T0817 — Drive-by Compromise...
  [simulate] exploits/scada/ignition/ignition_rce
  [simulate] exploits/scada/wonderware/archestra_dcom_exec
  [simulate] cve/siemens/cve_2019_13945_simatic_s7_dos
[*] Técnica T0819 — Exploit Public-Facing Application...
  [simulate] 47 módulos em modo simulação...
[*] Técnica T0822 — External Remote Services...
  [simulate] 12 módulos em modo simulação...
[*] Técnica T0859 — Valid Accounts...
  [simulate] creds/siemens/s7_default_creds
  [simulate] creds/rockwell/logix_default_creds
  [simulate] creds/schneider/modicon_default_creds
  [simulate] ... (5 módulos adicionais)
...
[+] Varredura de tática concluída: 9 técnicas, 93 módulos executados (simulate=True)
[+] Dispositivos encontrados (estimate via simulate): 3 potenciais
[i] Para executar ao vivo: mitre-scan initial-access 192.168.1.0/24 --destructive
```

**Varredura de Impair Process Control em host único:**

```
ixf > mitre-scan impair 10.0.0.100
[*] Varrendo tática: Impair Process Control (TA0106) em 10.0.0.100
[*] simulate=True | 9 técnicas mapeadas
[*] T0806 Brute Force I/O (1 módulo)...
[*] T0821 Modify Controller Tasking (8 módulos)...
[*] T0831 Manipulation of Control (6 módulos)...
[*] T0833 Modify Alarm Settings (3 módulos)...
[*] T0836 Modify Parameter (15 módulos)...
  [simulate] exploits/protocols/modbus/modbus_fc16_write_registers
  Modbus FC16 Write: alvo 10.0.0.100:502, registradores 0-10 (simulado)
[*] T0838 Modify Program (9 módulos)...
[*] T0843 Program Download (12 módulos)...
[*] T0845 Program Organization Units (4 módulos)...
[*] T0875 Change Program State (2 módulos)...
[+] Varredura Impair Process Control concluída: 9 técnicas, 60 módulos
```

### `mitre-all` — Varredura Completa

```
ixf > mitre-all 192.168.1.100
[*] Varredura MITRE ATT&CK para ICS completa em 192.168.1.100 (simulate=True)
[*] Executando 74 técnicas em 12 táticas...
[*] ── Initial Access (9 técnicas) ──────────────────────────────
[*] T0817 Drive-by Compromise...           [simulate] 3 módulos
[*] T0819 Exploit Public-Facing App...     [simulate] 47 módulos
[*] T0822 External Remote Services...      [simulate] 12 módulos
[*] T0859 Valid Accounts...                [simulate] 8 módulos
[*] T0862 Supply Chain Compromise...       [simulate] 2 módulos
[*] T0863 User Execution...                [simulate] 3 módulos
[*] T0864 Transient Cyber Asset...         [simulate] 1 módulo
[*] T0865 Spearphishing Attachment...      [simulate] 4 módulos
[*] T0883 Internet Accessible Device...    [simulate] 7 módulos
[*] ── Execution (8/9 técnicas) ────────────────────────────────
[*] T0800 Activate Firmware Update Mode... [simulate] 2 módulos
[*] T0807 Remote Services...               [simulate] 6 módulos
[*] T0821 Modify Controller Tasking...     [simulate] 8 módulos
...
[*] ── Impact (8/11 técnicas) ──────────────────────────────────
[*] T0813 Denial of Control...             [simulate] 8 módulos
[*] T0815 Denial of View...                [simulate] 4 módulos
[*] T0826 Loss of Availability...          [simulate] 5 módulos
[*] T0827 Loss of Control...               [simulate] 7 módulos
...
[+] Varredura MITRE completa concluída: 74 técnicas, 976 módulos
[+] Relatório: ixf_mitre_all_192.168.1.100_20260601.json
[i] Use 'report html' para relatório de assessment completo
```

### `mitre-coverage` — Relatório de Cobertura

```
ixf > mitre-coverage

  Cobertura MITRE ATT&CK para ICS — v19
  ──────────────────────────────────────────────────────────────────────
  Tática                          Cobertos  Total  Cobertura  Módulos
  ──────────────────────────────────────────────────────────────────────
  Initial Access (TA0108)         :  9/ 9   (100%)  ████████████  93
  Execution (TA0104)              :  8/ 9   ( 88%)  ██████████░   74
  Persistence (TA0110)            :  6/ 8   ( 75%)  █████████░░░  48
  Privilege Escalation (TA0111)   :  2/ 2   (100%)  ████████████  11
  Evasion (TA0103)                :  4/ 5   ( 80%)  █████████░░   28
  Discovery (TA0102)              : 11/13   ( 84%)  ██████████░░  134
  Lateral Movement (TA0109)       :  3/ 3   (100%)  ████████████  52
  Collection (TA0100)             :  8/ 9   ( 88%)  ██████████░   97
  Command and Control (TA0101)    :  3/ 3   (100%)  ████████████  19
  Inhibit Response (TA0107)       : 14/18   ( 77%)  █████████░░░  218
  Impair Process Ctrl (TA0106)    :  9/11   ( 81%)  █████████░░   143
  Impact (TA0105)                 :  8/11   ( 72%)  ████████░░░   59
  ──────────────────────────────────────────────────────────────────────
  TOTAL                           : 74/90   ( 82%)  ██████████░░  976+
  ──────────────────────────────────────────────────────────────────────

  Técnicas sem cobertura IXF (16):
    T0823  Graphical User Interface (Execution)
    T0808  Replication via Removable Media (Initial Access, Persistence)
    T0847  Replication via Removable Media (Persistence)
    T0875  Change Program State (Impair Process Control)
    T0879  Damage to Property (Impact)
    T0880  Loss of Safety (Impact)
    T0826  Loss of Availability (Impact)
    T0827  Loss of Control (Impact)
    T0828  Loss of Productivity and Revenue (Impact)
    T0829  Loss of Safety (Impact - fisicamente via pessoal)
    T0830  Loss of View (Inhibit Response)
    T0815  Denial of View (Inhibit Response - parcial)
    T0803  Block Command Message (Inhibit Response - parcial)
    T0804  Block Reporting Message (Inhibit Response - parcial)
    T0805  Block Serial COM (Inhibit Response)
    T0890  Exploitation for Privilege Escalation (parcial)
```

### `mitre-report` — Exportação

**Gerar layer para ATT&CK Navigator:**

```
ixf > mitre-report layer
[+] Layer ATT&CK Navigator salvo: ixf_mitre_layer_20260601.json
[i] Abra em: https://mitre-attack.github.io/attack-navigator/
[i] Importe via: "Open Existing Layer" → selecione ixf_mitre_layer_20260601.json
[i] Técnicas com cobertura IXF serão coloridas; técnicas sem cobertura ficam cinzas
```

**Gerar relatório HTML:**

```
ixf > mitre-report html
[+] Relatório de cobertura MITRE ICS salvo: ixf_mitre_report_20260601.html
[i] Inclui: tabela de cobertura por tática, listagem de técnicas por tática,
            módulos mapeados por técnica, metadados de versão ICS matrix
```

**Gerar dados brutos JSON:**

```
ixf > mitre-report json
[+] Relatório MITRE raw JSON salvo: ixf_mitre_data_20260601.json
{
  "matrix_version": "ics-v19",
  "generated_at": "2026-06-01T16:00:00Z",
  "total_techniques": 90,
  "covered_techniques": 74,
  "coverage_pct": 82.2,
  "tactics": [
    {
      "id": "TA0108",
      "name": "Initial Access",
      "techniques_total": 9,
      "techniques_covered": 9,
      "coverage_pct": 100.0,
      "module_count": 93
    },
    ...
  ],
  "techniques": [
    {
      "id": "T0817",
      "name": "Drive-by Compromise",
      "tactic": "Initial Access",
      "modules": [
        "exploits.scada.ignition.ignition_rce",
        "exploits.scada.wonderware.archestra_dcom_exec",
        "cve.siemens.cve_2019_13945_simatic_s7_dos"
      ]
    },
    ...
  ]
}
```

---

## `ttp T0843` — Saída Completa

```
ixf > ttp T0843 192.168.1.100
[*] TTP T0843 (Program Download) — 12 módulos — simulate=True
[*] Alvo: 192.168.1.100

[*] [1/12] Executando cve/siemens/cve_2021_22681_s7_1200_hardcoded_key...

  [SIMULATE MODE — no packets sent]
  ─────────────────────────────────────────────────────────────
  [i] O que aconteceria:
      CVE-2021-22681 Siemens S7-1200/1500 Hardcoded Key

      Passo 1: Conexão TCP para 192.168.1.100:102 (S7comm / TSAP)
      Passo 2: TPKT + COTP Connection Request (CR PDU)
      Passo 3: S7comm Setup Communication
      Passo 4: Autenticar usando chave simétrica hardcoded (ICSA-21-131-03)
      Passo 5: Download de programa STL/ladder controlado pelo atacante para slot 2
      Passo 6: Reinicialização a frio — PLC executa lógica do atacante
      Impacto Físico: Perda completa de controle sobre o processo industrial

  [i] Payload (hex): 03 00 00 16 11 E0 00 00 00 14 00 C1 02 01 00 C2 02 01 02...
  [i] MITRE ATT&CK para ICS: T0821 (Modify Controller Tasking), T0866

[*] [2/12] Executando cve/rockwell/cve_2022_1161_controllogix_modified_fw...

  [SIMULATE MODE — no packets sent]
  [i] CVE-2022-1161 Rockwell ControlLogix Modified Firmware
      Modificação de firmware ControlLogix via Ethernet/IP CIP
      Alvo: 192.168.1.100:44818 (EtherNet/IP)
      Impacto: Firmware modificado pode executar código arbitrário

[*] [3/12] Executando exploits/protocols/s7comm/s7_unauthorized_cpu_control...

  [SIMULATE MODE — no packets sent]
  [i] S7comm Unauthorized CPU Control
      Passo 1: Conexão S7comm sem autenticação (porta 102)
      Passo 2: Envio de PDU de controle de CPU (função 0x29 — Stop)
      Impacto: Para execução da CPU PLC sem autenticação

[*] [4/12] Executando assessment/mitre_ics/t0843_program_upload...
  [*] Módulo de assessment T0843 — verificando indicadores de program download...
  [simulate] Verificando portas 102 (S7comm), 44818 (EtherNet/IP), 102 (MMS)...

[*] [5/12] Executando cve/malware/crashoverride_industroyer...
  [simulate] Crashoverride/Industroyer — IEC 104 payload de download de programa...
  [simulate] Contexto histórico: Sandworm/Ukraine 2016 apagão de energia

...

[*] [12/12] Executando cve/malware/pipedream_iocontrol...
  [simulate] PIPEDREAM/INCONTROLLER — download de módulo para controladores OT...

[+] T0843 concluído: 12 módulos executados
    Correspondências em simulação: 3
    Verificações de conectividade (check): porta 102 aberta em 192.168.1.100

[i] Para executar ao vivo: ttp T0843 192.168.1.100 --destructive
[i] Para apenas conectividade: ttp-check T0843 192.168.1.100
```

---

## `ttp-list` — Saída Completa por Tática

### Initial Access (TA0108)

```
ixf > ttp-list --tactic initial-access
  Índice TTP — Initial Access (TA0108)
  ─────────────────────────────────────────────────────────────
  T0817   Drive-by Compromise                        3 módulos
  T0819   Exploit Public-Facing Application         47 módulos
  T0822   External Remote Services                  12 módulos
  T0859   Valid Accounts                             8 módulos
  T0862   Supply Chain Compromise                    2 módulos
  T0863   User Execution                             3 módulos
  T0864   Transient Cyber Asset                      1 módulo
  T0865   Spearphishing Attachment                   4 módulos
  T0883   Internet Accessible Device                 7 módulos
  ─────────────────────────────────────────────────────────────
  Total: 9/9 técnicas | 87 módulos
```

### Lateral Movement (TA0109)

```
ixf > ttp-list --tactic lateral-movement
  Índice TTP — Lateral Movement (TA0109)
  ─────────────────────────────────────────────────────────────
  T0843   Program Download                          12 módulos
  T0866   Exploitation of Remote Services           27 módulos
  T0867   Lateral Tool Transfer                     13 módulos
  ─────────────────────────────────────────────────────────────
  Total: 3/3 técnicas | 52 módulos
```

### Collection (TA0100)

```
ixf > ttp-list --tactic collection
  Índice TTP — Collection (TA0100)
  ─────────────────────────────────────────────────────────────
  T0801   Monitor Process State                      2 módulos
  T0802   Automated Collection                       5 módulos
  T0811   Data from Information Repositories         4 módulos
  T0843   Program Upload                            12 módulos
  T0852   Screen Capture                             2 módulos
  T0861   Point and Tag Identification               4 módulos
  T0882   Theft of Operational Information           3 módulos
  T0888   Remote System Information Discovery        6 módulos
  ─────────────────────────────────────────────────────────────
  Total: 8/9 técnicas | 38 módulos
```

### Inhibit Response Function (TA0107)

```
ixf > ttp-list --tactic inhibit
  Índice TTP — Inhibit Response Function (TA0107)
  ─────────────────────────────────────────────────────────────
  T0803   Block Command Message                      4 módulos
  T0804   Block Reporting Message                    3 módulos
  T0805   Block Serial COM                           1 módulo
  T0813   Denial of Control                          8 módulos
  T0814   Denial of Service                          7 módulos
  T0815   Denial of View                             4 módulos
  T0816   Device Restart/Shutdown                    5 módulos
  T0829   Loss of Safety                             6 módulos
  T0830   Loss of View                               3 módulos
  T0833   Modify Alarm Settings                      3 módulos
  T0856   Spoof Reporting Message                    2 módulos
  T0878   Alarm Suppression                          8 módulos
  T0881   Service Stop                               3 módulos
  T0832   Manipulation of View                       4 módulos
  ─────────────────────────────────────────────────────────────
  Total: 14/18 técnicas | 61 módulos
```

---

## Cobertura por Técnica — Tabela Completa

| ID | Nome | Tática | Cobertura | Módulos IXF |
|----|------|--------|-----------|-------------|
| T0800 | Activate Firmware Update Mode | Execution | Sim | 2 |
| T0801 | Monitor Process State | Collection | Sim | 2 |
| T0802 | Automated Collection | Collection | Sim | 5 |
| T0803 | Block Command Message | Inhibit | Sim | 4 |
| T0804 | Block Reporting Message | Inhibit | Sim | 3 |
| T0805 | Block Serial COM | Inhibit | Sim | 1 |
| T0806 | Brute Force I/O | Impair | Sim | 1 |
| T0807 | Remote Services | Execution | Sim | 6 |
| T0808 | Replication via Removable Media | Initial Access | **Não** | 0 |
| T0809 | Data Destruction | Impact | Sim | 3 |
| T0810 | Data Exfiltration over C2 Channel | Collection | Sim | 2 |
| T0811 | Data from Information Repositories | Collection | Sim | 4 |
| T0812 | Default Credentials | Initial Access | Sim | 34 |
| T0813 | Denial of Control | Impact/Inhibit | Sim | 8 |
| T0814 | Denial of Service | Inhibit | Sim | 7 |
| T0815 | Denial of View | Inhibit | Sim | 4 |
| T0816 | Device Restart/Shutdown | Inhibit | Sim | 5 |
| T0817 | Drive-by Compromise | Initial Access | Sim | 3 |
| T0818 | Engineering Workstation Compromise | Initial Access | Sim | 5 |
| T0819 | Exploit Public-Facing Application | Initial Access | Sim | 47 |
| T0820 | Exploitation of Remote Services | Evasion | Sim | 3 |
| T0821 | Modify Controller Tasking | Execution/Impair | Sim | 8 |
| T0822 | External Remote Services | Initial Access | Sim | 12 |
| T0823 | Graphical User Interface | Execution | **Não** | 0 |
| T0824 | I/O Image | Execution | Sim | 2 |
| T0825 | Location Identification | Discovery | Sim | 2 |
| T0826 | Loss of Availability | Impact | **Não** | 0 |
| T0827 | Loss of Control | Impact | **Não** | 0 |
| T0828 | Loss of Productivity and Revenue | Impact | **Não** | 0 |
| T0829 | Loss of Safety | Impact | Sim | 6 |
| T0830 | Loss of View | Inhibit | Sim | 3 |
| T0831 | Manipulation of Control | Impair | Sim | 6 |
| T0832 | Manipulation of View | Inhibit | Sim | 4 |
| T0833 | Modify Alarm Settings | Inhibit | Sim | 3 |
| T0834 | Native API | Execution | Sim | 4 |
| T0835 | Detect Operating Mode | Discovery | Sim | 2 |
| T0836 | Modify Parameter | Impair | Sim | 15 |
| T0837 | Module Firmware | Persistence | Sim | 5 |
| T0838 | Modify Program | Persistence/Impair | Sim | 9 |
| T0839 | Change Credential | Persistence | Sim | 4 |
| T0840 | Network Connection Enumeration | Discovery | Sim | 2 |
| T0841 | Network Sniffing | Discovery | Sim | 3 |
| T0842 | Network Topology Mapping | Discovery | Sim | 2 |
| T0843 | Program Download | Lateral Movement | Sim | 12 |
| T0844 | Program Upload | Collection | Sim | 5 |
| T0845 | Program Organization Units | Persistence | Sim | 4 |
| T0846 | Remote System Discovery | Discovery | Sim | 8 |
| T0847 | Replication via Removable Media | Persistence | **Não** | 0 |
| T0848 | Rogue Master | Impair | Sim | 3 |
| T0849 | Masquerading | Evasion | Sim | 1 |
| T0850 | Modify I/O Image | Impair | Sim | 3 |
| T0851 | Rootkit | Persistence | Sim | 2 |
| T0852 | Screen Capture | Collection | Sim | 2 |
| T0853 | Scripting | Execution | Sim | 3 |
| T0854 | Serial Connection Enumeration | Discovery | Sim | 1 |
| T0855 | Unauthorized Command Message | Impair | Sim | 4 |
| T0856 | Spoof Reporting Message | Evasion/Inhibit | Sim | 2 |
| T0857 | System Firmware | Persistence | Sim | 4 |
| T0858 | Change Credential | Execution | Sim | 4 |
| T0859 | Valid Accounts | Initial Access | Sim | 8 |
| T0860 | Wireless Compromise | Initial Access | Sim | 3 |
| T0861 | Point and Tag Identification | Discovery | Sim | 4 |
| T0862 | Supply Chain Compromise | Initial Access | Sim | 2 |
| T0863 | User Execution | Initial Access | Sim | 3 |
| T0864 | Transient Cyber Asset | Initial Access | Sim | 1 |
| T0865 | Spearphishing Attachment | Initial Access | Sim | 4 |
| T0866 | Exploitation of Remote Services | Lateral Movement | Sim | 27 |
| T0867 | Lateral Tool Transfer | Lateral Movement | Sim | 13 |
| T0868 | Detect Program State | Discovery | Sim | 2 |
| T0869 | Standard Application Layer Protocol | C2 | Sim | 5 |
| T0870 | Commonly Used Port | C2 | Sim | 4 |
| T0871 | Execution through API | Execution | Sim | 3 |
| T0872 | Indicator Removal on Host | Evasion | Sim | 3 |
| T0873 | Project File Infection | Persistence | Sim | 3 |
| T0874 | Hooking | Privilege Escalation | Sim | 1 |
| T0875 | Change Program State | Impair | **Não** | 0 |
| T0876 | Activate Firmware Update Mode | Execution | Sim | 2 |
| T0877 | I/O Module Discovery | Discovery | Sim | 3 |
| T0878 | Alarm Suppression | Inhibit | Sim | 8 |
| T0879 | Damage to Property | Impact | Sim | 4 |
| T0880 | Loss of Safety | Impact/Inhibit | Sim | 6 |
| T0881 | Service Stop | Inhibit | Sim | 3 |
| T0882 | Theft of Operational Information | Discovery | Sim | 3 |
| T0883 | Internet Accessible Device | Initial Access | Sim | 7 |
| T0884 | Connection Proxy | C2 | Sim | 4 |
| T0885 | Commonly Used Port (C2) | C2 | Sim | 4 |
| T0886 | Remote Services | C2 | Sim | 5 |
| T0887 | Wireless Sniffing | Discovery | Sim | 1 |
| T0888 | Remote System Information Discovery | Discovery | Sim | 6 |
| T0889 | Modify Program | Impair | Sim | 5 |
| T0890 | Exploitation for Privilege Escalation | Priv Esc | Sim | 3 |

**Técnicas sem cobertura IXF (16 no total):**
T0808, T0823, T0826, T0827, T0828, T0847, T0875 e variantes não técnicas de Impact.

---

## Layer ATT&CK Navigator Explicado

O arquivo de layer gerado por `mitre-report layer` é compatível com o [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) e segue o esquema de layer v4.5.

### Estrutura do Arquivo de Layer

```json
{
  "version": "4.5",
  "name": "IndustrialXPL-Forge Coverage",
  "description": "IXF module coverage for MITRE ATT&CK for ICS v19",
  "domain": "ics-attack",
  "filters": {
    "platforms": ["Field Controller/RTU/PLC/IED", "Safety Instrumented System/Protection Relay", "Engineering Workstation", "Human-Machine Interface", "Historian", "Data Historian"]
  },
  "sorting": 0,
  "layout": {
    "layout": "side",
    "aggregateFunction": "average",
    "showID": true,
    "showName": true,
    "showAggregateScores": true,
    "countUnscored": false,
    "expandedSubtechniques": "annotated"
  },
  "hideDisabled": false,
  "techniques": [
    {
      "techniqueID": "T0819",
      "score": 47,
      "comment": "47 módulos IXF mapeados — maior cobertura de técnica única",
      "enabled": true,
      "metadata": [
        {"name": "ixf_modules", "value": "47"},
        {"name": "sample_modules", "value": "cve/siemens/..., exploits/scada/..."}
      ]
    },
    {
      "techniqueID": "T0812",
      "score": 34,
      "comment": "34 módulos de credenciais padrão cobrindo 25+ vendors"
    },
    {
      "techniqueID": "T0843",
      "score": 12,
      "comment": "12 módulos — download de programa para Siemens, Rockwell, Schneider"
    },
    {
      "techniqueID": "T0808",
      "score": 0,
      "comment": "Sem cobertura IXF — replicação por mídia removível requer acesso físico",
      "enabled": false
    },
    ...
  ],
  "gradient": {
    "colors": ["#ff6666", "#ffe766", "#8ec843"],
    "minValue": 0,
    "maxValue": 50
  },
  "legendItems": [
    {"label": "Sem cobertura IXF", "color": "#cccccc"},
    {"label": "Cobertura baixa (1-5 módulos)", "color": "#ff6666"},
    {"label": "Cobertura média (6-20 módulos)", "color": "#ffe766"},
    {"label": "Cobertura alta (21+ módulos)", "color": "#8ec843"}
  ],
  "showTacticRowBackground": true,
  "tacticRowBackground": "#dddddd",
  "selectTechniquesAcrossTactics": true,
  "selectSubtechniquesWithParent": false,
  "metadata": [],
  "links": [],
  "showExceptionMarkings": false
}
```

### Como Usar no ATT&CK Navigator

1. Acesse: https://mitre-attack.github.io/attack-navigator/
2. Clique em **"Open Existing Layer"**
3. Selecione o arquivo `ixf_mitre_layer_20260601.json`
4. A matriz será colorida:
   - **Verde:** Técnicas com alta cobertura IXF (21+ módulos)
   - **Amarelo:** Técnicas com cobertura média (6-20 módulos)
   - **Vermelho:** Técnicas com baixa cobertura (1-5 módulos)
   - **Cinza:** Técnicas sem cobertura IXF
5. Passe o mouse sobre técnicas para ver contagens de módulos e comentários

### Exportar Layer como Imagem

No Navigator:
1. Clique em **"Export"** (ícone de câmera na barra de ferramentas)
2. Escolha formato: PNG, SVG ou JSON
3. Para relatórios: use SVG para qualidade máxima

### Integrar com Relatórios de Pentest

O layer JSON pode ser incorporado em relatórios de pentest como anexo, permitindo que clientes visualizem a cobertura de técnicas testadas em seu ambiente específico. Adicione anotações por técnica com as descobertas:

```json
{
  "techniqueID": "T0836",
  "score": 15,
  "comment": "ENCONTRADO: Registradores Modbus sem autenticação em 192.168.1.100"
}
```

---

## Módulos de Assessment por Técnica

Os módulos em `assessment/mitre_ics/` implementam checks de técnica MITRE específicos para uso em assessments de conformidade e testes de penetração controlados.

| Caminho do Módulo | Técnica MITRE | Descrição |
|-------------------|---------------|-----------|
| `assessment/mitre_ics/t0801_monitor_process_state` | T0801 | Lê estado de processo via Modbus |
| `assessment/mitre_ics/t0806_brute_force_io` | T0806 | Força bruta de módulo I/O |
| `assessment/mitre_ics/t0835_manipulate_io_image` | T0835 | Modificação de imagem I/O na memória PLC |
| `assessment/mitre_ics/t0836_modify_parameter` | T0836 | Escrita de parâmetro de processo via FC16 |
| `assessment/mitre_ics/t0843_program_upload` | T0843 | Upload de programa de lógica ladder do PLC |
| `assessment/mitre_ics/t0845_program_upload` | T0845 | Download/sobrescrita de programa PLC |
| `assessment/mitre_ics/t0848_rogue_master` | T0848 | Injeção de mestre Modbus desonesto |
| `assessment/mitre_ics/t0851_rootkit` | T0851 | Simulação de implante rootkit em PLC |
| `assessment/mitre_ics/t0878_alarm_suppression` | T0878 | Supressão de alarme via modificação de registrador |
| `assessment/mitre_ics/t0836_setpoint_manipulation` | T0836 | Manipulação de setpoint de processo |
| `assessment/mitre_ics/t0846_remote_discovery` | T0846 | Descoberta de sistemas remotos OT |
| `assessment/mitre_ics/t0843_program_download_check` | T0843 | Verificação de indicadores de download de programa |
| `assessment/mitre_ics/coverage_report` | Todos | Gera layer JSON do ATT&CK Navigator |
| `assessment/mitre_ics/full_mitre_sweep` | Todos | Executa todos os módulos de técnica contra alvo |
| `assessment/mitre_ics/t0800_firmware_update_mode` | T0800 | Testa modo de atualização de firmware |
| `assessment/mitre_ics/t0855_unauthorized_command` | T0855 | Injeta mensagem de comando não autorizado |
| `assessment/mitre_ics/t0856_spoof_reporting` | T0856 | Falsificação de mensagem de relatório |
| `assessment/mitre_ics/t0816_device_restart` | T0816 | Reinicialização de dispositivo via protocolo |
| `assessment/mitre_ics/t0813_denial_control` | T0813 | Negação de controle de processo |
| `assessment/mitre_ics/t0814_denial_service` | T0814 | Negação de serviço em dispositivo ICS |
| `assessment/mitre_ics/t0866_exploitation_remote` | T0866 | Exploração de serviços remotos (movimento lateral) |
| `assessment/mitre_ics/t0819_exploit_public_facing` | T0819 | Exploração de aplicação pública (SCADA web) |
| `assessment/mitre_ics/t0859_valid_accounts` | T0859 | Uso de contas válidas para acesso ICS |
| `assessment/mitre_ics/t0812_default_credentials` | T0812 | Verificação de credenciais padrão |
| `assessment/mitre_ics/t0840_network_enum` | T0840 | Enumeração de conexões de rede |
| `assessment/mitre_ics/t0842_network_sniffing` | T0842 | Sniffing de rede em segmento OT |
| `assessment/mitre_ics/t0861_point_tag_id` | T0861 | Identificação de pontos e tags do SCADA |
| `assessment/mitre_ics/t0882_theft_opinfo` | T0882 | Roubo de informação operacional |

**Como usar módulos de assessment:**

```
ixf > assess mitre_ics/full_mitre_sweep
[*] Carregando assessment/mitre_ics/full_mitre_sweep...
[i] Este módulo executa todos os 28 módulos de técnica MITRE em modo simulate
[i] Defina 'target' para executar checks de conectividade reais

ixf > set target 192.168.1.100
ixf > run
[*] Executando varredura completa MITRE ATT&CK para ICS...
[*] 28 módulos de assessment a executar...
...
```

---

---

## Técnicas MITRE por Malware ICS Real

### Stuxnet (2010) — T0847, T0843, T0831, T0836

```
ixf > use cve/apt/stuxnet_centrifuge_attack
ixf > set target 192.168.1.100
ixf > run

[*] [SIMULATE] Stuxnet — Primeiro arma cibernética documentada contra ICS

  Fase 1 [Propagação via USB]: T0847
    Explorar LNK (CVE-2010-2568) para execução automática via USB
    Propagar para workstations Siemens STEP 7 na rede

  Fase 2 [Rootkit de CLP]: T0843, T0851
    Interceptar chamadas WinCC/STEP 7 para esconder blocos OB35/OB1 maliciosos
    Injetar código S7 malicioso nos CLPs S7-315 e S7-417

  Fase 3 [Manipulação de centrífuga]: T0831, T0836
    Variar velocidade das centrífugas entre 1410 Hz e 2 Hz de forma oculta
    Modificar pressão de gás UF6 ao mesmo tempo
    Reportar valores normais ao SCADA (T0856 — spoofing de dados)

  Impacto: Destruição de ~1.000 centrífugas de enriquecimento de urânio em Natanz, Irã
```

### Industroyer/Crashoverride (2016) — T0859, T0813, T0816, T0879

```
ixf > use cve/malware/crashoverride_industroyer
ixf > run

[*] [SIMULATE] Industroyer/Crashoverride — Sandworm, Kiev, dezembro 2016

  Módulo IEC 104 (Principal):
    Enviar SELECT+EXECUTE para abrir disjuntores em múltiplas subestações
    Abrir todos os disjuntores sequencialmente com delay calculado

  Módulo Wiper:
    KillDisk: sobrescrever MBR de todos os computadores Windows acessíveis
    Resultado: sistemas não reinicializam + dificuldade de resposta à crise

  Módulo DoS:
    Flood de IEC 104 e IEC 61850 para impedir reconexão remota

  Impacto: 200.000 residências sem energia em Kiev por ~1 hora
```

### Pipedream/INCONTROLLER (2022) — T0821, T0836, T0843, T0855

```
ixf > use cve/malware/pipedream_incontroller
ixf > run

[*] [SIMULATE] Pipedream/INCONTROLLER — Chernovite, 2022

  Módulo Tagrun (CLPs Schneider Modicon):
    Manipular tags OPC via CODESYS runtime
    Modificar lógica de controle em tempo de execução

  Módulo Logicool (Omron FINS):
    Acessar CLPs Omron via FINS/UDP sem autenticação
    Upload de programa malicioso

  Módulo OPCInjector:
    Usar OPC DA/UA para injetar valores falsos de sensor

  Módulo EDS (sistema de engenharia):
    Comprometer estações Schneider EDS
    Manter persistência em software de engenharia

  Impacto potencial: comprometimento multi-vendor simultâneo
  Descoberto: abril 2022 antes de implantação em alvo real
```

---

## Tabela de Mapeamento Completo — Técnicas Mais Críticas

| TID | Técnica | Cobertura IXF | Módulo Prioritário | Malware Real |
|-----|---------|---------------|-------------------|--------------|
| T0836 | Modify Parameter | 9 módulos | `exploits/protocols/modbus/modbus_write_register` | FrostyGoop, Stuxnet |
| T0843 | Program Download | 12 módulos | `cve/siemens/cve_2021_22681_s7_1200_hardcoded_key` | Stuxnet, INCONTROLLER |
| T0879 | Damage to Property | 5 módulos | `cve/malware/triton_triconex_safety` | TRITON, Industroyer |
| T0880 | Modify Alarm Settings | 8 módulos | `assessment/mitre_ics/t0880_modify_alarm_settings` | TRITON |
| T0828 | Loss of Safety | 4 módulos | `cve/malware/triton_triconex_safety` | TRITON/TRISIS |
| T0813 | Denial of Control | 6 módulos | `exploits/protocols/modbus/modbus_fc_abuse` | Industroyer, FrostyGoop |
| T0814 | Denial of Service | 8 módulos | `cve/malware/frostygoop_modbus_heating` | FrostyGoop, Crashoverride |
| T0859 | Valid Accounts | 15 módulos | `creds/siemens/simatic_default_creds` | Industroyer2 |
| T0845 | Program Upload | 5 módulos | `exploits/protocols/s7comm/s7comm_block_read` | Stuxnet, INCONTROLLER |
| T0833 | Modify Control Logic | 5 módulos | `exploits/protocols/s7comm/s7comm_program_download` | TRITON, Stuxnet |

---

*Anterior: [SafeMode / DestructiveMode](05-safemode-destructivemode.md) | Próximo: [SAST / LLM](07-sast-llm.md)*
