# MITRE ATT&CK for ICS

O IXF integra o MITRE ATT&CK for ICS v19, mapeando 976+ módulos para 74 de 90 técnicas (82% de cobertura) em todas as 12 táticas. Cada técnica mapeada no IXF tem pelo menos um módulo executável sob `exploits/`, `cve/`, `assessment/mitre_ics/` ou `scanners/ics/`.

---

## Sumário

1. [Visão Geral das Táticas](#visão-geral-das-táticas)
2. [Aliases de Tática](#aliases-de-tática)
3. [Aliases de Técnica](#aliases-de-técnica)
4. [mitre — Consultar uma Técnica](#mitre--consultar-uma-técnica)
5. [mitre-list — Índice de Técnicas](#mitre-list--índice-de-técnicas)
6. [mitre-scan — Varredura de Tática](#mitre-scan--varredura-de-tática)
7. [mitre-all — Varredura Completa](#mitre-all--varredura-completa)
8. [mitre-coverage — Relatório de Cobertura](#mitre-coverage--relatório-de-cobertura)
9. [mitre-report — Exportação](#mitre-report--exportação)
10. [ttp — Executar uma Técnica](#ttp--executar-uma-técnica)
11. [ttp-check — Verificação Passiva de Técnica](#ttp-check--verificação-passiva-de-técnica)
12. [ttp-simulate — Simulação de Técnica](#ttp-simulate--simulação-de-técnica)
13. [ttp-list — Navegador TTP](#ttp-list--navegador-ttp)
14. [Módulos de Assessment por Técnica](#módulos-de-assessment-por-técnica)
15. [Mapeamento Completo Técnica-para-Módulo](#mapeamento-completo-técnica-para-módulo)
16. [Formato JSON do ATT&CK Navigator](#formato-json-do-attck-navigator)
17. [Integração com ATT&CK Navigator](#integração-com-attck-navigator)

---

## Visão Geral das Táticas

A tabela abaixo mostra todas as 12 táticas do MITRE ATT&CK for ICS v19 com sua cobertura no IXF. As contagens de cobertura IXF incluem módulos de exploits CVE, exploits em nível de protocolo, módulos baseados em credenciais e módulos de assessment dedicados.

| ID de Tática | Nome da Tática | Total de Técnicas (v19) | Cobertura IXF | % Cobertura IXF | Contagem de Módulos |
|-------------|----------------|------------------------|---------------|-----------------|---------------------|
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

> **Nota:** O MITRE ATT&CK for ICS v19 expandiu de 90 para 101 técnicas com a adição de sub-técnicas nas táticas Evasion e Impact. O IXF rastreia contra a linha de base original de 90 técnicas para estabilidade; a figura de 82% referencia essa linha de base.

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

## Aliases de Técnica

O IXF aceita tanto o ID canônico de técnica MITRE quanto aliases comuns:

| ID de Técnica | Nome Canônico | Aliases Aceitos |
|-------------|----------------|-----------------|
| T0800 | Activate Firmware Update Mode | `activate-firmware`, `afum` |
| T0801 | Monitor Process State | `monitor-process`, `mps` |
| T0802 | Automated Collection | `automated-collection`, `autocollect` |
| T0803 | Block Command Message | `block-command`, `bcm` |
| T0804 | Block Reporting Message | `block-reporting`, `brm` |
| T0805 | Block Serial COM | `block-serial`, `bscom` |
| T0806 | Brute Force I/O | `brute-io`, `bfio` |
| T0807 | Remote Services | `remote-services`, `remserv` |
| T0808 | Replication via Removable Media | `removable-media`, `usb-replication` |
| T0809 | Data Destruction | `data-destruction`, `datadestroy` |
| T0810 | Data Exfiltration over C2 Channel | `data-exfil`, `exfil-c2` |
| T0811 | Data from Information Repositories | `data-repos`, `info-repos` |
| T0812 | Default Credentials | `default-creds`, `defcreds` |
| T0813 | Denial of Control | `denial-of-control`, `doc` |
| T0814 | Denial of Service | `denial-of-service`, `dos` |
| T0815 | Denial of View | `denial-of-view`, `dov` |
| T0816 | Device Restart/Shutdown | `device-restart`, `restart-shutdown` |
| T0817 | Drive-by Compromise | `drive-by`, `dbc` |
| T0818 | Engineering Workstation Compromise | `ewc`, `eng-ws` |
| T0819 | Exploit Public-Facing Application | `exploit-public`, `epa` |
| T0820 | Exploitation of Remote Services | `exploit-remote`, `ers` |
| T0821 | Modify Controller Tasking | `modify-tasking`, `mct` |
| T0822 | External Remote Services | `external-remote`, `ext-remote` |
| T0823 | Graphical User Interface | `gui-execution`, `gui` |
| T0824 | I/O Image | `io-image`, `ioi` |
| T0826 | Loss of Availability | `loss-availability`, `loa` |
| T0827 | Loss of Control | `loss-control`, `loc` |
| T0831 | Manipulation of Control | `manipulation-control`, `moc` |
| T0832 | Manipulation of View | `manipulation-view`, `mov` |
| T0833 | Modify Alarm Settings | `modify-alarm`, `mas` |
| T0834 | Native API | `native-api`, `napi` |
| T0835 | Detect Operating Mode | `detect-opmode`, `dom` |
| T0836 | Modify Parameter | `modify-param`, `modparam` |
| T0837 | Module Firmware | `module-firmware`, `modfirm` |
| T0838 | Modify Program | `modify-program`, `modprog` |
| T0839 | Change Credential | `change-cred`, `chcred` |
| T0840 | Network Connection Enumeration | `net-enum`, `nce` |
| T0841 | Network Sniffing | `sniff`, `network-sniff` |
| T0842 | Network Topology Mapping | `topo-map`, `ntm` |
| T0843 | Program Download | `prog-download`, `progdown` |
| T0844 | Program Upload | `prog-upload`, `progup` |
| T0845 | Program Organization Units | `pou`, `program-org` |
| T0846 | Remote System Discovery | `remote-discovery`, `rsd` |
| T0847 | Replication via Removable Media | `removable-rep`, `usb-rep` |
| T0848 | Rogue Master | `rogue-master`, `rm` |
| T0849 | Masquerading | `masquerade`, `mask` |
| T0851 | Rootkit | `rootkit`, `rkit` |
| T0852 | Screen Capture | `screen-capture`, `screencap` |
| T0853 | Scripting | `scripting`, `script` |
| T0854 | Serial Connection Enumeration | `serial-enum`, `sce` |
| T0855 | Unauthorized Command Message | `unauthorized-cmd`, `ucm` |
| T0856 | Spoof Reporting Message | `spoof-report`, `srm` |
| T0857 | System Firmware | `system-firmware`, `sysfirm` |
| T0858 | Change Credential (variant) | `change-cred2`, `chcred2` |
| T0859 | Valid Accounts | `valid-accounts`, `va` |
| T0860 | Wireless Compromise | `wireless`, `wcompromise` |
| T0861 | Point and Tag Identification | `point-id`, `tag-id` |
| T0862 | Supply Chain Compromise | `supply-chain`, `scc` |
| T0863 | User Execution | `user-exec`, `uexec` |
| T0864 | Transient Cyber Asset | `transient-asset`, `tca` |
| T0865 | Spearphishing Attachment | `spearphish`, `spa` |
| T0866 | Exploitation of Remote Services (Lateral) | `exploit-lateral`, `erl` |
| T0867 | Lateral Tool Transfer | `lateral-tool`, `ltt` |
| T0869 | Standard Application Layer Protocol | `app-layer-proto`, `salp` |
| T0870 | Commonly Used Port | `common-port`, `cup` |
| T0871 | Execution through API | `api-exec`, `apiexec` |
| T0873 | Project File Infection | `project-infect`, `pfi` |
| T0874 | Hooking | `hooking`, `hook` |
| T0875 | Change Program State | `change-progstate`, `cps` |
| T0877 | I/O Module Discovery | `io-module-disc`, `iomd` |
| T0878 | Alarm Suppression | `alarm-suppress`, `alsup` |
| T0879 | Damage to Property | `damage-property`, `dtp` |
| T0880 | Loss of Safety | `safety-loss`, `safety-compromise` |
| T0881 | Service Stop | `service-stop`, `svc-stop` |
| T0882 | Theft of Operational Information | `theft-opinfo`, `toi` |
| T0883 | Internet Accessible Device | `internet-device`, `iad` |
| T0884 | Connection Proxy | `proxy`, `conn-proxy` |
| T0888 | Remote System Information Discovery | `remote-info`, `rsid` |
| T0889 | Modify Program (variante ICS) | `modify-prog2`, `mprog2` |
| T0890 | Exploitation for Privilege Escalation | `exploit-privesc`, `epe` |

---

## `mitre` — Consultar uma Técnica

Exibe informações detalhadas sobre uma técnica MITRE ATT&CK for ICS específica, incluindo módulos mapeados, associação tática e notas de remediação.

**Sintaxe:**
```
ixf > mitre <id_tecnica>
```

### Exemplo 1: Consultar T0819 (Exploit Public-Facing Application)

```
ixf > mitre T0819

  ╔══════════════════════════════════════════════════════════════════╗
  ║  MITRE ATT&CK for ICS — Detalhe de Técnica                      ║
  ╚══════════════════════════════════════════════════════════════════╝

  ID:          T0819
  Nome:        Exploit Public-Facing Application
  Tática:      Initial Access (TA0108)
  Módulos IXF: 47 módulos

  Descrição:
    Adversários exploram vulnerabilidades em aplicações ICS acessíveis
    pela internet, incluindo interfaces web SCADA, portais de estação
    de engenharia e gateways de acesso remoto expostos diretamente à
    internet ou acessíveis de redes TI.

  Módulos IXF (top 10 mostrados — use `search T0819` para ver todos os 47):
    cve/siemens/cve_2019_13945_scalance_x_rce
    cve/siemens/cve_2021_31894_s7_1500_rce
    cve/siemens/cve_2022_43767_wincc_path_traversal
    cve/schneider/cve_2021_22763_ecostruxure_auth_bypass
    cve/schneider/cve_2022_37300_modicon_m340_rce
    cve/rockwell/cve_2021_27478_factorytalk_rce
    cve/aveva/cve_2021_33544_intouch_rce
    cve/aveva/cve_2021_42536_system_platform_rce
    cve/honeywell/cve_2021_38153_experion_pks_rce
    cve/ge/cve_2022_29951_opshub_ssrf

  Fontes de Dados MITRE:
    - Application Log: Registro de Erros de Aplicação
    - Network Traffic: Conteúdo de Tráfego de Rede
    - Network Traffic: Criação de Conexão de Rede

  Remediação:
    - Segmentar aplicações ICS da exposição direta à internet via DMZ
    - Aplicar patches do fornecedor; assinar avisos ICS-CERT
    - Implantar WAF industrial (ex.: Claroty, Nozomi) para HMI baseado em HTTP
    - Aplicar MFA em todos os portais de acesso remoto
    - Monitorar padrões anormais de sessão HMI
```

### Exemplo 2: Consultar T0836 (Modify Parameter)

```
ixf > mitre T0836

  ╔══════════════════════════════════════════════════════════════════╗
  ║  MITRE ATT&CK for ICS — Detalhe de Técnica                      ║
  ╚══════════════════════════════════════════════════════════════════╝

  ID:          T0836
  Nome:        Modify Parameter
  Tática:      Impair Process Control (TA0106)
  Módulos IXF: 18 módulos

  Descrição:
    Adversários modificam parâmetros operacionais dentro do processo
    industrial — setpoints, ganhos PID, limites, thresholds — para
    afetar o processo físico sem acionar alarmes, contanto que a
    mudança permaneça dentro de intervalos visíveis ao operador.

  Módulos IXF:
    exploits/protocols/modbus/modbus_write_holding_register
    exploits/protocols/modbus/modbus_write_multiple_registers
    exploits/protocols/s7comm/s7_write_db_block
    exploits/protocols/enip/enip_write_tag
    exploits/protocols/opcua/opcua_write_value_anon
    exploits/protocols/fins/fins_memory_area_write
    exploits/protocols/dnp3/dnp3_direct_operate
    assessment/mitre_ics/t0836_modify_parameter
    cve/siemens/cve_2019_10929_s7_replay_writedb
    cve/schneider/cve_2018_7789_modicon_m340_auth_bypass

  Impacto Físico:
    - Ganhos PID modificados causam instabilidade de processo
    - Setpoints de pressão elevados excedem limites de projeto do vaso
    - Proporções de dosagem química alteradas produzem reações perigosas
    - Parâmetros de velocidade de motor modificados causam sobrecarga mecânica

  MITRE: T0836 | Tática: TA0106
```

### Exemplo 3: Consultar T0843 (Program Download) com saída completa de módulos executando

```
ixf > mitre T0843

  ╔══════════════════════════════════════════════════════════════════╗
  ║  MITRE ATT&CK for ICS — Detalhe de Técnica                      ║
  ╚══════════════════════════════════════════════════════════════════╝

  ID:          T0843
  Nome:        Program Download
  Tática:      Lateral Movement (TA0109), Execution (TA0104)
  Módulos IXF: 12 módulos

  Descrição:
    Adversários baixam um programa PLC modificado para um controlador,
    substituindo ou injetando lógica para alterar o comportamento do
    processo. É uma técnica multi-tática que aparece tanto em Execution
    quanto em Lateral Movement, pois consegue execução de código no
    controlador.

  Módulos IXF:
    cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
    cve/siemens/cve_2019_13945_scalance_s7_program_download
    cve/rockwell/cve_2022_1161_controllogix_modified_fw
    exploits/protocols/s7comm/s7_plc_program_upload_download
    exploits/protocols/enip/enip_program_download_controllogix
    exploits/protocols/pccc/pccc_slc500_program_download
    assessment/mitre_ics/t0843_program_download
    cve/schneider/cve_2018_7847_modicon_quantum_exec
    cve/ge/cve_2021_27454_rx3i_program_download
    cve/omron/cve_2022_34151_sysmac_studio_rce
    cve/abb/cve_2019_18995_totalflow_rce
    cve/yokogawa/cve_2020_5523_centum_program_download
```

**Executando todos os módulos T0843 no modo simulate:**
```
ixf > ttp T0843 192.168.1.100

  [ttp T0843] Executando 12 módulos para Program Download em 192.168.1.100
  Modo: SIMULATE (seguro)
  ─────────────────────────────────────────────────────────────────────────

  [1/12] cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
  [*] target => 192.168.1.100
  ┌─ SIMULATE MODE ─────────────────────────────────────────────────────────┐
  │ CVE-2021-22681 S7-1200/1500 Hardcoded Key — Upload de programa PLC     │
  │ Passo 1: TCP conectar :102, TPKT/COTP CR                               │
  │ Passo 2: Autenticar com chave simétrica codificada                     │
  │ Passo 3: Download de programa STL do atacante para slot 2              │
  │ Impacto: Lógica PLC do atacante executando no controlador              │
  │ MITRE: T0843, T0821                                                     │
  └─────────────────────────────────────────────────────────────────────────┘

  [2/12] exploits/protocols/s7comm/s7_plc_program_upload_download
  [*] target => 192.168.1.100
  ┌─ SIMULATE MODE ─────────────────────────────────────────────────────────┐
  │ S7comm Program Upload/Download — Transferência não autorizada de lógica │
  │ Passo 1: Conexão COTP, S7comm setup communication                      │
  │ Passo 2: Upload do programa existente (leitura)                        │
  │ Passo 3: Modificar bloco STL e fazer download de volta                 │
  │ Impacto: Lógica de processo adulterada, operação do PLC comprometida   │
  │ MITRE: T0843, T0844                                                     │
  └─────────────────────────────────────────────────────────────────────────┘

  [3/12] cve/rockwell/cve_2022_1161_controllogix_modified_fw
  [*] target => 192.168.1.100
  ┌─ SIMULATE MODE ─────────────────────────────────────────────────────────┐
  │ CVE-2022-1161 Rockwell ControlLogix Modified Firmware                   │
  │ Passo 1: Conectar via EtherNet/IP CIP :44818                           │
  │ Passo 2: Usar serviço CIP para download de firmware modificado         │
  │ Passo 3: Firmware adulterado persiste no reinicio                      │
  │ Impacto: Backdoor persistente no controlador Logix                     │
  │ MITRE: T0843, T0839                                                     │
  └─────────────────────────────────────────────────────────────────────────┘

  [4/12] assessment/mitre_ics/t0843_program_download
  ┌─ SIMULATE MODE ─────────────────────────────────────────────────────────┐
  │ Assessment T0843: Program Download — Framework de assessment estruturado │
  │ Checklist: Autenticação para transferência de programa verificada?      │
  │ Checklist: Integridade de programa verificada antes da execução?        │
  │ Checklist: Log de auditoria de mudanças de lógica presente?            │
  │ MITRE: T0843                                                             │
  └─────────────────────────────────────────────────────────────────────────┘

  ... [8 módulos adicionais em modo simulate] ...

  ─────────────────────────────────────────────────────────────────────────
  [ttp T0843] Resumo: 12/12 módulos executados | Modo: SIMULATE
  [i] Para teste ao vivo: ixf > ttp T0843 192.168.1.100 --live
```

### Exemplo 4: Consultar T0878 (Alarm Suppression)

```
ixf > mitre T0878

  ID:          T0878
  Nome:        Alarm Suppression
  Tática:      Inhibit Response Function (TA0107)
  Módulos IXF: 6 módulos

  Descrição:
    Adversários suprimem alarmes para prevenir que operadores sejam
    notificados de anomalias de processo, falhas de equipamentos ou
    violações de segurança enquanto o ataque prossegue.

  Precedente Real:
    - TRITON/TRISIS (2017): Desabilitou alarmes do Safety Instrumented
      System antes de tentar causar dano físico
    - Industroyer (2016): Suprimiu mensagens de status SCADA durante
      operações de disjuntor na subestação Ukrenergo

  Módulos IXF:
    assessment/mitre_ics/t0878_alarm_suppression
    exploits/protocols/modbus/modbus_write_alarm_suppression_coil
    exploits/protocols/dnp3/dnp3_unsolicited_response_disable
    exploits/protocols/opcua/opcua_alarm_acknowledge_flood
    cve/honeywell/cve_2021_38155_experion_alarm_bypass
    exploits/protocols/iec104/iec104_spontaneous_message_block
```

---

## `mitre-list` — Índice de Técnicas

Exibe todas as 74 técnicas cobertas organizadas por ID, ou filtra por tática.

### Saída Completa

```
ixf > mitre-list

  MITRE ATT&CK for ICS — Índice de Técnicas (74 cobertas / 90 total)
  ════════════════════════════════════════════════════════════════════════
  ID      Nome                                        Módulos  Tática
  ──────────────────────────────────────────────────────────────────────
  T0800   Activate Firmware Update Mode                  3     [Inhibit]
  T0801   Monitor Process State                          2     [Collection]
  T0802   Automated Collection                           5     [Collection]
  T0803   Block Command Message                          3     [Inhibit]
  T0804   Block Reporting Message                        2     [Inhibit]
  T0806   Brute Force I/O                                1     [Impair]
  T0807   Remote Services                                8     [Lateral Mvmt]
  T0808   Replication via Removable Media                2     [Persistence]
  T0809   Disk Wipe                                      3     [Impact]
  T0810   Data Exfiltration over C2 Channel              2     [Collection]
  T0811   Data from Information Repositories             4     [Collection]
  T0812   Default Credentials                           37     [Lateral Mvmt]
  T0813   Denial of Control                              5     [Impact]
  T0814   Denial of Service                              8     [Inhibit]
  T0815   Denial of View                                 3     [Inhibit]
  T0816   Device Restart/Shutdown                        9     [Inhibit]
  T0817   Drive-by Compromise                            3     [Initial Access]
  T0819   Exploit Public-Facing Application             47     [Initial Access]
  T0820   Exploitation of Remote Services               12     [Initial Access]
  T0821   Modify Controller Tasking                      4     [Execution]
  T0822   External Remote Services                       6     [Initial Access]
  T0823   Graphical User Interface                       2     [Execution]
  T0824   I/O Image                                      1     [Execution]
  T0826   Loss of Availability                           4     [Impact]
  T0827   Loss of Control                                2     [Impact]
  T0831   Manipulation of Control                        6     [Impair]
  T0832   Manipulation of View                           3     [Collection]
  T0833   Modify Alarm Settings                          3     [Impair]
  T0834   Native API                                     2     [Execution]
  T0835   Detect Operating Mode                          2     [Inhibit]
  T0836   Modify Parameter                              18     [Impair]
  T0837   Module Firmware                                3     [Persistence]
  T0838   Modify Program                                 5     [Inhibit]
  T0839   Firmware Modification                          7     [Persistence]
  T0840   Network Connection Enumeration                 2     [Discovery]
  T0841   Network Sniffing                               3     [Discovery]
  T0842   Network Topology Mapping                       4     [Discovery]
  T0843   Program Download                              12     [Lateral / Exec]
  T0844   Program Upload                                 8     [Collection]
  T0845   Program Organization Units                     2     [Execution]
  T0846   Remote System Discovery                        8     [Discovery]
  T0847   Replication via Removable Media                2     [Persistence]
  T0848   Rogue Master                                   3     [Initial Access]
  T0849   Masquerading                                   1     [Evasion]
  T0851   Rootkit                                        2     [Inhibit]
  T0852   Screen Capture                                 2     [Collection]
  T0853   Scripting                                      3     [Execution]
  T0854   Serial Connection Enumeration                  2     [Discovery]
  T0855   Unauthorized Command Message                   6     [Impair]
  T0856   Spoof Reporting Message                        2     [Evasion / Inhibit]
  T0857   System Firmware                                4     [Persistence]
  T0858   Change Credential                              4     [Evasion]
  T0859   Valid Accounts                                37     [Persistence]
  T0860   Wireless Compromise                            3     [Initial Access]
  T0861   Point and Tag Identification                   2     [Discovery]
  T0862   Supply Chain Compromise                        2     [Initial Access]
  T0863   User Execution                                 2     [Execution]
  T0864   Transient Cyber Asset                          1     [Initial Access]
  T0865   Spearphishing Attachment                       3     [Initial Access]
  T0866   Exploitation for Lateral Movement              5     [Lateral Mvmt]
  T0867   Lateral Tool Transfer                          2     [Lateral Mvmt]
  T0869   Standard Application Layer Protocol            4     [C2]
  T0870   Commonly Used Port                             3     [C2]
  T0871   Execution through API                          4     [Execution / Impair]
  T0873   Project File Infection                         3     [Impair]
  T0874   Hooking                                        1     [Evasion]
  T0875   Change Program State                           2     [Impair]
  T0877   I/O Module Discovery                           3     [Discovery]
  T0878   Alarm Suppression                              6     [Inhibit]
  T0879   Damage to Property                             2     [Impact]
  T0880   Loss of Safety                                 3     [Impact]
  T0881   Service Stop                                   4     [Inhibit]
  T0882   Theft of Operational Information               3     [C2 / Inhibit]
  T0883   Internet Accessible Device                     5     [Discovery]
  T0884   Connection Proxy                               2     [C2]
  T0885   Commonly Used Port (variante C2)               2     [C2]
  T0888   Remote System Information Discovery            4     [Discovery]
  T0889   Modify Program (variante ICS)                  3     [Persistence]
  T0890   Exploitation for Privilege Escalation          3     [Privesc]
  ──────────────────────────────────────────────────────────────────────
  Total cobertos: 74 técnicas | Total de módulos: 976+
```

### Filtrado por Tática — Initial Access

```
ixf > mitre-list --tactic initial-access

  MITRE ATT&CK for ICS — Initial Access (TA0108)
  ════════════════════════════════════════════════════════════════════════
  ID      Nome                                        Módulos
  ──────────────────────────────────────────────────────────────────────
  T0817   Drive-by Compromise                             3
  T0819   Exploit Public-Facing Application              47
  T0820   Exploitation of Remote Services                12
  T0822   External Remote Services                        6
  T0848   Rogue Master                                    3
  T0860   Wireless Compromise                             3
  T0862   Supply Chain Compromise                         2
  T0864   Transient Cyber Asset                           1
  T0865   Spearphishing Attachment                        3
  ──────────────────────────────────────────────────────────────────────
  Total: 9/9 técnicas cobertas (100%) | 80 módulos
```

### Filtrado por Tática — Discovery

```
ixf > mitre-list --tactic discovery

  MITRE ATT&CK for ICS — Discovery (TA0102)
  ════════════════════════════════════════════════════════════════════════
  ID      Nome                                        Módulos
  ──────────────────────────────────────────────────────────────────────
  T0840   Network Connection Enumeration                  2
  T0841   Network Sniffing                                3
  T0842   Network Topology Mapping                        4
  T0843   Program Download (fase de reconhecimento)      12
  T0846   Remote System Discovery                         8
  T0854   Serial Connection Enumeration                   2
  T0861   Point and Tag Identification                    2
  T0877   I/O Module Discovery                            3
  T0883   Internet Accessible Device                      5
  T0888   Remote System Information Discovery             4
  T0867   Lateral Tool Transfer (fase de descoberta)      2  [parcial]
  ──────────────────────────────────────────────────────────────────────
  Total: 11/13 técnicas cobertas (84%) | 47 módulos
```

### Filtrado por Tática — Inhibit Response Function

```
ixf > mitre-list --tactic inhibit

  MITRE ATT&CK for ICS — Inhibit Response Function (TA0107)
  ════════════════════════════════════════════════════════════════════════
  ID      Nome                                        Módulos
  ──────────────────────────────────────────────────────────────────────
  T0800   Activate Firmware Update Mode                   3
  T0803   Block Command Message                           3
  T0804   Block Reporting Message                         2
  T0814   Denial of Service                               8
  T0815   Denial of View                                  3
  T0816   Device Restart/Shutdown                         9
  T0835   Detect Operating Mode                           2
  T0838   Modify Program                                  5
  T0851   Rootkit                                         2
  T0856   Spoof Reporting Message                         2
  T0878   Alarm Suppression                               6
  T0881   Service Stop                                    4
  T0882   Theft of Operational Information                3
  T0889   Modify Program (variante ICS)                   3
  ──────────────────────────────────────────────────────────────────────
  Total: 14/18 técnicas cobertas (77%) | 55 módulos
  [!] Não cobertas: T0805, T0829, T0869 (sobreposição C2), T0880 (em Impact)
```

### Filtrado por Tática — Impair Process Control

```
ixf > mitre-list --tactic impair

  MITRE ATT&CK for ICS — Impair Process Control (TA0106)
  ════════════════════════════════════════════════════════════════════════
  ID      Nome                                        Módulos
  ──────────────────────────────────────────────────────────────────────
  T0806   Brute Force I/O                                 1
  T0831   Manipulation of Control                         6
  T0833   Modify Alarm Settings                           3
  T0836   Modify Parameter                               18
  T0855   Unauthorized Command Message                    6
  T0871   Execution through API                           4
  T0873   Project File Infection                          3
  T0875   Change Program State                            2
  T0889   Modify Program (variante ICS)                   3
  ──────────────────────────────────────────────────────────────────────
  Total: 9/11 técnicas cobertas (81%) | 46 módulos
  [!] Não cobertas: T0821 (Modify Controller Tasking), T0837 (Module Firmware)
```

### Filtrado por Tática — Impact

```
ixf > mitre-list --tactic impact

  MITRE ATT&CK for ICS — Impact (TA0105)
  ════════════════════════════════════════════════════════════════════════
  ID      Nome                                        Módulos
  ──────────────────────────────────────────────────────────────────────
  T0809   Data Destruction                                3
  T0813   Denial of Control                               5
  T0826   Loss of Availability                            4
  T0827   Loss of Control                                 2
  T0879   Damage to Property                              2
  T0880   Loss of Safety                                  3
  T0881   Service Stop (variante Impact)                  4
  T0882   Theft of Operational Information                3
  ──────────────────────────────────────────────────────────────────────
  Total: 8/11 técnicas cobertas (72%) | 26 módulos
  [!] Não cobertas: T0828 (Loss of Productivity), T0829 (Loss of Safety dup),
      T0830 (Loss of View)
```

---

## `mitre-scan` — Varredura de Tática

Executa todas as técnicas de uma tática inteira contra um alvo ou sub-rede. Seguro por padrão (simulate=True).

**Sintaxe:**
```
ixf > mitre-scan <tatica|id_tecnica> <alvo> [--live] [--rate-limit <ms>] [--output <arquivo>]
```

### Exemplo 1: Varredura de Discovery em Sub-rede

```
ixf > mitre-scan discovery 192.168.1.0/24

  ╔══════════════════════════════════════════════════════════════════╗
  ║  MITRE ATT&CK for ICS — Varredura de Tática                     ║
  ╚══════════════════════════════════════════════════════════════════╝
  Tática:      Discovery (TA0102)
  Alvo:        192.168.1.0/24
  Modo:        SIMULATE (seguro)
  Técnicas:    11 cobertas
  Total de módulos a executar: 47

  ─── T0840: Network Connection Enumeration ─────────────────────────
  [1/2] scanners/ics/modbus_scanner         192.168.1.0/24  [SIMULATE]
  [2/2] scanners/ics/enip_scanner           192.168.1.0/24  [SIMULATE]
  [+] T0840 completo: 2 módulos

  ─── T0841: Network Sniffing ────────────────────────────────────────
  [1/3] assessment/mitre_ics/t0841_network_sniff   [SIMULATE]
  [2/3] scanners/ics/passive_banner_grab           [SIMULATE]
  [3/3] scanners/ics/ics_protocol_fingerprint      [SIMULATE]
  [+] T0841 completo: 3 módulos

  ─── T0842: Network Topology Mapping ───────────────────────────────
  [1/4] scanners/ics/ics_network_mapper            [SIMULATE]
  [2/4] scanners/ics/profinet_dcp_scan             [SIMULATE]
  [3/4] scanners/ics/lldp_collector                [SIMULATE]
  [4/4] scanners/ics/snmp_topology_walk            [SIMULATE]
  [+] T0842 completo: 4 módulos

  ─── T0846: Remote System Discovery ────────────────────────────────
  [1/8] scanners/ics/s7_comm_scanner               [SIMULATE]
  [2/8] scanners/ics/omron_fins_scan               [SIMULATE]
  [3/8] scanners/ics/bacnet_discovery              [SIMULATE]
  [4/8] scanners/ics/dnp3_data_link_scan           [SIMULATE]
  [5/8] scanners/ics/iec104_scan                   [SIMULATE]
  [6/8] scanners/ics/opcua_discovery               [SIMULATE]
  [7/8] scanners/ics/profinet_dcp_scan             [SIMULATE]
  [8/8] scanners/ics/modbus_device_id              [SIMULATE]
  [+] T0846 completo: 8 módulos

  ... [T0843, T0854, T0861, T0877, T0883, T0888 omitidos por brevidade] ...

  ─────────────────────────────────────────────────────────────────────
  Varredura de tática Discovery completa.
  47 módulos executados em modo SIMULATE contra 192.168.1.0/24
  Resultados salvos em .tmp/mitre_scan_discovery_2026-06-01.json
```

### Exemplo 2: Varredura de Impair Process Control

```
ixf > mitre-scan impair 192.168.10.5 --rate-limit 500

  ╔══════════════════════════════════════════════════════════════════╗
  ║  MITRE ATT&CK for ICS — Varredura de Tática                     ║
  ╚══════════════════════════════════════════════════════════════════╝
  Tática:      Impair Process Control (TA0106)
  Alvo:        192.168.10.5
  Modo:        SIMULATE (seguro)
  Rate limit:  500ms entre módulos
  Técnicas:    9 cobertas

  ─── T0836: Modify Parameter ────────────────────────────────────────
  [1/18] exploits/protocols/modbus/modbus_write_holding_register    [SIMULATE]
  [2/18] exploits/protocols/modbus/modbus_write_multiple_registers  [SIMULATE]
  [3/18] exploits/protocols/s7comm/s7_write_db_block               [SIMULATE]
  ... [15 módulos adicionais] ...
  [+] T0836 completo: 18 módulos

  ─── T0831: Manipulation of Control ────────────────────────────────
  [1/6] exploits/protocols/modbus/modbus_write_coil                 [SIMULATE]
  [2/6] exploits/protocols/dnp3/dnp3_direct_operate                [SIMULATE]
  [3/6] exploits/protocols/enip/enip_set_attribute_anon            [SIMULATE]
  ... [3 módulos adicionais] ...
  [+] T0831 completo: 6 módulos

  ... [T0806, T0833, T0855, T0871, T0873, T0875, T0889 omitidos] ...

  ─────────────────────────────────────────────────────────────────────
  Varredura de tática Impair Process Control completa.
  46 módulos executados | Modo: SIMULATE | Rate: 500ms
```

---

## `mitre-all` — Varredura Completa

Executa todas as 74 técnicas cobertas em modo simulate contra um alvo.

```
ixf > mitre-all 192.168.1.100

  ╔══════════════════════════════════════════════════════════════════╗
  ║  IXF MITRE ATT&CK for ICS — Varredura Completa                  ║
  ╚══════════════════════════════════════════════════════════════════╝
  Alvo:     192.168.1.100
  Modo:     SIMULATE (seguro — nenhum pacote enviado)
  Táticas:  12 táticas
  Técnicas: 74 técnicas
  Módulos:  976+ módulos a executar em simulate

  Iniciando varredura MITRE completa...
  [Tática 1/12] Initial Access (TA0108) — 9 técnicas, 93 módulos
  [Tática 2/12] Execution (TA0104) — 8 técnicas, 74 módulos
  [Tática 3/12] Persistence (TA0110) — 6 técnicas, 48 módulos
  ...
  [Tática 12/12] Impact (TA0105) — 8 técnicas, 59 módulos

  ─────────────────────────────────────────────────────────────────────
  Varredura MITRE completa concluída.
  74 técnicas | 976+ módulos | Modo: SIMULATE
  Relatório salvo em .tmp/mitre_full_sweep_192.168.1.100_2026-06-01.json
  Camada Navigator salva em .tmp/ixf_mitre_layer_2026-06-01.json
```

---

## `mitre-coverage` — Relatório de Cobertura

Exibe uma tabela completa de cobertura por tática e técnica.

```
ixf > mitre-coverage

  IXF MITRE ATT&CK for ICS — Relatório de Cobertura
  ════════════════════════════════════════════════════════════════════════

  Tática                     ID      Total  Cobert.  %        Módulos
  ──────────────────────────────────────────────────────────────────────
  Initial Access             TA0108    9       9    100%        93
  Execution                  TA0104    9       8     88%        74
  Persistence                TA0110    8       6     75%        48
  Privilege Escalation       TA0111    2       2    100%        11
  Evasion                    TA0103    5       4     80%        28
  Discovery                  TA0102   13      11     84%       134
  Lateral Movement           TA0109    3       3    100%        52
  Collection                 TA0100    9       8     88%        97
  Command and Control        TA0101    3       3    100%        19
  Inhibit Response Function  TA0107   18      14     77%       218
  Impair Process Control     TA0106   11       9     81%       143
  Impact                     TA0105   11       8     72%        59
  ──────────────────────────────────────────────────────────────────────
  TOTAL                                90      74     82%       976+

  Técnicas com 10+ módulos:
    T0812 Default Credentials            37 módulos
    T0859 Valid Accounts                 37 módulos
    T0819 Exploit Public-Facing App      47 módulos
    T0836 Modify Parameter               18 módulos
    T0820 Exploitation of Remote Svc     12 módulos
    T0843 Program Download               12 módulos
    T0816 Device Restart/Shutdown         9 módulos

  [*] Camada ATT&CK Navigator JSON salva em .tmp/ixf_mitre_layer_2026-06-01.json
  [+] Abrir em: https://mitre-attack.github.io/attack-navigator/
```

---

## `mitre-report` — Exportação

Exporta o mapeamento MITRE completo em múltiplos formatos.

```
ixf > mitre-report json
[*] Gerando relatório MITRE JSON completo...
[+] Salvo em .tmp/ixf_mitre_report_2026-06-01.json

ixf > mitre-report csv
[*] Gerando relatório MITRE CSV...
[+] Salvo em .tmp/ixf_mitre_report_2026-06-01.csv

ixf > mitre-report navigator
[*] Gerando camada ATT&CK Navigator...
[+] Salvo em .tmp/ixf_mitre_layer_2026-06-01.json
[i] Importar em: https://mitre-attack.github.io/attack-navigator/
```

---

## `ttp` — Executar uma Técnica

Executa todos os módulos mapeados para uma técnica específica contra um alvo.

**Sintaxe:**
```
ixf > ttp <id_tecnica> <alvo> [--live] [--module <caminho>]
```

### Exemplo: ttp T0812 (Default Credentials) em modo simulate

```
ixf > ttp T0812 192.168.1.0/24

  [ttp T0812] Default Credentials — 37 módulos em 192.168.1.0/24
  Modo: SIMULATE (seguro)
  ─────────────────────────────────────────────────────────────────────────

  [1/37] creds/siemens/s7_default_creds               [SIMULATE]
  [2/37] creds/siemens/ssh_default_creds              [SIMULATE]
  [3/37] creds/siemens/web_default_creds              [SIMULATE]
  [4/37] creds/rockwell/logix_default_creds           [SIMULATE]
  [5/37] creds/schneider/web_default_creds            [SIMULATE]
  [6/37] creds/honeywell/experion_default_creds       [SIMULATE]
  [7/37] creds/ge/cimplicity_default_creds            [SIMULATE]
  [8/37] creds/omron/fins_default_creds               [SIMULATE]
  [9/37] creds/generic/ftp_default_creds              [SIMULATE]
  [10/37] creds/generic/ssh_default_creds             [SIMULATE]
  ... [27 módulos adicionais] ...

  ─────────────────────────────────────────────────────────────────────────
  [ttp T0812] Completo: 37/37 módulos | Modo: SIMULATE
```

---

## `ttp-check` — Verificação Passiva de Técnica

Executa apenas o método `check()` somente leitura de todos os módulos de uma técnica.

```
ixf > ttp-check T0846 192.168.1.0/24

  [ttp-check T0846] Remote System Discovery — verificação somente leitura
  ─────────────────────────────────────────────────────────────────────────

  [1/8] scanners/ics/s7_comm_scanner         192.168.1.0/24  check: [+] 3 alvos responderam
  [2/8] scanners/ics/omron_fins_scan         192.168.1.0/24  check: [-] nenhum
  [3/8] scanners/ics/bacnet_discovery        192.168.1.0/24  check: [+] 1 alvo respondeu
  [4/8] scanners/ics/modbus_device_id        192.168.1.0/24  check: [+] 7 alvos responderam
  [5/8] scanners/ics/iec104_scan             192.168.1.0/24  check: [-] nenhum
  [6/8] scanners/ics/opcua_discovery         192.168.1.0/24  check: [+] 2 alvos responderam
  [7/8] scanners/ics/dnp3_data_link_scan     192.168.1.0/24  check: [-] nenhum
  [8/8] scanners/ics/profinet_dcp_scan       192.168.1.0/24  check: [+] 4 alvos responderam

  ─────────────────────────────────────────────────────────────────────────
  Descobertos: S7comm (3), BACnet (1), Modbus (7), OPC UA (2), PROFINET (4)
  Total de dispositivos ICS únicos: 12
```

---

## `ttp-simulate` — Simulação de Técnica

Exibe saída de simulação completa para uma técnica sem nenhum módulo em execução.

```
ixf > ttp-simulate T0836 192.168.1.100

  [ttp-simulate T0836] Modify Parameter — saída de simulação completa
  Alvo: 192.168.1.100 | Modo: APENAS EXIBIÇÃO (sem execução de módulo)
  ─────────────────────────────────────────────────────────────────────────

  Técnica: T0836 — Modify Parameter
  Tática:  Impair Process Control (TA0106)

  O que um adversário faria:
    1. Descobrir registradores de setpoint via leitura Modbus FC03
    2. Identificar registradores de setpoint críticos (pressão, temperatura, fluxo)
    3. Escrever valores alterados em registradores alvo via FC16
    4. Modificações permanecem até que o operador perceba anormalidade de processo
    5. Se alarmes foram suprimidos (T0878), o operador pode não ser notificado

  Payloads de exemplo para 192.168.1.100:502:
    FC03 Read (sondar): 00 01 00 00 00 06 01 03 00 00 00 0A
    FC16 Write (atacar): 00 01 00 00 00 0B 01 10 00 00 00 02 04 XX XX YY YY

  MITRE: T0836 | Tática: TA0106
  Técnicas relacionadas: T0831, T0833, T0855, T0878
```

---

## `ttp-list` — Navegador TTP

Navega pelos TTPs disponíveis, filtrando por tática.

```
ixf > ttp-list initial-access

  TTPs Disponíveis — Initial Access (TA0108)
  ════════════════════════════════════════════════════════════════════════
  ID      Nome                               Módulos  Grupos APT Conhecidos
  ──────────────────────────────────────────────────────────────────────
  T0817   Drive-by Compromise                    3    APT33, Sandworm
  T0819   Exploit Public-Facing Application     47    APT33, Lazarus, Xenotime
  T0820   Exploitation of Remote Services       12    Sandworm, APT40
  T0822   External Remote Services               6    APT28, Turla
  T0848   Rogue Master                           3    Sandworm, APT41
  T0860   Wireless Compromise                    3    APT10
  T0862   Supply Chain Compromise                2    APT41, SolarWinds actors
  T0864   Transient Cyber Asset                  1    TEMP.Veles (TRITON)
  T0865   Spearphishing Attachment               3    APT28, Lazarus, APT33
  ──────────────────────────────────────────────────────────────────────

ixf > ttp-list impact

  TTPs Disponíveis — Impact (TA0105)
  ════════════════════════════════════════════════════════════════════════
  ID      Nome                               Módulos  Malware Relacionado
  ──────────────────────────────────────────────────────────────────────
  T0809   Data Destruction                       3    KillDisk, NotPetya
  T0813   Denial of Control                      5    Industroyer, CosmicEnergy
  T0826   Loss of Availability                   4    FrostyGoop, CosmicEnergy
  T0827   Loss of Control                        2    TRITON/TRISIS
  T0879   Damage to Property                     2    TRITON/TRISIS, Industroyer2
  T0880   Loss of Safety                         3    TRITON/TRISIS, PIPEDREAM
  T0881   Service Stop (Impact)                  4    EKANS/Snake
  T0882   Theft of Operational Information       3    Industroyer, APT33
  ──────────────────────────────────────────────────────────────────────
```

---

## Módulos de Assessment por Técnica

Os 28 módulos de assessment específicos de técnica sob `assessment/mitre_ics/`:

| Módulo | Técnica | Descrição |
|--------|---------|-----------|
| `t0800_activate_firmware_update_mode` | T0800 | Verificação de modo de atualização de firmware |
| `t0801_monitor_process_state` | T0801 | Monitoramento de estado de processo via Modbus read |
| `t0802_automated_collection` | T0802 | Assessment de coleta automatizada |
| `t0806_brute_force_io` | T0806 | Assessment de força bruta de módulo I/O |
| `t0812_default_credentials` | T0812 | Verificação de credenciais padrão |
| `t0814_denial_of_service` | T0814 | Assessment de DoS de dispositivo ICS |
| `t0816_device_restart` | T0816 | Assessment de reinicialização de dispositivo |
| `t0821_modify_controller_tasking` | T0821 | Verificação de modificação de tarefas do controlador |
| `t0831_manipulation_of_control` | T0831 | Assessment de manipulação de controle |
| `t0833_modify_alarm_settings` | T0833 | Verificação de modificação de configurações de alarme |
| `t0835_detect_operating_mode` | T0835 | Detecção de modo de operação do PLC |
| `t0836_modify_parameter` | T0836 | Assessment de modificação de parâmetro de processo |
| `t0838_modify_program` | T0838 | Verificação de modificação de programa PLC |
| `t0840_network_connection_enumeration` | T0840 | Enumeração de conexão de rede |
| `t0841_network_sniffing` | T0841 | Assessment de sniffing de rede |
| `t0843_program_download` | T0843 | Assessment de download de programa |
| `t0844_program_upload` | T0844 | Assessment de upload de programa |
| `t0846_remote_system_discovery` | T0846 | Assessment de descoberta de sistema remoto |
| `t0851_rootkit` | T0851 | Verificação de rootkit em dispositivo ICS |
| `t0855_unauthorized_command_message` | T0855 | Assessment de mensagem de comando não autorizada |
| `t0856_spoof_reporting_message` | T0856 | Assessment de spoofing de mensagem de relatório |
| `t0861_point_tag_identification` | T0861 | Identificação de ponto e tag |
| `t0871_execution_through_api` | T0871 | Assessment de execução via API |
| `t0873_project_file_infection` | T0873 | Verificação de infecção de arquivo de projeto |
| `t0877_io_module_discovery` | T0877 | Descoberta de módulo I/O |
| `t0878_alarm_suppression` | T0878 | Assessment de supressão de alarme |
| `t0879_damage_to_property` | T0879 | Assessment de dano à propriedade |
| `t0880_loss_of_safety` | T0880 | Assessment de perda de segurança |
| `coverage_report` | Todas | Relatório de cobertura MITRE completo |
| `full_mitre_sweep` | Todas | Varredura completa de todas as técnicas |

---

## Mapeamento Completo Técnica-para-Módulo

Tabela completa dos 74 técnicas cobertas com módulos primários:

| ID | Nome da Técnica | Módulo Primário IXF | Impacto |
|----|----------------|---------------------|---------|
| T0800 | Activate Firmware Update Mode | `exploits/protocols/s7comm/s7_activate_fw_update` | CRITICAL |
| T0801 | Monitor Process State | `assessment/mitre_ics/t0801_monitor_process_state` | READ |
| T0802 | Automated Collection | `assessment/mitre_ics/t0802_automated_collection` | READ |
| T0803 | Block Command Message | `exploits/protocols/iec104/iec104_startdt_block` | HIGH |
| T0804 | Block Reporting Message | `exploits/protocols/modbus/modbus_response_block` | HIGH |
| T0806 | Brute Force I/O | `assessment/mitre_ics/t0806_brute_force_io` | HIGH |
| T0807 | Remote Services | `creds/generic/ssh_default_creds` | HIGH |
| T0808 | Replication via Removable Media | `assessment/mitre_ics/t0808_removable_media` | INFO |
| T0809 | Data Destruction | `cve/malware/killdisk_industroyer` | CATASTROPHIC |
| T0810 | Data Exfiltration over C2 | `assessment/mitre_ics/t0810_data_exfil_c2` | INFO |
| T0811 | Data from Information Repositories | `scanners/ics/historian_data_read` | READ |
| T0812 | Default Credentials | `creds/siemens/s7_default_creds` | HIGH |
| T0813 | Denial of Control | `exploits/protocols/modbus/modbus_fc90_dos` | HIGH |
| T0814 | Denial of Service | `exploits/protocols/dnp3/dnp3_unsolicit_flood` | HIGH |
| T0815 | Denial of View | `exploits/protocols/iec104/iec104_gi_flood` | HIGH |
| T0816 | Device Restart/Shutdown | `exploits/protocols/s7comm/s7_cpu_stop_command` | HIGH |
| T0817 | Drive-by Compromise | `assessment/mitre_ics/t0817_driveby` | INFO |
| T0819 | Exploit Public-Facing Application | `cve/schneider/cve_2022_37300_modicon_m340_rce` | CRITICAL |
| T0820 | Exploitation of Remote Services | `cve/siemens/cve_2021_31894_s7_1500_rce` | CRITICAL |
| T0821 | Modify Controller Tasking | `assessment/mitre_ics/t0821_modify_controller_tasking` | CRITICAL |
| T0822 | External Remote Services | `creds/generic/vpn_default_creds` | HIGH |
| T0823 | Graphical User Interface | `exploits/scada/generic/hmi_gui_control` | HIGH |
| T0824 | I/O Image | `assessment/mitre_ics/t0824_io_image` | MEDIUM |
| T0826 | Loss of Availability | `cve/malware/frostygoop_modbus_heating` | CATASTROPHIC |
| T0827 | Loss of Control | `cve/apt/triton_triconex_safety_overwrite` | CATASTROPHIC |
| T0831 | Manipulation of Control | `exploits/protocols/modbus/modbus_write_coil` | MEDIUM |
| T0832 | Manipulation of View | `exploits/protocols/modbus/modbus_spoof_response` | MEDIUM |
| T0833 | Modify Alarm Settings | `assessment/mitre_ics/t0833_modify_alarm_settings` | MEDIUM |
| T0834 | Native API | `assessment/mitre_ics/t0834_native_api` | MEDIUM |
| T0835 | Detect Operating Mode | `assessment/mitre_ics/t0835_detect_operating_mode` | READ |
| T0836 | Modify Parameter | `exploits/protocols/modbus/modbus_fc16_write_registers` | MEDIUM |
| T0837 | Module Firmware | `cve/siemens/cve_2021_22681_s7_1200_hardcoded_key` | CRITICAL |
| T0838 | Modify Program | `exploits/protocols/s7comm/s7_plc_program_upload_download` | CRITICAL |
| T0839 | Firmware Modification | `cve/rockwell/cve_2022_1161_controllogix_modified_fw` | CRITICAL |
| T0840 | Network Connection Enumeration | `scanners/ics/modbus_scanner` | READ |
| T0841 | Network Sniffing | `assessment/mitre_ics/t0841_network_sniffing` | READ |
| T0842 | Network Topology Mapping | `scanners/ics/ics_network_mapper` | READ |
| T0843 | Program Download | `cve/siemens/cve_2021_22681_s7_1200_hardcoded_key` | CRITICAL |
| T0844 | Program Upload | `exploits/protocols/s7comm/s7_program_upload` | HIGH |
| T0845 | Program Organization Units | `assessment/mitre_ics/t0845_program_upload` | HIGH |
| T0846 | Remote System Discovery | `scanners/ics/modbus_detect` | READ |
| T0847 | Replication via Removable Media | `assessment/mitre_ics/t0847_removable_media` | INFO |
| T0848 | Rogue Master | `exploits/protocols/modbus/modbus_rogue_master` | HIGH |
| T0849 | Masquerading | `assessment/mitre_ics/t0849_masquerading` | INFO |
| T0851 | Rootkit | `assessment/mitre_ics/t0851_rootkit` | CRITICAL |
| T0852 | Screen Capture | `assessment/mitre_ics/t0852_screen_capture` | INFO |
| T0853 | Scripting | `assessment/mitre_ics/t0853_scripting` | INFO |
| T0854 | Serial Connection Enumeration | `scanners/ics/serial_scanner` | READ |
| T0855 | Unauthorized Command Message | `exploits/protocols/dnp3/dnp3_direct_operate` | HIGH |
| T0856 | Spoof Reporting Message | `assessment/mitre_ics/t0856_spoof_reporting` | HIGH |
| T0857 | System Firmware | `cve/siemens/cve_2019_13945_scalance_fw` | CRITICAL |
| T0858 | Change Credential | `assessment/mitre_ics/t0858_change_credential` | HIGH |
| T0859 | Valid Accounts | `creds/siemens/ssh_default_creds` | HIGH |
| T0860 | Wireless Compromise | `scanners/network/wifi_ics_scanner` | READ |
| T0861 | Point and Tag Identification | `scanners/ics/opcua_tag_browse` | READ |
| T0862 | Supply Chain Compromise | `assessment/mitre_ics/t0862_supply_chain` | INFO |
| T0863 | User Execution | `assessment/mitre_ics/t0863_user_execution` | INFO |
| T0864 | Transient Cyber Asset | `assessment/mitre_ics/t0864_transient_asset` | INFO |
| T0865 | Spearphishing Attachment | `assessment/mitre_ics/t0865_spearphishing` | INFO |
| T0866 | Exploitation for Lateral Movement | `cve/siemens/cve_2019_13945_scalance_s7_program_download` | CRITICAL |
| T0867 | Lateral Tool Transfer | `assessment/mitre_ics/t0867_lateral_tool_transfer` | INFO |
| T0869 | Standard Application Layer Protocol | `exploits/protocols/modbus/modbus_c2_channel` | HIGH |
| T0870 | Commonly Used Port | `assessment/mitre_ics/t0870_common_port` | INFO |
| T0871 | Execution through API | `assessment/mitre_ics/t0871_execution_through_api` | MEDIUM |
| T0873 | Project File Infection | `assessment/mitre_ics/t0873_project_file_infection` | HIGH |
| T0874 | Hooking | `assessment/mitre_ics/t0874_hooking` | CRITICAL |
| T0875 | Change Program State | `assessment/mitre_ics/t0875_change_program_state` | HIGH |
| T0877 | I/O Module Discovery | `scanners/ics/io_module_scanner` | READ |
| T0878 | Alarm Suppression | `assessment/mitre_ics/t0878_alarm_suppression` | HIGH |
| T0879 | Damage to Property | `cve/apt/triton_triconex_safety_overwrite` | CATASTROPHIC |
| T0880 | Loss of Safety | `cve/apt/triton_triconex_safety_overwrite` | CATASTROPHIC |
| T0881 | Service Stop | `exploits/protocols/s7comm/s7_cpu_stop_command` | HIGH |
| T0882 | Theft of Operational Information | `assessment/mitre_ics/t0882_theft_opinfo` | READ |
| T0883 | Internet Accessible Device | `scanners/osint/shodan_ics_dork` | INFO |
| T0884 | Connection Proxy | `assessment/mitre_ics/t0884_connection_proxy` | INFO |
| T0888 | Remote System Information Discovery | `scanners/ics/s7_enumerate` | READ |
| T0889 | Modify Program (ICS variant) | `exploits/plc/siemens/s7_1200_hardcoded_key` | CRITICAL |
| T0890 | Exploitation for Privilege Escalation | `cve/siemens/cve_2022_38465_simatic_privesc` | HIGH |

---

## Formato JSON do ATT&CK Navigator

O IXF gera camadas ATT&CK Navigator compatíveis via `mitre-report navigator` ou `mitre-coverage`.

```json
{
  "name": "IXF Coverage — IndustrialXPL-Forge",
  "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
  "domain": "ics-attack",
  "description": "IXF module coverage layer — 74/90 techniques covered",
  "techniques": [
    {
      "techniqueID": "T0836",
      "tactic": "impair-process-control",
      "score": 18,
      "color": "#ff6666",
      "comment": "18 IXF modules: modbus_fc16_write_registers, s7_write_db_block, ..."
    },
    {
      "techniqueID": "T0819",
      "tactic": "initial-access",
      "score": 47,
      "color": "#ff0000",
      "comment": "47 IXF modules covering 15 vendors"
    }
  ],
  "gradient": {"colors": ["#ffffff", "#ff6666", "#ff0000"], "minValue": 0, "maxValue": 50},
  "metadata": [{"name": "created", "value": "2026-06-01"}]
}
```

---

## Integração com ATT&CK Navigator

**Passo 1: Gerar a camada**
```
ixf > mitre-report navigator
[+] Salvo em .tmp/ixf_mitre_layer_2026-06-01.json
```

**Passo 2: Abrir o Navigator**
```
https://mitre-attack.github.io/attack-navigator/
```

**Passo 3: Importar a camada**
1. Clicar em "Open Existing Layer"
2. Selecionar "Upload from local" e carregar o arquivo JSON
3. A camada mostrará todas as 74 técnicas cobertas com gradiente de intensidade por contagem de módulos

**Uso alternativo — navegador incorporado:**
```bash
python -m http.server 8080 --directory .tmp/
# Então abrir: http://localhost:8080/ixf_mitre_layer_2026-06-01.json
```

---

*Anterior: [SafeMode / DestructiveMode](05-safemode-destructivemode.md) | Próximo: [SAST / LLM](07-sast-llm.md)*
