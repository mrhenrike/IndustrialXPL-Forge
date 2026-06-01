# MITRE ATT&CK for ICS

O IXF integra o MITRE ATT&CK for ICS v19, mapeando 976+ módulos para 74 das 90 técnicas (82% de cobertura) em todas as 12 táticas.

---

## Visão Geral das Táticas

| ID da Tática | Nome da Tática | Técnicas | Cobertura IXF |
|--------------|----------------|----------|---------------|
| TA0108 | Initial Access | 9 | 100% |
| TA0104 | Execution | 9 | 88% |
| TA0110 | Persistence | 8 | 75% |
| TA0111 | Privilege Escalation | 2 | 100% |
| TA0103 | Evasion | 5 | 80% |
| TA0102 | Discovery | 13 | 84% |
| TA0109 | Lateral Movement | 3 | 100% |
| TA0100 | Collection | 9 | 88% |
| TA0101 | Command and Control | 3 | 100% |
| TA0107 | Inhibit Response Function | 18 | 77% |
| TA0106 | Impair Process Control | 11 | 81% |
| TA0105 | Impact | 11 | 72% |

**Total: 74/90 (82%)**

---

## Aliases de Tática

| Nome Canônico | Aliases Aceitos |
|---------------|----------------|
| Initial Access | `initial-access`, `ia` |
| Execution | `execution`, `exec` |
| Persistence | `persistence` |
| Privilege Escalation | `privesc`, `pe` |
| Evasion | `evasion`, `defense-evasion` |
| Discovery | `discovery` |
| Lateral Movement | `lateral-movement`, `lateral`, `lm` |
| Collection | `collection` |
| Command and Control | `c2`, `c&c` |
| Inhibit Response Function | `inhibit`, `irf` |
| Impair Process Control | `impair`, `ipc` |
| Impact | `impact` |

---

## `ttp` — Executar uma Técnica

```
ixf > ttp T0843 192.168.1.100
[*] TTP T0843 (Program Download) — 12 módulos — simulate=True
[*] [1/12] cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
[*] [2/12] cve/rockwell/cve_2022_1161_controllogix_modified_fw
...
[+] Varredura T0843 concluída: 12 módulos, 0 erros
```

**Com flags:**
```
ixf > ttp T0859 192.168.1.100 --stop-on-first
ixf > ttp T0836 10.0.0.0/24 --rate-limit 500
ixf > ttp T0866 192.168.1.100 --output /tmp/resultados.json
```

---

## `mitre-scan` — Varredura por Tática

```
ixf > mitre-scan discovery 192.168.1.0/24
[*] Varrendo tática: Discovery (TA0102) em 192.168.1.0/24
[*] simulate=True (modo seguro)
...
[+] Varredura concluída: 11 técnicas, 34 módulos — 3 possíveis matches

ixf > mitre-scan T0843 192.168.1.100
```

---

## `mitre-all` — Varredura Completa

```
ixf > mitre-all 192.168.1.100
[*] Varredura completa MITRE ATT&CK for ICS (simulate=True)
[*] Executando 74 técnicas em 12 táticas...
[+] Varredura concluída: 74 técnicas, 850+ execuções de módulo
```

---

## `mitre-coverage` — Relatório de Cobertura

```
ixf > mitre-coverage

  Cobertura MITRE ATT&CK for ICS
  ──────────────────────────────────────────────────────────────────
  Tática                                   Coberto  Total  Pct
  Initial Access (TA0108)                     9       9    100%
  Execution (TA0104)                          8       9     88%
  ...
  ──────────────────────────────────────────────────────────────────
  TOTAL                                      74      90     82%
```

---

## `mitre-report` — Exportação

```
ixf > mitre-report layer
[+] Layer ATT&CK Navigator: ixf_mitre_layer_20260601.json
[i] Abrir em: https://mitre-attack.github.io/attack-navigator/

ixf > mitre-report html
[+] Relatório de cobertura MITRE ICS: ixf_mitre_report_20260601.html
```

---

## `ttp-list` — Browser de TTP

```
ixf > ttp-list
  Índice TTP — todas as técnicas
  T0801  Monitor Process State       2 módulos   [Collection]
  T0802  Automated Collection        5 módulos   [Collection]
  ...

ixf > ttp-list --tactic evasion
  Índice TTP — Evasion (TA0103)
  T0820  Exploitation Remote Srv     3 módulos
  T0856  Spoof Reporting Message     2 módulos
  T0874  Hooking                     1 módulo
```

---

## Módulos de Assessment por Técnica

```
ixf > use assessment/mitre_ics/t0843_program_upload
ixf > set target 192.168.1.100
ixf > run

  [SIMULATE MODE — nenhum pacote enviado]
  MITRE T0843: Program Upload
  Passo 1: Conectar à porta de engenharia do CLP (S7:102)
  Passo 2: Emitir comando de upload de programa sem autenticação
  Passo 3: Baixar programa CLP completo para arquivo local
  Passo 4: Analisar programa em busca de lógica de safety
```

---

*Anterior: [SafeMode / DestructiveMode](05-safemode-destructivemode.md) | Próximo: [SAST / LLM](07-sast-llm.md)*
