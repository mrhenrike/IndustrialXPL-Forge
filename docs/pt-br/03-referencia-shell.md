# Referência do Shell

Referência completa de todos os 36 comandos do shell interativo do IXF.

**Prompts do shell:**
- `ixf >` — contexto global, nenhum módulo carregado
- `ixf (Nome do Módulo) >` — módulo carregado e ativo

Comandos com hifens (ex.: `mitre-scan`) funcionam com ou sem hifens; mapeiam internamente para `command_mitre_scan`. Comandos com sublinhados também são aceitos (`mitre_scan`).

---

## Índice

1. [Navegação](#navegação) — `help`, `exit`, `use`, `back`
2. [Opções de Módulo](#opções-de-módulo) — `set`, `setg`, `unsetg`
3. [Inspeção de Módulo](#inspeção-de-módulo) — `show`
4. [Execução](#execução) — `run`, `check`
5. [Descoberta](#descoberta) — `search`, `exec`, `discover`
6. [CVE](#cve) — `cve`, `cve-scan`
7. [Relatórios](#relatórios) — `report`
8. [MITRE ATT&CK para ICS](#mitre-attck-para-ics) — `mitre`, `mitre-list`, `mitre-scan`, `mitre-all`, `mitre-coverage`, `mitre-report`, `mitre-tactic`
9. [Execução TTP](#execução-ttp) — `ttp`, `ttp-check`, `ttp-simulate`, `ttp-list`
10. [Assessment](#assessment) — `assess`
11. [Estatísticas e Inventário](#estatísticas-e-inventário) — `stats`, `vendors`, `protocols`, `coverage`
12. [LLM / SAST](#llm--sast) — `llm-key`, `llm-status`, `sast`
13. [Scripts NSE](#scripts-nse) — `nse`

---

## Navegação

### `help`

Exibe o menu de ajuda global ou a ajuda específica do módulo carregado.

**Sintaxe:** `help`

**Contexto:** global ou módulo

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| (nenhum) | — | — | — | — |

**Exemplo 1 — ajuda global:**
```
ixf > help

  IndustrialXPL-Forge v1.0.13 — IXF Shell Commands
  ─────────────────────────────────────────────────────────────
  use <module>          Carrega um módulo
  back                  Descarrega o módulo atual
  search <term>         Busca módulos por palavra-chave/CVE/vendor
  set <opt> <val>       Define opção do módulo
  setg <opt> <val>      Define opção global (todos os módulos)
  show [info|options]   Exibe detalhes do módulo
  run                   Executa o módulo carregado
  check                 Verificação de conectividade/vulnerabilidade
  discover <CIDR>       Varredura de descoberta de dispositivos OT
  cve <CVE-ID>          Carrega módulo por ID de CVE
  ttp <TID> <target>    Executa técnica MITRE ATT&CK
  mitre-scan <t> <ip>   Varredura de tática/técnica MITRE
  mitre-coverage        Porcentagem de cobertura por tática
  sast <path>           Análise estática de código PLC (LLM)
  stats                 Estatísticas de módulos
  vendors [filtro]      Lista vendors cobertos
  protocols             Lista protocolos cobertos
  report [formato]      Gera relatório de assessment
  nse <subcmd>          Gerencia scripts NSE do Nmap
  help                  Esta ajuda
  exit                  Encerra o IXF
```

**Exemplo 2 — ajuda dentro de módulo:**
```
ixf (Modbus TCP Device Detect) > help

  IndustrialXPL-Forge v1.0.13 — Módulo: Modbus TCP Device Detect
  ─────────────────────────────────────────────────────────────
  show options          Exibe opções do módulo
  show info             Exibe metadados completos do módulo
  set <opt> <val>       Define uma opção
  run                   Executa o módulo
  check                 Verifica conectividade (sem exploit)
  back                  Retorna ao contexto global
  help                  Esta ajuda
```

**Exemplo 3 — verificação de versão via help:**
```
ixf > help
  IndustrialXPL-Forge v1.0.13 — ...
  [i] PyPI: pip install industrialxpl-forge
  [i] Documentação: docs/pt-br/
```

**Cenário de erro:**
```
ixf (Módulo Ativo) > helpp
[-] Comando não reconhecido: 'helpp'. Digite 'help' para ver os comandos disponíveis.
```

**Comandos relacionados:** `exit`, `stats`, `show`

---

### `exit`

Encerra o shell IXF e retorna ao terminal do sistema.

**Sintaxe:** `exit`

**Contexto:** global ou módulo

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| (nenhum) | — | — | — | — |

**Exemplo 1 — saída a partir do contexto global:**
```
ixf > exit
[*] Encerrando IndustrialXPL-Forge. Fique seguro.
```

**Exemplo 2 — saída a partir de um módulo carregado:**
```
ixf (CVE-2021-22681 Siemens S7-1200) > exit
[*] Encerrando IndustrialXPL-Forge. Fique seguro.
```

**Exemplo 3 — uso com Ctrl+D (EOF):**
```
ixf > ^D
[*] Encerrando IndustrialXPL-Forge. Fique seguro.
```

**Cenário de erro:** O comando `exit` não produz erros. Ctrl+C na linha de prompt não encerra o IXF — usa-se `exit` ou `quit` para sair.

**Comandos relacionados:** `help`

---

### `use <caminho_modulo>`

Carrega um módulo pelo seu caminho. Aceita notação com barras (`scanners/ics/modbus_detect`) ou com pontos (`scanners.ics.modbus_detect`).

**Sintaxe:** `use <caminho_modulo>`

**Contexto:** global

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| caminho_modulo | string | Sim | — | Caminho relativo a `modules/` em notação barra ou ponto |

**Exemplo 1 — carregar módulo scanner:**
```
ixf > use scanners/ics/modbus_detect
[*] Módulo carregado: Modbus TCP Device Detect
[*] CVE: N/A | CVSS: N/A | Impacto: LOW

ixf (Modbus TCP Device Detect) >
```

**Exemplo 2 — carregar módulo CVE crítico:**
```
ixf > use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
[*] Módulo carregado: CVE-2021-22681 Siemens S7-1200/1500 PLC
[*] CVE: CVE-2021-22681 | CVSS: 9.8 | Impacto: CRITICAL
```

**Exemplo 3 — carregar usando notação com pontos:**
```
ixf > use cve.rockwell.cve_2022_1161_controllogix_modified_fw
[*] Módulo carregado: CVE-2022-1161 Rockwell ControlLogix Modified FW
[*] CVE: CVE-2022-1161 | CVSS: 8.8 | Impacto: CRITICAL
```

**Quando o runtime necessário está ausente (Tier 3):**
```
ixf > use cve/malware/frostygoop_modbus_heating
[!] Módulo requer runtime 'go'. Fallback Python disponível.
    Instale Go: https://go.dev/dl/
[*] Módulo carregado com fallback Python: FrostyGoop Modbus Heating Attack
[*] CVE: N/A | CVSS: N/A | Impacto: CATASTROPHIC
```

**Cenário de erro — módulo não encontrado:**
```
ixf > use cve/siemens/nao_existe
[-] Módulo não encontrado: 'cve/siemens/nao_existe'
[i] Tente: search siemens
```

**Cenário de erro — erro de sintaxe no módulo:**
```
ixf > use cve/siemens/modulo_com_erro
[-] Falha ao importar 'cve/siemens/modulo_com_erro': SyntaxError on line 42
```

**Comandos relacionados:** `back`, `search`, `cve`, `show`

---

### `back`

Descarrega o módulo atual e retorna ao contexto global.

**Sintaxe:** `back`

**Contexto:** apenas módulo

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| (nenhum) | — | — | — | — |

**Exemplo 1 — retornar ao contexto global:**
```
ixf (Modbus TCP Device Detect) > back
ixf >
```

**Exemplo 2 — back após configurar opções (opções são descartadas):**
```
ixf (CVE-2021-22681 S7-1200) > set target 192.168.1.100
[*] target => 192.168.1.100

ixf (CVE-2021-22681 S7-1200) > back
ixf >
```

**Exemplo 3 — tentativa de back no contexto global:**
```
ixf > back
[-] Nenhum módulo carregado. Use 'use <módulo>' para carregar um módulo.
```

**Cenário de erro — sem módulo carregado:**
```
ixf > back
[-] Nenhum módulo carregado. Use 'use <módulo>' para carregar um módulo.
```

**Comandos relacionados:** `use`, `exit`

---

## Opções de Módulo

### `set <opção> <valor>`

Define uma opção no módulo carregado. As opções são específicas do módulo e são perdidas ao executar `back`.

**Sintaxe:** `set <opção> <valor>`

**Contexto:** apenas módulo (exige módulo carregado)

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| opção | string | Sim | — | Nome da opção (case-insensitive) |
| valor | variável | Sim | — | Valor adequado ao tipo da opção (ver [Sistema de Módulos](04-sistema-modulos.md)) |

**Exemplo 1 — definir alvo e porta:**
```
ixf (Modbus TCP Device Detect) > set target 192.168.1.100
[*] target => 192.168.1.100

ixf (Modbus TCP Device Detect) > set port 5020
[*] port => 5020
```

**Exemplo 2 — definir opções booleanas (todas as formas aceitas):**
```
ixf (CVE-2021-22681 S7-1200) > set simulate false
[*] simulate => False

ixf (CVE-2021-22681 S7-1200) > set destructive true
[*] destructive => True

ixf (CVE-2021-22681 S7-1200) > set verbose yes
[*] verbose => True

ixf (CVE-2021-22681 S7-1200) > set ssl on
[*] ssl => True
```

**Exemplo 3 — definir wordlist e timeout:**
```
ixf (S7 Default Creds) > set wordlist ics_common_passwords.txt
[*] wordlist => ics_common_passwords.txt

ixf (S7 Default Creds) > set timeout 10
[*] timeout => 10

ixf (S7 Default Creds) > set threads 5
[*] threads => 5
```

**Cenário de erro — porta fora do intervalo válido:**
```
ixf (Modbus TCP Device Detect) > set port 99999
[-] Erro de validação para 'port': Port must be in range 1-65535, got: 99999
```

**Cenário de erro — IP inválido:**
```
ixf (CVE-2021-22681 S7-1200) > set target 300.300.300.300
[-] Erro de validação para 'target': '300.300.300.300' is not a valid IP address or hostname.
```

**Cenário de erro — opção inexistente:**
```
ixf (Modbus TCP Device Detect) > set opcao_invalida 123
[-] Opção não encontrada: 'opcao_invalida'. Use 'show options' para ver as opções disponíveis.
```

**Cenário de erro — booleano inválido:**
```
ixf (CVE-2021-22681 S7-1200) > set simulate talvez
[-] Erro de validação para 'simulate': Expected boolean (true/false/yes/no), got: 'talvez'
```

**Comandos relacionados:** `setg`, `unsetg`, `show options`

---

### `setg <opção> <valor>`

Define uma opção global que persiste em todos os módulos durante a sessão atual.

**Sintaxe:** `setg <opção> <valor>`

**Contexto:** global ou módulo

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| opção | string | Sim | — | Nome da opção |
| valor | variável | Sim | — | Valor (mesmos tipos de `set`) |

**Exemplo 1 — definir alvo global e verificar em módulo:**
```
ixf > setg target 10.0.0.100
[*] Global: target => 10.0.0.100

ixf > use scanners/ics/modbus_detect
[*] Módulo carregado: Modbus TCP Device Detect
[*] target já definido globalmente: 10.0.0.100

ixf (Modbus TCP Device Detect) > show options

     Opções — Modbus TCP Device Detect
  +------------+-----------+----------+------------------------------------------+
  | Opção      | Valor     | Obrig.   | Descrição                                |
  |------------+-----------+----------+------------------------------------------|
  | target     | 10.0.0.100| sim      | IP ou hostname do dispositivo alvo       |
  | port       | 502       | não      | Porta Modbus TCP                         |
  | simulate   | True      | não      | Modo de simulação (padrão: True)         |
  | destructive| False     | não      | Modo destrutivo — pode causar danos      |
  +------------+-----------+----------+------------------------------------------+
```

**Exemplo 2 — forçar modo seguro globalmente (recomendado no início da sessão):**
```
ixf > setg simulate true
[*] Global: simulate => True

ixf > setg timeout 15
[*] Global: timeout => 15
```

**Exemplo 3 — definir global dentro de módulo (persiste ao trocar de módulo):**
```
ixf (CVE-2021-22681 S7-1200) > setg target 192.168.10.50
[*] Global: target => 192.168.10.50

ixf (CVE-2021-22681 S7-1200) > back

ixf > use scanners/ics/s7_enumerate
[*] Módulo carregado: S7 CPU Enumerate
[*] target já definido globalmente: 192.168.10.50
```

**Opções globais comuns:** `target`, `timeout`, `simulate`, `destructive`

**Cenário de erro:**
```
ixf > setg port abc
[-] Erro de validação para 'port': Port must be an integer, got: 'abc'
```

**Comandos relacionados:** `set`, `unsetg`

---

### `unsetg <opção>`

Remove uma opção global, fazendo os módulos usarem seus valores padrão.

**Sintaxe:** `unsetg <opção>`

**Contexto:** global ou módulo

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| opção | string | Sim | — | Nome da opção global a remover |

**Exemplo 1 — remover opção global de alvo:**
```
ixf > unsetg target
[*] Global 'target' removido.
```

**Exemplo 2 — remover opção e verificar:**
```
ixf > setg simulate true
[*] Global: simulate => True

ixf > unsetg simulate
[*] Global 'simulate' removido.

ixf > use scanners/ics/modbus_detect
[*] Módulo carregado: Modbus TCP Device Detect
```

**Exemplo 3 — tentar remover opção inexistente:**
```
ixf > unsetg opcao_que_nao_existe
[!] Global 'opcao_que_nao_existe' não estava definido.
```

**Cenário de erro:**
```
ixf > unsetg
[-] Uso: unsetg <opção>
```

**Comandos relacionados:** `setg`, `set`

---

## Inspeção de Módulo

### `show [subcomando]`

Exibe informações sobre o módulo carregado. Diferentes subcomandos revelam diferentes aspectos.

**Sintaxe:** `show [info|options|advanced|devices|all]`

**Contexto:** apenas módulo

**Parâmetros:**

| Subcomando | Obrigatório | Descrição |
|------------|-------------|-----------|
| `options` | Não (padrão) | Opções padrão do módulo |
| `info` | Não | Metadados completos (`__info__`) |
| `advanced` | Não | Apenas opções avançadas |
| `devices` | Não | Tipos de dispositivos alvo |
| `all` | Não | `info` + `options` juntos |

**Exemplo 1 — `show options` (subcomando padrão):**
```
ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > show options

     Opções — CVE-2021-22681 Siemens S7-1200/1500 PLC
  +------------+-----------+----------+----------------------------------------------+
  | Opção      | Valor     | Obrig.   | Descrição                                    |
  |------------+-----------+----------+----------------------------------------------|
  | target     |           | sim      | IP do Siemens S7-1200 alvo                   |
  | port       | 102       | não      | Porta S7comm (padrão: 102)                   |
  | slot       | 2         | não      | Número do slot do PLC                        |
  | timeout    | 5         | não      | Timeout de conexão (segundos)                |
  | simulate   | True      | não      | Modo de simulação (padrão: True)             |
  | destructive| False     | não      | Exploração ao vivo — pode causar danos irrev.|
  +------------+-----------+----------+----------------------------------------------+
```

**Exemplo 2 — `show info`:**
```
ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > show info

  Informações do Módulo
  ─────────────────────────────────────────────────────
  name            : CVE-2021-22681 Siemens S7-1200/1500 PLC
  description     : Os PLCs S7-1200/1500 usam uma chave simétrica estática...
  authors         : ('Andre Henrique (@mrhenrike) | Uniao Geek',)
  references      : ('https://www.cisa.gov/ics-advisories/icsa-21-131-03',
                     'https://nvd.nist.gov/vuln/detail/CVE-2021-22681')
  devices         : ('Siemens SIMATIC S7-1200 firmware < 4.4.0',
                     'Siemens SIMATIC S7-1500 firmware < 2.9.7')
  impact          : CRITICAL
  exploit_type    : Cryptographic Key Disclosure / PLC Logic Overwrite
  cve             : CVE-2021-22681
  cvss            : 9.8
  severity        : CRITICAL
  mitre_techniques: ['T0821', 'T0866']
  mitre_tactics   : ['Lateral Movement', 'Inhibit Response Function']
```

**Exemplo 3 — `show advanced`:**
```
ixf (Ignition RCE) > show advanced

  Opções Avançadas
  ─────────────────────────────────────────────────────────────────
  Nome          Atual       Descrição
  ────          ─────       ─────────
  verbose       False       Habilita saída de debug detalhada
  timeout       5           Timeout de conexão (override)
  verify_cert   True        Verifica certificado TLS/SSL
  jitter        0.0         Jitter aleatório adicionado aos delays (s)
```

**Cenário de erro — show sem módulo carregado:**
```
ixf > show options
[-] Nenhum módulo carregado. Use 'use <módulo>' primeiro.
```

**Cenário de erro — subcomando inválido:**
```
ixf (Módulo) > show xyz
[-] Subcomando desconhecido: 'xyz'. Use: show [info|options|advanced|devices|all]
```

**Comandos relacionados:** `use`, `set`, `run`

---

## Execução

### `run`

Executa o módulo carregado. O comportamento depende das opções `simulate` e `destructive`.

**Sintaxe:** `run`

**Contexto:** apenas módulo

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| (nenhum) | — | — | — | — |

**Matriz de comportamento:**

| simulate | destructive | Comportamento |
|----------|-------------|---------------|
| `True` (padrão) | qualquer | Imprime saída de simulação; nenhum pacote enviado |
| `False` | `False` | Executa apenas `check()` (sonda segura sem exploit) |
| `False` | `True` | Exploit completo com confirmação DestructiveGate para impacto HIGH/CRITICAL/CATASTROPHIC |

**Exemplo 1 — modo simulação (padrão):**
```
ixf (FrostyGoop Modbus Heating Attack) > run

  [SIMULATE MODE — no packets sent]
  ─────────────────────────────────────────────────────────────
  [i] O que aconteceria:
      FrostyGoop TTP (2024) — Sandworm/GRU (Rússia)

      Fase 1 [Descoberta]: Varredura de porta Modbus TCP 502 no alvo 192.168.1.100
      Fase 2 [FC16 Write]: Escrita de 0x0000 nos registradores de aquecimento
      Fase 3 [Loop]: Repetição a cada 30s para impedir recuperação manual
      Impacto Físico: Controladores de aquecimento offline — 600 apartamentos
                      em Lviv (Ucrânia) perderam calefação por 2 dias (jan/2024)

  [i] Payload (hex): 00 01 00 00 00 0B 01 10 00 00 00 02 04 00 00 00 00
  [i] MITRE ATT&CK para ICS: T0836 (Modify Parameter), T0814 (Denial of Control)
  [i] Para executar ao vivo: set simulate false
```

**Exemplo 2 — execução ao vivo (simulate=false, destructive=false) — apenas check():**
```
ixf (Modbus FC90 DoS) > set simulate false
[*] simulate => False

ixf (Modbus FC90 DoS) > set target 192.168.1.100
ixf (Modbus FC90 DoS) > run
[*] simulate=False, destructive=False — executando apenas check()...
[+] VULNERÁVEL — Dispositivo Modbus detectado em 192.168.1.100:502
[i] Para executar o exploit: set destructive true
```

**Exemplo 3 — execução destrutiva com confirmação CATASTROPHIC:**
```
ixf (FrostyGoop Modbus Heating Attack) > set simulate false
[*] simulate => False
ixf (FrostyGoop Modbus Heating Attack) > set destructive true
[*] destructive => True
ixf (FrostyGoop Modbus Heating Attack) > run

  ██████████████████████████████████████████████████████████████████████
  ██  MODO DESTRUTIVO — IMPACTO CATASTRÓFICO                          ██
  ██  ESTA AÇÃO É IRREVERSÍVEL                                        ██
  ██████████████████████████████████████████████████████████████████████

  Módulo:  FrostyGoop Modbus Heating Attack (Go) — Extended
  Alvo:    192.168.1.100:502
  Impacto: CATASTROPHIC — Physical equipment damage / safety system disabling. IRREVERSIBLE.

  [!] AGUARDANDO 10 SEGUNDOS ANTES DO PROMPT — pressione Ctrl+C para abortar

  Digite a seguinte string EXATAMENTE para confirmar (case-sensitive):
  I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION

  Confirmação>
```

**Cenário de erro — alvo não definido:**
```
ixf (CVE-2021-22681 S7-1200) > run
[-] Defina a opção 'target' primeiro. Exemplo: set target 192.168.1.100
```

**Comandos relacionados:** `check`, `set simulate`, `set destructive`

---

### `check`

Executa uma sonda de conectividade e verificação de vulnerabilidade somente-leitura. Não envia exploits.

**Sintaxe:** `check`

**Contexto:** apenas módulo

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| (nenhum) | — | — | — | — |

**Exemplo 1 — check em dispositivo Modbus:**
```
ixf (Modbus TCP Device Detect) > set target 192.168.1.100
[*] target => 192.168.1.100

ixf (Modbus TCP Device Detect) > check
[*] Verificando 192.168.1.100:502...
[+] VULNERÁVEL — Dispositivo Modbus detectado
```

**Exemplo 2 — check em dispositivo não vulnerável:**
```
ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > set target 192.168.1.50
ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > check
[*] Verificando 192.168.1.50:102...
[-] NÃO VULNERÁVEL — Porta 102 inacessível ou S7comm+ não detectado
```

**Exemplo 3 — check com timeout:**
```
ixf (Modbus TCP Device Detect) > set target 10.10.10.99
ixf (Modbus TCP Device Detect) > set timeout 3
ixf (Modbus TCP Device Detect) > check
[*] Verificando 10.10.10.99:502 (timeout: 3s)...
[-] SEM RESPOSTA — Timeout após 3s
```

**Cenário de erro — sem alvo:**
```
ixf (Modbus TCP Device Detect) > check
[-] Defina 'target' antes de executar check. Exemplo: set target 192.168.1.100
```

**Comandos relacionados:** `run`, `set target`

---

## Descoberta

### `search <termo>`

Busca módulos indexados por palavra-chave, ID de CVE, nome de vendor ou protocolo.

**Sintaxe:** `search <termo>`

**Contexto:** global

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| termo | string | Sim | — | Substring para corresponder contra caminhos e nomes de módulos |

**Exemplo 1 — buscar por CVE específico:**
```
ixf > search CVE-2022-29965
[*] Resultados da busca para: CVE-2022-29965
    use cve/emerson/cve_2022_29965_roc800_hardcoded_creds
```

**Exemplo 2 — buscar por funcionalidade:**
```
ixf > search default_creds
[*] Resultados da busca para: default_creds (exibindo 50 de 184)
    use creds/siemens/ssh_default_creds
    use creds/siemens/telnet_default_creds
    use creds/rockwell/logix_default_creds
    use creds/schneider/modicon_default_creds
    use creds/ge/ge_rx3i_default_creds
    use creds/mitsubishi/melsec_default_creds
    ...
```

**Exemplo 3 — buscar por protocolo:**
```
ixf > search dnp3
[*] Resultados da busca para: dnp3
    use exploits/protocols/dnp3/dnp3_data_spoofing
    use exploits/protocols/dnp3/dnp3_replay_command
    use exploits/protocols/dnp3/dnp3_unauthorized_control
    use scanners/ics/dnp3_scanner
```

**Cenário de erro — sem resultados:**
```
ixf > search protocolo_inexistente_xyz
[*] Resultados da busca para: protocolo_inexistente_xyz
[!] Nenhum módulo encontrado. Tente: search modbus, search siemens, search cve
```

**Comandos relacionados:** `use`, `cve`, `stats`

---

### `exec <comando_shell>`

Executa um comando arbitrário do sistema operacional e exibe a saída. Timeout: 30 segundos.

**Sintaxe:** `exec <comando>`

**Contexto:** global ou módulo

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| comando | string | Sim | — | Qualquer comando de shell válido |

**Exemplo 1 — ping de um alvo:**
```
ixf > exec ping -c 3 192.168.1.1
PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=0.431 ms
64 bytes from 192.168.1.1: icmp_seq=2 ttl=64 time=0.389 ms
64 bytes from 192.168.1.1: icmp_seq=3 ttl=64 time=0.412 ms
--- 192.168.1.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss
```

**Exemplo 2 — executar ferramenta auxiliar:**
```
ixf > exec python tools/env_doctor.py
[env_doctor] Python: 3.12.3
[env_doctor] pymodbus: OK (3.8.0)
[env_doctor] snap7: OK
[env_doctor] nmap: OK (7.94)
[env_doctor] go: não instalado (Tier 3 indisponível)
```

**Exemplo 3 — listar arquivos de projeto:**
```
ixf > exec ls -la /opt/plc_projects/
total 48
drwxr-xr-x  4 user  user  4096 jun  1 10:00 .
drwxr-xr-x 12 user  user  4096 mai 30 08:15 ..
-rw-r--r--  1 user  user  2048 jun  1 09:30 water_treatment.st
-rw-r--r--  1 user  user  1536 mai 28 14:22 reactor_batch.sfc
```

**Cenário de erro — comando com timeout:**
```
ixf > exec sleep 60
[-] Timeout: o comando excedeu 30 segundos e foi encerrado.
```

**Comandos relacionados:** `sast`, `nse`

---

### `discover <CIDR>`

Lança uma varredura de descoberta de dispositivos OT em uma sub-rede. Carrega o módulo scanner adequado e inicia a varredura.

**Sintaxe:** `discover <CIDR>`

**Contexto:** global

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| CIDR | string | Sim | — | Faixa de rede no formato CIDR (ex.: `192.168.1.0/24`) |

**Exemplo 1 — descoberta básica de sub-rede:**
```
ixf > discover 192.168.1.0/24
[*] Carregando scanners/ics/modbus_detect para varredura OT...
[i] Para descoberta OT completa, execute: ttp T0846.001 192.168.1.0/24
[i] Para scan específico de protocolo: use scanners/ics/modbus_detect
```

**Exemplo 2 — descoberta com sub-rede menor:**
```
ixf > discover 10.0.0.0/28
[*] Carregando scanners/ics/modbus_detect para varredura OT (16 hosts)...
[*] Varrendo 10.0.0.1 - 10.0.0.14...
[+] 10.0.0.5  — Modbus TCP porta 502 aberta (unit ID 1)
[+] 10.0.0.8  — Modbus TCP porta 502 aberta (unit ID 255)
[-] 10.0.0.10 — sem resposta Modbus
[i] Para varredura ICS completa use: mitre-scan discovery 10.0.0.0/28
```

**Exemplo 3 — varredura multi-protocolo após discover:**
```
ixf > discover 172.16.0.0/24
[*] Iniciando varredura OT básica em 172.16.0.0/24...
[i] Para descoberta MITRE completa: ttp T0846 172.16.0.0/24
[i] Para varredura por protocolo:
    use scanners/ics/modbus_detect
    use scanners/ics/s7_enumerate
    use scanners/ics/enip_list_identity
    use scanners/ics/bacnet_device_id
    use scanners/ics/dnp3_link_status
```

**Cenário de erro — CIDR inválido:**
```
ixf > discover 999.999.999.0/24
[-] Faixa CIDR inválida: '999.999.999.0/24'. Exemplo: 192.168.1.0/24
```

**Comandos relacionados:** `ttp T0846`, `mitre-scan discovery`, `search scanner`

---

## CVE

### `cve <CVE-ID>`

Localiza e carrega um módulo pelo seu identificador CVE.

**Sintaxe:** `cve <CVE-ID>`

**Contexto:** global

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| CVE-ID | string | Sim | — | CVE, CNVD ou outro identificador (ex.: `CVE-2022-29965`) |

**Exemplo 1 — carregar módulo por CVE único:**
```
ixf > cve CVE-2021-22681
[*] Módulo carregado: CVE-2021-22681 Siemens S7-1200/1500 PLC
[*] CVSS: 9.8 | Impacto: CRITICAL

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) >
```

**Exemplo 2 — CVE de vendor diferente:**
```
ixf > cve CVE-2023-6448
[*] Módulo carregado: CVE-2023-6448 Unitronics Unistream PLC
[*] CVSS: 9.8 | Impacto: CRITICAL

ixf (CVE-2023-6448 Unitronics Unistream PLC) >
```

**Exemplo 3 — CVE com múltiplos módulos (seleção interativa):**
```
ixf > cve CVE-2022-3232
[*] Múltiplos módulos encontrados para CVE-2022-3232:
    1. use cve/ls_electric/cve_2022_3232_xgk_modbus_dos
    2. use cve/scanners/ls_electric/ls_electric_xgk_scanner
    Selecione o módulo (número ou caminho): 1
[*] Módulo carregado: CVE-2022-3232 LS Electric XGK Modbus DoS
```

**Cenário de erro — CVE não encontrado:**
```
ixf > cve CVE-2099-99999
[-] Nenhum módulo encontrado para 'CVE-2099-99999'.
[i] Tente: search CVE-2099 ou consulte cisa.gov/known-exploited-vulnerabilities
```

**Comandos relacionados:** `use`, `search`, `cve-scan`

---

### `cve-scan <CIDR>`

Esboço: descobre ativos e sugere o fluxo de trabalho para teste de CVE. Orienta a sequência `mitre-scan → cve → run`.

**Sintaxe:** `cve-scan <CIDR>`

**Contexto:** global

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| CIDR | string | Sim | — | Faixa de rede no formato CIDR |

**Exemplo 1 — orientação de fluxo CVE:**
```
ixf > cve-scan 192.168.1.0/24
[i] CVE scan: descubra ativos primeiro com mitre-scan discovery 192.168.1.0/24
[i] Em seguida carregue módulos CVE específicos com: cve <CVE-ID>
[i] Fluxo recomendado:
    1. discover 192.168.1.0/24
    2. mitre-scan discovery 192.168.1.0/24
    3. cve CVE-2021-22681   (para Siemens encontrados)
    4. set target <ip>
    5. check
    6. run
```

**Exemplo 2 — com sub-rede de rede industrial:**
```
ixf > cve-scan 10.0.1.0/24
[i] CVE scan para rede OT 10.0.1.0/24
[i] Recomendado: descubra com discover 10.0.1.0/24 primeiro
[i] Vendors comuns em ambientes OT:
    - Siemens: cve CVE-2021-22681, CVE-2019-13945
    - Rockwell: cve CVE-2022-1161, CVE-2023-3595
    - Schneider: cve CVE-2018-7789, CVE-2022-45789
```

**Exemplo 3 — ver CVEs mais críticos por vendor:**
```
ixf > cve-scan 172.16.0.0/24
[i] Use 'vendors' para ver todos os vendors cobertos e seus CVEs
[i] Use 'search <vendor>' para módulos de vendor específico
[i] CVEs CISA KEV prioritários para ICS/OT: search CISA
```

**Cenário de erro:**
```
ixf > cve-scan
[-] Uso: cve-scan <CIDR>. Exemplo: cve-scan 192.168.1.0/24
```

**Comandos relacionados:** `cve`, `discover`, `mitre-scan`

---

## Relatórios

### `report [formato]`

Gera um relatório de assessment a partir da sessão atual.

**Sintaxe:** `report [json|html|markdown]`

**Contexto:** global

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| formato | string | Não | `json` | `json`, `html`, `markdown` |

**Exemplo 1 — relatório JSON (padrão):**
```
ixf > report json
[*] Gerando relatório...
[+] Relatório salvo: ixf_report_20260601_153045.json

{
  "session_id": "abc123",
  "generated_at": "2026-06-01T15:30:45Z",
  "targets_tested": ["192.168.1.100", "192.168.1.200"],
  "modules_executed": 15,
  "findings": [
    {
      "module": "cve/siemens/cve_2021_22681_s7_1200_hardcoded_key",
      "target": "192.168.1.100",
      "result": "VULNERABLE",
      "cvss": "9.8",
      "impact": "CRITICAL"
    }
  ]
}
```

**Exemplo 2 — relatório HTML:**
```
ixf > report html
[*] Gerando relatório HTML...
[+] Relatório salvo: ixf_report_20260601_153112.html
[i] Abra no navegador: file:///path/to/ixf_report_20260601_153112.html
```

**Exemplo 3 — relatório Markdown:**
```
ixf > report markdown
[*] Gerando relatório Markdown...
[+] Relatório salvo: ixf_report_20260601_153201.md
[i] Adequado para inclusão em documentos de pentest
```

**Cenário de erro — formato inválido:**
```
ixf > report pdf
[-] Formato inválido: 'pdf'. Formatos disponíveis: json, html, markdown
```

**Comandos relacionados:** `mitre-report`, `assess`, `stats`

---

## MITRE ATT&CK para ICS

### `mitre <TID>`

Lista todos os módulos que cobrem uma técnica MITRE específica, com descrição da técnica e notas de remediação.

**Sintaxe:** `mitre <TID>`

**Contexto:** global

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| TID | string | Sim | — | ID de técnica MITRE ATT&CK para ICS (ex.: `T0843`) |

**Exemplo 1 — consultar T0843 (Program Download):**
```
ixf > mitre T0843

  ╔══════════════════════════════════════════════════════════════════╗
  ║  MITRE ATT&CK para ICS — Detalhe da Técnica                      ║
  ╚══════════════════════════════════════════════════════════════════╝

  ID:          T0843
  Nome:        Program Download
  Tática:      Lateral Movement (TA0109)
  Módulos IXF: 12 módulos

  Descrição:
    Adversários podem fazer upload ou download de programas de/para
    controladores industriais. Isso pode incluir modificação de lógica
    de controle, firmware ou arquivos de configuração, podendo alterar
    o processo físico controlado.

  Módulos IXF:
    cve.siemens.cve_2021_22681_s7_1200_hardcoded_key
    cve.rockwell.cve_2022_1161_controllogix_modified_fw
    exploits.protocols.s7comm.s7_unauthorized_cpu_control
    assessment.mitre_ics.t0843_program_upload
    cve.malware.crashoverride_industroyer
    ... (8 módulos adicionais)

  Remediação:
    - Implementar autenticação forte para upload/download de programas
    - Monitorar comunicação S7comm na porta 102
    - Usar recursos de proteção de acesso do PLC (senha, nível de proteção)
    - Habilitar auditoria de mudanças de programa
```

**Exemplo 2 — consultar T0878 (Alarm Suppression):**
```
ixf > mitre T0878
  ID:          T0878
  Nome:        Alarm Suppression
  Tática:      Inhibit Response Function (TA0107)
  Módulos IXF: 8 módulos

  Módulos IXF:
    assessment.mitre_ics.t0878_alarm_suppression
    cve.malware.crashoverride_industroyer
    exploits.protocols.modbus.modbus_alarm_disable
    ...
```

**Exemplo 3 — consultar técnica de descoberta:**
```
ixf > mitre T0846
  ID:          T0846
  Nome:        Remote System Discovery
  Tática:      Discovery (TA0102)
  Módulos IXF: 8 módulos

  Módulos IXF:
    scanners.ics.modbus_detect
    scanners.ics.s7_enumerate
    scanners.ics.enip_list_identity
    scanners.ics.bacnet_device_id
    assessment.mitre_ics.t0846_remote_discovery
    ...
```

**Cenário de erro — TID inválido:**
```
ixf > mitre T9999
[-] Técnica 'T9999' não encontrada no MITRE ATT&CK para ICS.
[i] Use 'mitre-list' para ver todas as técnicas mapeadas.
```

**Comandos relacionados:** `mitre-list`, `ttp`, `mitre-scan`

---

### `mitre-list [tática]`

Lista todas as técnicas MITRE mapeadas com contagens de módulos. Filtro opcional por tática.

**Sintaxe:** `mitre-list [nome_tática_ou_alias]`

**Contexto:** global

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| tática | string | Não | — | Nome de tática, alias ou TA-ID (ex.: `discovery`, `initial-access`, `TA0108`) |

**Exemplo 1 — listar todas as técnicas mapeadas:**
```
ixf > mitre-list
  MITRE ATT&CK para ICS — Índice de Técnicas
  ─────────────────────────────────────────────────────────────────
  T0817   Drive-by Compromise                        3 módulos
  T0819   Exploit Public-Facing Application         47 módulos
  T0822   External Remote Services                  12 módulos
  T0859   Valid Accounts                             8 módulos
  T0862   Supply Chain Compromise                    2 módulos
  T0863   User Execution                             3 módulos
  T0864   Transient Cyber Asset                      1 módulo
  T0865   Spearphishing Attachment                   4 módulos
  T0883   Internet Accessible Device                 7 módulos
  ...
  [Total: 74 técnicas mapeadas, 976+ módulos]
```

**Exemplo 2 — filtrar por tática Discovery:**
```
ixf > mitre-list discovery
  MITRE ATT&CK para ICS — Técnicas de Discovery (TA0102)
  ─────────────────────────────────────────────────────────────────
  T0840   Network Connection Enumeration             2 módulos
  T0842   Network Sniffing                           3 módulos
  T0846   Remote System Discovery                    8 módulos
  T0861   Point and Tag Identification               4 módulos
  T0868   Detect Program State                       2 módulos
  T0869   Standard Application Layer Protocol        5 módulos
  T0877   I/O Module Discovery                       3 módulos
  T0882   Theft of Operational Information           3 módulos
  T0888   Remote System Information Discovery        6 módulos
  T0887   Wireless Sniffing                          1 módulo
  T0854   Serial Connection Enumeration              1 módulo
```

**Exemplo 3 — filtrar por tática Impact:**
```
ixf > mitre-list impact
  MITRE ATT&CK para ICS — Técnicas de Impact (TA0105)
  ─────────────────────────────────────────────────────────────────
  T0809   Data Destruction                           3 módulos
  T0813   Denial of Control                          8 módulos
  T0815   Denial of View                             4 módulos
  T0826   Loss of Availability                       5 módulos
  T0827   Loss of Control                            7 módulos
  T0828   Loss of Productivity and Revenue           2 módulos
  T0829   Loss of Safety                             6 módulos
  T0879   Damage to Property                         4 módulos
```

**Cenário de erro — tática inválida:**
```
ixf > mitre-list tatica_inexistente
[-] Tática não reconhecida: 'tatica_inexistente'.
[i] Táticas válidas: initial-access, execution, persistence, privilege-escalation,
    evasion, discovery, lateral-movement, collection, command-and-control,
    inhibit, impair, impact
```

**Comandos relacionados:** `mitre`, `ttp-list`, `mitre-coverage`

---

### `mitre-scan <tática_ou_TID> <alvo> [--destructive]`

Executa uma varredura de tática MITRE ou técnica única contra um alvo.

**Sintaxe:** `mitre-scan <tática|TID> <alvo> [--destructive]`

**Contexto:** global

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| tática ou TID | string | Sim | — | Nome de tática/alias ou ID de técnica (ex.: `discovery`, `T0843`) |
| alvo | string | Sim | — | IP, hostname ou faixa CIDR alvo |
| `--destructive` | flag | Não | — | Desabilita modo simulação (apenas labs autorizados) |

**Exemplo 1 — varredura de tática Discovery em sub-rede:**
```
ixf > mitre-scan discovery 192.168.1.0/24
[*] Varrendo tática: Discovery (TA0102) em 192.168.1.0/24
[*] simulate=True (modo seguro)
[*] Técnica T0840 — Network Connection Enumeration...
[*] Técnica T0842 — Network Sniffing...
[*] Técnica T0846 — Remote System Discovery...
[+] T0846: 3 dispositivos Modbus encontrados
[*] Técnica T0861 — Point and Tag Identification...
...
[+] Varredura de tática concluída: 11 técnicas, 37 módulos executados
[+] Dispositivos encontrados: 192.168.1.5, 192.168.1.12, 192.168.1.100
```

**Exemplo 2 — varredura de técnica única:**
```
ixf > mitre-scan T0843 192.168.1.100
[*] Varrendo T0843 (Program Download) em 192.168.1.100...
[*] simulate=True | Módulos: 12
[*] Executando cve/siemens/cve_2021_22681_s7_1200_hardcoded_key...
  [SIMULATE] Conexão S7comm para 192.168.1.100:102...
[*] Executando cve/rockwell/cve_2022_1161_controllogix_modified_fw...
  [SIMULATE] Tentativa de modificação de firmware ControlLogix...
[+] T0843 concluído: 12 módulos, 3 correspondências em simulação
```

**Exemplo 3 — varredura de Initial Access:**
```
ixf > mitre-scan initial-access 10.0.0.0/24
[*] Varrendo tática: Initial Access (TA0108) em 10.0.0.0/24
[*] simulate=True (modo seguro)
[*] Técnica T0817 — Drive-by Compromise...
[*] Técnica T0819 — Exploit Public-Facing Application...
[*] Técnica T0822 — External Remote Services...
...
[+] Varredura concluída: 9 técnicas, 93 módulos executados
```

**Cenário de erro — tática inválida:**
```
ixf > mitre-scan tatica_invalida 192.168.1.100
[-] Tática ou técnica não reconhecida: 'tatica_invalida'
[i] Use 'mitre-list' para ver táticas e técnicas disponíveis.
```

**Comandos relacionados:** `mitre-all`, `ttp`, `ttp-list`

---

### `mitre-all <alvo>`

Varre todas as 74+ técnicas MITRE ATT&CK para ICS mapeadas (sempre em modo simulação).

**Sintaxe:** `mitre-all <alvo>`

**Contexto:** global

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| alvo | string | Sim | — | IP, hostname ou faixa CIDR alvo |

**Exemplo 1 — varredura completa em IP único:**
```
ixf > mitre-all 192.168.1.100
[*] Varredura MITRE ATT&CK para ICS completa em 192.168.1.100 (simulate=True)
[*] Executando 74 técnicas em 12 táticas...
[*] ── Initial Access (9 técnicas) ──────────────────────────────
[*] T0817 Drive-by Compromise...           [simulate] 3 módulos
[*] T0819 Exploit Public-Facing App...     [simulate] 47 módulos
[*] T0822 External Remote Services...      [simulate] 12 módulos
...
[*] ── Impact (8 técnicas) ─────────────────────────────────────
[*] T0813 Denial of Control...             [simulate] 8 módulos
...
[+] Varredura MITRE completa concluída: 74 técnicas, 976 módulos
[+] Relatório: ixf_mitre_all_192.168.1.100_20260601.json
```

**Exemplo 2 — varredura em sub-rede:**
```
ixf > mitre-all 10.0.0.0/28
[*] Varredura MITRE completa em 10.0.0.0/28 (16 hosts)
[*] simulate=True (forçado — mitre-all nunca executa ao vivo)
[*] Isso pode levar vários minutos para sub-redes grandes...
```

**Exemplo 3 — combinado com report:**
```
ixf > mitre-all 192.168.1.100
[+] Varredura concluída.

ixf > report html
[+] Relatório salvo: ixf_report_20260601_165000.html
```

**Cenário de erro:**
```
ixf > mitre-all
[-] Uso: mitre-all <alvo>. Exemplo: mitre-all 192.168.1.100
```

**Comandos relacionados:** `mitre-scan`, `mitre-coverage`, `report`

---

### `mitre-coverage`

Exibe porcentagem de cobertura por tática.

**Sintaxe:** `mitre-coverage`

**Contexto:** global

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| (nenhum) | — | — | — | — |

**Exemplo 1 — cobertura completa:**
```
ixf > mitre-coverage

  Cobertura MITRE ATT&CK para ICS
  ──────────────────────────────────────────────────────────────
  Initial Access (TA0108)             :  9/9   (100%)  ████████████
  Execution (TA0104)                  :  8/9   ( 88%)  ██████████▒
  Persistence (TA0110)                :  6/8   ( 75%)  █████████▒▒▒
  Privilege Escalation (TA0111)       :  2/2   (100%)  ████████████
  Evasion (TA0103)                    :  4/5   ( 80%)  █████████▒▒
  Discovery (TA0102)                  : 11/13  ( 84%)  ██████████▒▒
  Lateral Movement (TA0109)           :  3/3   (100%)  ████████████
  Collection (TA0100)                 :  8/9   ( 88%)  ██████████▒
  Command and Control (TA0101)        :  3/3   (100%)  ████████████
  Inhibit Response Function (TA0107)  : 14/18  ( 77%)  █████████▒▒▒
  Impair Process Control (TA0106)     :  9/11  ( 81%)  █████████▒▒
  Impact (TA0105)                     :  8/11  ( 72%)  █████████▒▒▒
  ──────────────────────────────────────────────────────────────
  TOTAL                               : 74/90  ( 82%)  ██████████▒▒
```

**Exemplo 2 — combinado com mitre-report:**
```
ixf > mitre-coverage
[...saída acima...]

ixf > mitre-report layer
[+] Layer ATT&CK Navigator salvo: ixf_mitre_layer_20260601.json
```

**Exemplo 3 — verificar técnicas sem cobertura:**
```
ixf > mitre-coverage
[i] Técnicas sem cobertura IXF:
    T0890  Exploitation for Privilege Escalation
    T0875  Change Program State
    T0823  Graphical User Interface
    T0808  Replication via Removable Media
    T0863  User Execution (via physical access)
    T0816  Device Restart/Shutdown (manual)
    T0829  Loss of Safety (non-technical)
    T0828  Loss of Productivity and Revenue
    T0827  Loss of Control (physical sabotage)
    T0826  Loss of Availability (network-level)
    T0833  Modify Alarm Settings
    T0807  Remote Services (generic)
    T0855  Unauthorized Command Message (custom)
    T0885  Commonly Used Port (C2)
    T0884  Connection Proxy
    T0872  Indicator Removal on Host (PLC)
```

**Cenário de erro:** Este comando não produz erros. Se o índice ainda estiver sendo carregado, exibe um spinner.

**Comandos relacionados:** `mitre-report`, `mitre-list`, `mitre-all`

---

### `mitre-report [formato]`

Gera um layer ATT&CK Navigator compatível ou relatório de cobertura.

**Sintaxe:** `mitre-report [json|html|layer]`

**Contexto:** global

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| formato | string | Não | `layer` | `layer` = JSON ATT&CK Navigator; `json` = dados brutos; `html` = relatório HTML |

**Exemplo 1 — gerar layer Navigator:**
```
ixf > mitre-report layer
[+] Layer ATT&CK Navigator salvo: ixf_mitre_layer_20260601.json
[i] Abra em: https://mitre-attack.github.io/attack-navigator/
[i] Importe via: "Open Existing Layer" → selecione o arquivo JSON
```

**Exemplo 2 — relatório HTML:**
```
ixf > mitre-report html
[+] Relatório de cobertura MITRE ICS salvo: ixf_mitre_report_20260601.html
[i] Inclui: tabela de cobertura, técnicas por tática, módulos mapeados
```

**Exemplo 3 — dados brutos JSON:**
```
ixf > mitre-report json
[+] Relatório MITRE raw JSON salvo: ixf_mitre_data_20260601.json
[i] Inclui: todos os mapeamentos técnica-módulo, metadados de cobertura
```

**Cenário de erro:**
```
ixf > mitre-report csv
[-] Formato inválido: 'csv'. Formatos disponíveis: json, html, layer
```

**Comandos relacionados:** `mitre-coverage`, `report`

---

### `mitre-tactic <tática> <alvo>`

Alias para `mitre-scan`. Aceita os mesmos parâmetros.

**Sintaxe:** `mitre-tactic <tática|TID> <alvo> [--destructive]`

**Exemplo:**
```
ixf > mitre-tactic inhibit 192.168.1.100
[*] (alias para mitre-scan inhibit 192.168.1.100)
[*] Varrendo tática: Inhibit Response Function (TA0107) em 192.168.1.100...
```

**Comandos relacionados:** `mitre-scan`

---

## Execução TTP

### `ttp <TID> <alvo> [flags]`

Executa todos os módulos mapeados a uma técnica MITRE específica contra um alvo.

**Sintaxe:** `ttp <TID> <alvo> [--destructive] [--stop-on-first] [--output <arquivo>] [--rate-limit <ms>]`

**Contexto:** global

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| TID | string | Sim | — | ID de técnica MITRE (ex.: `T0843`, `T0843.001`) |
| alvo | string | Sim | — | IP, hostname ou faixa CIDR alvo |
| `--destructive` | flag | Não | — | Desabilita modo simulação |
| `--stop-on-first` | flag | Não | — | Para após o primeiro hit confirmado |
| `--output <arquivo>` | string | Não | — | Salva resultados no arquivo especificado |
| `--rate-limit <ms>` | int | Não | `0` | Milissegundos entre módulos |

**Exemplo 1 — varredura TTP básica em modo simulação:**
```
ixf > ttp T0843 192.168.1.100
[*] TTP T0843 (Program Download) — 12 módulos — simulate=True
[*] Executando cve/siemens/cve_2021_22681_s7_1200_hardcoded_key...
  [SIMULATE] Conexão S7comm — chave hardcoded identificada como vector
[*] Executando cve/rockwell/cve_2022_1161_controllogix_modified_fw...
  [SIMULATE] Modificação de firmware ControlLogix — vetor plausível
[*] Executando exploits/protocols/s7comm/s7_unauthorized_cpu_control...
  [SIMULATE] Stop CPU via S7comm — porta 102 potencialmente aberta
...
[+] T0843 concluído: 12 módulos, 3 correspondências em simulação
[i] Para executar ao vivo: ttp T0843 192.168.1.100 --destructive
```

**Exemplo 2 — com rate-limit e saída em arquivo:**
```
ixf > ttp T0878 10.0.0.0/24 --rate-limit 500
[*] TTP T0878 (Alarm Suppression) — sub-rede 10.0.0.0/24 — 500ms entre módulos
[*] simulate=True | 8 módulos por host
[*] [1/256] Varrendo 10.0.0.1...
[*] [2/256] Varrendo 10.0.0.2...
...

ixf > ttp T0859 192.168.1.1 --stop-on-first --output resultados.json
[*] TTP T0859 (Valid Accounts) — para no primeiro hit
[*] Módulo 1: creds/siemens/s7_default_creds... [simulate] credenciais padrão detectadas
[!] Hit encontrado — parando (--stop-on-first)
[+] Resultado salvo: resultados.json
```

**Exemplo 3 — técnica com sub-técnica:**
```
ixf > ttp T0846.001 192.168.1.0/24
[*] TTP T0846.001 (Remote System Discovery — OT Network Scan)
[*] 4 módulos mapeados à sub-técnica T0846.001
[*] simulate=True
...
```

**Cenário de erro — TID não mapeado:**
```
ixf > ttp T0999 192.168.1.100
[-] Técnica 'T0999' não mapeada no IXF.
[i] Use 'ttp-list' para ver técnicas disponíveis.
```

**Comandos relacionados:** `ttp-check`, `ttp-simulate`, `ttp-list`, `mitre-scan`

---

### `ttp-check <TID> <alvo>`

Executa apenas a sonda `check()` para todos os módulos de uma técnica (somente leitura, sem exploits).

**Sintaxe:** `ttp-check <TID> <alvo>`

**Contexto:** global

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| TID | string | Sim | — | ID de técnica MITRE |
| alvo | string | Sim | — | IP ou hostname alvo |

**Exemplo 1 — check de T0843:**
```
ixf > ttp-check T0843 192.168.1.100
[*] T0843 check-only em 192.168.1.100...
[+] POTENCIAL: cve/siemens/cve_2022_38465_s7_global_key — porta 102 aberta
[-] NÃO VULNERÁVEL: cve/rockwell/cve_2023_3595_controllogix_rce — porta 44818 fechada
[+] POTENCIAL: exploits/protocols/s7comm/s7_stop_cpu — serviço S7comm respondeu
[-] NÃO VULNERÁVEL: cve/schneider/cve_2022_45789_modicon — porta 502 fechada
[i] 2 potenciais identificados de 12 módulos checados
```

**Exemplo 2 — check de T0859 (Valid Accounts):**
```
ixf > ttp-check T0859 10.0.0.50
[*] T0859 check-only em 10.0.0.50...
[+] POTENCIAL: creds/siemens/s7_default_creds — SSH porta 22 aberta
[+] POTENCIAL: creds/siemens/telnet_default_creds — Telnet porta 23 aberta
[-] NÃO VULNERÁVEL: creds/rockwell/logix_default_creds — EIP porta 44818 fechada
[i] 2 potenciais identificados de 8 módulos checados
```

**Exemplo 3 — check de T0800 (Firmware Update):**
```
ixf > ttp-check T0800 192.168.1.200
[*] T0800 check-only em 192.168.1.200...
[+] POTENCIAL: cve/siemens/cve_2021_22681_s7_1200_hardcoded_key — porta 102 aberta
[+] POTENCIAL: cve/mitsubishi/cve_2022_33139_melsec_fw — porta 5007 aberta
```

**Cenário de erro:**
```
ixf > ttp-check
[-] Uso: ttp-check <TID> <alvo>. Exemplo: ttp-check T0843 192.168.1.100
```

**Comandos relacionados:** `ttp`, `ttp-simulate`, `check`

---

### `ttp-simulate <TID> <alvo>`

Força modo simulação para todos os módulos de uma técnica (seguro, sem pacotes além do check).

**Sintaxe:** `ttp-simulate <TID> <alvo>`

**Contexto:** global

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| TID | string | Sim | — | ID de técnica MITRE |
| alvo | string | Sim | — | IP, hostname ou CIDR alvo |

**Exemplo 1 — simulação de T0866:**
```
ixf > ttp-simulate T0866 192.168.1.100
[*] T0866 simulação em 192.168.1.100 (simulate forçado)
[*] Técnica: Exploitation of Remote Services (Lateral Movement)
[*] 5 módulos mapeados
[SIMULATE] exploits/scada/ignition/ignition_rce — porta 8088 HTTP
  Conexão para 192.168.1.100:8088; envio de payload RCE (simulado)
  Impacto potencial: Remote Code Execution no servidor Ignition
[SIMULATE] exploits/protocols/opcua/opcua_browse_leak
  Enumeração anônima de nós OPC UA na porta 4840 (simulado)
...
```

**Exemplo 2 — comparando ttp vs ttp-simulate:**
```
ixf > ttp T0836 192.168.1.100
[*] TTP T0836 — simulate=True (padrão — equivale a ttp-simulate)

ixf > ttp-simulate T0836 192.168.1.100
[*] TTP T0836 — simulate FORÇADO (ignora setg simulate false)
```

**Exemplo 3 — uso em ambiente de teste SIEM:**
```
ixf > ttp-simulate T0878 10.0.1.100
[*] T0878 simulação em 10.0.1.100 — use para testar detecção SIEM
[*] Gera payload típico de supressão de alarme nos logs
```

**Cenário de erro:**
```
ixf > ttp-simulate T0843
[-] Uso: ttp-simulate <TID> <alvo>. Exemplo: ttp-simulate T0843 192.168.1.100
```

**Comandos relacionados:** `ttp`, `ttp-check`, `ttp-list`

---

### `ttp-list [--tactic <nome>]`

Lista todos os TTP-IDs com contagens de módulos. Filtro opcional por tática.

**Sintaxe:** `ttp-list [--tactic <nome_tática>]`

**Contexto:** global

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| `--tactic` | string | Não | — | Filtra por nome de tática ou alias |

**Exemplo 1 — listar todas as técnicas:**
```
ixf > ttp-list
  Índice TTP — todas as técnicas
  ─────────────────────────────────────────────────────────────
  T0800   Activate Firmware Update Mode     2 módulos   [Execution]
  T0801   Monitor Process State             2 módulos   [Collection]
  T0802   Automated Collection              5 módulos   [Collection]
  T0803   Block Command Message             4 módulos   [Inhibit Response]
  T0804   Block Reporting Message           3 módulos   [Inhibit Response]
  T0805   Block Serial COM                  1 módulo    [Inhibit Response]
  T0806   Brute Force I/O                   1 módulo    [Impair Process]
  T0807   Remote Services                   6 módulos   [Initial Access]
  T0808   Replication via Removable Media   0 módulos   [Initial Access]
  T0809   Data Destruction                  3 módulos   [Impact]
  T0810   Data Exfil over C2 Channel        2 módulos   [Collection]
  T0811   Data from Info Repositories       4 módulos   [Collection]
  T0812   Default Credentials              34 módulos   [Initial Access]
  T0813   Denial of Control                 8 módulos   [Impact]
  T0814   Denial of Service                 7 módulos   [Inhibit Response]
  T0815   Denial of View                    4 módulos   [Impact]
  T0816   Device Restart/Shutdown           5 módulos   [Inhibit Response]
  T0817   Drive-by Compromise               3 módulos   [Initial Access]
  T0819   Exploit Public-Facing App        47 módulos   [Initial Access]
  ...
  [74 técnicas listadas]
```

**Exemplo 2 — filtrar por Evasion:**
```
ixf > ttp-list --tactic evasion
  Índice TTP — Evasion (TA0103)
  ─────────────────────────────────────────────────────────────
  T0820   Exploitation of Remote Services  3 módulos
  T0849   Masquerading                     1 módulo
  T0856   Spoof Reporting Message          2 módulos
  T0858   Change Credential                4 módulos
  T0874   Hooking                          1 módulo
  T0872   Indicator Removal on Host        3 módulos
```

**Exemplo 3 — filtrar por Impair Process Control:**
```
ixf > ttp-list --tactic impair
  Índice TTP — Impair Process Control (TA0106)
  ─────────────────────────────────────────────────────────────
  T0806   Brute Force I/O                   1 módulo
  T0821   Modify Controller Tasking         8 módulos
  T0831   Manipulation of Control           6 módulos
  T0833   Modify Alarm Settings             3 módulos
  T0835   Detect Operating Mode             2 módulos
  T0836   Modify Parameter                 15 módulos
  T0838   Modify Program                    9 módulos
  T0843   Program Download                 12 módulos
  T0845   Program Organization Units        4 módulos
```

**Cenário de erro:**
```
ixf > ttp-list --tactic tática_invalida
[-] Tática não reconhecida: 'tática_invalida'.
[i] Táticas válidas: initial-access, execution, persistence, privilege-escalation,
    evasion, discovery, lateral-movement, collection, command-and-control,
    inhibit, impair, impact
```

**Comandos relacionados:** `ttp`, `mitre-list`, `mitre-coverage`

---

## Assessment

### `assess <caminho_modulo>`

Carrega e executa imediatamente um módulo de assessment.

**Sintaxe:** `assess <caminho_modulo>`

**Contexto:** global

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| caminho_modulo | string | Sim | — | Caminho relativo ao diretório `assessment/` |

**Exemplo 1 — auditoria IEC 62443 de zona e conduto:**
```
ixf > assess iec62443/zone_conduit_audit
[*] Carregando assessment/iec62443/zone_conduit_audit...
[*] Executando IEC 62443 Zone and Conduit Audit...

  ═══════════════════════════════════════════════════════════════
  AUDITORIA DE ZONA E CONDUTO — IEC 62443-3-2
  ═══════════════════════════════════════════════════════════════

  [?] A rede OT está segmentada da rede IT? (s/n): s
  [?] Existe firewall industrial entre zonas? (s/n): n

  RESULTADO: GAP CRÍTICO — Ausência de firewall entre zonas OT e IT
  Referência: IEC 62443-3-2 cláusula 5.4.1 — Separação de Zonas
  Remediação: Implementar IDMZ (Industrial DMZ) ou firewall unidirecional
```

**Exemplo 2 — scoring de risco ICS:**
```
ixf > assess risk/ics_risk_scorer
[*] Carregando assessment/risk/ics_risk_scorer...
[*] Calculando score de risco ICS...

  Score de Risco ICS: 78/100 (ALTO)
  - Exposição de protocolos sem autenticação: 35/35
  - Dispositivos com CVEs críticos: 25/30
  - Segmentação de rede: 10/20
  - Controles de acesso: 8/15
```

**Exemplo 3 — checklist NIST SP 800-82:**
```
ixf > assess nist_sp800_82/control_checklist
[*] Executando NIST SP 800-82r3 Control Checklist...
[i] 18 domínios de controle a verificar...
```

**Cenário de erro:**
```
ixf > assess iec62443/modulo_inexistente
[-] Módulo de assessment não encontrado: 'iec62443/modulo_inexistente'
[i] Use 'search assessment' para ver módulos disponíveis.
```

**Comandos relacionados:** `run`, `use`, `report`

---

## Estatísticas e Inventário

### `stats`

Exibe estatísticas de módulos e resumo de cobertura.

**Sintaxe:** `stats`

**Contexto:** global

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| (nenhum) | — | — | — | — |

**Exemplo 1 — saída completa de stats:**
```
ixf > stats
[i] Estatísticas de Módulos IXF

  Total: 976 módulos
  ──────────────────────────────────────
  Categoria        Qtd    %
  cve               486   49%
  exploits          159   16%
  creds              34    3%
  scanners           31    3%
  assessment         18    1%
  malware ttps       26    2%
  outros            222   22%
  ──────────────────────────────────────

[i] Vendors cobertos: 150 | TTPs de malware: 26
[i] MITRE ATT&CK para ICS: 12 táticas, 74/90 técnicas mapeadas (82%)
[i] Protocolos cobertos: 50
[i] PyPI: pip install industrialxpl-forge
[i] Versão: 1.0.13
```

**Exemplo 2 — stats após executar módulos:**
```
ixf > stats
[i] Estatísticas de Módulos IXF
[i] Módulos executados nesta sessão: 15
[i] Módulos com resultados (simulate): 15
[i] Módulos com hits confirmados (check): 3
```

**Exemplo 3 — comparação de versões:**
```
ixf > stats
[i] Versão: 1.0.13
[i] Última atualização: 2026-05-30
[i] Para atualizar: pip install --upgrade industrialxpl-forge
```

**Cenário de erro:** Não produz erros. Se o índice ainda estiver carregando, exibe um spinner.

**Comandos relacionados:** `vendors`, `protocols`, `mitre-coverage`

---

### `vendors [filtro]`

Lista todos os vendors OT/ICS cobertos com contagens de módulos CVE.

**Sintaxe:** `vendors [filtro_substring]`

**Contexto:** global

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| filtro | string | Não | — | Filtro de substring case-insensitive |

**Exemplo 1 — listar todos os vendors (top 20):**
```
ixf > vendors
  Vendors (150 cobertos)
  ─────────────────────────────────────────
  Vendor                          Módulos
  Schneider Electric                   39
  Rockwell Automation                  38
  Siemens                              27
  GE Digital / Emerson                 24
  Honeywell                            21
  Mitsubishi Electric                  18
  ABB                                  15
  Omron                                13
  Yokogawa                             12
  Phoenix Contact                      11
  Beckhoff                             10
  Moxa                                  9
  Advantech                             8
  Inductive Automation                  7
  Kepware Technologies                  6
  Wago                                  5
  COPA-DATA                             4
  Unitronics                            4
  Emerson (Fisher/ROC)                  4
  Delta Electronics                     3
  ...
  [130 vendors adicionais]
```

**Exemplo 2 — filtrar por Siemens:**
```
ixf > vendors siemens
  Vendors (1 coberto)
  ─────────────────────────────────────────
  Siemens                              27
```

**Exemplo 3 — filtrar por país/região:**
```
ixf > vendors germany
  Vendors (12 cobertos — Alemanha)
  ─────────────────────────────────────────
  Siemens                              27
  Beckhoff                             10
  Phoenix Contact                      11
  Wago                                  5
  COPA-DATA                             4
  Belden/Hirschmann                     2
  ...
```

**Cenário de erro — nenhum resultado:**
```
ixf > vendors vendorinexistentexyz
[!] Nenhum vendor encontrado com filtro 'vendorinexistentexyz'.
[i] Use 'vendors' sem filtro para ver todos os vendors cobertos.
```

**Comandos relacionados:** `protocols`, `stats`, `search`

---

### `protocols`

Lista todos os protocolos OT/ICS cobertos com contagens de módulos de exploit.

**Sintaxe:** `protocols`

**Contexto:** global

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| (nenhum) | — | — | — | — |

**Exemplo 1 — saída completa de protocols:**
```
ixf > protocols
  Cobertura de Protocolos (50 protocolos)
  ─────────────────────────────────────────
  Protocolo                   Módulos Exploit  Porta Padrão
  MODBUS/TCP                       18          502/TCP
  EtherNet/IP (ENIP)               14          44818/TCP
  S7COMM (Siemens)                  8          102/TCP
  DNP3                              4          20000/TCP
  IEC 60870-5-104                   6          2404/TCP
  OPC UA                            5          4840/TCP
  BACnet/IP                         4          47808/UDP
  PROFINET DCP                      3          —/UDP
  Modbus RTU (serial)               3          —/RS485
  IEC 61850 MMS                     4          102/TCP
  GE SRTP                           3          18245/TCP
  Mitsubishi MELSEC                 4          5006/TCP
  Omron FINS                        3          9600/UDP
  Siemens WinCC                     5          —
  Honeywell Experion DCS            2          —
  Yokogawa CENTUM CS3000            2          —
  ABB 800xA                         2          —
  Emerson DeltaV                    3          —
  HTTP/HTTPS (SCADA web)            8          80/443
  SSH / Telnet (legacy OT)          6          22/23
  SNMP (OT devices)                 3          161/UDP
  FTP/TFTP (firmware)               2          21/69
  ...
  [50 protocolos listados]
```

**Exemplo 2 — verificar após busca de protocolo:**
```
ixf > protocols
[...saída acima...]

ixf > search modbus
[*] Resultados: 43 módulos Modbus encontrados
```

**Cenário de erro:** Não produz erros.

**Comandos relacionados:** `vendors`, `stats`, `search`

---

### `coverage`

Alias para `mitre-coverage`. Ver documentação de `mitre-coverage` acima.

**Sintaxe:** `coverage`

**Exemplo:**
```
ixf > coverage
[*] (alias para mitre-coverage)
  Cobertura MITRE ATT&CK para ICS
  ...
```

---

## LLM / SAST

### `llm-key <provider> <api_key>`

Configura uma chave de API de provedor LLM para análise SAST. Chaves são armazenadas apenas na sessão (nunca escritas em disco por este comando).

**Sintaxe:** `llm-key <provider> <api_key>`

**Contexto:** global ou módulo

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| provider | string | Sim | — | `openai`, `anthropic`, `gemini`, `deepseek` ou `grok` |
| api_key | string | Sim | — | String da chave de API |

**Exemplo 1 — configurar Google Gemini:**
```
ixf > llm-key gemini AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
[+] Chave LLM configurada: provider=gemini len=39
```

**Exemplo 2 — configurar OpenAI:**
```
ixf > llm-key openai sk-svcacct-AbCdEfGhIjKlMnOpQrStUvWxYz...
[+] Chave LLM configurada: provider=openai len=82
```

**Exemplo 3 — configurar Anthropic Claude:**
```
ixf > llm-key anthropic sk-ant-api03-...
[+] Chave LLM configurada: provider=anthropic len=67
```

**Alternativa via variável de ambiente (recomendada — chave nunca entra no IXF):**
```bash
export GOOGLE_AI_STUDIO_API_KEY=AIzaSy...
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-api03-...
export DEEPSEEK_API_KEY=sk-deepseek-...
export XAI_API_KEY=xai-...
ixf
```

**Cenário de erro — provider inválido:**
```
ixf > llm-key mistral sk-key-123
[-] Provider inválido: 'mistral'. Providers disponíveis: openai, anthropic, gemini, deepseek, grok
```

**Cenário de erro — chave vazia:**
```
ixf > llm-key openai
[-] Uso: llm-key <provider> <api_key>
```

**Comandos relacionados:** `llm-status`, `sast`

---

### `llm-status`

Exibe o status de todos os providers LLM configurados.

**Sintaxe:** `llm-status`

**Contexto:** global

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| (nenhum) | — | — | — | — |

**Exemplo 1 — apenas Gemini configurado:**
```
ixf > llm-status

  Providers LLM
  ─────────────────────────────────────
  Provider     Status
  openai       não configurado
  anthropic    não configurado
  gemini       configurado ✓
  deepseek     não configurado
  grok         não configurado
  ─────────────────────────────────────
  Ativo: gemini (gemini-2.5-flash)
```

**Exemplo 2 — múltiplos providers configurados:**
```
ixf > llm-status

  Providers LLM
  ─────────────────────────────────────
  Provider     Status
  openai       configurado ✓
  anthropic    configurado ✓
  gemini       configurado ✓
  deepseek     não configurado
  grok         não configurado
  ─────────────────────────────────────
  Ativo: openai (gpt-4o)
  [i] OpenAI tem prioridade quando múltiplos providers estão configurados
```

**Exemplo 3 — nenhum provider configurado:**
```
ixf > llm-status

  Providers LLM
  ─────────────────────────────────────
  Provider     Status
  openai       não configurado
  anthropic    não configurado
  gemini       não configurado
  deepseek     não configurado
  grok         não configurado
  ─────────────────────────────────────
  Ativo: nenhum
  [!] Configure um provider para usar SAST: llm-key <provider> <api_key>
  [i] Ou defina a variável de ambiente antes de iniciar o IXF:
      export GOOGLE_AI_STUDIO_API_KEY=...
```

**Cenário de erro:** Não produz erros.

**Comandos relacionados:** `llm-key`, `sast`

---

### `sast <caminho> [--mode <modo>] [--diff <outro_arquivo>]`

Executa análise SAST com LLM em arquivo de código-fonte PLC/RTU ou diretório.

**Sintaxe:** `sast <caminho> [--mode sast|reverse|diff|exploit-gen] [--diff <outro_arquivo>]`

**Contexto:** global

**Parâmetros:**

| Argumento | Tipo | Obrigatório | Padrão | Valores Válidos |
|-----------|------|-------------|--------|-----------------|
| caminho | string | Sim | — | Caminho para arquivo PLC ou diretório de projeto |
| `--mode` | string | Não | `sast` | `sast`, `reverse`, `diff`, `exploit-gen` |
| `--diff` | string | Não | — | Segundo arquivo para modo `diff` |

**Modos disponíveis:**

| Modo | Descrição |
|------|-----------|
| `sast` | Análise completa de vulnerabilidades (setpoints, segurança, autenticação, rede, lógica) |
| `reverse` | Engenharia reversa de firmware/binário PLC compilado |
| `diff` | Comparação de duas versões de código PLC para mudanças não autorizadas |
| `exploit-gen` | Geração de PoC de exploit baseado nas descobertas |

**Exemplo 1 — análise SAST em diretório de projeto:**
```
ixf > sast /opt/plc_projects/water_treatment/ --mode sast
[*] Analisando: water_treatment/ (5 arquivos, 245 linhas)
[*] Linguagens: ST (3), FBD (1), IL (1)
[*] Provider: gemini | Sanitizado: 2 credenciais, 1 IP público
[*] Enviando 9.7 KB para o LLM (sanitizado)...

  RELATÓRIO DE ANÁLISE SAST — water_treatment/
  ─────────────────────────────────────────────────────────────

  DESCOBERTA [SEVERIDADE: CRITICAL]: Setpoint de Dosagem de Cloro Não Validado
    Localização: water_treatment.st, linha 48
    Tipo: Falha de Validação de Entrada / Setpoint Inseguro
    Descrição: SP_CHLORINE_HIGH := 4000.0 — 2000x o limite seguro da OMS
    Vetor de Ataque: Escrita Modbus FC16 em HR[200] (DOSE_FACTOR)
    Impacto Físico: 4000 mg/L de cloro — dose letal para crianças
    MITRE: T0836 (Modify Parameter), T0880 (Loss of Safety)
    Remediação: Validar DOSE_FACTOR <= 2.0; adicionar interlock de hardware

  DESCOBERTA [SEVERIDADE: HIGH]: Condição de Corrida em Dosagem de pH
    Localização: water_treatment.st, linhas 65-71
    Descrição: Loop de controle de pH sem mutex — escrita simultânea possível
    Impacto Físico: pH instável — corrosão de tubulações ou dano a equipamentos
    Remediação: Implementar semáforo ou lógica de bloqueio de scan cycle
```

**Exemplo 2 — modo diff para detecção de mudanças:**
```
ixf > sast /opt/plc/v2.3_original.st --mode diff --diff /opt/plc/v2.3_modified.st
[*] Comparando: v2.3_original.st vs v2.3_modified.st
[*] Provider: gemini

  RELATÓRIO DE ANÁLISE DIFERENCIAL
  ─────────────────────────────────────────────────────────────

  DESCOBERTA [SEVERIDADE: CRITICAL]: Limite de Segurança Removido
    Original:   SP_TEMP_TRIP := 280.0;  (* Seguro conforme especificação *)
    Modificado: SP_TEMP_TRIP := 450.0;  (* Elevado sem documentação *)
    Impacto: Setpoint de trip de temperatura elevado 60% acima do spec seguro
    Técnica: Manipulação de sistema de segurança estilo TRITON (T0816)
    Recomendação: Reverter imediatamente; investigar quem fez a mudança
```

**Exemplo 3 — modo reverse engineering:**
```
ixf > sast /opt/firmware/controller_v2.bin --mode reverse
[*] Arquivo binário: controller_v2.bin (128 KB)
[*] Extraindo strings e hexdump...
[*] Enviando para LLM para engenharia reversa...

  RELATÓRIO DE ENGENHARIA REVERSA
  ─────────────────────────────────────────────────────────────

  Identificado: Programa compilado Siemens S7-300
  Strings encontradas: 12 strings interessantes
    - "PASSWORD=admin123" no offset 0x2A80
    - "192.168.100.1" no offset 0x3C20 (IP interno)
    - "EMERGENCY_BYPASS" no offset 0x4100
    - "DEBUG_MODE=1" no offset 0x5200
```

**Cenário de erro — nenhum provider LLM configurado:**
```
ixf > sast /opt/plc/code.st
[-] Nenhum provider LLM configurado.
[i] Configure com: llm-key gemini <api_key>
[i] Ou defina: export GOOGLE_AI_STUDIO_API_KEY=...
```

**Cenário de erro — arquivo não encontrado:**
```
ixf > sast /path/inexistente/code.st
[-] Arquivo ou diretório não encontrado: '/path/inexistente/code.st'
```

**Comandos relacionados:** `llm-key`, `llm-status`

---

## Scripts NSE

### `nse <subcomando>`

Gerencia e executa scripts NSE (Nmap Scripting Engine) para reconhecimento de dispositivos OT/ICS.

**Sintaxe:** `nse <install|list|run|update>`

**Contexto:** global

**Parâmetros:**

| Subcomando | Obrigatório | Descrição |
|------------|-------------|-----------|
| `install` | Não | Instala scripts NSE ICS no diretório de scripts do Nmap |
| `list` | Não | Lista scripts NSE disponíveis no IXF |
| `run <script> <alvo>` | Não | Executa um script NSE em um alvo |
| `update` | Não | Atualiza scripts NSE para a versão mais recente |

**Exemplo 1 — instalar scripts NSE:**
```
ixf > nse install
[*] Instalando scripts NSE ICS...
[+] modbus-enum.nse      → /usr/share/nmap/scripts/
[+] s7-enumerate.nse     → /usr/share/nmap/scripts/
[+] enip-list.nse        → /usr/share/nmap/scripts/
[+] bacnet-info.nse      → /usr/share/nmap/scripts/
[+] dnp3-info.nse        → /usr/share/nmap/scripts/
[+] opcua-enum.nse       → /usr/share/nmap/scripts/
[+] profinet-dcp.nse     → /usr/share/nmap/scripts/
[+] ics-detect.nse       → /usr/share/nmap/scripts/
[*] Atualizando banco de dados de scripts: nmap --script-updatedb
[+] 8 scripts instalados com sucesso.
```

**Exemplo 2 — listar scripts disponíveis:**
```
ixf > nse list
  Scripts NSE ICS disponíveis:
  ─────────────────────────────────────────────────────────────
  modbus-enum.nse      Enumera dispositivos Modbus TCP (unit IDs, registradores)
  s7-enumerate.nse     Enumera PLCs Siemens S7 (info CPU, versão firmware)
  enip-list.nse        Enumera dispositivos EtherNet/IP (identidade CIP)
  bacnet-info.nse      Obtém informações de dispositivos BACnet/IP
  dnp3-info.nse        Proba comunicação DNP3 (Data Link Layer)
  opcua-enum.nse       Enumera nós OPC UA (sessão anônima)
  profinet-dcp.nse     Identifica dispositivos PROFINET via DCP
  ics-detect.nse       Detecção multi-protocolo ICS (wrapper geral)
```

**Exemplo 3 — executar script NSE:**
```
ixf > nse run modbus-enum 192.168.1.100
[*] Executando: nmap --script modbus-enum -p 502 192.168.1.100
Starting Nmap 7.94 ...
PORT    STATE SERVICE
502/tcp open  modbus
| modbus-enum:
|   Unit ID 1:
|     Device Identification: Schneider Electric Modicon M340
|     Vendor Name: Schneider Electric
|     Product Code: BMXP342020
|     Revision: V2.50
|_    Serial Number: 0042F5A8
```

**Cenário de erro — Nmap não instalado:**
```
ixf > nse run modbus-enum 192.168.1.100
[-] Nmap não encontrado no PATH.
[i] Instale com: apt-get install nmap (Linux) ou https://nmap.org/download (Windows)
```

**Cenário de erro — script não encontrado:**
```
ixf > nse run script_inexistente 192.168.1.100
[-] Script 'script_inexistente.nse' não encontrado.
[i] Use 'nse list' para ver scripts disponíveis.
```

**Comandos relacionados:** `discover`, `search scanner`, `exec nmap`

---

## Apêndice: Tabela Resumida de Todos os 36 Comandos

| Comando | Contexto | Descrição Curta |
|---------|----------|-----------------|
| `help` | global/módulo | Exibe ajuda global ou do módulo |
| `exit` | global/módulo | Encerra o IXF |
| `use <módulo>` | global | Carrega um módulo |
| `back` | módulo | Descarrega o módulo atual |
| `set <opt> <val>` | módulo | Define opção do módulo |
| `setg <opt> <val>` | global/módulo | Define opção global (todos os módulos) |
| `unsetg <opt>` | global/módulo | Remove opção global |
| `show [sub]` | módulo | Exibe info/opções/avançado/dispositivos/tudo |
| `run` | módulo | Executa o módulo carregado |
| `check` | módulo | Proba de conectividade somente-leitura |
| `search <termo>` | global | Busca módulos por palavra-chave/CVE/vendor |
| `exec <cmd>` | global/módulo | Executa comando de shell |
| `discover <CIDR>` | global | Varredura de descoberta OT |
| `cve <CVE-ID>` | global | Carrega módulo por CVE ID |
| `cve-scan <CIDR>` | global | Fluxo guiado de CVE scan |
| `report [fmt]` | global | Gera relatório de assessment |
| `mitre <TID>` | global | Consulta técnica MITRE específica |
| `mitre-list [tática]` | global | Lista técnicas MITRE mapeadas |
| `mitre-scan <t> <alvo>` | global | Varredura de tática/técnica MITRE |
| `mitre-all <alvo>` | global | Varre todas as 74 técnicas (simulate) |
| `mitre-coverage` | global | Cobertura por tática |
| `mitre-report [fmt]` | global | Exporta layer ATT&CK Navigator |
| `mitre-tactic <t> <alvo>` | global | Alias para mitre-scan |
| `ttp <TID> <alvo>` | global | Executa todos os módulos de uma técnica |
| `ttp-check <TID> <alvo>` | global | Apenas check() dos módulos da técnica |
| `ttp-simulate <TID> <alvo>` | global | Simulação forçada dos módulos da técnica |
| `ttp-list [--tactic]` | global | Lista todos os TTP-IDs com contagens |
| `assess <módulo>` | global | Carrega e executa módulo de assessment |
| `stats` | global | Estatísticas e resumo de cobertura |
| `vendors [filtro]` | global | Lista vendors cobertos |
| `protocols` | global | Lista protocolos cobertos |
| `coverage` | global | Alias para mitre-coverage |
| `llm-key <prov> <key>` | global | Configura chave API de LLM |
| `llm-status` | global | Status dos providers LLM |
| `sast <caminho>` | global | Análise SAST com LLM em código PLC |
| `nse <sub>` | global | Gerencia scripts NSE ICS |

---

---

## Fluxos de Trabalho Recomendados

### Workflow 1 — Avaliação de Segurança Inicial

Sequência recomendada para uma avaliação de segurança completa de ambiente OT desconhecido:

```
# Etapa 1: Entender o ambiente disponível
ixf > stats
ixf > mitre-coverage

# Etapa 2: Definir alvo global para a sessão
ixf > setg target 192.168.1.0/24
ixf > setg simulate true

# Etapa 3: Descoberta passiva
ixf > mitre-scan discovery 192.168.1.0/24

# Etapa 4: Fingerprinting por protocolo
ixf > use scanners/ics/modbus_detect
ixf > run  # target herdado do setg

ixf > back
ixf > use scanners/ics/s7_comm_scanner
ixf > run

ixf > back
ixf > use scanners/ics/bacnet_scanner
ixf > run

# Etapa 5: Varredura de técnicas MITRE relevantes
ixf > ttp-check T0843 192.168.1.0/24
ixf > ttp-check T0836 192.168.1.0/24
ixf > ttp-check T0859 192.168.1.0/24

# Etapa 6: Assessment de conformidade
ixf > unsetg target
ixf > assess iec62443/zone_conduit_audit
ixf > assess risk/ics_risk_scorer

# Etapa 7: Relatórios
ixf > report html
ixf > mitre-report layer
```

### Workflow 2 — Teste de Detecção SIEM

Para validar capacidades de detecção SIEM/IDS sem impacto:

```
# Gerar saída de simulação para criar assinaturas SIEM
ixf > setg simulate true
ixf > setg target 192.168.1.100

# Simular ataques de malware ICS conhecidos
ixf > use cve/malware/frostygoop_modbus_heating
ixf > run
# → Copiar payload hex para criar assinatura IDS

ixf > back
ixf > use cve/malware/industroyer2_iec104
ixf > run
# → Copiar ASDU IEC 104 para regra SIEM

ixf > back
ixf > ttp-simulate T0836 192.168.1.100
# → Gerar todas as variantes de T0836 para detecção

ixf > mitre-report html
# → Relatório com todos os TTPs simulados
```

### Workflow 3 — Red Team Focado em Vendor

```
# Investigar vulnerabilidades específicas de um vendor
ixf > vendors siemens
ixf > search siemens

# Executar todos os módulos Siemens em simulate
ixf > setg target 192.168.1.50
ixf > setg simulate true

# Verificar CVEs críticos
ixf > cve CVE-2021-22681
ixf > show info
ixf > run

ixf > back
ixf > cve CVE-2022-38465
ixf > run

# Executar TTP relevantes
ixf > ttp T0843 192.168.1.50  # Program Download
ixf > ttp T0859 192.168.1.50  # Valid Accounts

# Relatório focado em Siemens
ixf > report json
```

---

## Dicas e Atalhos

### Tab-completion

No shell interativo, a tecla Tab completa comandos e caminhos de módulo:

```
ixf > use scanners/ics/<TAB>
  modbus_detect
  s7_comm_scanner
  bacnet_scanner
  dnp3_detect
  opcua_scanner
  ...

ixf > ttp T08<TAB>
  T0800  T0801  T0802  T0803  T0804  T0805
  T0806  T0807  T0808  T0809  T0810  T0811
  ...
```

### Histórico de comandos

```
# Setas ↑/↓ — navegar histórico
# Ctrl+R — busca reversa no histórico
# Ctrl+A — início da linha
# Ctrl+E — final da linha
```

### Atalhos de sessão úteis

```
# Forçar SafeMode no início de qualquer sessão
ixf > setg simulate true
ixf > setg verbose false

# Testar conectividade antes de executar exploits
ixf > check   # Sempre antes de 'run' ao vivo

# Voltar ao contexto global rapidamente
ixf > back

# Ver histórico de auditoria da sessão
ixf > exec cat .log/destructive_ops_$(date +%Y-%m-%d).log 2>/dev/null || echo "Sem logs hoje"
```

---

*Anterior: [Início Rápido](02-inicio-rapido.md) | Próximo: [Sistema de Módulos](04-sistema-modulos.md)*

---

## Apendice: Exemplos Adicionais de Comandos

### Exemplo de Sessao Completa de Descoberta

```
ixf > setg simulate true
[*] Global: simulate => True

ixf > setg timeout 10
[*] Global: timeout => 10

ixf > discover 192.168.1.0/24
[*] Iniciando varredura de descoberta OT em 192.168.1.0/24...

ixf > search siemens
[*] Resultados: 27 modulos Siemens

ixf > cve CVE-2022-38465
[*] Modulo carregado: CVE-2022-38465 Siemens S7 Global Private Key

ixf (CVE-2022-38465 S7 Global Key) > set target 192.168.1.50
ixf (CVE-2022-38465 S7 Global Key) > run
  [SIMULATE] CVE-2022-38465 -- chave privada global S7
  Impacto: descriptografia de comunicacoes S7comm-Plus

ixf (CVE-2022-38465 S7 Global Key) > back

ixf > mitre-scan discovery 192.168.1.50
ixf > mitre-coverage
ixf > report json
```

### Referencia Rapida de Flags de Saida

| Saida | Significado | Quando Aparece |
|-------|-------------|----------------|
| `[*]` | Status/informativo | Progresso normal |
| `[+]` | Sucesso/confirmado | Resultado positivo, hit |
| `[-]` | Negativo/nao encontrado | Nao vulneravel |
| `[!]` | Aviso/atencao | Condicao requer atencao |
| `[i]` | Informacao/dica | Contexto adicional |
| `[SIMULATE]` | Modo simulacao ativo | run() em simulate=True |

---

*Anterior: [Inicio Rapido](02-inicio-rapido.md) | Proximo: [Sistema de Modulos](04-sistema-modulos.md)*
<!-- fim da referencia do shell -->
