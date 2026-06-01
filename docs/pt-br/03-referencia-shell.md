# Referência do Shell

Referência completa dos 35 comandos do shell interativo IXF.

**Prompts do shell:**
- `ixf >` — contexto global, nenhum módulo carregado
- `ixf (Nome do Módulo) >` — módulo carregado

---

## Navegação

### `help`
Exibe o menu de ajuda global ou específico do módulo.

### `exit`
Encerra o shell IXF.

### `use <caminho_modulo>`
Carrega um módulo. Aceita notação com barras (`scanners/ics/modbus_detect`) ou pontos (`scanners.ics.modbus_detect`).

```
ixf > use scanners/ics/modbus_detect
[*] Módulo carregado: Modbus TCP Device Detect
[*] CVE: N/A | CVSS: N/A | Impact: LOW
```

### `back`
Descarrega o módulo atual e retorna ao contexto global.

---

## Opções de Módulo

### `set <opção> <valor>`
Define uma opção no módulo carregado.

```
ixf > set target 192.168.1.100
ixf > set port 502
ixf > set simulate false
ixf > set timeout 10
```

**Erro de validação:**
```
ixf > set port 99999
[-] Erro de validação para 'port': Porta deve estar entre 1 e 65535
```

### `setg <opção> <valor>`
Define uma opção global que persiste em todos os módulos da sessão.

```
ixf > setg target 10.0.0.100
[*] Global: target => 10.0.0.100
```

### `unsetg <opção>`
Remove uma opção global.

---

## Inspeção de Módulo

### `show [subcomando]`
**Subcomandos:** `info | options | advanced | devices | all`

```
ixf (Modbus TCP Device Detect) > show options

     Opções — Modbus TCP Device Detect
+------------+-----------+----------+----------------------------------------+
| Opção      | Valor     | Obrig.   | Descrição                              |
|------------+-----------+----------+----------------------------------------|
| target     |           | sim      | IP alvo ou hostname                    |
| port       | 502       | não      | Porta Modbus TCP (padrão: 502)         |
| simulate   | True      | não      | Modo simulação (padrão: True)          |
| destructive| False     | não      | Habilitar envio de pacote real         |
+------------+-----------+----------+----------------------------------------+
```

---

## Execução

### `run`
Executa o módulo. O comportamento depende das opções `simulate` e `destructive`.

| simulate | destructive | Comportamento |
|----------|-------------|---------------|
| `True` (padrão) | qualquer | Apenas imprime saída de simulação |
| `False` | `False` | Apenas executa `check()` |
| `False` | `True` | Exploit completo com confirmação DestructiveGate |

### `check`
Sonda de conectividade somente leitura.

```
ixf (Modbus TCP Device Detect) > check
[+] VULNERÁVEL — Dispositivo Modbus detectado
```

---

## Descoberta

### `search <termo>`
Busca módulos por palavra-chave, ID de CVE, nome de vendor ou protocolo.

```
ixf > search CVE-2022-29965
ixf > search default_creds
ixf > search dnp3
```

### `discover <CIDR>`
Varredura de descoberta de dispositivos OT em uma sub-rede.

```
ixf > discover 192.168.1.0/24
```

---

## Comandos CVE

### `cve <ID-CVE>`
Encontra e carrega um módulo pelo identificador CVE.

```
ixf > cve CVE-2021-22681
[*] Módulo carregado: CVE-2021-22681 Siemens S7-1200/1500 PLC
```

---

## Relatórios

### `report [formato]`
Gera um relatório de avaliação.

```
ixf > report json
ixf > report html
ixf > report markdown
```

---

## MITRE ATT&CK for ICS

### `mitre <TID>`
Lista módulos que cobrem uma técnica MITRE específica.

```
ixf > mitre T0843
```

### `mitre-list [tática]`
Lista todas as técnicas MITRE mapeadas com contagem de módulos.

```
ixf > mitre-list
ixf > mitre-list discovery
```

### `mitre-scan <tática_ou_TID> <alvo> [--destructive]`
Executa varredura de tática ou técnica MITRE.

```
ixf > mitre-scan discovery 192.168.1.0/24
ixf > mitre-scan T0843 192.168.1.100
```

### `mitre-all <alvo>`
Varre todas as 74+ técnicas MITRE mapeadas (sempre em simulate).

### `mitre-coverage`
Exibe percentual de cobertura por tática.

```
ixf > mitre-coverage
  TOTAL: 74/90 (82%)
```

### `mitre-report [formato]`
Gera layer ATT&CK Navigator ou relatório.

```
ixf > mitre-report layer
[+] Layer ATT&CK Navigator salvo: ixf_mitre_layer_20260601.json
```

---

## TTP

### `ttp <TID> <alvo> [flags]`
Executa todos os módulos mapeados a uma técnica MITRE.

```
ixf > ttp T0843 192.168.1.100
ixf > ttp T0878 10.0.0.0/24 --rate-limit 500
ixf > ttp T0859 192.168.1.1 --stop-on-first --output resultados.json
```

**Flags:**

| Flag | Descrição |
|------|-----------|
| `--destructive` | Desabilita modo simulate |
| `--stop-on-first` | Para após primeiro hit confirmado |
| `--output <arquivo>` | Salva resultados em arquivo |
| `--rate-limit <ms>` | Milissegundos entre módulos |

### `ttp-check <TID> <alvo>`
Varredura somente `check()` (somente leitura, sem exploits).

### `ttp-simulate <TID> <alvo>`
Força modo simulate em todos os módulos da técnica.

### `ttp-list [--tactic <nome>]`
Lista todos os TTP-IDs com contagem de módulos.

```
ixf > ttp-list --tactic evasion
```

---

## Assessment

### `assess <caminho>`
Carrega e executa imediatamente um módulo de assessment.

```
ixf > assess iec62443/zone_conduit_audit
ixf > assess risk/ics_risk_scorer
```

---

## Estatísticas

### `stats`
Exibe estatísticas de módulos e resumo de cobertura.

```
ixf > stats
  Total: 976 módulos
  Vendors: 150 | TTPs de malware: 26
  MITRE ATT&CK for ICS: 12 táticas, 103 técnicas mapeadas
```

### `vendors [filtro]`
Lista todos os vendors OT/ICS cobertos.

```
ixf > vendors
ixf > vendors siemens
```

### `protocols`
Lista todos os protocolos OT/ICS cobertos.

### `coverage`
Alias para `mitre-coverage`.

---

## LLM / SAST

### `llm-key <provider> <api_key>`
Configura chave de API LLM para análise SAST.

```
ixf > llm-key gemini AIzaSyBGaoio5aKf3rWNFjpqc8trP4EJPyABYH8
[+] Chave LLM configurada: provider=gemini
```

**Providers aceitos:** `openai`, `anthropic`, `gemini`, `deepseek`, `grok`

### `llm-status`
Exibe status de todos os providers LLM.

```
ixf > llm-status
  Active: gemini
```

### `sast <caminho> [--mode <modo>] [--diff <outro>]`
Análise offline de código-fonte PLC/RTU via LLM.

```
ixf > sast /opt/plc_projects/water_treatment/ --mode sast
ixf > sast /opt/plc/original.st --mode diff --diff /opt/plc/modified.st
```

**Modos:** `sast`, `reverse`, `diff`, `exploit-gen`

---

## Outros Comandos

### `exec <comando_shell>`
Executa um comando shell e exibe a saída.

```
ixf > exec ping 192.168.1.1 -c 3
ixf > exec python tools/env_doctor.py
```

---

*Anterior: [Início Rápido](02-inicio-rapido.md) | Próximo: [Sistema de Módulos](04-sistema-modulos.md)*
