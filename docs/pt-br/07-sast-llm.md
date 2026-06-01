# SAST / Análise LLM

O IXF inclui um módulo de Análise Estática de Segurança (SAST) offline, alimentado por LLMs. Analisa código-fonte PLC/RTU em busca de vulnerabilidades de segurança, setpoints inseguros, lacunas de autenticação e vetores de ataque específicos para OT.

---

## Provedores LLM Suportados

| Provider | Modelo | Variável de Ambiente |
|----------|--------|---------------------|
| OpenAI | `gpt-4o` | `OPENAI_API_KEY` |
| Anthropic | `claude-3-5-sonnet-20241022` | `ANTHROPIC_API_KEY` |
| Google Gemini | `gemini-2.5-flash` | `GOOGLE_AI_STUDIO_API_KEY` |
| DeepSeek | `deepseek-chat` | `DEEPSEEK_API_KEY` |
| Grok (xAI) | `grok-2-latest` | `XAI_API_KEY` |

**Prioridade de seleção:** OpenAI (se configurado) → primeiro provider configurado.

---

## Configurando uma Chave LLM

### Opção 1: Variável de ambiente (recomendada)

```bash
export GOOGLE_AI_STUDIO_API_KEY=AIzaSyBGaoio5aKf3rWNFjpqc8trP4EJPyABYH8
export OPENAI_API_KEY=sk-svcacct-...
ixf
```

### Opção 2: Comando do shell (somente na sessão, nunca gravado em disco)

```
ixf > llm-key gemini AIzaSyBGaoio5aKf3rWNFjpqc8trP4EJPyABYH8
[+] Chave LLM configurada: provider=gemini len=39
```

### Verificar status

```
ixf > llm-status

  Providers LLM
  ─────────────────────────────────────
  Provider    Status
  openai      não configurado
  gemini      configurado
  ─────────────────────────────────────
  Ativo: gemini
```

---

## Executando Análise SAST

```
ixf > sast <caminho> [--mode <modo>] [--diff <outro_arquivo>]
```

| Argumento | Tipo | Obrig. | Padrão | Descrição |
|-----------|------|--------|--------|-----------|
| caminho | string | sim | — | Arquivo fonte PLC ou diretório do projeto |
| `--mode` | string | não | `sast` | Modo de análise |
| `--diff` | string | não | — | Segundo arquivo para modo diff |

---

## Modos de Análise

### `sast` (Padrão) — Análise Completa de Vulnerabilidades

```
ixf > sast /opt/plc_projects/water_treatment/ --mode sast
[*] Alvo: water_treatment/ (5 arquivos, 245 linhas)
[*] Linguagens: ST (3), FBD (1), IL (1)
[*] Provider: gemini | Sanitizado: 2 credencial(is), 1 IP público
[*] Enviando 9,7 KB ao LLM (sanitizado)...

  RELATÓRIO DE ANÁLISE SAST
  ═══════════════════════════════════════════════════════════════

  FINDING [SEVERITY: CRITICAL]: Setpoint de Dosagem de Cloro Não Validado
    Localização: water_treatment.st, linha 48
    Descrição: SP_CHLORINE_HIGH := 4000.0 — 2000x o limite seguro da OMS
    Vetor de Ataque: Escrita FC16 Modbus em HR[200] (DOSE_FACTOR)
    Impacto Físico: 4000 mg/L de cloro — dose letal para crianças
    MITRE ATT&CK for ICS: T0836, T0880
    Exploit: modbus_write_register(unit=1, address=200, value=2000)
    Remediação: Validar DOSE_FACTOR <= 2.0; adicionar intertravamento físico

  FINDING [SEVERITY: CRITICAL]: Parâmetros PID Modificáveis Sem Auth
    Localização: pump_station.fbd, PID_PressureControl
    ...
```

---

### `reverse` — Engenharia Reversa

Para firmware binário/compilado:

```
ixf > sast /opt/firmware/controller_v2.bin --mode reverse
```

---

### `diff` — Detecção de Mudanças

Comparar duas versões do mesmo programa PLC:

```
ixf > sast /opt/plc/v2.3_original.st --mode diff --diff /opt/plc/v2.3_modificado.st

  RELATÓRIO DE ANÁLISE DIFERENCIAL
  FINDING [SEVERITY: CRITICAL]: Limite de Safety Removido
    Original:  SP_TEMP_TRIP := 280.0;  (* Seguro conforme especificação *)
    Modificado: SP_TEMP_TRIP := 450.0;  (* Elevado sem documentação *)
    Impacto: Ponto de trip de temperatura elevado 60% acima da especificação segura
```

---

### `exploit-gen` — Geração de Exploit

```
ixf > sast /opt/plc/reactor_batch.sfc --mode exploit-gen
```

---

## Linguagens PLC Suportadas

| Linguagem | Extensões de Arquivo |
|-----------|---------------------|
| Structured Text (ST) | `.st`, `.iecst`, `.scl` |
| Ladder Diagram (LD) | `.lad`, `.ld`, `.ldr` |
| Function Block Diagram (FBD) | `.fbd` |
| Instruction List (IL) | `.il`, `.awl`, `.stl` |
| Sequential Function Chart (SFC) | `.sfc` |
| Siemens SCL/AWL | `.scl`, `.awl`, `.stl` |
| Rockwell Studio 5000 (L5X) | `.l5x` |
| ABB Automation Builder | `.ap1`, `.ap15` |
| CODESYS | `.pro`, `.project`, `.pou` |

---

## Sanitização Antes do Envio ao LLM

O IXF aplica múltiplas camadas de sanitização antes de enviar qualquer código ao provider LLM.

| Tipo de Dado | Substituído Por | Exemplo |
|-------------|-----------------|---------|
| IPs públicos | `[IP_REDACTED]` | `8.8.8.8` → `[IP_REDACTED]` |
| IPs privados | **Preservados** | `192.168.1.1` mantido |
| Credenciais/senhas | `[CREDENTIAL_REDACTED]` | `password := 'admin'` → `[CREDENTIAL_REDACTED]` |
| Hostnames externos | `[HOST_REDACTED]` | `plc.empresa.com` → `[HOST_REDACTED]` |
| Blobs hex longos (>32 chars) | `[HEXBLOB_REDACTED]` | Chaves binárias |
| Blobs Base64 longos (>40 chars) | `[B64BLOB_REDACTED]` | Certificados |
| Linhas >300 chars | Truncadas com `[LINE_TRUNCATED]` | Dados binários |

### Orçamento de Tokens

O payload enviado ao LLM é limitado a **32.000 caracteres** (~8.000 tokens). O relatório de sanitização é exibido antes da análise.

---

## Categorias de Análise SAST

O LLM analisa 8 categorias específicas de OT/ICS:

1. **Setpoints e parâmetros de processo** — limites inseguros, valores hardcoded, falta de verificação de range
2. **Lógica de sistema de safety** — E-Stop, STO/SOS/SLS, bypass de alarme, watchdog
3. **Autenticação e controle de acesso** — flags de bypass, credenciais hardcoded
4. **Validação de entradas** — entradas Modbus/OPC/IHM sem verificação de limites
5. **Race conditions e timing** — acesso concorrente a variáveis compartilhadas
6. **Rede/comunicação** — protocolos em texto claro, chamadas sem autenticação
7. **Falhas de lógica e cenários de ataque** — padrões exploráveis passo a passo
8. **Resumo de achados** — estruturado CRITICAL/HIGH/MEDIUM/LOW

---

## Exemplos SAST Incluídos

O IXF inclui 17 exemplos realistas em `industrialxpl/resources/sast_examples/`:

| Arquivo | Processo | Vulnerabilidades Principais |
|---------|---------|----------------------------|
| `nuclear_reactor_cooling.st` | Resfriamento nuclear | SCRAM bypassed via Maintenance_Mode |
| `water_treatment_chemical_dosing.st` | Tratamento de água | Cloro 4000 mg/L |
| `gas_pipeline_pressure_control.st` | Gasoduto | ESD + SIS ambos bypassed |
| `power_grid_substation.st` | Rede elétrica | DNP3 sem SAv5 |
| `oil_refinery_process.st` | Refinaria | Aquecedor acima do limite de projeto |
| `wind_farm_scada.st` | Parque eólico | MQTT sem auth |

Para analisar um exemplo:

```
ixf > llm-key gemini AIzaSy...
ixf > sast industrialxpl/resources/sast_examples/water_treatment_chemical_dosing.st
```

---

*Anterior: [MITRE ATT&CK for ICS](06-mitre-attack-ics.md) | Próximo: [Protocolos e Vendors](08-protocolos-vendors.md)*
