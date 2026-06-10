# SafeMode / DestructiveMode

O IXF é projetado para ser **seguro por padrão**. Todo módulo começa em modo de simulação e exige opt-in explícito em múltiplas etapas antes que qualquer payload de exploit ao vivo seja transmitido. Esta arquitetura de segurança foi desenhada para proteger ambientes de produção de acidentes acidentais durante testes autorizados.

---

## Índice

1. [Os Dois Modos](#os-dois-modos)
2. [Os 7 Níveis de Impacto](#os-7-níveis-de-impacto)
3. [Fluxo Completo CATASTROPHIC](#fluxo-completo-catastrophic)
4. [Fluxo Completo CRITICAL](#fluxo-completo-critical)
5. [A String Exata de Confirmação](#a-string-exata-de-confirmação)
6. [print_simulation() Anotado](#print_simulation-anotado)
7. [Formato e Localização do Log de Auditoria](#formato-e-localização-do-log-de-auditoria)
8. [Matriz de Combinações simulate/destructive](#matriz-de-combinações-simulatedestructive)
9. [Uso via API Python](#uso-via-api-python)
10. [setg simulate true — Modo Seguro Global](#setg-simulate-true--modo-seguro-global)
11. [Diagrama de Fluxo ASCII](#diagrama-de-fluxo-ascii)
12. [10 Boas Práticas](#10-boas-práticas)

---

## Os Dois Modos

### SafeMode (Padrão)

Todo módulo tem `simulate=True` por padrão. Neste modo:

- **Nenhum pacote é enviado** ao alvo
- `run()` chama `DestructiveGate.print_simulation()` que imprime o que *aconteceria*
- A saída mostra o payload exato, técnicas MITRE e o fluxo de ataque passo a passo
- Seguro para uso em testes de detecção SIEM/IDS sem impactar sistemas de produção
- Todas as opções de módulo podem ser configuradas normalmente
- `check()` *pode* ser executado (é somente-leitura por design)

**Exemplo de saída em SafeMode:**
```
ixf (FrostyGoop Modbus Heating Attack) > run

  [SIMULATE MODE — no packets sent]
  ─────────────────────────────────────────────────────────────
  [i] O que aconteceria:
      FrostyGoop TTP (2024) — Sandworm/GRU (Rússia)

      Fase 1 [Descoberta Modbus]: Varredura de porta Modbus TCP 502 no alvo
      Fase 2 [FC16 Write]: Escrita de 0x0000 nos registradores de controle de aquecimento
      Fase 3 [Loop]: Repetição a cada 30s para impedir recuperação manual
      Impacto Físico: Sistema de aquecimento offline — 600 apartamentos perdem
                      calefação (exemplo histórico: Lviv, Ucrânia jan/2024)

  [i] Payload (hex): 00 01 00 00 00 0B 01 10 00 00 00 02 04 00 00 00 00
  [i] MITRE ATT&CK para ICS: T0836 (Modify Parameter), T0814 (Denial of Control)
  [i] Para executar ao vivo: set simulate false
```

### DestructiveMode

Requer **ambas** as condições:
1. `set simulate false`
2. `set destructive true`

Então `run` dispara o fluxo de confirmação do `DestructiveGate`.

**Nota importante:** Mesmo com `simulate=false` e `destructive=false`, o IXF executa apenas o método `check()` (proba somente-leitura). O exploit real só é executado quando `destructive=true`.

---

## Os 7 Níveis de Impacto

Cada módulo declara um nível de impacto em `__info__["impact"]`. O nível determina qual confirmação é exigida antes da execução ao vivo.

### Nível 1: INFO

**Descrição:** `"Passive observation only. No packets sent."`

**Quando se aplica:** Módulos que nunca tocam a rede. Ferramentas de assessment, checklists de conformidade, geradores de relatório de cobertura, documentação.

**Ação necessária:** Automática — nenhum prompt exibido.

**Exemplos de módulos:**
- `assessment/mitre_ics/coverage_report` — gera relatório JSON
- `assessment/ir/iacs_ir_playbook` — checklist interativo de IR
- `assessment/iec62443/zone_conduit_audit` — auditoria de conformidade

**Saída típica ao executar:**
```
ixf (ICS Kill Chain Assessment) > run
[*] Executando módulo de assessment...
[i] Módulo INFO — apenas análise passiva
[*] Gerando relatório de kill chain...
```

### Nível 2: READ

**Descrição:** `"Read-only queries. No state change on target."`

**Quando se aplica:** Módulos que leem dados do alvo, mas nunca escrevem ou modificam nada. Scanners de protocolo, grabbers de banner, leitores de registradores.

**Ação necessária:** Automática — nenhum prompt exibido.

**Exemplos de módulos:**
- `scanners/ics/modbus_detect` — detecta dispositivo Modbus via FC3 (leitura)
- `scanners/ics/s7_enumerate` — enumera info de CPU S7 (leitura de dados PLC)
- `assessment/mitre_ics/t0801_monitor_process_state` — lê estado de processo

**Saída típica:**
```
ixf (Modbus TCP Device Detect) > set simulate false
ixf (Modbus TCP Device Detect) > run
[*] Módulo READ — apenas consultas somente-leitura
[*] Conectando a 192.168.1.100:502...
[+] Dispositivo Modbus detectado (unit ID 1, resposta FC3 válida)
```

### Nível 3: LOW

**Descrição:** `"Non-destructive write. Reversible."`

**Quando se aplica:** Módulos que escrevem dados não críticos. Toggle de LED, escrita em coil de teste, atualização de tag não relacionada à produção. A mudança é facilmente revertida por um operador.

**Ação necessária:** Aviso exibido, **sem prompt de confirmação**.

**Exemplos de módulos:**
- `exploits/protocols/modbus/modbus_single_coil_write` — escrita em coil único
- `assessment/mitre_ics/t0835_manipulate_io_image` — manipulação de imagem I/O

**Saída típica:**
```
ixf (Modbus Single Coil Write) > set simulate false
ixf (Modbus Single Coil Write) > set destructive true
ixf (Modbus Single Coil Write) > run
[!] AVISO: Impacto LOW — escrita não destrutiva reversível em 192.168.1.100:502
[*] Enviando escrita de coil Modbus FC5...
[+] Coil 0x0001 definido como ON em 192.168.1.100
[i] Para reverter: defina coil 0x0001 como OFF manualmente
```

### Nível 4: MEDIUM

**Descrição:** `"Process parameter modification. May affect operation. Reversible."`

**Quando se aplica:** Módulos que alteram parâmetros de processo (setpoints, timers, contadores). A mudança pode afetar o processo em execução, mas pode ser revertida por um operador.

**Ação necessária:** **Pressionar Enter** para confirmar.

**Exemplos de módulos:**
- `exploits/protocols/modbus/modbus_fc16_write_registers` — escreve múltiplos registradores
- `assessment/mitre_ics/t0836_modify_parameter` — modifica parâmetro de processo

**Saída típica:**
```
ixf (Modbus FC16 Write Registers) > set simulate false
ixf (Modbus FC16 Write Registers) > set destructive true
ixf (Modbus FC16 Write Registers) > run

  [!] AVISO DE IMPACTO MÉDIO
  Módulo: Modbus FC16 Write Multiple Registers
  Alvo:   192.168.1.100:502
  Ação:   Escrita em registradores de parâmetro de processo
  Impacto: Modificação de parâmetro de processo. Pode afetar operação. Reversível.

  Pressione Enter para continuar, ou Ctrl+C para abortar:
```

### Nível 5: HIGH

**Descrição:** `"Device restart / process stop. Requires operator intervention."`

**Quando se aplica:** Módulos que param uma CPU PLC, disparam uma reinicialização de dispositivo ou interrompem um processo controlado. A recuperação requer ação física ou remota de um operador.

**Ação necessária:** **Digitar a string exata de confirmação**.

**Exemplos de módulos:**
- `exploits/protocols/s7/s7_stop_cpu` — para CPU PLC via S7comm
- `creds/siemens/s7_default_creds` — brute-force de credenciais (poderia bloquear conta)
- `assessment/mitre_ics/t0806_brute_force_io` — força bruta de I/O

**Saída típica:**
```
ixf (S7 Stop CPU) > set simulate false
ixf (S7 Stop CPU) > set destructive true
ixf (S7 Stop CPU) > run

  ████████████████████████████████████████████████
  ██  MODO DESTRUTIVO — IMPACTO ALTO           ██
  ████████████████████████████████████████████████

  Módulo:  S7 CPU Stop via S7comm
  Alvo:    192.168.1.50:102
  Impacto: HIGH — Device restart / process stop. Requires operator intervention.
  Ação:    Para a CPU do PLC via função S7comm — requer reinicialização manual.

  Digite a seguinte string EXATAMENTE para confirmar:
  I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION

  Confirmação>
```

### Nível 6: CRITICAL

**Descrição:** `"Firmware modification / safety bypass / PLC logic overwrite. MAY BE IRREVERSIBLE."`

**Quando se aplica:** Módulos que modificam firmware, sobrescrevem lógica de programa PLC ou bypassam intertraves de segurança. O dano pode ser permanente ou exigir restauração de fábrica.

**Ação necessária:** **Digitar a string exata de confirmação**.

**Exemplos de módulos:**
- `cve/siemens/cve_2021_22681_s7_1200_hardcoded_key` — sobrescreve lógica PLC
- `exploits/plc/siemens/s7_1200_hardcoded_key` — modificação de firmware
- `assessment/mitre_ics/t0845_program_upload` — download de programa PLC

**Saída típica:**
```
ixf (CVE-2021-22681 Siemens S7-1200) > set simulate false
ixf (CVE-2021-22681 Siemens S7-1200) > set destructive true
ixf (CVE-2021-22681 Siemens S7-1200) > run

  ████████████████████████████████████████████████████████████
  ██  MODO DESTRUTIVO — IMPACTO CRÍTICO                     ██
  ██  PODE SER IRREVERSÍVEL                                 ██
  ████████████████████████████████████████████████████████████

  Módulo:  CVE-2021-22681 Siemens S7-1200/1500 Hardcoded Key
  Alvo:    192.168.1.50:102
  Impacto: CRITICAL — Firmware modification / safety bypass / PLC logic overwrite. MAY BE IRREVERSIBLE.
  Ação:    Sobrescreve lógica do PLC usando chave criptográfica hardcoded divulgada.

  Digite a seguinte string EXATAMENTE para confirmar:
  I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION

  Confirmação>
```

### Nível 7: CATASTROPHIC

**Descrição:** `"Physical equipment damage / safety system disabling. IRREVERSIBLE."`

**Quando se aplica:** Módulos que podem danificar equipamento físico, desabilitar sistemas de segurança (SIS/safety bypass), ou criar condições que poderiam prejudicar pessoal. O tier mais alto.

**Ação necessária:** Digitar a string exata de confirmação + **contagem regressiva obrigatória de 10 segundos**.

**Exemplos de módulos:**
- `cve/malware/frostygoop_modbus_heating` — desabilita aquecimento (Lviv 2024)
- `cve/apt/triton_triconex_safety_overwrite` — sobrescreve sistema de segurança Triconex
- `cve/malware/crashoverride_industroyer` — IEC 104 payload (apagão Ucrânia 2016)
- `cve/malware/pipedream_iocontrol` — framework OT PIPEDREAM/INCONTROLLER

**Saída típica (ver seção completa abaixo):**
```
  ██████████████████████████████████████████████████████████████████████
  ██  MODO DESTRUTIVO — IMPACTO CATASTRÓFICO                          ██
  ██  ESTA AÇÃO É IRREVERSÍVEL                                        ██
  ██████████████████████████████████████████████████████████████████████
  ...
  [!] AGUARDANDO 10 SEGUNDOS ANTES DO PROMPT — pressione Ctrl+C para abortar
  ...
```

---

## Fluxo Completo CATASTROPHIC

O fluxo mais restritivo. Exemplo usando `cve/malware/frostygoop_modbus_heating`:

### Etapa 1: Carregar módulo e configurar alvo

```
ixf > use cve/malware/frostygoop_modbus_heating
[*] Módulo carregado: FrostyGoop Modbus Heating Attack (Go) — Extended
[*] CVE: N/A | CVSS: N/A | Impacto: CATASTROPHIC

ixf (FrostyGoop Modbus Heating Attack) > set target 192.168.1.100
[*] target => 192.168.1.100

ixf (FrostyGoop Modbus Heating Attack) > set port 502
[*] port => 502
```

### Etapa 2: Desabilitar modo simulação

```
ixf (FrostyGoop Modbus Heating Attack) > set simulate false
[*] simulate => False
```

### Etapa 3: Habilitar modo destrutivo

```
ixf (FrostyGoop Modbus Heating Attack) > set destructive true
[*] destructive => True
```

### Etapa 4: Executar — ver o banner e aguardar a contagem regressiva

```
ixf (FrostyGoop Modbus Heating Attack) > run

  ██████████████████████████████████████████████████████████████████████
  ██  MODO DESTRUTIVO — IMPACTO CATASTRÓFICO                          ██
  ██  ESTA AÇÃO É IRREVERSÍVEL                                        ██
  ██████████████████████████████████████████████████████████████████████

  Módulo:  FrostyGoop Modbus Heating Attack (Go) — Extended
  Alvo:    192.168.1.100:502
  Impacto: CATASTROPHIC — Physical equipment damage / safety system disabling. IRREVERSIBLE.
  Ação:    Envia comandos Modbus FC16 para desabilitar controladores de aquecimento.
           Impacto histórico: 600 apartamentos em Lviv, Ucrânia perderam calefação por 2 dias.

  [!] AGUARDANDO 10 SEGUNDOS ANTES DO PROMPT — pressione Ctrl+C para abortar
  [10]... [9]... [8]... [7]... [6]... [5]... [4]... [3]... [2]... [1]...

  Digite a seguinte string EXATAMENTE para confirmar (case-sensitive):
  I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION

  Confirmação>
```

### Etapa 5: Confirmar ou Abortar

**Para prosseguir (entrada exata necessária):**
```
  Confirmação> I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION
[*] Confirmado. Entrada de auditoria escrita. Executando...
[*] [FrostyGoop] Conectando a 192.168.1.100:502 (unit 1)...
[*] [FrostyGoop] Conexão estabelecida.
[*] [FrostyGoop] Enviando FC16 Write para zerar registradores de aquecimento...
[+] [FrostyGoop] Escrita FC16 confirmada — registradores zerados em 192.168.1.100:502
```

**Qualquer outra entrada aborta:**
```
  Confirmação> sim
[-] ABORTADO. Entrada de auditoria escrita. Digite a string exata de confirmação para prosseguir.
```

**Ctrl+C também aborta:**
```
  Confirmação> ^C
[-] ABORTADO pelo usuário.
```

**String incorreta (similar mas não exata) aborta:**
```
  Confirmação> I accept full responsibility for this destructive operation
[-] ABORTADO. A confirmação é case-sensitive. String exata necessária:
    I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION
```

---

## Fluxo Completo CRITICAL

Exemplo usando `cve/siemens/cve_2021_22681_s7_1200_hardcoded_key`:

### Etapas completas

```
ixf > use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
[*] Módulo carregado: CVE-2021-22681 Siemens S7-1200/1500 Hardcoded Key
[*] CVE: CVE-2021-22681 | CVSS: 9.8 | Impacto: CRITICAL

ixf (CVE-2021-22681 Siemens S7-1200/1500) > set target 192.168.1.50
[*] target => 192.168.1.50

ixf (CVE-2021-22681 Siemens S7-1200/1500) > set slot 2
[*] slot => 2

ixf (CVE-2021-22681 Siemens S7-1200/1500) > set simulate false
[*] simulate => False

ixf (CVE-2021-22681 Siemens S7-1200/1500) > set destructive true
[*] destructive => True

ixf (CVE-2021-22681 Siemens S7-1200/1500) > run

  ████████████████████████████████████████████████████████████
  ██  MODO DESTRUTIVO — IMPACTO CRÍTICO                     ██
  ██  PODE SER IRREVERSÍVEL                                 ██
  ████████████████████████████████████████████████████████████

  Módulo:  CVE-2021-22681 Siemens S7-1200/1500 Hardcoded Key
  Alvo:    192.168.1.50:102 (slot 2)
  Impacto: CRITICAL — Firmware modification / safety bypass / PLC logic overwrite. MAY BE IRREVERSIBLE.
  Ação:    Faz upload de lógica PLC controlada pelo atacante usando chave simétrica hardcoded divulgada.

  Digite a seguinte string EXATAMENTE para confirmar (case-sensitive):
  I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION

  Confirmação> I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION
[*] Confirmado. Entrada de auditoria escrita. Executando...
[*] [CVE-2021-22681] Conectando a 192.168.1.50:102 slot 2...
[+] [CVE-2021-22681] Conexão COTP estabelecida.
[*] [CVE-2021-22681] S7comm Setup Communication...
[*] [CVE-2021-22681] Autenticando com chave hardcoded...
[+] [CVE-2021-22681] Autenticação bem-sucedida — fazendo upload de lógica...
```

---

## A String Exata de Confirmação

A string exata necessária para impactos `HIGH`, `CRITICAL` e `CATASTROPHIC`:

```
I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION
```

**Regras:**
- Deve ser digitada **exatamente** — qualquer variação (espaços extras, capitalização errada, texto parcial) abortará a operação.
- Case-sensitive: todas as letras em maiúsculas.
- Sem espaços iniciais ou finais além do espaçamento normal entre palavras.
- Uma única cópia exata desta string, não duplicada.

**Exemplos que ABORTAM:**
```
i accept full responsibility for this destructive operation  ← minúsculas
I Accept Full Responsibility For This Destructive Operation  ← title case
I ACCEPT RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION       ← faltando "FULL"
I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION! ← ponto de exclamação
 I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION ← espaço inicial
```

**O único input que CONFIRMA:**
```
I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION
```

---

## `print_simulation()` Anotado

Quando `simulate=True`, `run()` chama `DestructiveGate.print_simulation()`. Esta seção explica cada campo da saída e como módulos de diferentes tipos a utilizam.

### Assinatura da função

```python
DestructiveGate.print_simulation(
    description: str,           # Obrigatório: o que aconteceria (passo a passo)
    payload_hex: str = None,    # Opcional: hex dump do payload de exploit
    payload_human: str = None,  # Opcional: descrição legível do payload
    mitre_techniques: list = None,  # Opcional: IDs de técnica MITRE
) -> None
```

### Parâmetros

| Parâmetro | Tipo | Obrigatório | Descrição |
|-----------|------|-------------|-----------|
| `description` | string | Sim | Descrição multi-linha do que aconteceria. Use `\n` para quebras de linha. |
| `payload_hex` | string | Não | Hex dump do payload de exploit (truncado para 120 chars na exibição). |
| `payload_human` | string | Não | Descrição legível do payload. |
| `mitre_techniques` | list[str] | Não | IDs de técnica MITRE para exibir. |

### Exemplo 1: Módulo de Scanner (Tipo READ)

```python
if self.simulate:
    DestructiveGate.print_simulation(
        description=(
            "Modbus TCP Device Detect — varredura somente-leitura\n\n"
            "Passo 1: Abrir socket TCP para {}:{}\n"
            "Passo 2: Enviar Modbus FC3 Read Holding Registers (requisição mínima)\n"
            "Passo 3: Verificar formato do cabeçalho MBAP de resposta\n"
            "Resultado: Confirmar presença de dispositivo Modbus e unit IDs disponíveis"
        ).format(self.target, self.port),
        payload_hex="00 01 00 00 00 06 01 03 00 00 00 01",
        payload_human=(
            "Cabeçalho MBAP (6 bytes) + PDU Modbus FC3: "
            "unit_id=1, start_register=0, quantity=1"
        ),
        mitre_techniques=["T0846"],
    )
    return
```

**Saída:**
```
  [SIMULATE MODE — no packets sent]
  ─────────────────────────────────────────────────────────────
  [i] O que aconteceria:
      Modbus TCP Device Detect — varredura somente-leitura

      Passo 1: Abrir socket TCP para 192.168.1.100:502
      Passo 2: Enviar Modbus FC3 Read Holding Registers (requisição mínima)
      Passo 3: Verificar formato do cabeçalho MBAP de resposta
      Resultado: Confirmar presença de dispositivo Modbus e unit IDs disponíveis

  [i] Payload (human): Cabeçalho MBAP (6 bytes) + PDU Modbus FC3: unit_id=1...
  [i] Payload (hex):   00 01 00 00 00 06 01 03 00 00 00 01
  [i] MITRE ATT&CK para ICS: T0846
  [i] Para executar ao vivo: set simulate false
```

### Exemplo 2: Módulo de Exploit CVE (Tipo CRITICAL)

```python
if self.simulate:
    DestructiveGate.print_simulation(
        description=(
            "CVE-2021-22681 Siemens S7-1200/1500 Hardcoded Key\n\n"
            "Passo 1: Conexão TCP para {}:{} (S7comm / TSAP)\n"
            "Passo 2: TPKT + COTP Connection Request (CR PDU)\n"
            "Passo 3: S7comm Setup Communication\n"
            "Passo 4: Autenticar usando chave simétrica hardcoded "
            "(divulgada em ICSA-21-131-03)\n"
            "Passo 5: Download de programa STL/ladder controlado pelo atacante "
            "para slot {} do PLC\n"
            "Passo 6: Iniciar reinicialização a frio — PLC executa lógica do atacante\n"
            "Impacto Físico: Perda completa de controle sobre o processo industrial "
            "gerenciado por este PLC"
        ).format(self.target, self.port, self.slot),
        payload_hex=(
            "03 00 00 16 11 E0 00 00 00 14 00 "
            "C1 02 01 00 C2 02 01 02 C0 01 0A"
        ),
        payload_human=(
            "TPKT/COTP CR seguido de PDU S7comm tipo 0x72 "
            "(atualização de firmware) com autenticação de chave hardcoded"
        ),
        mitre_techniques=["T0821", "T0866"],
    )
    return
```

### Exemplo 3: Módulo de Malware ICS (Tipo CATASTROPHIC)

```python
if self.simulate:
    DestructiveGate.print_simulation(
        description=(
            "TRITON/TRISIS — Sobrescrição de Sistema de Segurança Triconex\n\n"
            "Vetor: Schneider Electric Triconex Safety Instrumented System (SIS)\n"
            "Ator: APT XENOTIME (Saudi Arabia 2017)\n\n"
            "Fase 1 [Reconhecimento]: Identificar controlador Triconex na rede\n"
            "  - Scanner: procurar porta TriStation 1131 no alvo {}\n"
            "Fase 2 [Acesso Inicial]: Comprometer estação de engenharia\n"
            "Fase 3 [Implante]: Fazer upload de TRITON malware para memória SIS\n"
            "Fase 4 [Sabotagem]: Overwrite de lógica de safety com 'always true'\n"
            "  - Resultado: Sistema de segurança falha em detectar condições perigosas\n"
            "Fase 5 [Impacto]: Processo industrial pode continuar além de limites seguros\n\n"
            "Impacto Real (2017): Planta petroquímica na Arábia Saudita forçada a "
            "parar produção. Único caso documentado de malware visando SIS."
        ).format(self.target),
        payload_hex="XX XX XX XX [TriStation 1131 protocol payload]",
        payload_human=(
            "Frame TriStation 1131 com código TRITON malware para "
            "sobrescrever lógica de safety no controlador alvo"
        ),
        mitre_techniques=["T0857", "T0816", "T0829"],
    )
    return
```

---

## Formato e Localização do Log de Auditoria

Toda operação destrutiva (confirmada ou abortada) é registrada em:

```
.log/destructive_ops_YYYY-MM-DD.log
```

O arquivo de log é criado no diretório onde o IXF é executado. Uma nova entrada é criada para cada operação, seja confirmada ou abortada.

### Formato de Entrada de Log

```
YYYY-MM-DDTHH:MM:SSZ | STATUS | module=<caminho.do.modulo> | target=<ip>:<porta> | impact=<NIVEL>
```

### Exemplos de Entradas de Log

```
2026-06-01T20:15:43Z | CONFIRMED | module=cve.malware.frostygoop_modbus_heating | target=192.168.1.100:502 | impact=CATASTROPHIC
2026-06-01T20:16:01Z | ABORTED   | module=cve.malware.crashoverride_industroyer | target=192.168.1.200:2404 | impact=CATASTROPHIC
2026-06-01T20:18:33Z | CONFIRMED | module=cve.siemens.cve_2021_22681_s7_1200_hardcoded_key | target=192.168.1.50:102 | impact=CRITICAL
2026-06-01T20:20:12Z | ABORTED   | module=exploits.protocols.s7.s7_stop_cpu | target=10.0.0.1:102 | impact=HIGH
2026-06-01T20:25:01Z | CONFIRMED | module=assessment.mitre_ics.t0836_modify_parameter | target=192.168.1.100:502 | impact=MEDIUM
```

### Localização do arquivo de log

O caminho pode ser alterado no nível do módulo `safety.py` para implantações customizadas. O padrão é:

```
<diretório_de_trabalho>/.log/destructive_ops_YYYY-MM-DD.log
```

Em implantações Windows:
```
D:\Projetos-SafeLabs\submodules\OT\IndustrialXPL-Forge\.log\destructive_ops_2026-06-01.log
```

Em implantações Linux:
```
/opt/industrialxpl-forge/.log/destructive_ops_2026-06-01.log
```

### Revisão de logs de auditoria

```bash
# Ver todas as operações confirmadas
grep "CONFIRMED" .log/destructive_ops_*.log

# Ver apenas CATASTROPHIC
grep "CATASTROPHIC" .log/destructive_ops_*.log

# Ver operações em um alvo específico
grep "192.168.1.100" .log/destructive_ops_*.log

# Contar operações por dia
wc -l .log/destructive_ops_*.log
```

---

## Matriz de Combinações simulate/destructive

A tabela abaixo documenta o comportamento exato do IXF para cada combinação possível de valores `simulate` e `destructive`:

| simulate | destructive | Comportamento | Pacotes enviados? | Impacto físico? |
|----------|-------------|---------------|-------------------|-----------------|
| `True` (padrão) | `False` (padrão) | `print_simulation()` apenas | Não | Não |
| `True` | `True` | `print_simulation()` apenas (simulate tem prioridade) | Não | Não |
| `False` | `False` | Executa apenas `check()` (proba somente-leitura) | Mínimo (check) | Não |
| `False` | `True` + impacto INFO/READ | `run()` direto, sem confirmação | Sim (leitura) | Não |
| `False` | `True` + impacto LOW | `run()` com aviso | Sim | Mínimo/reversível |
| `False` | `True` + impacto MEDIUM | `run()` após pressionar Enter | Sim | Possível/reversível |
| `False` | `True` + impacto HIGH | `run()` após string de confirmação | Sim | Alto/requer intervenção |
| `False` | `True` + impacto CRITICAL | `run()` após string de confirmação | Sim | Alto/pode ser irreversível |
| `False` | `True` + impacto CATASTROPHIC | Contagem regressiva 10s + `run()` após string | Sim | Físico/IRREVERSÍVEL |

### Regra da prioridade

`simulate=True` **sempre tem prioridade** sobre `destructive=True`. Não importa como `destructive` está definido, se `simulate=True` o exploit **nunca** enviará pacotes de exploit.

```
ixf > setg simulate true
ixf > use cve/malware/frostygoop_modbus_heating
ixf > set destructive true    # ignorado porque simulate=True
ixf > run
  [SIMULATE MODE — no packets sent]  ← simulate=True tem prioridade
```

---

## Uso via API Python

O `DestructiveGate` pode ser usado diretamente em scripts Python para automação avançada.

```python
from industrialxpl.core.exploit.utils import import_exploit
from industrialxpl.core.exploit.safety import DestructiveGate

# Carregar módulo
ExploitClass = import_exploit(
    "industrialxpl.modules.cve.malware.frostygoop_modbus_heating"
)
module = ExploitClass()
module.target = "192.168.1.100"
module.port = 502
module.unit_id = 1

# Obter nível de impacto
info = module.get_info()
impact = info.get("impact", "UNKNOWN")
print(f"Nível de impacto do módulo: {impact}")

# Modo simulação (padrão seguro)
module.simulate = True
module.run()  # Imprime simulação, nenhum pacote enviado

# Para execução ao vivo em um script autorizado:
# 1. Definir simulate=False, destructive=True
# 2. Tratar a confirmação programaticamente
module.simulate = False
module.destructive = True

# O portão ainda requer confirmação interativa a menos que seja sobreposto
# Para scripts não-interativos com autorização explicit:
confirmed = DestructiveGate.require_confirmation(
    module_name=info["name"],
    target=f"{module.target}:{module.port}",
    impact=impact,
    description=info.get("destructive_description", info.get("description", "")),
    non_interactive=True,  # Para scripts CI/CD — bypassa o prompt, usa log de auditoria
    confirmation_token="I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION",
)

if confirmed:
    module.run()
else:
    print("Não confirmado — abortar")
```

### Verificação de nível de impacto sem execução

```python
from industrialxpl.core.exploit.safety import IMPACT_LEVELS

# Listar todos os níveis de impacto com descrições
for level, description in IMPACT_LEVELS.items():
    print(f"{level:15s}: {description}")
```

Saída:
```
INFO           : Passive observation only. No packets sent.
READ           : Read-only queries. No state change on target.
LOW            : Non-destructive write. Reversible.
MEDIUM         : Process parameter modification. May affect operation. Reversible.
HIGH           : Device restart / process stop. Requires operator intervention.
CRITICAL       : Firmware modification / safety bypass / PLC logic overwrite. MAY BE IRREVERSIBLE.
CATASTROPHIC   : Physical equipment damage / safety system disabling. IRREVERSIBLE.
```

---

## `setg simulate true` — Modo Seguro Global

Para garantir que todos os módulos em uma sessão sejam executados em modo simulação, use `setg` no início da sessão:

```
ixf > setg simulate true
[*] Global: simulate => True

ixf > use cve/malware/frostygoop_modbus_heating
[*] Módulo carregado: FrostyGoop Modbus Heating Attack

ixf (FrostyGoop Modbus Heating Attack) > set destructive true
[*] destructive => True
[!] AVISO: destructive=True, mas simulate=True (global) — simulate tem prioridade

ixf (FrostyGoop Modbus Heating Attack) > run
  [SIMULATE MODE — no packets sent]
  [i] simulate=True (global setg) — módulo executando em modo seguro
```

**Uso recomendado ao iniciar uma sessão em ambiente de produção:**

```
ixf > setg simulate true
ixf > setg timeout 10
ixf > setg target <ip-do-lab>
```

Para reverter para execução ao vivo para um módulo específico:

```
ixf > use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
ixf > set simulate false    # Sobrepõe o global APENAS para este módulo
ixf > set destructive true
ixf > run
```

---

## Diagrama de Fluxo ASCII

```
ixf > use <módulo>
ixf > set target <ip>
ixf > run
     │
     ├─► simulate=True  ──────────────► print_simulation() ────► [NENHUM PACOTE]
     │    (padrão)                       exibe ataque hipotético
     │                                   exibe payload hex
     │                                   exibe técnicas MITRE
     │
     └─► simulate=False
              │
              ├─► destructive=False ──► check() apenas ──────────► [SOMENTE LEITURA]
              │                         proba de conectividade
              │                         retorna True/False
              │
              └─► destructive=True
                        │
                        ├─► impact INFO/READ ──────────────────► run() direto
                        │    (sem prompt)                         módulo passivo/leitura
                        │
                        ├─► impact LOW ───────────────────────► aviso exibido
                        │    (sem confirmação)                    run() direto
                        │                                         escrita reversível
                        │
                        ├─► impact MEDIUM ────────────────────► pressione Enter
                        │    (confirmação simples)               run() após Enter
                        │                                         modificação de parâmetro
                        │
                        ├─► impact HIGH ──────────────────────► banner de aviso
                        │    (string de confirmação)             prompt de string exata
                        │                                         log de auditoria
                        │                                         run() se confirmado
                        │
                        ├─► impact CRITICAL ─────────────────► banner CRITICAL
                        │    (string de confirmação)             prompt de string exata
                        │                                         log de auditoria
                        │                                         run() se confirmado
                        │
                        └─► impact CATASTROPHIC ─────────────► banner CATASTROPHIC
                             (contagem + string)                 sleep(10s) com contagem
                                                                 prompt de string exata
                                                                 log de auditoria
                                                                 run() se confirmado
                                                                 [RISCO IRREVERSÍVEL]
```

---

## 10 Boas Práticas

### 1. Nunca desabilite o modo simulação em ambientes de produção

O modo simulação não é apenas uma proteção técnica — é uma proteção processual. Antes de qualquer teste ao vivo, certifique-se de ter autorização escrita, janela de manutenção aprovada e pessoal de operações ciente.

```
ixf > setg simulate true  ← Execute isto PRIMEIRO em qualquer sessão
```

### 2. Sempre execute `check()` antes de `run()` em modo ao vivo

`check()` é somente-leitura e confirma que o alvo está acessível e potencialmente vulnerável antes de você comprometer uma operação destrutiva.

```
ixf > check
[+] VULNERÁVEL — Modbus detectado em 192.168.1.100:502
ixf > run  ← Somente agora
```

### 3. Use `setg simulate true` no início de cada sessão para impor modo seguro globalmente

Mesmo que você planeje executar módulos ao vivo mais tarde, começar com `setg simulate true` garante que você não acidentalmente execute algo destrutivo enquanto explora o ambiente.

### 4. Revise os logs de auditoria após cada sessão de teste autorizada

```bash
cat .log/destructive_ops_$(date +%Y-%m-%d).log
```

Verifique se as operações registradas correspondem ao seu plano de teste e que nada inesperado foi executado.

### 5. Para treinamento/detecção SIEM: use modo simulação para disparar detecção sem impacto

O modo simulação gera as saídas de log e comunicações de rede que você precisaria para testar regras SIEM, mas sem realmente explorar nada.

### 6. Documente cada sessão de teste com `report` antes de fechar o IXF

```
ixf > report json
[+] Relatório salvo: ixf_report_20260601_153045.json
```

Este relatório inclui todos os módulos executados, alvos testados e resultados — essencial para documentação de pentest.

### 7. Use `ttp-check` em vez de `ttp` para reconhecimento inicial

`ttp-check` executa apenas as probas `check()` (somente-leitura) sem qualquer payload de exploit.

```
ixf > ttp-check T0843 192.168.1.100
```

### 8. Nunca compartilhe ou versione arquivos de log de auditoria contendo informações de sistemas de produção

Os logs em `.log/` podem conter IPs, portas e informações sobre vulnerabilidades confirmadas. Trate-os como material confidencial de pentest.

### 9. Para módulos CATASTROPHIC: sempre use em um ambiente de lab isolado

Módulos classificados como CATASTROPHIC não devem ser executados ao vivo fora de ambientes de lab completamente isolados e controlados. A contagem regressiva de 10 segundos existe para dar tempo de reconsiderar.

### 10. Configure `destructive=False` globalmente e sobrepõe apenas quando necessário

```
ixf > setg destructive false   ← padrão seguro
ixf > setg simulate true       ← padrão seguro

# Para execução ao vivo de um módulo específico em lab autorizado:
ixf > use <módulo>
ixf > set simulate false        ← sobrescreve global APENAS para este módulo
ixf > set destructive true      ← sobrescreve global APENAS para este módulo
ixf > run
```

---

---

## Referência Rápida — Combinações de Modo

| simulate | destructive | impact | Comportamento de run() |
|----------|-------------|--------|----------------------|
| True | qualquer | qualquer | Imprime simulação — nenhum pacote enviado |
| False | False | qualquer | Executa apenas `check()` com aviso |
| False | True | INFO/READ | Execução automática sem confirmação |
| False | True | LOW | Execução com aviso simples |
| False | True | MEDIUM | Aguarda Enter para confirmar |
| False | True | HIGH | Banner laranja + string de confirmação |
| False | True | CRITICAL | Banner vermelho + string de confirmação |
| False | True | CATASTROPHIC | Banner vermelho + 10s espera + confirmação |

## Garantias Arquiteturais do SafeMode

O SafeMode é implementado em múltiplas camadas independentes para garantir que nenhum bug acidental possa enviar tráfego destrutivo:

**Camada 1 — Herança da classe base:** `simulate=True` é o valor padrão em `Exploit` base.

**Camada 2 — Verificação em run() de cada módulo:** Cada módulo verifica `self.simulate` explicitamente antes de qualquer código ao vivo.

**Camada 3 — DestructiveGate no interpreter:** O `command_run()` do shell verifica novamente o nível de impacto e requer confirmação antes de chamar `mod.run()`.

**Camada 4 — Log append-only:** Toda tentativa (confirmada ou abortada) é auditada antes da execução.

---

*Anterior: [Sistema de Módulos](04-sistema-modulos.md) | Próximo: [MITRE ATT&CK para ICS](06-mitre-attack-ics.md)*

---

## Exemplos Adicionais de Modulos por Nivel de Impacto

### MEDIUM -- Sessao de Terminal Completa

```
ixf > use exploits/protocols/modbus/modbus_fc16_write_registers
[*] Modulo carregado: Modbus FC16 Write Multiple Registers
[*] CVE: N/A | Impacto: MEDIUM

ixf (Modbus FC16 Write Multiple Registers) > show options
  +------------+-----------+----------+----------------------------------------------+
  | Opcao      | Valor     | Obrig.   | Descricao                                    |
  | target     |           | sim      | IP do dispositivo Modbus                     |
  | port       | 502       | nao      | Porta Modbus TCP                             |
  | unit_id    | 1         | nao      | Modbus Unit ID (1-247)                       |
  | start_addr | 0         | nao      | Endereco inicial do registrador              |
  | quantity   | 1         | nao      | Numero de registradores a escrever           |
  | values     | 0         | nao      | Valores a escrever (virgula-separado)        |
  | simulate   | True      | nao      | Modo simulacao (padrao: True)                |
  | destructive| False     | nao      | Modo destrutivo                              |
  +------------+-----------+----------+----------------------------------------------+

ixf (Modbus FC16 Write Multiple Registers) > set target 192.168.1.100
ixf (Modbus FC16 Write Multiple Registers) > set start_addr 100
ixf (Modbus FC16 Write Multiple Registers) > set values 1500
ixf (Modbus FC16 Write Multiple Registers) > set simulate false
ixf (Modbus FC16 Write Multiple Registers) > set destructive true
ixf (Modbus FC16 Write Multiple Registers) > run

  [!] AVISO DE IMPACTO MEDIO
  Modulo: Modbus FC16 Write Multiple Registers
  Alvo:   192.168.1.100:502
  Impacto: MEDIUM -- modificacao de parametro de processo, reversivel

  Pressione Enter para continuar ou Ctrl+C para abortar:
[*] Executando escrita Modbus FC16...
[*] Payload: 00 01 00 00 00 09 01 10 00 64 00 01 02 05 DC
[+] Escrita FC16 confirmada: registrador 100 = 1500 em 192.168.1.100:502
```

### INFO -- Assessment Passivo

```
ixf > assess mitre_ics/coverage_report
[*] Executando: Gerando relatorio de cobertura MITRE ATT&CK para ICS...
[*] Modulo INFO -- apenas analise passiva, sem conexoes de rede

[+] Layer ATT&CK Navigator gerado: ixf_mitre_layer_20260601.json
[+] Relatorio de cobertura: 74/90 tecnicas (82%)
[i] Abra o layer em: https://mitre-attack.github.io/attack-navigator/
```

---

## Interacao com o Portao de Seguranca via Linha de Comando

```bash
# Modo seguro global -- todas as execucoes em simulacao
ixf --simulate -c "ttp T0836 192.168.1.100"

# Flag --simulate ignorada para modulos INFO/READ (sem efeito)
ixf --simulate -c "assess mitre_ics/coverage_report"

# Modo verificacao apenas (somente check())
ixf -c "use exploits/protocols/s7comm/s7_stop_cpu; set target 192.168.1.50; check"
```

---

*Anterior: [Sistema de Modulos](04-sistema-modulos.md) | Proximo: [MITRE ATT&CK para ICS](06-mitre-attack-ics.md)*

---

## Considerações de Segurança Operacional

### Usando o IXF em Ambientes Regulados

Em ambientes sujeitos a regulamentações como NERC CIP, ISO 27001, ou IEC 62443:

1. **Documente a autorização** antes de qualquer teste
2. **Notifique as partes interessadas** (operadores, proprietários de ativos)
3. **Mantenha os logs de auditoria** do IXF como evidência de autorização
4. **Coordene com sala de controle** para testes de alto impacto
5. **Tenha um plano de rollback** documentado antes de qualquer `run` ao vivo

### Configurações de Segurança Recomendadas para Laboratório

```bash
# Configuração recomendada para lab de segurança OT
# No início de cada sessão de lab:
ixf > setg simulate true    # Trava global de simulação
ixf > setg lhost 10.0.0.1  # Host ouvinte (apenas para módulos de reverse)

# Verificar configuração global antes de prosseguir
ixf > show global

# Quando pronto para teste ao vivo (apenas em lab, apenas em alvos autorizados):
ixf > setg simulate false   # Libera modo ao vivo (com cautela)
```

---

## Comparativo de Nivel de Ruido: IXF vs Nmap

O IXF foi projetado para ser o scanner ativo **menos agressivo** para ambientes OT/ICS. Diferente do Nmap, que gera pacotes SYN, probes de deteccao de OS e multiplos PDUs de script por porta, o IXF envia um unico PDU de protocolo bem formado -- identico ao que uma workstation de engenharia legitima envia durante operacoes normais.

```
Ferramenta / Modo        Ruido    Risco em OT
---------------------------------------------------------
tcpdump (passivo)        1/5  ||||                Zero -- apenas escuta, nenhum pacote enviado
Wireshark (passivo)      1/5  ||||                Zero -- apenas escuta, nenhum pacote enviado
IXF check()              2/5  ||||||||            1 conn TCP, 1 PDU valido, 1 resposta
IXF run() simulate=true  2/5  ||||||||            Identico ao check() -- sem escrita
nmap -sS -T1             3/5  ||||||||||||        SYN scan lento, TCP half-open
IXF run() simulate=false 3/5  ||||||||||||        1 conn, 1 PDU de leitura (FC03/FC43)
nmap -sS -T2 (OT safe)   3/5  ||||||||||||        Aceitavel com timing conservador
nmap -sV -T3             4/5  ||||||||||||||||    Probes de versao por porta aberta
nmap --script modbus-*   4/5  ||||||||||||||||    Multiplos PDUs por porta
nmap -A (agressivo)      5/5  ||||||||||||||||||||  OS detect + scripts -- EVITAR em OT
nmap -T4 / -T5           5/5  ||||||||||||||||||||  NUNCA em OT -- pode derrubar PLCs/RTUs
```

### Timing do IXF vs Nmap -T

| Flag Nmap | IXF equivalente | Timeout | Delay | Retries | Quando usar |
|-----------|----------------|---------|-------|---------|-------------|
| `-T0` | `setg TIMING paranoid` | 5.0s | 10s | 1 | Stealth maximo |
| `-T1` | `setg TIMING sneaky` | 3.0s | 5s | 1 | ICS muito lentos |
| `-T2` | `setg TIMING polite` | 2.0s | 1s | 2 | **Recomendado para OT** |
| `-T3` | `setg TIMING normal` | 1.0s | 300ms | 3 | Padrao -- seguro para maioria do OT |
| `-T4` | `setg TIMING aggressive` | 0.5s | 50ms | 2 | Lab / redes rapidas apenas |
| `-T5` | `setg TIMING insane` | 0.2s | 0ms | 1 | Nunca em OT producao |

### Flags do Nmap como Opcoes Globais do IXF

```bash
# nmap -T2 --max-retries 1 --host-timeout 30s --max-rate 10 --scan-delay 500ms
setg TIMING T2
setg MAX_RETRIES 1
setg HOST_TIMEOUT 30
setg MAX_RATE 10
setg SCAN_DELAY 500

# nmap --version-intensity 2
setg PROBE_LEVEL 2

# nmap -Pn
setg SKIP_PING true

# nmap -oN saida.txt
setg OUTPUT saida.txt

# nmap -v
setg VERBOSE true
```

### Por que o IXF e mais Seguro que o Nmap em OT

| Aspecto | Nmap | IXF |
|---------|------|-----|
| Handshake TCP | SYN-only (half-open) | Full connect (handshake completo) |
| Payload | Probes genericos + banner | PDU correto do protocolo (Modbus/S7/ENIP) |
| PDUs por porta | 1 a 20+ (scripts, version probes) | 1 por check, 1-3 com PROBE_LEVEL 1-2 |
| Consciencia de OT | Nenhuma | Projetado para protocolos OT |
| Rate limiting | Flags manuais | Defaults conservadores (MAX_RATE=10, DELAY=300ms) |
| Protecao de escrita | Nenhuma | Exige `destructive=true` + confirmacao explicita |

---

*Anterior: [Sistema de Módulos](04-sistema-modulos.md) | Próximo: [MITRE ATT&CK for ICS](06-mitre-attack-ics.md)*
