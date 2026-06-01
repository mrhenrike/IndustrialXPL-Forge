# SafeMode / DestructiveMode

O IXF é projetado para ser **seguro por padrão**. Todo módulo começa em modo simulação e requer uma opção explícita de múltiplas etapas antes que qualquer payload de exploit ao vivo seja transmitido.

---

## Os Dois Modos

### SafeMode (Padrão)

Todo módulo assume `simulate=True`. Neste modo:

- Nenhum pacote é enviado ao alvo
- `run()` chama `DestructiveGate.print_simulation()` que imprime o que *aconteceria*
- Seguro para testes de detecção em SIEM/IDS sem impactar sistemas em produção

```
ixf (FrostyGoop Modbus Heating Attack) > run

  [SIMULATE MODE — nenhum pacote enviado]
  ─────────────────────────────────────────────────────────────
  [i] O que aconteceria:
      FrostyGoop TTP (2024) — Sandworm/GRU (Rússia)

      Fase 1 [Descoberta Modbus]: Varrer porta 502 no alvo
      Fase 2 [Escrita FC16]: Escrever 0x0000 em holding registers (desabilitar aquecimento)
      Fase 3 [Loop]: Repetir a cada 30s para prevenir recuperação
      Impacto Físico: Sistema de aquecimento offline — 600 apartamentos sem aquecimento

  [i] Payload (hex): 00 01 00 00 00 0B 01 10 00 00 00 02 04 00 00 00 00
  [i] MITRE ATT&CK for ICS: T0836, T0814
  [i] Para executar ao vivo: set simulate false + set destructive true
```

### DestructiveMode

Requer ambos:
1. `set simulate false`
2. `set destructive true`

---

## Níveis de Impacto

| Nível | Descrição | Confirmação Necessária |
|-------|-----------|----------------------|
| `INFO` | Apenas observação passiva. Sem pacotes enviados. | Automática |
| `READ` | Consultas somente leitura. Sem mudança de estado. | Automática |
| `LOW` | Escrita não destrutiva. Reversível. | Aviso simples exibido |
| `MEDIUM` | Modificação de parâmetro de processo. Reversível. | Pressionar Enter |
| `HIGH` | Reinicialização de dispositivo / parada de processo. | Digitar string de confirmação |
| `CRITICAL` | Modificação de firmware / bypass de safety. PODE SER IRREVERSÍVEL. | Digitar string de confirmação |
| `CATASTROPHIC` | Dano físico / desabilitação de safety. IRREVERSÍVEL. | Digitar string + aguardar 10 segundos |

---

## Fluxo de Confirmação DestructiveGate

### Passo 1: Definir Flags

```
ixf (FrostyGoop Modbus Heating Attack) > set simulate false
ixf (FrostyGoop Modbus Heating Attack) > set destructive true
```

### Passo 2: Executar

```
ixf (FrostyGoop Modbus Heating Attack) > run
```

### Passo 3: Ver o Banner

Para impacto `CATASTROPHIC`, aguarda 10 segundos antes do prompt:

```
  ████████████████████████████████████████████████████████████████
  ██  MODO DESTRUTIVO — IMPACTO CATASTRÓFICO                     ██
  ██  ESTA AÇÃO É IRREVERSÍVEL                                    ██
  ████████████████████████████████████████████████████████████████

  Módulo:  FrostyGoop Modbus Heating Attack
  Alvo:    192.168.1.100:502
  Impacto: CATASTROPHIC — Dano físico a equipamentos. IRREVERSÍVEL.

  [!] AGUARDANDO 10 SEGUNDOS ANTES DO PROMPT — Ctrl+C para abortar

  Digite EXATAMENTE a seguinte string para confirmar:
  I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION

  Confirmação>
```

### Passo 4: Confirmar ou Abortar

**Para prosseguir:**
```
  Confirmação> I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION
[*] Confirmado. Entrada de auditoria gravada. Executando...
```

**Qualquer outra entrada aborta:**
```
  Confirmação> sim
[-] ABORTADO. Entrada de auditoria gravada.
```

---

## A String de Confirmação

A string exata necessária para impactos `HIGH`, `CRITICAL` e `CATASTROPHIC`:

```
I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION
```

Esta string deve ser digitada **exatamente** — qualquer variação aborta a operação.

---

## Log de Auditoria

Toda operação destrutiva (confirmada ou abortada) é registrada em:

```
.log/destructive_ops_AAAA-MM-DD.log
```

Exemplo de entrada:

```
2026-06-01T20:15:43Z | CONFIRMED | module=cve.malware.frostygoop | target=192.168.1.100:502 | impact=CATASTROPHIC
2026-06-01T20:16:01Z | ABORTED   | module=cve.malware.industroyer | target=192.168.1.200:2404 | impact=CATASTROPHIC
```

---

## Saída do `print_simulation()` Explicada

```
  [SIMULATE MODE — nenhum pacote enviado]
  ─────────────────────────────────────────────────────────────
  [i] O que aconteceria:         ← parâmetro description
      <descrição passo a passo>

  [i] Payload (humano):  <payload legível>       ← payload_human (opcional)
  [i] Payload (hex):     00 01 00 00 ... [trunc.] ← payload_hex (opcional)
  [i] MITRE ATT&CK for ICS: T0836, T0814         ← mitre_techniques (opcional)
  [i] Para executar ao vivo: set simulate false
```

---

## Boas Práticas

1. **Nunca desative o modo simulate em ambientes de produção**
2. **Sempre execute `check()` antes de `run()` no modo ao vivo**
3. **Use `setg simulate true` no início da sessão para forçar modo seguro globalmente**
4. **Revise os logs de auditoria após cada sessão de teste autorizado**
5. **Para treinamento/detecção SIEM: use modo simulate para acionar detecção sem impacto**

---

*Anterior: [Sistema de Módulos](04-sistema-modulos.md) | Próximo: [MITRE ATT&CK for ICS](06-mitre-attack-ics.md)*
