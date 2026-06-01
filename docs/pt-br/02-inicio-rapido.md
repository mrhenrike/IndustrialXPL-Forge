# Início Rápido

Este guia percorre uma sessão completa do IXF, do lançamento ao primeiro exploit real, cobrindo o modo de simulação, carregamento de módulos, configuração de opções e o portão SafeMode/DestructiveMode.

---

## Passo 1: Iniciar o IXF

```
$ ixf
[*] Indexing modules…
[+] 976 modules indexed.

  ___           _           _       _  __  ______  _       ______
 ...
  IndustrialXPL-Forge v1.0.12 — OT/ICS/SCADA Security Assessment Framework
  Author: André Henrique (@mrhenrike) | União Geek | https://uniaogeek.com.br/
  Python-First. Implementação pura em Python.
  simulate=True por padrão (modo seguro).

ixf >
```

---

## Passo 2: Buscar Módulos

Use `search` para encontrar módulos por palavra-chave, vendor, ID de CVE ou protocolo:

```
ixf > search modbus
[*] Resultados para: modbus
    use exploits/protocols/modbus/modbus_client
    use exploits/protocols/modbus/modbus_replay_attack
    use scanners/ics/modbus_detect
    ... (50 resultados)

ixf > search CVE-2021-22681
[*] Resultados para: CVE-2021-22681
    use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key

ixf > search siemens
[*] Resultados para: siemens (77 resultados)
```

---

## Passo 3: Carregar um Módulo

```
ixf > use scanners/ics/modbus_detect
[*] Módulo carregado: Modbus TCP Device Detect
[*] CVE: N/A | CVSS: N/A | Impact: LOW

ixf (Modbus TCP Device Detect) >
```

---

## Passo 4: Ver Opções do Módulo

```
ixf (Modbus TCP Device Detect) > show options

     Opções — Modbus TCP Device Detect
+------------+-----------+----------+-----------------------------------+
| Opção      | Valor     | Obrig.   | Descrição                         |
|------------+-----------+----------+-----------------------------------|
| target     |           | sim      | IP ou hostname alvo               |
| port       | 502       | não      | Porta Modbus TCP (padrão: 502)    |
| unit_id    | 1         | não      | ID de unidade Modbus (1-247)      |
| timeout    | 5         | não      | Timeout de conexão (segundos)     |
| simulate   | True      | não      | Modo simulação (padrão: True)     |
| destructive| False     | não      | Habilitar envio real de pacotes   |
+------------+-----------+----------+-----------------------------------+
```

---

## Passo 5: Definir Alvo

```
ixf (Modbus TCP Device Detect) > set target 192.168.1.100
[*] target => 192.168.1.100
```

---

## Passo 6: Executar em Modo Simulação (Padrão — Seguro)

Com `simulate=True` (padrão), `run` imprime exatamente o que o módulo *faria* sem enviar pacotes:

```
ixf (Modbus TCP Device Detect) > run

  [SIMULATE MODE — nenhum pacote enviado]
  ─────────────────────────────────────────────────────────────
  [i] O que aconteceria:
      Enviar probe Modbus Function Code 4 para 192.168.1.100:502
      Payload (hex): 00 01 00 00 00 06 01 04 00 00 00 01
      Verificar echo do Transaction ID para confirmar dispositivo Modbus.

  [i] MITRE ATT&CK for ICS: T0888 (Remote System Discovery)
  [i] Para executar ao vivo: set simulate false
```

---

## Passo 7: Verificação de Conectividade

`check` realiza uma sonda TCP somente leitura independentemente do modo simulate:

```
ixf (Modbus TCP Device Detect) > check
[*] Verificando 192.168.1.100:502...
[+] VULNERÁVEL — Dispositivo Modbus detectado (echo de Transaction ID confirmado)
```

---

## Passo 8: Carregar um Exploit CVE

```
ixf (Modbus TCP Device Detect) > back
ixf > use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key

[*] Módulo carregado: CVE-2021-22681 Siemens S7-1200/1500 PLC
[*] CVE: CVE-2021-22681 | CVSS: 9.8 | Impact: CRITICAL

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > set target 192.168.1.50
ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > run

  [SIMULATE MODE — nenhum pacote enviado]
  ─────────────────────────────────────────────────────────────
  CVE-2021-22681 Siemens S7-1200/1500 PLC
  CVSS 9.8 (CRITICAL) | Chave TLS hardcoded — MitM/Descriptografia S7comm+

  Passo 1: Extrair chave privada hardcoded do firmware S7-1200
  Passo 2: Realizar MitM no S7comm+ TCP/102
  Passo 3: Descriptografar todo tráfego S7comm+ com a chave extraída
  Passo 4: Forjar comandos autenticados para ler/escrever memória do CLP
```

---

## Passo 9: Execução ao Vivo (Apenas Laboratórios Autorizados)

> **Aviso:** Execute somente em sistemas de sua propriedade ou com autorização escrita explícita.

```
ixf (CVE-2021-22681) > set simulate false
[*] simulate => False

ixf (CVE-2021-22681) > set destructive true
[*] destructive => True

ixf (CVE-2021-22681) > run

  ████████████████████████████████████████████████████████████
  ██  MODO DESTRUTIVO — IMPACTO CRÍTICO                      ██
  ████████████████████████████████████████████████████████████

  Módulo:  CVE-2021-22681 Siemens S7-1200/1500 PLC
  Alvo:    192.168.1.50:102
  Impacto: CRITICAL — Modificação de firmware. PODE SER IRREVERSÍVEL.

  Digite exatamente a seguinte string para confirmar:
  I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION

  Confirmação> I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION
[+] Confirmado. Executando...
```

---

## Início Rápido MITRE ATT&CK

```
ixf > ttp T0843 192.168.1.100
[*] Varrendo T0843 (Program Download) em 192.168.1.100...

ixf > mitre-coverage
  Cobertura MITRE ATT&CK for ICS
  TOTAL: 74/90 (82%)
```

---

## Modo Não-Interativo

```bash
ixf use scanners/ics/modbus_detect set target 192.168.1.100 run
ixf search CVE-2015-5374
ixf report json
```

---

## Diagnósticos

```bash
python tools/env_doctor.py
```

---

*Anterior: [Instalação](01-instalacao.md) | Próximo: [Referência do Shell](03-referencia-shell.md)*
