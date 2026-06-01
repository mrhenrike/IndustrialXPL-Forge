# Sistema de Módulos

Este documento explica a arquitetura de módulos do IXF, o formato de metadados `__info__`, todos os 10 tipos de opção e os padrões centrais `check()` / `run()`.

---

## Convenções de Caminho de Módulo

Módulos residem em `industrialxpl/modules/` e são referenciados por seus caminhos relativos.

**Notação com barras** (usada no shell):
```
scanners/ics/modbus_detect
cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
cve/malware/crashoverride_industroyer
assessment/mitre_ics/t0843_program_upload
```

**Notação com pontos** (caminho de importação Python):
```
scanners.ics.modbus_detect
cve.siemens.cve_2021_22681_s7_1200_hardcoded_key
```

Ambas as notações são intercambiáveis no shell.

---

## Categorias de Módulo

| Diretório | Conteúdo |
|-----------|---------|
| `exploits/protocols/` | Abuso de design de protocolo (Modbus, S7, DNP3, BACnet, IEC 104, OPC UA, ...) |
| `exploits/plc/` | Exploits específicos de CLP por vendor |
| `exploits/scada/` | Exploits de software SCADA/IHM |
| `exploits/mes/` | Exploits MES/ERP (Ignition, SAP, ActiveMQ, ...) |
| `scanners/ics/` | Descoberta e fingerprinting por protocolo |
| `scanners/osint/` | Dorks Shodan, ELITEWOLF, OT Hunt |
| `creds/` | Teste de credenciais padrão por vendor |
| `cve/` | PoCs específicos de CVE por vendor |
| `cve/apt/` | Réplicas de TTP de malware APT |
| `cve/malware/` | Módulos de simulação de TTP de malware ICS |
| `assessment/mitre_ics/` | Módulos de técnica MITRE ATT&CK for ICS |
| `assessment/iec62443/` | Verificações de conformidade IEC 62443 |
| `assessment/sast/` | Análise SAST/LLM de código PLC |

---

## Anatomia do Módulo

```python
"""Breve descrição."""
import socket

from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptPort, mute,
    print_error, print_status, DestructiveGate,
)


class Exploit(Exploit):
    __info__ = {
        "name":             "Nome do Módulo",
        "description":      "O que este módulo faz em uma frase.",
        "authors":          ("Seu Nome",),
        "references":       ("https://aviso-url.com",),
        "devices":          ("Vendor Produto Modelo",),
        "impact":           "HIGH",
        "exploit_type":     "Buffer Overflow",
        "cve":              "CVE-YYYY-NNNNN",
        "cvss":             "9.8",
        "severity":         "CRITICAL",
        "mitre_techniques": ["T0866"],
        "mitre_tactics":    ["Initial Access"],
    }

    target      = OptIP("",    "IP do dispositivo alvo")
    port        = OptPort(502, "Porta do protocolo")
    simulate    = OptBool(True,  "Modo simulação (padrão: True)")
    destructive = OptBool(False, "Habilitar exploração ao vivo")

    @mute
    def check(self) -> bool:
        if not self.target:
            return False
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect((self.target, self.port))
            s.close()
            return True
        except Exception:
            return False

    def run(self) -> None:
        if not self.target:
            print_error("Defina a opção 'target' primeiro.")
            return
        if self.simulate:
            DestructiveGate.print_simulation(
                description="CVE-YYYY-NNNNN\nPasso 1: ...\nPasso 2: ...",
                mitre_techniques=["T0866"],
            )
            return
        print_status("[CVE-YYYY] Explorando {}:{}...".format(self.target, self.port))
```

---

## Referência das Chaves `__info__`

| Chave | Tipo | Obrig. | Descrição |
|-------|------|--------|-----------|
| `name` | string | sim | Nome legível do módulo |
| `description` | string | sim | Descrição de 2 a 4 frases |
| `authors` | tuple[str] | sim | Autor(es) |
| `references` | tuple[str] | sim | Advisories CVE, URLs de PoC |
| `devices` | tuple[str] | sim | Dispositivos ou software alvo |
| `impact` | string | sim | `INFO`, `READ`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `CATASTROPHIC` |
| `exploit_type` | string | sim | Categoria curta (ex.: `Buffer Overflow`) |
| `source_poc` | string | não | URL do PoC público original |
| `cve` | string | sim | ID CVE ou `N/A` |
| `cvss` | string | sim | Pontuação CVSS ou `N/A` |
| `severity` | string | sim | Espelha `impact` |
| `mitre_techniques` | list[str] | sim | IDs de técnicas MITRE ATT&CK for ICS |
| `mitre_tactics` | list[str] | sim | Nomes de táticas |

---

## Tipos de Opção

### `OptIP`
Aceita um endereço IPv4 ou hostname.

| Valor | Válido? |
|-------|--------|
| `"192.168.1.100"` | Sim |
| `"target.local"` | Sim |
| `""` | Sim (vazio = não definido) |
| `"999.999.999.999"` | Não |

### `OptPort`
Aceita um inteiro entre 1 e 65535.

### `OptInteger`
Aceita qualquer inteiro. Restrições opcionais de `min_value` e `max_value`.

```python
unit_id = OptInteger(1, "ID de unidade Modbus (1-247)", min_value=1, max_value=247)
```

### `OptFloat`
Aceita qualquer número de ponto flutuante.

### `OptString`
Aceita qualquer string.

### `OptBool`
Aceita valores booleanos. Formas de string são aceitas:

| Entrada | Interpretado como |
|---------|------------------|
| `True`, `False` | Bool direto |
| `"true"`, `"yes"`, `"1"`, `"on"` | `True` |
| `"false"`, `"no"`, `"0"`, `"off"` | `False` |

```
ixf > set simulate false
ixf > set verbose yes
ixf > set destructive on
```

### `OptMAC`
Aceita endereço MAC. Separadores `:` e `-` são aceitos.

| Valor | Válido? | Normalizado |
|-------|--------|------------|
| `"00:11:22:33:44:55"` | Sim | `00:11:22:33:44:55` |
| `"AA-BB-CC-DD-EE-FF"` | Sim | `aa:bb:cc:dd:ee:ff` |
| `"00:11:22:33:44"` | Não | — |

### `OptWordlist`
Aceita caminho de arquivo de lista de palavras. Suporta:
- Caminho absoluto: `/tmp/senhas.txt`
- Prefixo `file://`: `file:///opt/listas/senhas.txt`
- Caminho relativo a `resources/wordlists/`: `ics_common_passwords.txt`

### `OptEncoder`
Aceita nome de encoder como string.

---

## Decoradores

### `@mute`
Suprime a saída padrão durante a execução. Usado em `check()` em varreduras multi-thread.

### `@multi`
Permite que um módulo aceite um arquivo de alvos via `target=file:///caminho/alvos.txt`.

```
ixf > set target file:///opt/alvos.txt
ixf > run
[multi] Alvo: 192.168.1.1
[multi] Alvo: 192.168.1.2
```

---

## Validação do Módulo

```bash
python -c "
from industrialxpl.core.exploit.utils import index_modules, import_exploit
mods = index_modules()
errs = []
for m in mods:
    try:
        import_exploit('industrialxpl.modules.' + m)()
    except Exception as e:
        errs.append((m, str(e)))
print(f'{len(mods)} módulos | {len(errs)} erros')
"
```

---

*Anterior: [Referência do Shell](03-referencia-shell.md) | Próximo: [SafeMode / DestructiveMode](05-safemode-destructivemode.md)*
