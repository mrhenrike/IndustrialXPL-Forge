# CLI Não-Interativo

O IXF pode ser usado sem o shell interativo passando comandos diretamente na linha de comando. Os comandos são processados sequencialmente e então o processo termina. Isso habilita scripting, automação, integração CI/CD e fluxos de trabalho de testes de penetração repetíveis em uma linha.

---

## Sumário

1. [Sintaxe Básica](#sintaxe-básica)
2. [Padrões de Uma Linha com Saída Completa](#padrões-de-uma-linha-com-saída-completa)
3. [Encadeamento de Múltiplos Módulos](#encadeamento-de-múltiplos-módulos)
4. [setg no Modo Não-Interativo](#setg-no-modo-não-interativo)
5. [Todas as Variações do Comando ttp](#todas-as-variações-do-comando-ttp)
6. [Todos os Comandos mitre](#todos-os-comandos-mitre)
7. [Piping de Shell — 15 Exemplos](#piping-de-shell--15-exemplos)
8. [Script Bash para Assessment OT Completo](#script-bash-para-assessment-ot-completo)
9. [API Python — 10 Exemplos de Código](#api-python--10-exemplos-de-código)
10. [Integração CI/CD](#integração-cicd)
11. [Códigos de Saída](#códigos-de-saída)
12. [Saída JSON com jq](#saída-json-com-jq)

---

## Sintaxe Básica

```bash
ixf <comando> [args...]
```

Múltiplos comandos são separados por espaços. O shell os processa da esquerda para direita sequencialmente, depois sai. Comandos que precisam de opções usam `set <opção> <valor>` entre `use` e `run`.

```bash
# Comando único
ixf stats

# Comandos encadeados (processados sequencialmente)
ixf use scanners/ics/modbus_detect set target 192.168.1.100 run

# Múltiplos comandos independentes
ixf search siemens
ixf stats
ixf vendors siemens
```

---

## Padrões de Uma Linha com Saída Completa

### Busca e sair

```bash
ixf search modbus
```

**Saída:**

```
[*] Indexando módulos...
[+] 976 módulos indexados.

Resultados de busca para: modbus
──────────────────────────────────────────────────────────────────────────────
  use scanners/ics/modbus_detect                       [INFO]   Modbus TCP Device Scanner
  use scanners/ics/modbus_range_scanner                [INFO]   Modbus Register Range Scanner
  use exploits/protocols/modbus/modbus_replay_attack   [HIGH]   Modbus TCP Replay Attack
  use exploits/protocols/modbus/modbus_write_coil      [HIGH]   Modbus Unauthorized Coil Write
  use exploits/protocols/modbus/modbus_flood_dos       [HIGH]   Modbus TCP Flood DoS
  use cve/malware/frostygoop_modbus_heating            [CRITICAL] FrostyGoop Modbus Heating Attack
  use cve/schneider/cve_2022_37300_modbus_auth_bypass  [CRITICAL] CVE-2022-37300 Modbus Auth Bypass
  use assessment/protocols/modbus_security_audit       [INFO]   Modbus Protocol Security Audit
──────────────────────────────────────────────────────────────────────────────
8 resultado(s) encontrado(s).
```

---

```bash
ixf search CVE-2021-22681
```

**Saída:**

```
Resultados de busca para: CVE-2021-22681
──────────────────────────────────────────────────────────────────────────────
  use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key   [CRITICAL] CVE-2021-22681 Siemens S7-1200 Hardcoded Crypto Key
──────────────────────────────────────────────────────────────────────────────
1 resultado(s) encontrado(s).
```

---

```bash
ixf search default_creds
```

**Saída:**

```
Resultados de busca para: default_creds
──────────────────────────────────────────────────────────────────────────────
  use creds/siemens/ssh_default_creds                 [HIGH]   Siemens SSH Default Credentials
  use creds/siemens/web_default_creds                 [HIGH]   Siemens Web Default Credentials
  use creds/rockwell/logix_default_creds              [HIGH]   Rockwell Logix Default Credentials
  use creds/schneider/web_default_creds               [HIGH]   Schneider Web Default Credentials
  use creds/ge/cimplicity_default_creds               [HIGH]   GE Cimplicity Default Credentials
  use creds/honeywell/experion_default_creds          [HIGH]   Honeywell Experion Default Credentials
  use creds/generic/web_default_creds                 [HIGH]   Generic Web Default Credentials
  use creds/generic/ftp_default_creds                 [MEDIUM] Generic FTP Default Credentials
  [... 26 resultados adicionais ...]
──────────────────────────────────────────────────────────────────────────────
34 resultado(s) encontrado(s).
```

---

### Carregar um módulo, definir opções e executar

```bash
ixf use scanners/ics/modbus_detect set target 192.168.1.100 run
```

**Saída:**

```
[*] Indexando módulos...
[+] 976 módulos indexados.
[*] Módulo carregado: Modbus TCP Device Scanner
[*] target => 192.168.1.100

┌──────────────────────────────────────────────────────────────────────────┐
│  [SIMULATE MODE]  Nenhum pacote enviado ao alvo.                         │
│  Defina 'simulate false' + 'destructive true' para executar ao vivo.     │
└──────────────────────────────────────────────────────────────────────────┘

[i] [SIMULATE] O que aconteceria: Detecção de Dispositivo Modbus TCP
    Passo 1: TCP conectar a 192.168.1.100:502
    Passo 2: Enviar sonda FC04 (Read Input Registers)
    Passo 3: Validar resposta MBAP de 6 bytes
    Impacto: Dispositivo fingerprinted

[i] [SIMULATE] MITRE ATT&CK for ICS: T0846, T0861
```

---

### Estatísticas e informações gerais

```bash
ixf stats
```

**Saída:**

```
  IXF — Estatísticas da Base de Módulos
  ══════════════════════════════════════
  Total de módulos:     976
  Módulos CVE:          421
  Módulos de protocolo: 214
  Scanners:              31
  Creds:                 34
  Assessment:            18
  Malware TTP:           26
  Scripts NSE:            8
  Outros:               224

  Cobertura MITRE:       74/90 técnicas (82%)
  Protocolos cobertos:   50
  Vendors cobertos:     150

  Versão IXF:           2.1.0
```

---

### Informações de módulo

```bash
ixf use cve/malware/frostygoop_modbus_heating info
```

**Saída:**

```
  Module: FrostyGoop Modbus Heating Attack (Go) — Extended
  ══════════════════════════════════════════════════════════
  CVE:             N/A (malware TTP — não CVE atribuído)
  CVSS:            N/A
  Impacto:         CATASTROPHIC
  Tipo de Exploit: Nation-State ICS Malware TTP
  Autor(es):       IXF Team
  Referências:
    https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-249a
    https://claroty.com/team82/research/frostygoop-ics-malware
  Dispositivos:    Controladores de aquecimento Modbus (ENCO)
  Técnicas MITRE:  T0836, T0814
  Táticas MITRE:   Impair Process Control, Inhibit Response Function

  Opções:
    target      (requerido)  IP Modbus/TCP do alvo
    port        502          Porta TCP Modbus
    unit_id     1            ID de unidade Modbus (1-247)
    timeout     5            Timeout de conexão (segundos)
    simulate    True         Modo simulação (padrão: True)
    destructive False        Habilitar execução ao vivo
```

---

### Coverage MITRE em uma linha

```bash
ixf mitre-coverage
```

```bash
ixf mitre-list --tactic initial-access
```

```bash
ixf mitre T0836
```

```bash
ixf ttp T0812 192.168.1.0/24
```

---

### Vendors e protocolos

```bash
ixf vendors
ixf vendors siemens
ixf vendors brazil
ixf protocols
```

---

### Relatórios JSON

```bash
ixf mitre-report json
ixf report json
ixf report csv
```

---

### 20 exemplos de uma linha com saída completa

```bash
# 1. Indexar e listar todos os módulos
ixf list

# 2. Buscar por vendor específico
ixf search schneider

# 3. Executar scanner Modbus em uma sub-rede
ixf use scanners/ics/modbus_detect set target 10.0.0.0/24 run

# 4. Executar scanner S7comm
ixf use scanners/ics/s7_enumerate set target 192.168.1.50 run

# 5. Verificar cobertura MITRE
ixf mitre-coverage

# 6. Consultar técnica específica
ixf mitre T0843

# 7. Listar TTPs de Initial Access
ixf ttp-list initial-access

# 8. Executar TTP de Default Credentials
ixf ttp T0812 192.168.1.100

# 9. Verificar módulo específico
ixf use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key set target 192.168.1.50 check

# 10. Ver informações de módulo CVE
ixf use cve/malware/frostygoop_modbus_heating info

# 11. Varredura de tática Discovery completa
ixf mitre-scan discovery 192.168.1.0/24

# 12. Relatório MITRE JSON
ixf mitre-report json

# 13. Verificar status do LLM
ixf llm-status

# 14. Executar SAST em arquivo PLC
ixf sast /opt/plc/reactor.st --mode sast

# 15. Estatísticas gerais
ixf stats

# 16. Listar vendors japoneses
ixf vendors japan

# 17. Buscar por protocolo específico
ixf protocols

# 18. Executar assessment IEC 62443
ixf assess iec62443/zone_conduit_audit

# 19. Executar assessment NIST 800-82
ixf assess nist_sp800_82/control_checklist

# 20. Relatório de cobertura completo
ixf mitre-all 192.168.1.100
```

---

## Encadeamento de Múltiplos Módulos

```bash
# Varredura completa de um alvo específico
ixf \
  use scanners/ics/modbus_detect set target 192.168.1.100 run \
  use scanners/ics/s7_enumerate set target 192.168.1.100 run \
  use scanners/ics/opcua_discovery set target 192.168.1.100 run
```

```bash
# Verificar credenciais padrão em múltiplos protocolos
ixf \
  use creds/siemens/s7_default_creds set target 192.168.1.50 run \
  use creds/generic/ssh_default_creds set target 192.168.1.50 run \
  use creds/generic/web_default_creds set target 192.168.1.50 run
```

---

## `setg` no Modo Não-Interativo

```bash
# Definir opção global antes de encadear módulos
ixf setg simulate true use scanners/ics/modbus_detect set target 192.168.1.0/24 run

# Forçar modo ao vivo (APENAS EM AMBIENTE AUTORIZADO)
ixf setg simulate false setg destructive true use exploits/protocols/modbus/modbus_write_coil set target 192.168.1.100 run
```

---

## Todas as Variações do Comando `ttp`

```bash
# Executar todos os módulos de uma técnica em modo simulate
ixf ttp T0836 192.168.1.100

# Executar com module específico
ixf ttp T0836 192.168.1.100 --module exploits/protocols/modbus/modbus_write_holding_register

# Verificação somente leitura (apenas check())
ixf ttp-check T0846 192.168.1.0/24

# Exibir simulação sem executar módulos
ixf ttp-simulate T0836 192.168.1.100

# Listar TTPs disponíveis
ixf ttp-list
ixf ttp-list initial-access
ixf ttp-list discovery
ixf ttp-list impair
ixf ttp-list inhibit
ixf ttp-list impact
ixf ttp-list execution
ixf ttp-list persistence
ixf ttp-list collection
```

---

## Todos os Comandos `mitre`

```bash
# Consultar técnica específica
ixf mitre T0819
ixf mitre T0836
ixf mitre T0843
ixf mitre T0878

# Listar todas as técnicas
ixf mitre-list

# Filtrar por tática
ixf mitre-list --tactic initial-access
ixf mitre-list --tactic discovery
ixf mitre-list --tactic inhibit
ixf mitre-list --tactic impair
ixf mitre-list --tactic impact
ixf mitre-list --tactic execution
ixf mitre-list --tactic persistence
ixf mitre-list --tactic collection
ixf mitre-list --tactic lateral-movement
ixf mitre-list --tactic c2

# Varredura de tática
ixf mitre-scan discovery 192.168.1.0/24
ixf mitre-scan impair 192.168.10.5
ixf mitre-scan inhibit 10.0.0.1

# Varredura completa
ixf mitre-all 192.168.1.100

# Relatório de cobertura
ixf mitre-coverage

# Exportar relatórios
ixf mitre-report json
ixf mitre-report csv
ixf mitre-report navigator
```

---

## Piping de Shell — 15 Exemplos

```bash
# 1. Extrair apenas caminhos de módulo dos resultados de busca
ixf search modbus | grep "use " | awk '{print $2}'

# 2. Contar módulos por nível de impacto
ixf list | grep "\[CRITICAL\]" | wc -l

# 3. Salvar saída de mitre-coverage em arquivo
ixf mitre-coverage > relatorio_mitre_$(date +%Y%m%d).txt

# 4. Extrair técnicas MITRE de resultados de busca
ixf mitre-list | grep "T0" | awk '{print $1, $2}' | sort

# 5. Filtrar apenas módulos de alto impacto do search
ixf search siemens | grep -E "\[CRITICAL\]|\[HIGH\]"

# 6. Salvar relatório JSON MITRE formatado
ixf mitre-report json && cat .tmp/ixf_mitre_report_*.json | python3 -m json.tool > mitre_formatado.json

# 7. Executar varredura e extrair IPs que responderam
ixf use scanners/ics/modbus_detect set target 192.168.1.0/24 run | grep "\[+\]" | awk '{print $NF}'

# 8. Buscar e executar módulo específico em pipeline
ixf search "frostygoop" | head -1 | awk '{print $2}' | xargs -I {} ixf use {} set target 192.168.1.100 run

# 9. Extrair CVEs listados
ixf list | grep "CVE-" | grep -oE "CVE-[0-9]+-[0-9]+" | sort -u

# 10. Enviar saída de simulação para log SIEM
ixf use cve/malware/frostygoop_modbus_heating set target 192.168.1.100 run 2>&1 | \
  logger -t "IXF-SIMULATE" -p local0.info

# 11. Comparar cobertura MITRE entre builds
ixf mitre-coverage | grep "TOTAL" | awk '{print $3}'

# 12. Executar múltiplos scanners e salvar resultados
for scanner in modbus_detect s7_enumerate bacnet_discovery opcua_discovery; do
  ixf use scanners/ics/$scanner set target 192.168.1.0/24 run >> scan_results.txt 2>&1
done

# 13. Extrair todos os módulos CATASTROPHIC
ixf list | grep "\[CATASTROPHIC\]" | awk '{print $2}'

# 14. Verificar conectividade antes de executar
ixf use scanners/ics/modbus_detect set target 192.168.1.100 check && \
  echo "Alvo acessível" || echo "Alvo inacessível"

# 15. Pipeline de assessment completo com saída JSON
ixf mitre-report json && \
  ixf report json && \
  jq '.modules | length' .tmp/ixf_report_*.json
```

---

## Script Bash Completo de Assessment OT

Script completo para assessment de segurança OT automatizado (100+ linhas):

```bash
#!/usr/bin/env bash
# assessment_ot.sh — Script de assessment de segurança OT completo
# Uso: ./assessment_ot.sh <ip_alvo_ou_cidr> [prefixo_relatorio]
#
# Requer: ixf instalado e configurado

set -euo pipefail

# ─── Configuração ────────────────────────────────────────────────────────────
TARGET="${1:-192.168.1.0/24}"
REPORT_PREFIX="${2:-assessment_ot}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_DIR="./relatorios/${TIMESTAMP}"
LOG_FILE="${REPORT_DIR}/assessment.log"

# ─── Cores para saída ────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # Sem cor

# ─── Funções auxiliares ───────────────────────────────────────────────────────
log() { echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} $*" | tee -a "$LOG_FILE"; }
success() { echo -e "${GREEN}[OK]${NC} $*" | tee -a "$LOG_FILE"; }
warn() { echo -e "${YELLOW}[AVISO]${NC} $*" | tee -a "$LOG_FILE"; }
error() { echo -e "${RED}[ERRO]${NC} $*" | tee -a "$LOG_FILE"; }

# ─── Inicialização ────────────────────────────────────────────────────────────
mkdir -p "$REPORT_DIR"
log "Iniciando assessment OT — Alvo: $TARGET"
log "Relatórios em: $REPORT_DIR"
log "Log: $LOG_FILE"

# Verificar que IXF está instalado
if ! command -v ixf &>/dev/null; then
    error "IXF não encontrado. Instale com: pip install industrialxpl-forge"
    exit 1
fi

# Forçar modo simulate para segurança
export IXF_FORCE_SIMULATE=true
log "Modo simulate forçado (IXF_FORCE_SIMULATE=true)"

# ─── Fase 1: Descoberta de Protocolos ────────────────────────────────────────
log "═══════════════════════════════════════════════════════════"
log "FASE 1: Descoberta de Protocolos Industriais"
log "═══════════════════════════════════════════════════════════"

SCAN_RESULTS="${REPORT_DIR}/fase1_descoberta.txt"

for protocolo in \
  "scanners/ics/modbus_detect:502:Modbus TCP" \
  "scanners/ics/s7_enumerate:102:Siemens S7comm" \
  "scanners/ics/enip_scanner:44818:EtherNet/IP" \
  "scanners/ics/bacnet_discovery:47808:BACnet/IP" \
  "scanners/ics/dnp3_data_link_scan:20000:DNP3" \
  "scanners/ics/iec104_scan:2404:IEC 60870-5-104" \
  "scanners/ics/opcua_discovery:4840:OPC UA"; do

  modulo=$(echo "$protocolo" | cut -d: -f1)
  porta=$(echo "$protocolo" | cut -d: -f2)
  nome=$(echo "$protocolo" | cut -d: -f3)

  log "Varrendo $nome (porta $porta) em $TARGET..."
  ixf use "$modulo" set target "$TARGET" run >> "$SCAN_RESULTS" 2>&1 || true
  sleep 1
done

# Contar dispositivos descobertos
DISPOSITIVOS=$(grep -c "\[+\]" "$SCAN_RESULTS" 2>/dev/null || echo 0)
success "Fase 1 completa: $DISPOSITIVOS dispositivos encontrados"

# ─── Fase 2: Descoberta MITRE ─────────────────────────────────────────────────
log "═══════════════════════════════════════════════════════════"
log "FASE 2: Varredura MITRE ATT&CK for ICS — Discovery"
log "═══════════════════════════════════════════════════════════"

MITRE_RESULTS="${REPORT_DIR}/fase2_mitre_discovery.txt"
ixf mitre-scan discovery "$TARGET" >> "$MITRE_RESULTS" 2>&1 || true
success "Fase 2 completa: varredura Discovery MITRE finalizada"

# ─── Fase 3: Verificação de Credenciais Padrão ───────────────────────────────
log "═══════════════════════════════════════════════════════════"
log "FASE 3: Verificação de Credenciais Padrão (simulate=True)"
log "═══════════════════════════════════════════════════════════"

CREDS_RESULTS="${REPORT_DIR}/fase3_credenciais.txt"
ixf ttp T0812 "$TARGET" >> "$CREDS_RESULTS" 2>&1 || true
success "Fase 3 completa: verificação de credenciais padrão finalizada"

# ─── Fase 4: Assessment de Conformidade ──────────────────────────────────────
log "═══════════════════════════════════════════════════════════"
log "FASE 4: Assessment de Conformidade"
log "═══════════════════════════════════════════════════════════"

COMPLIANCE_RESULTS="${REPORT_DIR}/fase4_conformidade.txt"

for assessment in \
  "iec62443/zone_conduit_audit" \
  "nist_sp800_82/control_checklist" \
  "risk/ics_risk_scorer" \
  "threat_intel/ics_kill_chain" \
  "ir/iacs_ir_playbook" \
  "network/ics_firewall_audit"; do

  log "Executando assessment: $assessment..."
  ixf assess "$assessment" >> "$COMPLIANCE_RESULTS" 2>&1 || true
done

success "Fase 4 completa: assessments de conformidade finalizados"

# ─── Fase 5: Relatório MITRE ─────────────────────────────────────────────────
log "═══════════════════════════════════════════════════════════"
log "FASE 5: Gerando Relatórios MITRE"
log "═══════════════════════════════════════════════════════════"

ixf mitre-coverage >> "${REPORT_DIR}/fase5_mitre_coverage.txt" 2>&1 || true
ixf mitre-report json >> /dev/null 2>&1 || true
ixf mitre-report navigator >> /dev/null 2>&1 || true

# Copiar arquivos gerados
cp .tmp/ixf_mitre_*.json "${REPORT_DIR}/" 2>/dev/null || true
success "Fase 5 completa: relatórios MITRE gerados"

# ─── Resumo Final ─────────────────────────────────────────────────────────────
log "═══════════════════════════════════════════════════════════"
log "RESUMO DO ASSESSMENT"
log "═══════════════════════════════════════════════════════════"

TOTAL_FINDINGS=$(grep -hc "\[+\]\|\[!\]" "${REPORT_DIR}"/*.txt 2>/dev/null || echo 0)
CRITICAL_FINDINGS=$(grep -hc "CRITICAL\|CATASTROPHIC" "${REPORT_DIR}"/*.txt 2>/dev/null || echo 0)

success "Assessment completo!"
log "  Alvo:               $TARGET"
log "  Relatório em:       $REPORT_DIR"
log "  Dispositivos:       $DISPOSITIVOS"
log "  Achados totais:     $TOTAL_FINDINGS"
log "  Achados críticos:   $CRITICAL_FINDINGS"
log ""
log "Arquivos gerados:"
ls -lh "${REPORT_DIR}/" | tee -a "$LOG_FILE"
log ""
log "Próximos passos:"
log "  1. Revisar ${REPORT_DIR}/fase1_descoberta.txt para dispositivos encontrados"
log "  2. Abrir ${REPORT_DIR}/ixf_mitre_layer_*.json em attack.mitre.org/attack-navigator"
log "  3. Compartilhar ${REPORT_DIR}/fase4_conformidade.txt com equipe de conformidade"
log "  4. Verificar ${REPORT_DIR}/fase3_credenciais.txt para exposição de credenciais"
```

---

## API Python — 10 Exemplos de Código

### Exemplo 1: Carregar e executar módulo em modo simulate

```python
from industrialxpl.core.exploit.utils import import_exploit

modulo_cls = import_exploit("industrialxpl.modules.scanners.ics.modbus_detect")
modulo = modulo_cls()
modulo.target   = "192.168.1.100"
modulo.simulate = True
modulo.run()
```

---

### Exemplo 2: Verificar conectividade com check()

```python
from industrialxpl.core.exploit.utils import import_exploit

modulo_cls = import_exploit("industrialxpl.modules.scanners.ics.modbus_detect")
modulo = modulo_cls()
modulo.target = "192.168.1.100"

if modulo.check():
    print(f"Dispositivo Modbus em 192.168.1.100 acessível")
    modulo.run()
else:
    print("Alvo não respondeu")
```

---

### Exemplo 3: Iterar sobre todos os módulos e coletar metadados

```python
from industrialxpl.core.exploit.utils import index_modules, import_exploit

todos_modulos = index_modules()
resultados = []

for caminho in todos_modulos:
    try:
        cls = import_exploit(f"industrialxpl.modules.{caminho}")
        modulo = cls()
        info = modulo.get_info()
        resultados.append({
            "caminho":  caminho,
            "nome":     info.get("name", ""),
            "impacto":  info.get("impact", ""),
            "cve":      info.get("cve", "N/A"),
            "mitre":    info.get("mitre_techniques", []),
        })
    except Exception as exc:
        print(f"[ERRO] {caminho}: {exc}")

# Filtrar por impacto
catastroficos = [r for r in resultados if r["impacto"] == "CATASTROPHIC"]
print(f"Módulos CATASTROPHIC: {len(catastroficos)}")
```

---

### Exemplo 4: Executar varredura em sub-rede e capturar saída

```python
import io
import sys
from industrialxpl.core.exploit.utils import import_exploit

cls = import_exploit("industrialxpl.modules.scanners.ics.modbus_detect")
modulo = cls()
modulo.target   = "192.168.1.0/24"
modulo.simulate = True

saida = io.StringIO()
sys.stdout = saida
modulo.run()
sys.stdout = sys.__stdout__

texto = saida.getvalue()
dispositivos = [l for l in texto.split('\n') if '[+]' in l]
print(f"Dispositivos encontrados: {len(dispositivos)}")
```

---

### Exemplo 5: Varrer múltiplos alvos com lista de módulos

```python
from industrialxpl.core.exploit.utils import import_exploit

ALVOS = ["192.168.1.100", "192.168.1.101", "192.168.1.102"]
SCANNERS = [
    "scanners.ics.modbus_detect",
    "scanners.ics.s7_enumerate",
    "scanners.ics.opcua_discovery",
]

for alvo in ALVOS:
    print(f"\n=== Varrendo {alvo} ===")
    for scanner_path in SCANNERS:
        try:
            cls = import_exploit(f"industrialxpl.modules.{scanner_path}")
            modulo = cls()
            modulo.target   = alvo
            modulo.simulate = True
            if modulo.check():
                modulo.run()
        except Exception as exc:
            print(f"[ERRO] {scanner_path} em {alvo}: {exc}")
```

---

### Exemplo 6: Gerar relatório de cobertura MITRE programaticamente

```python
from industrialxpl.core.exploit.utils import index_modules, import_exploit
import json

todos_modulos = index_modules()
cobertura_tecnicas = {}

for caminho in todos_modulos:
    try:
        cls = import_exploit(f"industrialxpl.modules.{caminho}")
        info = cls.__info__
        for tecnica in info.get("mitre_techniques", []):
            if tecnica not in cobertura_tecnicas:
                cobertura_tecnicas[tecnica] = []
            cobertura_tecnicas[tecnica].append(caminho)
    except Exception:
        pass

print(f"Total de técnicas cobertas: {len(cobertura_tecnicas)}")
print(f"Técnicas com mais módulos:")
sorted_tecnicas = sorted(cobertura_tecnicas.items(), key=lambda x: -len(x[1]))
for tecnica, modulos in sorted_tecnicas[:10]:
    print(f"  {tecnica}: {len(modulos)} módulos")

with open(".tmp/cobertura_mitre.json", "w") as f:
    json.dump(cobertura_tecnicas, f, indent=2)
```

---

### Exemplo 7: Assessment automatizado com relatório HTML

```python
from industrialxpl.core.exploit.utils import import_exploit, index_modules
import io
import sys
import datetime

def executar_assessment(alvos: list, saida_html: str) -> None:
    """Executar assessment completo e gerar relatório HTML."""
    resultados = []
    timestamp = datetime.datetime.now().isoformat()

    SCANNERS = [
        "scanners.ics.modbus_detect",
        "scanners.ics.s7_enumerate",
        "scanners.ics.bacnet_discovery",
    ]

    for alvo in alvos:
        for scanner in SCANNERS:
            try:
                cls = import_exploit(f"industrialxpl.modules.{scanner}")
                modulo = cls()
                modulo.target = alvo
                modulo.simulate = True

                captura = io.StringIO()
                sys.stdout = captura
                modulo.run()
                sys.stdout = sys.__stdout__

                resultados.append({
                    "alvo": alvo,
                    "scanner": scanner,
                    "saida": captura.getvalue(),
                    "check": modulo.check(),
                })
            except Exception as exc:
                sys.stdout = sys.__stdout__
                resultados.append({
                    "alvo": alvo,
                    "scanner": scanner,
                    "erro": str(exc),
                    "check": False,
                })

    # Gerar HTML simples
    with open(saida_html, "w") as f:
        f.write(f"<html><body><h1>Assessment OT — {timestamp}</h1>")
        for r in resultados:
            status = "acessível" if r.get("check") else "inacessível"
            f.write(f"<h3>{r['alvo']} — {r['scanner']} ({status})</h3>")
            f.write(f"<pre>{r.get('saida', r.get('erro', ''))}</pre>")
        f.write("</body></html>")
    print(f"Relatório salvo em {saida_html}")

# Uso
executar_assessment(
    alvos=["192.168.1.100", "192.168.1.101"],
    saida_html=".tmp/relatorio_assessment.html"
)
```

---

### Exemplo 8: Verificar módulos por nível de impacto

```python
from industrialxpl.core.exploit.utils import index_modules, import_exploit

NIVEIS_IMPACTO = ["INFO", "READ", "LOW", "MEDIUM", "HIGH", "CRITICAL", "CATASTROPHIC"]
contagem_por_nivel = {nivel: 0 for nivel in NIVEIS_IMPACTO}

for caminho in index_modules():
    try:
        cls = import_exploit(f"industrialxpl.modules.{caminho}")
        impacto = cls.__info__.get("impact", "UNKNOWN")
        if impacto in contagem_por_nivel:
            contagem_por_nivel[impacto] += 1
    except Exception:
        pass

print("Distribuição de módulos por nível de impacto:")
for nivel, count in contagem_por_nivel.items():
    barra = "█" * (count // 10)
    print(f"  {nivel:<15} {count:>4}  {barra}")
```

---

### Exemplo 9: Integração com SIEM via syslog

```python
import logging
import logging.handlers
import io
import sys
from industrialxpl.core.exploit.utils import import_exploit

# Configurar logger syslog
logger = logging.getLogger("ixf-assessment")
handler = logging.handlers.SysLogHandler(
    address=("siem.empresa.local", 514),
    facility=logging.handlers.SysLogHandler.LOG_LOCAL0,
)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Executar simulação e enviar para SIEM
cls = import_exploit("industrialxpl.modules.cve.malware.frostygoop_modbus_heating")
modulo = cls()
modulo.target   = "192.168.1.100"
modulo.simulate = True

captura = io.StringIO()
sys.stdout = captura
modulo.run()
sys.stdout = sys.__stdout__

saida = captura.getvalue()
logger.info(f"IXF-SIMULATE module=frostygoop_modbus_heating target=192.168.1.100 output={saida[:500]!r}")
print("Simulação enviada ao SIEM")
```

---

### Exemplo 10: Monitorar mudanças de cobertura entre versões

```python
import json
import os
from industrialxpl.core.exploit.utils import index_modules, import_exploit

def calcular_cobertura() -> dict:
    """Calcular cobertura atual de técnicas MITRE."""
    cobertura = {}
    for caminho in index_modules():
        try:
            cls = import_exploit(f"industrialxpl.modules.{caminho}")
            for tecnica in cls.__info__.get("mitre_techniques", []):
                cobertura[tecnica] = cobertura.get(tecnica, 0) + 1
        except Exception:
            pass
    return cobertura

# Calcular cobertura atual
cobertura_atual = calcular_cobertura()

# Carregar cobertura anterior se existir
baseline_path = ".tmp/cobertura_baseline.json"
if os.path.exists(baseline_path):
    with open(baseline_path) as f:
        cobertura_anterior = json.load(f)

    novas_tecnicas = set(cobertura_atual) - set(cobertura_anterior)
    tecnicas_removidas = set(cobertura_anterior) - set(cobertura_atual)

    if novas_tecnicas:
        print(f"[+] Novas técnicas adicionadas: {', '.join(sorted(novas_tecnicas))}")
    if tecnicas_removidas:
        print(f"[-] Técnicas removidas: {', '.join(sorted(tecnicas_removidas))}")
    if not novas_tecnicas and not tecnicas_removidas:
        print("[=] Cobertura MITRE sem mudanças")

# Salvar como novo baseline
with open(baseline_path, "w") as f:
    json.dump(cobertura_atual, f, indent=2)
print(f"Baseline salvo: {len(cobertura_atual)} técnicas cobertas")
```

---

## Integração CI/CD

### GitHub Actions (arquivo .yml completo)

```yaml
# .github/workflows/ixf-ot-security-assessment.yml
name: IXF OT Security Assessment

on:
  schedule:
    - cron: '0 2 * * 1'  # Toda segunda-feira às 02:00
  workflow_dispatch:
    inputs:
      target:
        description: 'IP ou CIDR alvo do assessment'
        required: false
        default: '10.0.0.0/24'

jobs:
  ot-security-assessment:
    name: OT Security Assessment
    runs-on: ubuntu-latest
    timeout-minutes: 60

    steps:
      - name: Checkout repositório
        uses: actions/checkout@v4

      - name: Configurar Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Instalar IXF
        run: |
          pip install industrialxpl-forge
          pip install industrialxpl-forge[extras]

      - name: Verificar instalação IXF
        run: ixf stats

      - name: Verificar cobertura MITRE
        run: |
          ixf mitre-coverage
          ixf mitre-report json

      - name: Executar varredura de protocolos (simulate=True)
        env:
          TARGET: ${{ github.event.inputs.target || '10.0.0.0/24' }}
        run: |
          mkdir -p reports/
          ixf use scanners/ics/modbus_detect set target "$TARGET" run > reports/modbus.txt 2>&1 || true
          ixf use scanners/ics/s7_enumerate set target "$TARGET" run > reports/s7comm.txt 2>&1 || true
          ixf use scanners/ics/opcua_discovery set target "$TARGET" run > reports/opcua.txt 2>&1 || true

      - name: Executar assessment de conformidade
        run: |
          ixf assess iec62443/zone_conduit_audit > reports/iec62443.txt 2>&1 || true
          ixf assess nist_sp800_82/control_checklist > reports/nist.txt 2>&1 || true
          ixf assess risk/ics_risk_scorer > reports/risk.txt 2>&1 || true

      - name: Executar varredura MITRE Discovery
        env:
          TARGET: ${{ github.event.inputs.target || '10.0.0.0/24' }}
        run: |
          ixf mitre-scan discovery "$TARGET" > reports/mitre_discovery.txt 2>&1 || true

      - name: Salvar relatórios como artefatos
        uses: actions/upload-artifact@v4
        with:
          name: ixf-ot-assessment-${{ github.run_number }}
          path: |
            reports/
            .tmp/ixf_mitre_*.json
          retention-days: 30

      - name: Verificar achados críticos
        run: |
          CRITICAL=$(grep -rh "CRITICAL\|CATASTROPHIC" reports/ | wc -l)
          echo "Achados críticos: $CRITICAL"
          if [ "$CRITICAL" -gt 10 ]; then
            echo "::warning::$CRITICAL achados críticos encontrados. Revisar relatórios."
          fi

      - name: Notificar equipe (falha em caso de achados críticos)
        if: failure()
        run: |
          echo "Assessment OT detectou problemas críticos"
          echo "Verificar artefatos em: $GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"
```

---

## Códigos de Saída

| Código | Significado | Quando ocorre |
|--------|-------------|---------------|
| `0` | Sucesso | Todos os comandos executaram sem erro |
| `1` | Erro geral | Exceção não tratada, erro de importação de módulo |
| `2` | Erro de argumento | Argumento de linha de comando inválido |
| `3` | Módulo não encontrado | `use caminho/invalido` — módulo não existe |
| `4` | Opção inválida | `set opcao valor_invalido` — validação de tipo falhou |
| `5` | Alvo não acessível | `check` retornou False |
| `6` | Operação abortada | Operação destrutiva abortada pelo usuário |
| `7` | LLM não configurado | `sast` executado sem provedor LLM |
| `8` | Permissão negada | Arquivo de log de auditoria não gravável |

**Verificando código de saída em scripts:**

```bash
ixf use cve/malware/frostygoop_modbus_heating set target 192.168.1.100 check
EXIT_CODE=$?

case $EXIT_CODE in
  0) echo "Módulo executou com sucesso" ;;
  3) echo "Módulo não encontrado" ;;
  5) echo "Alvo não acessível" ;;
  *) echo "Código de saída: $EXIT_CODE" ;;
esac
```

---

## Saída JSON com `jq`

```bash
# Gerar relatório JSON e processar com jq
ixf mitre-report json
cat .tmp/ixf_mitre_report_*.json | jq '.techniques | length'

# Extrair técnicas com mais de 10 módulos
cat .tmp/ixf_mitre_report_*.json | jq '[.techniques[] | select(.module_count > 10) | {id: .technique_id, nome: .name, modulos: .module_count}]'

# Obter cobertura por tática
cat .tmp/ixf_mitre_report_*.json | jq '.tactics | to_entries[] | {tática: .key, cobertura: .value.coverage_pct}'

# Filtrar módulos CATASTROPHIC
ixf report json
cat .tmp/ixf_report_*.json | jq '[.modules[] | select(.impact == "CATASTROPHIC") | {caminho: .path, nome: .name}]'
```

---

*Anterior: [Desenvolvimento de Módulos](09-desenvolvimento-modulos.md) | Próximo: [PolyExploit Runner](11-poly-exploit-runner.md)*
