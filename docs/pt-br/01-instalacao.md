# Instalação

Este documento cobre todos os métodos de instalação do IndustrialXPL-Forge (IXF), requisitos de sistema, dependências opcionais, notas por plataforma e procedimentos de verificação e desinstalação.

---

## Sumário

- [Requisitos do Sistema](#requisitos-do-sistema)
- [Instalação via PyPI (Recomendado)](#instalação-via-pypi-recomendado)
- [Instalação a Partir do Código-Fonte](#instalação-a-partir-do-código-fonte)
- [Instalação em Ambiente Virtual](#instalação-em-ambiente-virtual)
- [Extras de Dependências Opcionais](#extras-de-dependências-opcionais)
  - [Tier 0 — Biblioteca Padrão do Python](#tier-0--biblioteca-padrão-do-python-sempre-disponível)
  - [Tier 1 — Dependências pip principais](#tier-1--dependências-pip-principais-instaladas-automaticamente)
  - [Tier 2 — Extras pip opcionais](#tier-2--extras-pip-opcionais)
  - [Tier 3 — Runtimes externos](#tier-3--runtimes-externos-totalmente-opcionais)
- [Notas por Plataforma](#notas-por-plataforma)
  - [Windows](#windows)
  - [Linux](#linux--debian-ubuntu-kali-parrot)
  - [macOS](#macos)
  - [Kali Linux / Parrot OS](#kali-linux--parrot-os-pentest-distributions)
  - [Docker](#docker)
- [Verificando a Instalação](#verificando-a-instalação)
- [Diagnóstico com env_doctor.py](#diagnóstico-com-env_doctorpy)
- [Solução de Problemas Comuns](#solução-de-problemas-comuns)
- [Atualização](#atualização)
- [Desinstalar](#desinstalar)
- [Gerenciamento de Arquivos de Sessão](#gerenciamento-de-arquivos-de-sessão)

---

## Requisitos do Sistema

### Versões Python Suportadas

| Versão Python | Status | Notas |
|---------------|--------|-------|
| 3.9 | Suportado | Mínimo absoluto |
| 3.10 | Suportado | Estável |
| 3.11 | Recomendado | Melhor desempenho |
| 3.12 | Recomendado | Totalmente testado |
| 3.13 | Suportado | Testado em CI |

Versões anteriores ao Python 3.9 **não são suportadas**. Recursos de tipagem e sintaxe usados no IXF requerem Python 3.9+.

### Recursos de Hardware

| Recurso | Mínimo | Recomendado | Análise SAST LLM |
|---------|--------|-------------|-----------------|
| CPU | 1 núcleo | 2+ núcleos | 2+ núcleos |
| RAM | 256 MB | 512 MB | 1 GB |
| Disco | 150 MB | 500 MB | 1 GB (com artefatos de malware compilados) |
| Rede | Acesso à rede local | Interface dedicada OT | N/A (SAST é offline) |

### Sistemas Operacionais Testados

| SO | Versão | Arquitetura | Status |
|----|--------|-------------|--------|
| Ubuntu | 22.04, 24.04 | x86_64, ARM64 | Totalmente suportado |
| Debian | 11, 12 | x86_64 | Totalmente suportado |
| Kali Linux | 2024.x, 2025.x | x86_64 | Totalmente suportado |
| Parrot OS | 6.x | x86_64 | Totalmente suportado |
| Windows | 10, 11 | x86_64 | Totalmente suportado |
| macOS | 11+ (Big Sur) | x86_64, Apple Silicon | Totalmente suportado |
| RHEL / CentOS Stream | 9+ | x86_64 | Suportado |
| Alpine Linux | 3.18+ | x86_64 | Suportado (Docker) |

---

## Instalação via PyPI (Recomendado)

A instalação mais simples e rápida. Instala automaticamente todas as dependências do Tier 1.

```bash

        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    
```

Após a instalação, o comando CLI `ixf` estará disponível globalmente no seu `PATH`:

```bash
ixf
```

Saída esperada na primeira execução:

```
[*] Indexing modules…
[+] 976 modules indexed.

  ___           _           _       _  __  ______  _       ______
 |_ _|_ __   __| |_   _ ___| |_ _ __(_) \ \/ / _ \| |     |  ___|__  _ __ __ _  ___
  | || '_ \ / _` | | | / __| __| '__| |  \  /|  __/| |     | |_ / _ \| '__/ _` |/ _ \
  | || | | | (_| | |_| \__ \ |_| |  | |  /  \| |   | |___  |  _| (_) | | | (_| |  __/
 |___|_| |_|\__,_|\__,_|___/\__|_|  |_| /_/\_\_|   |_____| |_|  \___/|_|  \__, |\___|
                                                                              |___/
  IndustrialXPL-Forge v1.0.12 — OT/ICS/SCADA Security Assessment Framework
  Author: André Henrique (@mrhenrike) | União Geek | https://uniaogeek.com.br/
  Python-First. Pure Python — install with 
        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    .
  Type 'help' for commands.  simulate=True by default (safe mode).

ixf >
```

### Instalação com pip3 explícito

Em sistemas onde `pip` aponta para Python 2 (sistemas legados):

```bash
pip3 install industrialxpl-forge
```

### Instalação com python -m pip (mais seguro)

Garante que o pacote é instalado para o interpretador Python correto:

```bash
python -m 
        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    
python3 -m 
        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    
```

---

## Instalação a Partir do Código-Fonte

Para desenvolvedores, contribuidores ou usuários que precisam da versão mais recente do repositório.

### Clonar o Repositório

```bash
git clone https://github.com/mrhenrike/IndustrialXPL-Forge.git
cd IndustrialXPL-Forge
```

### Instalar Dependências

```bash
pip install -r requirements.txt
```

### Executar Diretamente

```bash
python ixf.py
```

Ou usando o módulo Python:

```bash
python -m industrialxpl
```

### Instalação em Modo de Desenvolvimento

Para desenvolvimento ativo do framework, use modo editável (`-e`). Inclui ferramentas de teste, lint e análise de código:

```bash
pip install -e ".[dev]"
```

Isso instala adicionalmente:
- `pytest` — framework de testes
- `pytest-cov` — cobertura de código
- `ruff` — linter/formatter rápido
- `mypy` — verificação de tipos estáticos
- `pre-commit` — hooks de git pré-commit

### Instalação Completa com Todos os Extras

Para laboratórios que necessitam de cobertura completa de protocolo OT, análise LLM e suporte a barramento de campo:

```bash
pip install -e ".[full]"
```

---

## Instalação em Ambiente Virtual

Altamente recomendado para isolar dependências do IXF do Python do sistema.

### Com venv (built-in do Python)

```bash
# Criar ambiente virtual
python3 -m venv ixf-env

# Ativar (Linux/macOS)
source ixf-env/bin/activate

# Ativar (Windows PowerShell)
.\ixf-env\Scripts\Activate.ps1

# Ativar (Windows CMD)
ixf-env\Scripts\activate.bat

# Instalar IXF no ambiente virtual

        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    

# Verificar instalação
ixf
```

### Com conda / miniforge

```bash
# Criar ambiente conda com Python 3.11
conda create -n ixf python=3.11 -y
conda activate ixf

        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    
ixf
```

### Com pipx (instalação isolada com CLI global)

`pipx` instala a CLI em um ambiente virtual isolado mas torna `ixf` disponível globalmente:

```bash
pip install pipx
pipx install industrialxpl-forge
ixf
```

### Com poetry (para projetos que usam IXF como dependência)

```bash
poetry add industrialxpl-forge
poetry run ixf
```

---

## Extras de Dependências Opcionais

O IXF segue um **modelo de dependências em tiers**. A instalação básica via `
        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    ` cobre automaticamente os Tiers 0 e 1.

### Tier 0 — Biblioteca Padrão do Python (sempre disponível)

Módulos da biblioteca padrão do Python usados pelo IXF. Nenhuma instalação adicional necessária — estão disponíveis em qualquer instalação Python.

| Módulo stdlib | Uso no IXF |
|---------------|-----------|
| `socket` | Conexões TCP/UDP brutas para protocolos OT |
| `struct` | Empacotamento/desempacotamento de frames binários (Modbus, S7, DNP3) |
| `select` | I/O assíncrono em varreduras multi-socket |
| `subprocess` | Execução de runtimes externos (C, Go, Java) |
| `threading` | Módulos de varredura paralela |
| `pathlib` | Operações de caminho seguro e portável |
| `json` | Serialização de resultados de assessment |
| `re` | Análise de padrões em respostas de protocolo |
| `os` | Operações de sistema de arquivos |
| `hashlib` | Hashing para integridade de módulo |
| `base64` | Codificação de payloads |
| `ssl` | Comunicação TLS (OPC UA, S7comm+) |
| `logging` | Sistema de log estruturado do framework |
| `datetime` | Carimbos de tempo em logs de auditoria |
| `collections` | Estruturas de dados para indexação de módulos |
| `typing` | Anotações de tipo estático |
| `abc` | Classes base abstratas para a hierarquia de módulos |
| `functools` | Decoradores `@mute`, `@multi` |

### Tier 1 — Dependências pip principais (instaladas automaticamente)

Instaladas automaticamente com `
        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    `.

| Pacote | Versão Mínima | Versão Máxima | Uso no IXF |
|--------|---------------|---------------|-----------|
| `requests` | >=2.31.0 | <3.0 | Módulos de exploração HTTP/REST para IHMs web, OPC UA REST, APIs SCADA |
| `urllib3` | >=1.26.0 | <3.0 | Transporte HTTP subjacente |
| `paramiko` | >=3.0 | — | Teste de credenciais SSH padrão (Cisco, Juniper, dispositivos OT com SSH) |
| `pysnmp` | >=6.1 | — | Scanner SNMP, enumeração de MIB, leitura de community strings padrão |
| `scapy` | >=2.5 | — | Criação de pacotes raw (ataques Camada 2/3, PROFINET DCP, GOOSE, MMS) |
| `rich` | >=13.0 | — | Tabelas de terminal, código de cores, banners, saída formatada |
| `psutil` | >=5.9 | — | Informações de processo e sistema para diagnósticos |
| `pyreadline3` | >=3.4 | — | **Somente Windows** — histórico de comandos e Tab-completion no shell IXF |

### Tier 2 — Extras pip opcionais

Instalados explicitamente com extras do pacote. Cada extra adiciona suporte a categorias específicas de protocolo ou funcionalidade.

#### Extra `[ot]` — Bibliotecas de protocolo OT/ICS

```bash

        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    
```

Instala:
- `pymodbus` — cliente/servidor Modbus TCP e RTU. Suporta Modbus TCP (502), Modbus RTU sobre serial e Modbus RTU sobre TCP
- `asyncua` — pilha OPC UA completa com suporte a Security Mode, certificados e namespaces
- `cpppo` — Ethernet/IP e CIP para Rockwell ControlLogix, CompactLogix e Micro820

Uso típico:
```
# Com pymodbus disponível, módulos Modbus usam a pilha completa em vez de sockets raw
ixf > use exploits/protocols/modbus/modbus_client
# Nota: a pilha raw socket (Tier 0) é sempre o fallback
```

#### Extra `[fieldbus]` — Barramento de campo industrial

```bash

        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    
```

Instala:
- `python-can` — interface CAN bus para ataques CANopen, CANopen DS402, J1939

Requer hardware CAN ou adaptador USB-CAN (SocketCAN, Peak PCAN, Kvaser, etc.).

#### Extra `[sast]` — Análise LLM para SAST

```bash

        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    
```

Instala:
- `openai` — cliente oficial OpenAI (GPT-4o, GPT-4 Turbo)
- `anthropic` — cliente Anthropic (Claude Sonnet, Haiku)

O IXF também suporta Google Gemini via `requests` (já no Tier 1) e DeepSeek/Grok via REST direto.

#### Extra `[full]` — Tudo

```bash

        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    
```

Equivalente a `[ot]` + `[fieldbus]` + `[sast]`. Instala todas as dependências opcionais.

### Tier 3 — Runtimes externos (totalmente opcionais)

O IXF sempre possui **fallback Python puro** quando runtimes externos estão ausentes. Runtimes do Tier 3 são usados apenas para compilar e executar artefatos nativos (malware ICS de réplica, exploits nativos compilados).

| Runtime | Versão Mínima | Uso no IXF | Instalação |
|---------|---------------|-----------|------------|
| `gcc` | 9.0+ | Compilar KillDisk (C), flood Modbus DoS nativo | `sudo apt install gcc` |
| `g++` | 9.0+ | Compilar NotPetya wiper (C++), bypass watchdog S7 | `sudo apt install g++` |
| `go` | 1.20+ | Compilar FrostyGoop estendido (Go) | https://go.dev/dl/ |
| `node` / `npm` | 18.0+ | Módulos JavaScript/TypeScript | https://nodejs.org/ |
| `java` / `javac` | 11+ | Exploits de desserialização Java (MES, aplicações JMX) | https://adoptium.net/ |
| `ruby` | 3.0+ | Módulos Ruby herdados | https://www.ruby-lang.org/ |
| `pwsh` | 7.2+ | Módulos de exploração OT/EWS PowerShell | https://github.com/PowerShell/PowerShell |
| `perl` | 5.30+ | Scripts ICS legados | Gerenciador de pacotes do SO |
| `nmap` | 7.80+ | Execução de scripts NSE IXF | https://nmap.org/download |

#### Verificar disponibilidade de runtimes

```bash
python tools/env_doctor.py
```

Saída de exemplo com runtimes parcialmente disponíveis:

```
[Python]
  Python 3.11.9  OK

[Tier 1 — Required pip]
  requests     2.32.4   OK
  paramiko     3.5.1    OK
  scapy        2.5.0    OK
  rich         13.9.4   OK
  psutil       6.1.0    OK
  pysnmp       6.2.1    OK

[Tier 2 — Optional pip (OT)]
  pymodbus     3.7.4    OK
  asyncua      1.1.5    OK
  cpppo        4.1.0    OK

[Tier 2 — Optional pip (SAST)]
  openai       1.35.0   OK
  anthropic    0.28.0   OK

[Tier 3 — External runtimes]
  gcc          13.2.0   OK
  g++          13.2.0   OK
  go           go1.22.4 OK
  node         v20.14.0 OK
  java         17.0.9   OK
  ruby         not found  OPTIONAL
  pwsh         not found  OPTIONAL
  perl         5.36.0   OK
  nmap         7.94     OK

[IXF Module Index]
  976 módulos indexados.
```

---

## Notas por Plataforma

### Windows

#### Suporte a readline / histórico de comandos

No Windows, `readline` não faz parte da biblioteca padrão. O IXF instala automaticamente `pyreadline3` quando `sys.platform == 'win32'`. Isso fornece:
- Histórico de comandos (teclas seta cima/baixo)
- Tab-completion de comandos e caminhos de módulo
- Suporte a Ctrl+A, Ctrl+E para navegação de cursor

Se você encontrar:

```
AttributeError: 'NoneType' object has no attribute 'write_history_file'
```

Atualize para a versão mais recente:

```bash
pip install --upgrade industrialxpl-forge
```

#### Execução de scripts Nmap NSE no Windows

Para usar o comando `nse install` no Windows com Nmap instalado em `C:\Program Files\Nmap\`:

Execute o PowerShell ou Prompt de Comando como **Administrador**, depois:

```powershell
ixf
ixf > nse install
```

Ou use a ferramenta autônoma:

```powershell
python tools/nse_install.py --install
```

#### Scapy no Windows

Scapy no Windows requer:
1. [Npcap](https://npcap.com/) (recomendado) ou WinPcap instalado
2. Python rodando como Administrador para criação de sockets raw

Para operação sem privilégios (sem Scapy), os módulos que necessitam de sockets raw usarão automaticamente fallbacks TCP/UDP de socket padrão.

#### Caminhos de arquivo no Windows

O IXF usa `pathlib.Path` internamente, então tanto barras invertidas quanto barras normais funcionam:

```
ixf > sast C:\plc_projects\water_treatment\
ixf > sast C:/plc_projects/water_treatment/
```

#### Codificação de terminal no Windows

Para saída de caracteres Unicode correta (banners, tabelas rich):

```powershell
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001
```

Ou defina permanentemente no PowerShell profile:

```powershell
$OutputEncoding = [System.Text.Encoding]::UTF8
```

### Linux / Debian, Ubuntu, Kali, Parrot

#### Instalação do sistema

```bash
# Atualizar índice de pacotes
sudo apt update

# Python 3 e pip (se não estiverem instalados)
sudo apt install python3 python3-pip python3-venv -y

# Dependências para Scapy (sockets raw)
sudo apt install libpcap-dev tcpdump -y

# Instalar IXF
pip3 install industrialxpl-forge
```

#### Sockets raw no Linux

Módulos que enviam frames de Camada 2 raw (PROFINET DCP, IEC 61850 GOOSE, EtherCAT) requerem privilégios de socket raw. Execute com sudo ou configure `CAP_NET_RAW`:

```bash
# Opção 1: Executar com sudo (simples, laboratório)
sudo ixf

# Opção 2: Dar CAP_NET_RAW ao Python (sem sudo completo)
sudo setcap cap_net_raw+ep $(which python3)
ixf
```

#### Instalação via pipx no Linux

```bash
sudo apt install pipx
pipx install industrialxpl-forge
pipx ensurepath
source ~/.bashrc
ixf
```

### Linux / Debian, Ubuntu, Kali, Parrot

Para distribuições baseadas em RHEL (CentOS Stream, Rocky Linux, AlmaLinux):

```bash
sudo dnf install python3 python3-pip libpcap-devel -y
pip3 install industrialxpl-forge
```

Para Arch Linux / Manjaro:

```bash
sudo pacman -S python python-pip libpcap

        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    
```

### macOS

#### Instalação com Homebrew (recomendado)

```bash
# Instalar Python 3 via Homebrew
brew install python@3.11

# Instalar IXF
pip3 install industrialxpl-forge

# Verificar
ixf
```

#### Apple Silicon (M1/M2/M3)

O IXF funciona nativamente em Apple Silicon. Scapy pode exigir instalação adicional via brew:

```bash
brew install libpcap
pip3 install industrialxpl-forge
```

#### Permissões de socket raw no macOS

macOS requer sudo para sockets raw com Scapy. Para operação sem privilégios, módulos baseados em socket TCP/UDP funcionam normalmente sem sudo.

```bash
# Para módulos que precisam de sockets raw (ex.: PROFINET DCP Layer 2):
sudo ixf
```

### Kali Linux / Parrot OS (Pentest Distributions)

Kali e Parrot são distribuições de pentest preferidas para uso do IXF. Scapy e outras ferramentas de rede já vêm pré-instaladas.

```bash
# Kali / Parrot — Python3 e pip já disponíveis

        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    

# Ou em ambiente virtual (para isolar de pacotes do sistema Kali)
python3 -m venv ~/ixf-env
source ~/ixf-env/bin/activate

        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    
ixf
```

### Docker

Para uso em contêiner, isolamento de laboratório ou CI/CD:

#### Usando a imagem base Python

```dockerfile
FROM python:3.11-slim

RUN 
        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    

# Para módulos que precisam de ferramentas de rede
RUN apt-get update && apt-get install -y nmap libpcap-dev && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["ixf"]
```

#### Construir e executar

```bash
docker build -t ixf .
docker run -it --rm --net=host ixf
```

> **Nota de segurança:** `--net=host` dá ao contêiner acesso à rede do host. Use em laboratórios isolados. Em produção, use redes Docker específicas com controles de acesso.

#### Docker Compose para laboratório OT

```yaml
version: "3.8"
services:
  ixf:
    image: python:3.11-slim
    command: bash -c "
        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
     && ixf"
    stdin_open: true
    tty: true
    network_mode: host
    volumes:
      - ./resultados:/app/resultados
```

---

## Verificando a Instalação

### Verificação básica

```bash
ixf
```

O banner deve exibir a versão e a contagem de módulos. Se o shell IXF abre com o prompt `ixf >`, a instalação está correta.

### Verificar versão instalada

```bash
python -c "import industrialxpl; print(industrialxpl.__version__)"
```

Saída esperada:
```
1.0.12
```

### Verificar se o comando ixf está no PATH

```bash
# Linux/macOS
which ixf
# /home/user/.local/bin/ixf

# Windows PowerShell
Get-Command ixf
# C:\Users\User\AppData\Local\Programs\Python\Python311\Scripts\ixf.exe
```

### Verificação rápida de saúde

Execute diretamente dentro do shell IXF:

```
ixf > stats
```

Saída esperada:

```
  IXF Module Statistics
  ─────────────────────────────────────────────────────
  Category          Count    %
  cve                 412    42%
  exploits            287    29%
  scanners             98    10%
  assessment           89     9%
  creds                62     6%
  ...
  ─────────────────────────────────────────────────────
  Total: 976 módulos

  Vendors covered: 150 | Malware TTPs: 26
  MITRE ATT&CK for ICS: 12 táticas, 103 técnicas mapeadas
  PyPI: 
        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
     | GitHub: github.com/mrhenrike/IndustrialXPL-Forge
```

---

## Diagnóstico com env_doctor.py

A ferramenta `env_doctor.py` verifica o ambiente Python, todas as dependências e runtimes externos.

```bash
python tools/env_doctor.py
```

### Opções disponíveis

```bash
# Verificação completa (padrão)
python tools/env_doctor.py

# Mostrar apenas erros
python tools/env_doctor.py --errors-only

# Saída em formato JSON (para integração CI/CD)
python tools/env_doctor.py --json

# Verificar apenas runtimes externos (Tier 3)
python tools/env_doctor.py --tier3

# Verificar instalação de scripts NSE Nmap
python tools/env_doctor.py --nse
```

### Saída completa de exemplo

```
═══════════════════════════════════════════════════════════
  IndustrialXPL-Forge — Environment Doctor
  Verificando pré-requisitos e dependências...
═══════════════════════════════════════════════════════════

[Python]
  Python 3.11.9 (main, Apr 20 2024) [GCC 11.4.0]  OK
  Platform: Linux-6.8.0-kali1-amd64-x86_64-with-glibc2.38

[Tier 1 — Required pip packages]
  requests       2.32.4    OK   (requerido: >=2.31.0,<3.0)
  urllib3        2.3.0     OK
  paramiko       3.5.1     OK
  pysnmp         6.2.1     OK
  scapy          2.5.0     OK
  rich           13.9.4    OK
  psutil         6.1.0     OK

[Tier 2 — Optional pip: OT protocols]
  pymodbus       3.7.4     OK
  asyncua        1.1.5     OK
  cpppo          4.1.0     OK

[Tier 2 — Optional pip: SAST/LLM]
  openai         1.35.0    OK
  anthropic      0.28.0    OK

[Tier 3 — External runtimes]
  gcc            13.2.0    OK    /usr/bin/gcc
  g++            13.2.0    OK    /usr/bin/g++
  go             1.22.4    OK    /usr/local/go/bin/go
  node           20.14.0   OK    /usr/bin/node
  java           17.0.9    OK    /usr/bin/java
  nmap           7.94      OK    /usr/bin/nmap
  ruby                     MISSING  OPTIONAL — fallback Python disponível
  pwsh                     MISSING  OPTIONAL — fallback Python disponível
  perl           5.36.0    OK

[NSE Scripts]
  IXF NSE scripts dir: /usr/share/industrialxpl_forge/nse/
  Scripts disponíveis: 8
  Scripts instalados no Nmap: 8 (em /usr/share/nmap/scripts/)

[IXF Module Index]
  976 módulos indexados  OK

═══════════════════════════════════════════════════════════
  Resultado: OK (0 erros, 2 avisos — runtimes opcionais ausentes)
═══════════════════════════════════════════════════════════
```

---

## Solução de Problemas Comuns

### Erro: `ixf: command not found`

**Causa:** O diretório Scripts/bin do pip não está no `PATH`.

**Solução:**

Linux/macOS:
```bash
export PATH="$HOME/.local/bin:$PATH"
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

Windows:
```powershell
# Adicionar ao PATH do usuário
$userBin = "$env:APPDATA\..\Local\Programs\Python\Python311\Scripts"
[Environment]::SetEnvironmentVariable("PATH", "$env:PATH;$userBin", "User")
```

### Erro: `ModuleNotFoundError: No module named 'industrialxpl'`

**Causa:** IXF instalado em ambiente virtual diferente do Python atual.

**Solução:**
```bash
# Verificar qual Python está ativo
which python3
python3 -m pip show industrialxpl-forge

# Se não encontrado, reinstalar no Python atual
python3 -m 
        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    
```

### Erro: `ImportError: cannot import name 'scapy'`

**Causa:** Scapy não instalado ou instalado incorretamente.

**Solução:**
```bash
pip install --upgrade scapy
# Linux: pode precisar de libpcap
sudo apt install libpcap-dev
```

### Erro: `PermissionError: [Errno 1] Operation not permitted` em sockets raw

**Causa:** Módulos que precisam de sockets raw (Layer 2) sem privilégios.

**Solução:**
```bash
# Opção 1
sudo ixf

# Opção 2 (mais permanente, Linux)
sudo setcap cap_net_raw+ep $(which python3)
ixf
```

### Erro: `AttributeError: 'NoneType' object has no attribute 'write_history_file'` (Windows)

**Causa:** Versão desatualizada do IXF com bug no pyreadline3 no Windows.

**Solução:**
```bash
pip install --upgrade industrialxpl-forge
```

### Erro: `pip install` falha com conflito de dependências

**Causa:** Conflitos com pacotes existentes no ambiente Python.

**Solução:**
```bash
# Instalar em ambiente virtual limpo
python3 -m venv ixf-clean-env
source ixf-clean-env/bin/activate  # Linux/macOS
# ou: ixf-clean-env\Scripts\activate  (Windows)

        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    
```

### Erro: `No modules found` ao executar `search`

**Causa:** Indexação de módulos falhou silenciosamente, geralmente por importação defeituosa de um módulo.

**Diagnóstico:**
```bash
python -c "
from industrialxpl.core.exploit.utils import index_modules, import_exploit
mods = index_modules()
print(f'{len(mods)} módulos indexados')
"
```

### Shell IXF não inicia (trava em `Indexing modules…`)

**Causa:** Dependência ausente causando ImportError silencioso na indexação.

**Diagnóstico:**
```bash
python tools/env_doctor.py
# Verificar erros de Tier 1 — todas devem estar OK
```

---

## Atualização

### Atualizar para a versão mais recente via PyPI

```bash
pip install --upgrade industrialxpl-forge
```

### Verificar versão atual antes de atualizar

```bash
pip show industrialxpl-forge
```

Saída:
```
Name: industrialxpl-forge
Version: 1.0.11
Summary: OT/ICS/SCADA Security Assessment Framework
Home-page: https://github.com/mrhenrike/IndustrialXPL-Forge
Author: André Henrique
...
```

### Atualizar código-fonte (instalação do repositório)

```bash
cd IndustrialXPL-Forge
git pull origin main
pip install -e ".[dev]"
```

### Verificar mudanças antes de atualizar

Consulte o [CHANGELOG no GitHub](https://github.com/mrhenrike/IndustrialXPL-Forge/releases) antes de atualizar em ambientes de produção ou laboratórios críticos.

---

## Desinstalar

```bash
pip uninstall industrialxpl-forge -y
```

### O que o pip NÃO remove

Os seguintes arquivos são armazenados localmente e **não são removidos** pelo pip uninstall:

| Arquivo/Diretório | Localização | Conteúdo |
|-------------------|-------------|---------|
| `.ixf_history` | `~/.ixf_history` | Histórico de comandos do shell IXF |
| `industrialxpl.log` | `./industrialxpl.log` | Log rotativo de sessão atual |
| `.log/destructive_ops_*.log` | `./.log/` | Logs de auditoria de operações destrutivas |
| `.tmp/malware_builds/` | `./.tmp/malware_builds/` | Artefatos compilados pelo Malware Builder |

Para remoção completa:

```bash
pip uninstall industrialxpl-forge -y
rm -f ~/.ixf_history
rm -rf .log/ .tmp/malware_builds/
```

---

## Gerenciamento de Arquivos de Sessão

### Histórico de comandos

O IXF armazena o histórico de comandos do shell em `~/.ixf_history`. Os últimos 1.000 comandos são mantidos. O histórico é carregado automaticamente em cada nova sessão.

```bash
# Visualizar histórico
cat ~/.ixf_history

# Limpar histórico
> ~/.ixf_history  # Linux/macOS
Clear-Content ~/.ixf_history  # Windows PowerShell
```

### Logs de sessão

O IXF gera dois tipos de log:

**Log rotativo de sessão** (`industrialxpl.log`):
- Criado no diretório de trabalho atual
- Contém ações de módulo, resultados de check(), erros
- Rotacionado automaticamente em 10 MB

**Log de auditoria destrutivo** (`.log/destructive_ops_YYYY-MM-DD.log`):
- Uma entrada por operação destrutiva (confirmada ou abortada)
- Imutável (apenas append)
- Inclui: timestamp UTC, status (CONFIRMED/ABORTED), módulo, alvo, nível de impacto

Exemplo de entrada de log de auditoria:
```
2026-06-01T20:15:43Z | CONFIRMED | module=cve.malware.frostygoop_modbus_heating | target=192.168.1.100:502 | impact=CATASTROPHIC | user=lab-operator
2026-06-01T20:16:01Z | ABORTED   | module=cve.malware.industroyer_crashoverride | target=192.168.1.200:2404 | impact=CATASTROPHIC | user=lab-operator
```

---

*Próximo: [Início Rápido](02-inicio-rapido.md)*
