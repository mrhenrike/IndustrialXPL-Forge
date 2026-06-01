# Instalação

## Requisitos do Sistema

| Requisito | Mínimo | Recomendado |
|-----------|--------|-------------|
| Python | 3.9 | 3.11 ou 3.12 |
| SO | Windows 10, Linux, macOS 11 | Ubuntu 22.04 / Windows 11 |
| RAM | 256 MB | 512 MB |
| Disco | 150 MB | 500 MB (com artefatos nativos de malware) |

Versões Python testadas: **3.9, 3.10, 3.11, 3.12, 3.13**.

---

## Instalação via PyPI (Recomendado)

```bash
pip install industrialxpl-forge
```

Após a instalação o comando CLI `ixf` estará disponível globalmente:

```bash
ixf
```

Saída esperada:

```
[*] Indexing modules…
[+] 976 modules indexed.

  ___           _           _       _  __  ______  _       ______
 ...
  IndustrialXPL-Forge v1.0.12 — OT/ICS/SCADA Security Assessment Framework
  simulate=True por padrão (modo seguro).

ixf >
```

---

## Instalação a Partir do Código-Fonte

```bash
git clone https://github.com/mrhenrike/IndustrialXPL-Forge.git
cd IndustrialXPL-Forge
pip install -r requirements.txt
python ixf.py
```

Para desenvolvimento (inclui ferramentas de teste e lint):

```bash
pip install -e ".[dev]"
```

---

## Extras de Dependências Opcionais

O IXF segue um **modelo de dependências em tiers**. A instalação básica cobre os Tiers 0 e 1.

### Tier 0 — Biblioteca Padrão do Python (sempre disponível)

`socket`, `struct`, `select`, `subprocess`, `threading`, `pathlib`, `json`, `re`, `os`

Nenhuma instalação adicional necessária.

### Tier 1 — Dependências pip principais (instaladas automaticamente)

| Pacote | Versão | Uso |
|--------|--------|-----|
| `requests` | >=2.31.0,<3.0 | Módulos de exploração HTTP/REST |
| `urllib3` | >=1.26.0,<3.0 | Transporte HTTP |
| `paramiko` | >=3.0 | Teste de credenciais SSH padrão |
| `pysnmp` | >=6.1 | Scanner e enumeração SNMP |
| `scapy` | >=2.5 | Criação de pacotes (ataques Camada 2/3) |
| `rich` | >=13.0 | Tabelas de terminal, cores, banners |
| `psutil` | >=5.9 | Informações de processo e sistema |
| `pyreadline3` | >=3.4 | **Somente Windows** — histórico e tab-completion |

### Tier 2 — Extras pip opcionais

```bash
# Bibliotecas de protocolo OT/ICS
pip install industrialxpl-forge[ot]
# Instala: pymodbus (Modbus TCP/RTU), asyncua (OPC UA), cpppo (EtherNet/IP/CIP)

# Fieldbus industrial
pip install industrialxpl-forge[fieldbus]
# Instala: python-can (CAN bus / CANopen)

# SAST / Análise LLM
pip install industrialxpl-forge[sast]
# Instala: openai, anthropic

# Tudo
pip install industrialxpl-forge[full]
```

### Tier 3 — Runtimes externos (totalmente opcionais)

O IXF sempre possui **fallback Python** quando estão ausentes.

| Runtime | Uso no IXF | Instalação |
|---------|-----------|------------|
| `gcc` / `g++` | Compilar exploits nativos C/C++ (KillDisk, NotPetya) | Gerenciador de pacotes do SO |
| `go` | Compilar FrostyGoop estendido | https://go.dev/dl/ |
| `node` | Módulos JavaScript/TypeScript | https://nodejs.org/ |
| `java` / `javac` | Exploits de desserialização Java | https://adoptium.net/ |
| `ruby` | Módulos de exploit Ruby | https://www.ruby-lang.org/ |
| `pwsh` | Módulos OT PowerShell | https://github.com/PowerShell/PowerShell |
| `perl` | Scripts ICS legados | Gerenciador de pacotes do SO |

Verificar disponibilidade de runtimes:

```bash
python tools/env_doctor.py
```

---

## Notas por Plataforma

### Windows

`pyreadline3` é instalado automaticamente no Windows (`sys_platform == 'win32'`). Fornece histórico de comandos (setas cima/baixo) e Tab-completion no shell IXF.

Se você encontrar `AttributeError: 'NoneType' object has no attribute 'write_history_file'`, atualize para v1.0.12 ou posterior:

```bash
pip install --upgrade industrialxpl-forge
```

### Linux / macOS

`readline` faz parte da biblioteca padrão. Nenhuma configuração adicional necessária.

---

## Verificando a Instalação

```bash
ixf
```

O banner deve exibir a versão e a contagem de módulos. Para confirmar todas as dependências principais:

```bash
python tools/env_doctor.py
```

Saída de exemplo:

```
[Python]
  Python 3.11.9  OK

[Tier 1 — Required pip]
  requests  2.32.4   OK
  paramiko  3.5.1    OK
  scapy     2.5.0    OK
  rich      13.9.4   OK
  psutil    6.1.0    OK
  pysnmp    6.2.1    OK

[IXF Module Index]
  976 módulos indexados.
```

---

## Desinstalar

```bash
pip uninstall industrialxpl-forge
```

Logs e histórico são armazenados localmente e não são removidos pelo pip:
- `~/.ixf_history` — histórico de comandos
- `./industrialxpl.log` — log rotativo de sessão
- `./.log/destructive_ops_*.log` — logs de auditoria de operações destrutivas

---

*Próximo: [Início Rápido](02-inicio-rapido.md)*
