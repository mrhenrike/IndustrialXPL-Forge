# IndustrialXPL-Forge — Documentação

> **O Maior Framework de Assessment e Exploração de Segurança OT/ICS/SCADA do Mundo**

[![PyPI](https://img.shields.io/pypi/v/industrialxpl-forge?color=red&label=PyPI)](https://pypi.org/project/industrialxpl-forge/)
[![Python](https://img.shields.io/pypi/pyversions/industrialxpl-forge?color=blue&label=Python)](https://pypi.org/project/industrialxpl-forge/)
[![Licença: MIT](https://img.shields.io/badge/Licen%C3%A7a-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Módulos](https://img.shields.io/badge/M%C3%B3dulos-1190%2B-brightgreen)](https://github.com/mrhenrike/IndustrialXPL-Forge)

---

## Índice

| # | Documento | Descrição |
|---|-----------|-----------|
| 1 | [Instalação](01-instalacao.md) | Requisitos, pip install, instalação por fonte, tiers de dependência |
| 2 | [Início Rápido](02-inicio-rapido.md) | Sessão de terminal completa e anotada, do lançamento ao primeiro exploit |
| 3 | [Referência do Shell](03-referencia-shell.md) | Todos os 35 comandos com sintaxe, tipos de argumento e exemplos de I/O |
| 4 | [Sistema de Módulos](04-sistema-modulos.md) | Anatomia do módulo, chaves `__info__`, todos os 10 tipos `OptXxx` |
| 5 | [SafeMode / DestructiveMode](05-safemode-destructivemode.md) | Níveis de impacto, fluxo de confirmação, log de auditoria |
| 6 | [MITRE ATT&CK for ICS](06-mitre-attack-ics.md) | `ttp`, `mitre-scan`, `mitre-coverage`, exportação de layer Navigator |
| 7 | [SAST / Análise LLM](07-sast-llm.md) | Análise offline de código PLC, provedores, sanitização, modos |
| 8 | [Protocolos e Vendors](08-protocolos-vendors.md) | 50 protocolos com portas, 150+ vendors por região |
| 9 | [Desenvolvimento de Módulos](09-desenvolvimento-modulos.md) | Escrevendo novos módulos: template, convenções, validação |
| 10 | [CLI Não-Interativo](10-cli-nao-interativo.md) | Uso em uma linha, pipes, integração CI/CD |
| 11 | [PolyExploit Runner](11-poly-exploit-runner.md) | Runtimes C/C++/Go/Ruby, compilação, malware builder |
| 12 | [Assessment e Conformidade](12-assessment-conformidade.md) | IEC 62443, NIST 800-82r3, MITRE ICS, scoring de risco, IR playbook |

---

## Versão en-US

A documentação em inglês está disponível em [../en-us/](_index.md).

---

## Sobre o IXF

O IndustrialXPL-Forge (IXF) é um framework Python modular para assessment de segurança e exploração de ambientes de **Tecnologia Operacional (OT)**, **Sistemas de Controle Industrial (ICS)**, **SCADA**, **IHM (HMI)**, **CLP (PLC)**, **RTU**, **DCS** e **IIoT**.

**Princípios de design:**

- **Python-First** — toda a funcionalidade essencial roda com `
        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    `; sem ferramentas externas obrigatórias
- **SafeMode por padrão** — todo módulo começa com `simulate=True`; nenhum pacote é enviado até habilitação explícita
- **Autorize antes de agir** — projetado exclusivamente para testes autorizados, pesquisa e educação

**Números principais:**

| Métrica | Valor |
|---------|-------|
| Total de módulos | 1190+ |
| Módulos CVE | 3.300+ |
| Vendors cobertos | 150+ |
| Protocolos cobertos | 50+ |
| Técnicas MITRE ATT&CK for ICS | 96/103 (93%) |
| TTPs de malware ICS | 26 (2010–2024) |
| Linguagens PLC suportadas (SAST) | 7 |

---

*Autor: André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | [União Geek](https://uniaogeek.com.br/)*
