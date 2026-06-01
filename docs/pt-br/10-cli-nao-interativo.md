# CLI Não-Interativo

O IXF pode ser usado sem o shell interativo, passando comandos diretamente na linha de comando. Útil para scripts, automação, pipelines CI/CD e fluxos de pentest em uma linha.

---

## Sintaxe Básica

```bash
ixf <comando> [args...]
```

---

## Exemplos em Uma Linha

### Buscar e sair

```bash
ixf search modbus
ixf search CVE-2021-22681
ixf search default_creds
```

### Carregar módulo, definir opções e executar

```bash
ixf use scanners/ics/modbus_detect set target 192.168.1.100 run
```

### Verificação somente (sem exploit)

```bash
ixf use scanners/ics/modbus_detect set target 192.168.1.100 check
```

### Estatísticas

```bash
ixf stats
ixf vendors siemens
ixf protocols
ixf coverage
```

### Gerar relatório

```bash
ixf report json
ixf report html
```

---

## Opções Globais

```bash
ixf setg target 192.168.1.100 use scanners/ics/modbus_detect run use scanners/ics/s7_comm_scanner run
```

---

## Execução TTP

```bash
ixf ttp T0843 192.168.1.100
ixf ttp-list --tactic discovery
ixf mitre-coverage
ixf mitre-report layer
```

---

## Piping com Shell

```bash
# Listar todos os módulos Siemens
ixf search siemens | grep "use cve"

# Contar módulos CVE
ixf search CVE | wc -l

# Salvar resultados
ixf search modbus > modulos_modbus.txt
```

---

## Script Bash

```bash
#!/bin/bash
ALVO="192.168.1.100"

echo "[*] Executando descoberta OT IXF em $ALVO"

ixf use scanners/ics/modbus_detect set target "$ALVO" check
ixf use scanners/ics/s7_comm_scanner set target "$ALVO" check
ixf use scanners/ics/bacnet_scanner set target "$ALVO" check
ixf ttp-check T0843 "$ALVO"

echo "[*] Concluído."
```

---

## API Python

```python
from industrialxpl.core.exploit.utils import import_exploit

cls = import_exploit("industrialxpl.modules.scanners.ics.modbus_detect")
mod = cls()
mod.target = "192.168.1.100"
mod.port = 502

# Verificação somente leitura
is_vulnerable = mod.check()
print("Modbus detectado:", is_vulnerable)

# Executar em modo simulação (padrão)
mod.run()
```

---

## Integração CI/CD

```yaml
# .github/workflows/ot-scan.yml
name: OT Security Scan
on: [push]

jobs:
  ot-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install industrialxpl-forge
      - name: Verificar integridade dos módulos
        run: |
          python -c "
          from industrialxpl.core.exploit.utils import index_modules
          mods = index_modules()
          print(f'{len(mods)} módulos indexados')
          assert len(mods) > 900
          "
      - name: Cobertura MITRE
        run: ixf mitre-coverage
```

---

## Códigos de Saída

| Código | Significado |
|--------|-------------|
| `0` | Sucesso |
| `1` | Erro (falha de importação, dependência ausente) |
| `2` | Erro de validação do módulo |

---

*Anterior: [Desenvolvimento de Módulos](09-desenvolvimento-modulos.md) | Próximo: [PolyExploit Runner](11-poly-exploit-runner.md)*
