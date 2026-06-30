# IXF Incorporation Playbook

Pipeline faseado para incorporar ferramentas e corpus ICS/malware no IndustrialXPL-Forge.

## Política de licença

| Upstream | Decisão |
|----------|---------|
| MIT / Apache-2 / BSD | Reimplementar ou adaptar com NOTICE em `industrialxpl/` |
| GPL (lib60870, ICSSploit, ICSSecurityScripts) | **REFERENCE_ONLY** — spec de comportamento, sem código no wheel |
| Binários malware originais | **SKIP** — apenas hashes, YARA, análise |

## O que NÃO commitar

- `.ixf/` (cross-compilers)
- Runtime DB Lisa em `data/db/*`
- PDFs binários de estudo (só `excerpt` em `studies/*.json`)
- Credenciais, `.env`, samples malware executáveis

## Pre-Gate (antes de codar)

1. `LicenseAudit` — SPDX do upstream
2. `DepsAudit` — novo extra em `pyproject.toml` se necessário
3. `docs/incorporation/Fx-{slug}.md` — parity spec (1 página)
4. `tools/env_doctor.py` — Tier 2/3 do extra

## Post-Gate (antes de merge)

```bash
cd IndustrialXPL-Forge
PYTHONPATH=. python3 tools/env_doctor.py
PYTHONPATH=. python3 tools/verify_family_matrix.py
PYTHONPATH=. python3 tools/verify_incorporation_gate.py --phase Fx
PYTHONPATH=. python3 tools/test_e2e_lab.py --skip-lisa
```

Double-check manual:

- Diff sem secrets
- `--simulate` default em módulos ofensivos
- `CHANGELOG.md` + bump `pyproject.toml` / `interpreter.py`

## Fases de gate

| Fase | Comando | Critério |
|------|---------|----------|
| F00 | `--phase F00` | Infra gates + matriz legada |
| F-AIM0 | `--phase F-AIM0` | Ingest + deep study ≥75% fetch OK |
| F-AIM1 | `--phase F-AIM1` | IOC ≥50 hashes + forensics smoke |
| F01+ | `--phase F01` | Por bloco do roadmap |

Config: [`tools/incorporation_gates.json`](../tools/incorporation_gates.json)

## awesome-ics-malware

```bash
PYTHONPATH=. python3 tools/ingest_awesome_ics_malware.py
PYTHONPATH=. python3 tools/deep_study_external.py
PYTHONPATH=. python3 tools/score_incorporation.py
```

Saídas:

- `industrialxpl/resources/research/awesome-ics-malware/manifest.json`
- `industrialxpl/resources/research/awesome-ics-malware/studies/*.json`
- `industrialxpl/resources/ioc/awesome-ics-malware-hashes.json`

## Extras PyPI (acumulativo)

| Extra | Fase |
|-------|------|
| `forensics` | F-AIM1 |
| `fuzzing` | F01 |
| `ot-scan` | F02 |
| `bacnet-lab` | F05 |
| `detection-lab` | F10 |
| `mozi-lab` | F08 |
| `full` | união de todos |
