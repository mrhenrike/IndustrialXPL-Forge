# Terms of Use — IndustrialXPL-Forge

**Effective date:** 2026-06-30  
**Maintainer:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) / [União Geek](https://uniaogeek.com.br)

## 1. Acceptance

By accessing, cloning, installing, or using IndustrialXPL-Forge (IXF) — including the
public **malware** and **ics-tools** vendor corpora in `industrialxpl/resources/vendor/` —
you agree to these Terms of Use and to the [DISCLAIMER.md](DISCLAIMER.md).

If you do not agree, do not use this software or its incorporated sources.

## 2. Purpose and public research distribution

IXF and its incorporated vendor trees are **intentionally published** on GitHub (and
framework components on PyPI) to support:

- Academic and industry cybersecurity research
- Defensive engineering (detection, hunting, IR playbooks)
- Authorized penetration testing and red-team training
- Blue-team simulation and tabletop exercises

Publication does **not** grant permission to attack systems without authorization.

## 3. User responsibility (you)

**You alone** are responsible for:

- Determining whether your use is legal in your jurisdiction
- Obtaining **explicit written authorization** before testing third-party systems
- Isolating malware samples and compile outputs in lab environments
- Compliance with export-control, computer-crime, and critical-infrastructure regulations
- Any harm, loss, or liability arising from your use or misuse

The authors, maintainers, and União Geek **disclaim all liability** for unauthorized or
negligent use by third parties who clone or download this repository.

## 4. Prohibited uses

Without limiting applicable law, you must **not**:

- Use IXF or incorporated malware sources against systems without authorization
- Deploy weaponized binaries derived from vendor trees to production or third-party networks
- Disrupt utilities, healthcare, transportation, or other safety-critical infrastructure
- Violate upstream licenses when redistributing incorporated sources
- Represent the maintainers as endorsing your specific offensive operations

## 5. Incorporated malware and ICS tools

The repository includes historical malware families and ICS utility references **as-is**
for study. They may contain harmful code if executed. You must:

- Treat all binaries as malicious
- Never run untrusted samples on production hosts
- Prefer IXF `simulate=true` / analysis modules over live execution
- Follow [SECURITY.md](SECURITY.md) for compile and probe actions

## 6. PyPI package

`pip install industrialxpl-forge` delivers the IXF framework. The **complete vendor
corpus** (~2 GB) is obtained via **Git clone** of this repository due to distribution
size limits on PyPI. Functionality that requires vendor paths documents fallbacks or
lab-only prerequisites in module help text.

## 7. No warranty

THE SOFTWARE AND CORPORA ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. SEE
[LICENSE](LICENSE) (MIT) AND [DISCLAIMER.md](DISCLAIMER.md).

## 8. Changes

These terms may be updated in the repository. Continued use after changes constitutes acceptance.

## 9. Contact

**henrique.santos@uniaogeek.com.br**
