# Assessment e Conformidade

O IXF inclui 18+ módulos de assessment cobrindo IEC 62443, NIST SP 800-82r3, MITRE ATT&CK for ICS, pontuação de risco, playbooks de resposta a incidentes e auditorias de protocolo.

---

## Sumário

1. [Executando Módulos de Assessment](#executando-módulos-de-assessment)
2. [IEC 62443 — Auditoria de Zona e Conduto](#iec-62443--auditoria-de-zona-e-conduto)
3. [NIST SP 800-82r3 — Checklist de Segurança ICS](#nist-sp-800-82r3--checklist-de-segurança-ics)
4. [Pontuação de Risco ICS](#pontuação-de-risco-ics)
5. [ICS Kill Chain — 8 Estágios](#ics-kill-chain--8-estágios)
6. [Playbook de IR — Todas as Fases](#playbook-de-ir--todas-as-fases)
7. [Auditorias de Protocolo](#auditorias-de-protocolo)
8. [Módulos de Assessment MITRE (28 listados)](#módulos-de-assessment-mitre-28-listados)
9. [Assessments de Segurança de Rede](#assessments-de-segurança-de-rede)
10. [Sessão Completa de Assessment (30+ comandos)](#sessão-completa-de-assessment-30-comandos)
11. [Matriz de Combinações simulate/destructive](#matriz-de-combinações-simulatedestructive)
12. [Scoring de Risco com Cálculo Detalhado](#scoring-de-risco-com-cálculo-detalhado)
13. [Todos os 18 Módulos de Assessment com Sessão de Terminal](#todos-os-18-módulos-de-assessment-com-sessão-de-terminal)

---

## Executando Módulos de Assessment

Use o comando `assess` para carregar e imediatamente executar um assessment:

```
ixf > assess <caminho_modulo>
```

Ou use o fluxo padrão `use` → `set target` → `run`:

```
ixf > use assessment/iec62443/zone_conduit_audit
ixf > set target 192.168.1.0/24
ixf > run
```

**Assessments disponíveis via `ixf list assessment`:**

```
ixf > search assessment

  use assessment/iec62443/zone_conduit_audit          [INFO]   IEC 62443 Zone and Conduit Audit
  use assessment/nist_sp800_82/control_checklist      [INFO]   NIST SP 800-82r3 Control Checklist
  use assessment/risk/ics_risk_scorer                 [INFO]   ICS Risk Scoring Assessment
  use assessment/threat_intel/ics_kill_chain          [INFO]   ICS Cyber Kill Chain Analysis
  use assessment/ir/iacs_ir_playbook                  [INFO]   ICS/OT Incident Response Playbook
  use assessment/network/ics_firewall_audit           [INFO]   ICS/OT Firewall Audit
  use assessment/network/industrial_network_assessment [INFO]  Industrial Network Assessment
  use assessment/protocols/modbus_security_audit      [INFO]   Modbus Protocol Security Audit
  use assessment/protocols/opcua_security_audit       [INFO]   OPC UA Security Audit
  use assessment/protocols/dnp3_security_audit        [INFO]   DNP3 Secure Authentication Audit
  use assessment/protocols/iec61850_security_audit    [INFO]   IEC 61850 Security Audit
  use assessment/sast/plc_code_llm_review             [INFO]   PLC Code LLM SAST Review
  use assessment/mitre_ics/coverage_report            [INFO]   MITRE Coverage Report
  use assessment/mitre_ics/full_mitre_sweep           [INFO]   Full MITRE ATT&CK for ICS Sweep
  [... 28 módulos de assessment adicionais ...]
```

---

## IEC 62443 — Auditoria de Zona e Conduto

A norma IEC 62443 é o padrão internacional para segurança de sistemas de automação e controle industrial (IACS).

```
ixf > assess iec62443/zone_conduit_audit
[*] Carregando assessment/iec62443/zone_conduit_audit...
[*] Executando Auditoria de Zona e Conduto IEC 62443...

  Auditoria de Zona e Conduto IEC 62443
  ══════════════════════════════════════════════════════════════════
  Verificação                                  Resultado  Notas
  Separação de zona IT/OT                      MANUAL     Verificar regras de firewall Nível 3→2
  Lista branca de protocolo (Purdue)           MANUAL     Verificar apenas protocolos OT na zona ICS
  Autenticação de acesso remoto                MANUAL     VPN MFA requerida para zonas OT
  Presença de jump server / DMZ                MANUAL     Historian em DMZ, não diretamente em OT
  Documentação de zona/conduto                 MANUAL     Zonas definidas no plano de segurança
  Caminho de controle redundante               MANUAL     Separação de rede primária/secundária
  Inventário de ativos OT                      MANUAL     Todos dispositivos ICS catalogados?
  Gerenciamento de patches OT                  MANUAL     Ciclo de patch definido para firmware PLC?
  Controle de mídia removível                  MANUAL     Política USB em zona OT?
  Monitoramento de segurança OT                MANUAL     SIEM ingere logs de protocolo ICS?
  ══════════════════════════════════════════════════════════════════
  [i] IEC 62443-3-3: Requisitos de baseline de Security Level alvo SL2
  [i] Referência: https://www.isa.org/standards-publications/isa-standards/isa-62443
```

### Níveis de Segurança IEC 62443 (SL1-SL4)

| Nível | Definição | Ameaças Previstas |
|-------|-----------|-------------------|
| **SL 1** | Proteção contra violação não intencional ou acidental | Erros de operador, falhas de equipamento incidentais |
| **SL 2** | Proteção contra violação intencional com meios simples | Atacante com habilidade básica, recursos e motivação genérica |
| **SL 3** | Proteção contra violação intencional com meios sofisticados | Atacante com habilidade elevada, recursos e motivação específica |
| **SL 4** | Proteção contra violação intencional com meios patrocinados por estado | APT com recursos ilimitados, motivação nacional |

### Modelo de Zona/Conduto IEC 62443

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │  Nível 4 — Rede Corporativa / Business                             │
  │  (TI: ERP, e-mail, internet)                                       │
  └──────────────────┬──────────────────────────────────────────────────┘
                     │ Firewall / DMZ (Conduto)
  ┌──────────────────▼──────────────────────────────────────────────────┐
  │  Nível 3.5 — DMZ                                                   │
  │  (Historian, Jump Server, Patch Server)                            │
  └──────────────────┬──────────────────────────────────────────────────┘
                     │ Firewall Industrial (Conduto)
  ┌──────────────────▼──────────────────────────────────────────────────┐
  │  Nível 3 — Zona de Supervisão                                      │
  │  (SCADA, HMI central, servidor de engenharia)                      │
  └──────────────────┬──────────────────────────────────────────────────┘
                     │ Switch Industrial / VLAN (Conduto)
  ┌──────────────────▼──────────────────────────────────────────────────┐
  │  Nível 2 — Zona de Controle                                        │
  │  (DCS, PLCs principais, controladores de safety)                   │
  └──────────────────┬──────────────────────────────────────────────────┘
                     │ Protocolo Industrial (Conduto: Modbus, Profibus)
  ┌──────────────────▼──────────────────────────────────────────────────┐
  │  Nível 1 — Zona de Campo                                           │
  │  (PLCs de campo, RTUs, drives, instrumentação)                     │
  └──────────────────┬──────────────────────────────────────────────────┘
                     │ Processo físico
  ┌──────────────────▼──────────────────────────────────────────────────┐
  │  Nível 0 — Processo                                                │
  │  (Sensores, atuadores, válvulas, motores)                          │
  └─────────────────────────────────────────────────────────────────────┘
```

---

## NIST SP 800-82r3 — Checklist de Segurança ICS

NIST SP 800-82 Revisão 3 é o guia de segurança ICS do NIST, alinhado ao NIST Cybersecurity Framework.

```
ixf > assess nist_sp800_82/control_checklist
[*] Executando Checklist de Controle de Segurança ICS NIST SP 800-82r3...

  Checklist de Controle NIST SP 800-82r3
  ══════════════════════════════════════════════════════════════════
  Domínio de Controle          Verificação                              Notas
  Controle de Acesso           AC-2: Gerenciamento de conta            Verificar ciclo de vida de conta OT
  Controle de Acesso           AC-3: Aplicação de acesso               RBAC implementado para HMI/SCADA?
  Controle de Acesso           AC-17: Acesso remoto                    MFA para todo acesso remoto
  Auditoria e Prestação Contas AU-2: Eventos de auditoria              Quais eventos OT são logados?
  Auditoria e Prestação Contas AU-6: Revisão de auditoria              Logs OT coletados e revisados?
  Configuração                 CM-6: Configurações seguras             Baseline de configuração definido?
  Configuração                 CM-7: Funcionalidade mínima             Protocolos/portas não usados desabilitados?
  Resposta a Incidentes        IR-4: Tratamento de incidentes          Procedimentos de IR específicos para OT?
  Resposta a Incidentes        IR-6: Relatório de incidentes           ICS-CERT notificado em incidentes?
  Manutenção                   MA-4: Manutenção não local              Acesso de manutenção remoto monitorado?
  Proteção de Mídia            MP-2: Acesso à mídia                   Dispositivos USB controlados?
  Proteção Física              PE-3: Controle de acesso físico         Acesso físico a painéis de controle?
  Planejamento                 PL-8: Arquitetura de segurança          Arquitetura OT documentada?
  Avaliação de Risco           RA-3: Avaliação de risco                Assessment de risco ICS anual?
  Proteção de Sistema          SC-7: Proteção de fronteira             Segmentação de rede OT?
  Proteção de Sistema          SC-8: Confidencialidade de transmissão  Criptografia em comunicações OT?
  Integridade de Sistema       SI-2: Correção de falhas                Gerenciamento de patches para ICS?
  Integridade de Sistema       SI-3: Proteção contra malware           Antimalware em EWS/HMI?
  ══════════════════════════════════════════════════════════════════
  [i] Referência: https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final
  [i] Controles mapeados para: NIST CSF v2.0 (GV, ID, PR, DE, RS, RC)
```

### Domínios de Controle NIST 800-82r3

| Família | Abreviação | Foco em OT |
|---------|-----------|-----------|
| Access Control | AC | RBAC para HMI, autenticação de programação PLC |
| Audit and Accountability | AU | Logs de protocolo ICS, auditoria de operações destrutivas |
| Configuration Management | CM | Baseline de firmware, gerenciamento de mudanças de lógica PLC |
| Incident Response | IR | Playbook OT-específico, preservação de evidências |
| Maintenance | MA | Acesso de manutenção remoto monitorado |
| Media Protection | MP | Política de USB em zona OT |
| Physical Protection | PE | Controle de acesso físico a salas de controle |
| Risk Assessment | RA | Assessment de risco ICS anual, CVSS para vulnerabilidades OT |
| System and Communications Protection | SC | Segmentação, criptografia |
| System and Information Integrity | SI | Patches de ICS, antimalware em EWS |

---

## Pontuação de Risco ICS

```
ixf > assess risk/ics_risk_scorer
[*] Pontuação de Risco ICS...
[*] Defina 'target' para analisar um host específico, ou execute sem target para metodologia.

  Metodologia de Pontuação de Risco ICS
  ══════════════════════════════════════════════════════════════════
  Fator                           Peso  Assessment
  Exposição de rede               30%   ICS acessível pela internet: CRÍTICO
  Força de autenticação           25%   Sem auth no Modbus: ALTO
  Separação do sistema de safety  25%   SIS na mesma rede: ALTO
  Nível de patch                  15%   Firmware > 3 anos: ALTO
  Logging/monitoramento            5%   Sem SOC OT-específico: MÉDIO
  ══════════════════════════════════════════════════════════════════
  [i] Use pontuação ICS-CERT da CISA: https://www.cisa.gov/ics-cert
```

### Cálculo Detalhado de Scoring de Risco

```
ixf > use assessment/risk/ics_risk_scorer
ixf (ICS Risk Scorer) > set target 192.168.1.100
ixf (ICS Risk Scorer) > run

  Pontuação de Risco ICS — 192.168.1.100
  ══════════════════════════════════════════════════════════════════

  [1/5] Verificando exposição de rede...
  [*] Verificando se 192.168.1.100 é acessível pela internet via SHODAN API...
  [i] Resultado: Não encontrado no Shodan (rede privada 192.168.x.x)
  [*] Verificando segmentação: atingível a partir de rede TI?
  [i] Executar manualmente: ping 192.168.1.100 da estação de trabalho TI
  Pontuação de Exposição: BAIXO (5/30)

  [2/5] Verificando força de autenticação...
  [*] Testando autenticação Modbus TCP...
  [+] Dispositivo Modbus encontrado na porta 502 sem autenticação.
  [i] Modbus TCP não tem autenticação nativa — verificar controle compensatório
  Pontuação de Autenticação: ALTO (20/25) [sem auth = pontuação alta de risco]

  [3/5] Verificando separação de sistema de safety...
  [i] Verificação manual necessária: SIS/ESD na mesma rede que PLC básico de processo?
  [i] Recomendação: SIS deve estar em rede separada fisicamente (IEC 61511)
  Pontuação de Safety: MANUAL — inserir: 0 (separado) / 15 (mesma rede) / 25 (sem SIS)
  Pontuação de Safety: 15/25 [assumindo mesma rede para demonstração]

  [4/5] Verificando nível de patch...
  [*] Consultando NVD para CVEs recentes de Modbus TCP...
  [i] Versão de firmware: verificação manual necessária (ixf > use scanners/ics/modbus_detect)
  [i] Último advisory de patch: verificar siemens.com/cert ou ICS-CERT
  Pontuação de Patch: MÉDIO (10/15) [assumindo firmware > 18 meses]

  [5/5] Verificando logging/monitoramento...
  [i] Verificação manual: existe solução OT-SOC (Claroty, Nozomi, Dragos)?
  [i] Logs de protocolo ICS (Modbus, S7) estão sendo coletados pelo SIEM?
  Pontuação de Monitoramento: BAIXO (4/5) [assumindo monitoramento básico]

  ══════════════════════════════════════════════════════════════════
  PONTUAÇÃO DE RISCO ICS TOTAL
  ══════════════════════════════════════════════════════════════════
  Exposição de rede     (30%): 5/30   = 16,7%  [BAIXO]
  Autenticação          (25%): 20/25  = 80,0%  [ALTO]
  Separação de Safety   (25%): 15/25  = 60,0%  [MÉDIO]
  Nível de Patch        (15%): 10/15  = 66,7%  [MÉDIO]
  Monitoramento          (5%): 4/5    = 80,0%  [ALTO]

  Pontuação de Risco Ponderada: (5+20+15+10+4) / 100 = 54/100

  Classificação de Risco: MÉDIO-ALTO (54/100)

  ──────────────────────────────────────────────────────────────────
  Remediações Priorizadas:
  1. [ALTO] Implementar autenticação para acesso Modbus (firewall ou gateway de autenticação)
  2. [MÉDIO] Isolar SIS em rede dedicada com intertravamento físico
  3. [MÉDIO] Estabelecer programa de gerenciamento de patches OT (<90 dias)
  ══════════════════════════════════════════════════════════════════
```

---

## ICS Kill Chain — 8 Estágios

```
ixf > assess threat_intel/ics_kill_chain
[*] Análise da ICS Cyber Kill Chain...

  ICS Cyber Kill Chain — Framework de Resposta a Incidentes
  ══════════════════════════════════════════════════════════════════
  Estágio 1: Identificação do Alvo
    Técnicas: OSINT, Shodan, honeypots ICS, spearphishing de pesquisa
    MITRE:    T0865, T0883, T0862
    Indicadores: Buscas de CVE de vendor-específico, varreduras Shodan no setor
    Defesa:   Monitoramento de presença online; não expor detalhes de vendor/modelo

  Estágio 2: Acesso Inicial
    Técnicas: Spearphishing, abuso de VPN, pivot IT→OT, exploit de app pública
    MITRE:    T0817, T0819, T0820, T0865
    Exemplos: Sandworm via spearphishing de energia; TRITON via VPN comprometido
    Defesa:   MFA em VPN; segmentação IT/OT; WAF para HMI web

  Estágio 3: Estabelecer Persistência
    Técnicas: Backdoor de PLC, comprometimento de historian, modificação de firmware
    MITRE:    T0839, T0857, T0843
    Exemplos: EKANS plantou backdoor em historian antes de executar
    Defesa:   Verificação de integridade de firmware; baseline de lógica PLC

  Estágio 4: Descoberta
    Técnicas: Varredura Modbus, enumeração S7, leitura de tag, mapeamento de rede
    MITRE:    T0846, T0840, T0842, T0861
    Exemplos: Industroyer realizou reconhecimento extensivo antes do ataque
    Defesa:   Monitorar varreduras de protocolo ICS; alerta em FC incomuns

  Estágio 5: Movimento Lateral
    Técnicas: Estação de engenharia, servidor jump, credenciais compartilhadas
    MITRE:    T0866, T0807, T0812
    Exemplos: APT33 comprometeu EWS para alcançar PLCs
    Defesa:   Separação de credenciais; EWS isolada; monitorar RDP para OT

  Estágio 6: Escalação de Privilégio
    Técnicas: Acesso admin PLC, software de engenharia, keys de desenvolvedor
    MITRE:    T0859, T0890, T0812
    Exemplos: TRITON usou credencial obtida de admin de processo
    Defesa:   Princípio de privilégio mínimo em contas OT

  Estágio 7: Condicionamento
    Técnicas: Modificação de setpoint, supressão de alarme, spoofing de safety
    MITRE:    T0836, T0878, T0831, T0856
    Exemplos: TRITON suprimiu alarmes SIS antes de tentativa de dano físico
    Defesa:   Baseline de processo; alertas de desvio de setpoint; proteção de alarme

  Estágio 8: Executar Ataque ICS
    Técnicas: Escrita Modbus, IEC 104 EXEC, flash de firmware, sobrescrita de lógica
    MITRE:    T0855, T0814, T0816, T0827, T0829
    Exemplos: FrostyGoop (2024), Industroyer (2016), TRITON (2017)
    Defesa:   DetecçãO baseada em protocolo; travar writes em produção; SafeMode

  ══════════════════════════════════════════════════════════════════
  [i] Referência: Framework IR ICS Dragos
  [i] Referência: Advisory CISA AA22-103A (INCONTROLLER/PIPEDREAM)
  [i] Referência: SANS ICS515: ICS Active Defense and Incident Response
```

---

## Playbook de IR — Todas as Fases

```
ixf > assess ir/iacs_ir_playbook
[*] Playbook de Resposta a Incidentes ICS/OT...

  Playbook de Resposta a Incidentes ICS/OT
  ══════════════════════════════════════════════════════════════════
  Fase           Ação                                              Prioridade
  ══════════════════════════════════════════════════════════════════
  DETECÇÃO
    Monitor      Anomalias de rede OT (Modbus FC incomuns)        Imediata
    Monitor      Alertas de IDS/OT-SOC (Claroty, Nozomi)          Imediata
    Monitor      Desvios de setpoint do DCS                        Imediata
    Monitor      Alarmes inesperados em PLC/RTU                    Imediata
    Monitor      Mudanças não autorizadas em lógica PLC             Alta
    Monitor      Falhas de autenticação em EWS/SCADA               Alta

  CONTENÇÃO
    Isolar       Segmento de rede comprometido (<1 hora)           Crítica
    Isolar       PLC/RTU comprometido (desconectar rede, não power-off) Alta
    Bloquear     Acesso remoto (VPN, RDP) temporariamente           Alta
    Notificar    Equipe de operações e gestão de processo            Alta
    Coordenar    Com sala de controle (operadores humanos em standby) Crítica

  COLETA DE EVIDÊNCIAS
    Preservar    Programas PLC (fazer backup antes de qualquer alteração)  Alta
    Preservar    Logs de historian (<2 horas)                        Alta
    Preservar    Logs de rede/firewall OT                             Alta
    Preservar    Logs de SCADA/HMI                                    Alta
    Capturar     Dump de memória de EWS se comprometida              Média
    Fotografar   Estado de painéis físicos e displays               Média

  ERRADICAÇÃO
    Verificar    Integridade de lógica PLC (comparar com backup)    Alta
    Verificar    Integridade de firmware (hash vs. oficial do vendor) Alta
    Revogar      Credenciais comprometidas                           Alta
    Remover      Backdoors ou scripts maliciosos descobertos         Alta
    Atualizar    Regras de firewall OT baseado em IoCs              Média

  RECUPERAÇÃO
    Restaurar    De backup de programa PLC verificado (<4 horas)    Crítica
    Verificar    Processo físico em estado seguro antes de reiniciar Alta
    Reiniciar    PLCs de forma controlada com operadores presentes   Alta
    Testar       Funcionamento normal antes de retornar ao auto      Alta
    Monitorar    Período de 24-48h com vigilância elevada            Alta

  PÓS-INCIDENTE
    Atualizar    Regras de firewall e configurações de rede (<1 semana) Alta
    Rever        Credenciais e ciclo de vida de conta OT             Alta
    Documentar   Linha do tempo completa do incidente                Alta
    Reportar     Para ICS-CERT (obrigatório em infraestrutura crítica) Alta
    Realizar     Revisão post-mortem com equipes OT e SI             Média
    Implementar  Controles adicionais baseados em lições aprendidas  Média
  ══════════════════════════════════════════════════════════════════

  Playbooks Específicos por Vertical:
    Energia:         Proteger relés de proteção, EMS/SCADA
    Água:            Proteger controles de dosagem, HMIs SCADA
    Petróleo e Gás:  Proteger RTUs, controladores de compressores
    Manufatura:      Proteger PLCs, MES, historian
    Transporte:      Proteger sistemas de sinalização e controle

  Contatos de Emergência:
    CISA ICS-CERT: (888) 282-0870 | ics-cert@cisa.dhs.gov
    FBI Cyber Division: 1-855-292-3937
    Vendor OT CERT (Siemens): siemens-cert@siemens.com
```

---

## Auditorias de Protocolo

### Auditoria de Segurança OPC UA

```
ixf > use assessment/protocols/opcua_security_audit
ixf (OPC UA Security Audit) > set target 192.168.1.100
ixf (OPC UA Security Audit) > run

  Auditoria de Segurança do Servidor OPC UA — 192.168.1.100:4840
  ══════════════════════════════════════════════════════════════════
  Verificação                                Resultado   Notas
  SecurityMode=None                          MANUAL      Servidor aceita sessão anônima?
  Validação de certificado                   MANUAL      Verificação de cert de cliente habilitada?
  Browse anônimo                             MANUAL      Testar navegação de namespace sem auth
  Escrita sem auth                           MANUAL      Testar escrita de tag não autenticada
  Exposição de endpoint de descoberta        MANUAL      Info de endpoint não vazada?
  Autenticação por nome de usuário           MANUAL      Política de senha forte habilitada?
  Revogação de certificado                   MANUAL      CRL verificada em conexão?
  ══════════════════════════════════════════════════════════════════
  [i] SecurityPolicy recomendada: Basic256Sha256 ou Aes256-Sha256-RsaPss
  [i] Referência: OPC Foundation UA Security — https://opcfoundation.org/security
```

### Auditoria de Autenticação Segura DNP3

```
ixf > assess protocols/dnp3_security_audit

  Auditoria de DNP3 Secure Authentication v5 — Assessment
  ══════════════════════════════════════════════════════════════════
  Verificação                                Resultado   Notas
  Desafio-resposta SAv5                      MANUAL      Verificar por IEC 62351-5
  Proteção contra replay                     MANUAL      Chaves de sessão únicas aplicadas
  Verificação de número de sequência         MANUAL      Números de seq de aplicação validados
  Controle não autorizado                    MANUAL      Testar controle sem SAv5
  Gerenciamento de chaves                    MANUAL      Rotação de chave SAv5 implementada?
  Suporte a HMAC                             MANUAL      HMAC SHA-256 usado para controles?
  ══════════════════════════════════════════════════════════════════
  [i] DNP3 SAv5 implementado per IEC 62351-5
  [i] Referência: IEEE 1815-2012 (DNP3)
```

### Auditoria de Segurança IEC 61850

```
ixf > assess protocols/iec61850_security_audit

  Auditoria de Segurança de Subestação IEC 61850
  ══════════════════════════════════════════════════════════════════
  Verificação                                Resultado   Notas
  Autenticação GOOSE                         MANUAL      IEC 62351-6 HMAC habilitado?
  Controle de acesso MMS                     MANUAL      Auth MMS requerida para controles?
  Integridade de SAMPLED VALUES              MANUAL      Proteção de integridade SV?
  Segmentação de rede de subestação          MANUAL      Barramento estação/bay/processo segm.?
  Autenticação de estação de engenharia      MANUAL      Acesso a ferramenta de configuração?
  Atualização de firmware segura             MANUAL      Assinatura de firmware verificada?
  ══════════════════════════════════════════════════════════════════
  [i] Referência: IEC 62351 (Segurança de sistemas de potência)
  [i] Referência: NERC CIP-005 a CIP-013
```

### Auditoria de Segurança Modbus

```
ixf > use assessment/protocols/modbus_security_audit
ixf (Modbus Security Audit) > set target 192.168.1.100
ixf (Modbus Security Audit) > run

  Auditoria de Segurança do Protocolo Modbus — 192.168.1.100:502
  ══════════════════════════════════════════════════════════════════
  Verificação                                Resultado   Notas
  Autenticação de acesso                     FALHA       Modbus TCP não tem auth nativa
  Criptografia em trânsito                   FALHA       Modbus TCP não tem criptografia
  Controle de acesso por IP                  MANUAL      Firewall permite apenas EWS authorized?
  Limitação de Function Code                 MANUAL      FC de escrita bloqueados na fronteira?
  Limitação de Unit ID                       MANUAL      Apenas IDs de unidade conhecidos aceitos?
  Monitoramento de anomalias de FC           MANUAL      IDS alerta em FC incomuns?
  Registro de auditoria de escritas          MANUAL      FC03 writes são logados?
  ══════════════════════════════════════════════════════════════════
  [i] Modbus TCP não tem segurança nativa — compensar com controles de rede
  [i] Alternativa: Modbus Security (RFC 8236 — extensão TLS do Modbus)
  [i] Referência: CISA ICS Security Best Practices Guide
```

---

## Módulos de Assessment MITRE (28 listados)

```
ixf > list assessment/mitre_ics

  Módulos de Assessment MITRE ATT&CK for ICS (28 módulos)
  ════════════════════════════════════════════════════════════════════════
  Módulo                                      Técnica  Descrição
  ──────────────────────────────────────────────────────────────────────
  t0800_activate_firmware_update_mode         T0800    Modo de atualização de firmware
  t0801_monitor_process_state                 T0801    Monitoramento de estado de processo
  t0802_automated_collection                  T0802    Coleta automatizada
  t0806_brute_force_io                        T0806    Força bruta de I/O
  t0812_default_credentials                   T0812    Credenciais padrão
  t0814_denial_of_service                     T0814    DoS de dispositivo ICS
  t0816_device_restart                        T0816    Reinicialização de dispositivo
  t0821_modify_controller_tasking             T0821    Modificação de tarefas do controlador
  t0831_manipulation_of_control               T0831    Manipulação de controle
  t0833_modify_alarm_settings                 T0833    Modificação de config. de alarme
  t0835_detect_operating_mode                 T0835    Detecção de modo de operação PLC
  t0836_modify_parameter                      T0836    Modificação de parâmetro de processo
  t0838_modify_program                        T0838    Modificação de programa PLC
  t0840_network_connection_enumeration        T0840    Enumeração de conexão de rede
  t0841_network_sniffing                      T0841    Sniffing de rede
  t0843_program_download                      T0843    Download de programa
  t0844_program_upload                        T0844    Upload de programa
  t0846_remote_system_discovery               T0846    Descoberta de sistema remoto
  t0851_rootkit                               T0851    Rootkit em dispositivo ICS
  t0855_unauthorized_command_message          T0855    Mensagem de comando não autorizada
  t0856_spoof_reporting_message               T0856    Spoofing de mensagem de relatório
  t0861_point_tag_identification              T0861    Identificação de ponto e tag
  t0871_execution_through_api                 T0871    Execução via API
  t0873_project_file_infection                T0873    Infecção de arquivo de projeto
  t0877_io_module_discovery                   T0877    Descoberta de módulo I/O
  t0878_alarm_suppression                     T0878    Supressão de alarme
  t0879_damage_to_property                    T0879    Dano à propriedade
  t0880_loss_of_safety                        T0880    Perda de segurança
  coverage_report                             Todas    Relatório de cobertura MITRE completo
  full_mitre_sweep                            Todas    Varredura completa de todas as técnicas
  ──────────────────────────────────────────────────────────────────────
  Total: 30 módulos de assessment MITRE
```

**Executando assessment de técnica específica:**

```
ixf > use assessment/mitre_ics/t0836_modify_parameter
ixf (MITRE T0836: Modify Parameter) > set target 192.168.1.100
ixf (MITRE T0836: Modify Parameter) > run

  Assessment MITRE T0836: Modify Parameter — 192.168.1.100:502
  ══════════════════════════════════════════════════════════════════
  Técnica:     T0836 — Modify Parameter
  Tática:      Impair Process Control (TA0106)

  Checklist de Assessment:
  [ ] FC16 Write a registradores requer autenticação?
  [ ] Setpoints têm validação de intervalo no PLC?
  [ ] Alarmes são acionados em mudanças de setpoint anormais?
  [ ] Log de auditoria registra escritas em registradores?
  [ ] Segmentação de rede impede acesso Modbus não autorizado?
  [ ] Operadores monitoram desvios de setpoint em tempo real?

  Resultado de Verificação Ativa:
  [+] FC03 Read Holding Registers: bem-sucedido (sem auth)
  [!] Holding registers 0-9 acessíveis sem autenticação
  [!] FC16 Write provavelmente possível — testar manualmente com autorização

  Remediação:
  1. Implementar firewall com whitelist de IP para porta Modbus 502
  2. Restringir FC de escrita (FC05, FC06, FC15, FC16) a apenas EWS autorizada
  3. Habilitar alarme em DCS/SCADA para desvios de setpoint > 10%
  4. Implementar Modbus Secure (TLS) ou migrar para OPC UA com Basic256Sha256
```

---

## Assessments de Segurança de Rede

### Auditoria de Firewall ICS

```
ixf > assess network/ics_firewall_audit

  Auditoria de Firewall e Segmentação de Rede ICS/OT
  ══════════════════════════════════════════════════════════════════
  Verificação                   Resultado   Notas
  Segmentação IT/OT             MANUAL      Regras de firewall Nível 3→2 presentes?
  Lista branca de protocolo     MANUAL      Apenas protocolos industriais em OT?
  VPN de acesso remoto          MANUAL      VPN MFA para todo acesso remoto OT?
  Exposição à internet          MANUAL      Nenhum ICS diretamente na internet?
  DMZ do Historian              MANUAL      Historian em DMZ, não em rede OT?
  Regras de acesso de saída     MANUAL      OT bloqueado de comunicar para internet?
  Controle de acesso de salto   MANUAL      Jump server usado para todos os acessos OT?
  Logging de firewall           MANUAL      Logs de FW OT coletados e revisados?
  ══════════════════════════════════════════════════════════════════
```

### Assessment de Rede Industrial

```
ixf > assess network/industrial_network_assessment

  Assessment de Infraestrutura de Rede Industrial
  ══════════════════════════════════════════════════════════════════
  Verificação                     Resultado   Notas
  Strings de comunidade SNMP      MANUAL      Verificar "public"/"private" padrão
  Switches não gerenciados        MANUAL      Identificar switches não gerenciados em OT
  Topologia de rede flat           MANUAL      Detectar rede flat permitindo pivot
  Gerenciamento Telnet/HTTP       MANUAL      Protocolos de gerenciamento inseguros?
  Autenticação de protocolo de roteamento MANUAL OSPF/BGP authentication verificada?
  Portas de gerenciamento expostas MANUAL     Portas 22, 80, 443, 23 nos dispositivos OT?
  Redundância de rede             MANUAL      Redundância N+1 para comunicações críticas?
  ══════════════════════════════════════════════════════════════════
```

---

## Sessão Completa de Assessment (30+ comandos)

Workflow de assessment de conformidade completo:

```bash
# Sessão completa de assessment ICS — workflow de 30+ comandos

# 1. Verificar estatísticas do IXF
ixf stats

# 2. Verificar cobertura MITRE
ixf mitre-coverage

# 3. Assessment IEC 62443
ixf assess iec62443/zone_conduit_audit

# 4. Assessment NIST SP 800-82r3
ixf assess nist_sp800_82/control_checklist

# 5. Pontuação de risco
ixf use assessment/risk/ics_risk_scorer
ixf set target 192.168.1.100
ixf run

# 6. Análise de Kill Chain
ixf assess threat_intel/ics_kill_chain

# 7. Playbook de IR
ixf assess ir/iacs_ir_playbook

# 8. Auditoria de firewall
ixf assess network/ics_firewall_audit

# 9. Assessment de rede industrial
ixf assess network/industrial_network_assessment

# 10. Auditoria de segurança Modbus
ixf use assessment/protocols/modbus_security_audit
ixf set target 192.168.1.100
ixf run

# 11. Auditoria OPC UA
ixf use assessment/protocols/opcua_security_audit
ixf set target 192.168.1.100
ixf run

# 12. Auditoria DNP3
ixf assess protocols/dnp3_security_audit

# 13. Auditoria IEC 61850
ixf assess protocols/iec61850_security_audit

# 14. Assessment T0836 (Modify Parameter)
ixf use assessment/mitre_ics/t0836_modify_parameter
ixf set target 192.168.1.100
ixf run

# 15. Assessment T0843 (Program Download)
ixf use assessment/mitre_ics/t0843_program_download
ixf set target 192.168.1.100
ixf run

# 16. Assessment T0878 (Alarm Suppression)
ixf use assessment/mitre_ics/t0878_alarm_suppression
ixf set target 192.168.1.100
ixf run

# 17. Assessment T0812 (Default Credentials)
ixf ttp T0812 192.168.1.100

# 18. Varredura de Discovery MITRE
ixf mitre-scan discovery 192.168.1.0/24

# 19. Relatório de cobertura MITRE
ixf use assessment/mitre_ics/coverage_report
ixf run

# 20-30. Varreduras de scanners de protocolo
ixf use scanners/ics/modbus_detect set target 192.168.1.0/24 run
ixf use scanners/ics/s7_enumerate set target 192.168.1.0/24 run
ixf use scanners/ics/enip_scanner set target 192.168.1.0/24 run
ixf use scanners/ics/bacnet_discovery set target 192.168.1.0/24 run
ixf use scanners/ics/dnp3_data_link_scan set target 192.168.1.0/24 run
ixf use scanners/ics/iec104_scan set target 192.168.1.0/24 run
ixf use scanners/ics/opcua_discovery set target 192.168.1.0/24 run
ixf use scanners/ics/profinet_dcp_scan set target eth0 run
ixf use scanners/network/ot_port_sweep set target 192.168.1.0/24 run
ixf use scanners/osint/shodan_ics_dork set target 192.168.1.100 run

# 31. Gerar relatórios finais
ixf mitre-report json
ixf mitre-report navigator
ixf report json
ixf report csv

# 32. Visualizar relatórios
ixf mitre-coverage
```

---

## Matriz de Combinações simulate/destructive

Para módulos de assessment, a matriz abaixo define o comportamento em cada combinação:

| `simulate` | `destructive` | Comportamento do Assessment |
|------------|--------------|----------------------------|
| `True` | `False` | Exibe checklist e metodologia. Sem conexão de rede. Modo padrão. |
| `True` | `True` | Igual a `True`/`False`. simulate tem precedência. |
| `False` | `False` | Executa verificações somente leitura. Conecta para verificar, mas não modifica. |
| `False` | `True` | Executa verificações ativas completas incluindo testes controlados. Gate de confirmação ativado para impactos >LOW. |

**Nota:** A maioria dos módulos de assessment tem impacto `INFO` ou `READ`, então os ramos `False`/`True` executam sem prompt de confirmação.

---

---

## Métricas de Maturidade de Segurança OT

O IXF Risk Scorer avalia maturidade em 5 domínios:

| Domínio | Peso | Avalia |
|---------|------|--------|
| Exposição de rede | 30% | ICS exposto, segmentação IT/OT, acesso remoto |
| Autenticação | 25% | Credenciais padrão, MFA, contas compartilhadas |
| Segurança de safety | 25% | Separação SIS, bypass de safety possível |
| Patching | 15% | Versão de firmware, SOes em EOL |
| Visibilidade | 5% | Logs OT, SIEM com regras ICS |

**Níveis de maturidade:**

| Pontuação | Nível | Características |
|-----------|-------|----------------|
| 0-20 | Nível 1 — Inicial | Sem programa formal; controles ad hoc |
| 21-40 | Nível 2 — Repetível | Alguns controles implementados; sem consistência |
| 41-60 | Nível 3 — Definido | Processos documentados; aplicação inconsistente |
| 61-80 | Nível 4 — Gerenciado | Controles mensuráveis; programa formal |
| 81-100 | Nível 5 — Otimizado | Melhoria contínua; referência em segurança OT |

---

## Glossário de Termos de Assessment OT/ICS

| Termo | Definição |
|-------|-----------|
| **ICS** | Industrial Control Systems — sistemas de controle industrial |
| **SCADA** | Supervisory Control and Data Acquisition — supervisão e aquisição de dados |
| **PLC** | Programmable Logic Controller — controlador lógico programável |
| **RTU** | Remote Terminal Unit — unidade terminal remota |
| **HMI** | Human-Machine Interface — interface homem-máquina |
| **DCS** | Distributed Control System — sistema de controle distribuído |
| **SIS** | Safety Instrumented System — sistema instrumentado de segurança |
| **SIL** | Safety Integrity Level — nível de integridade de segurança |
| **SL** | Security Level (IEC 62443) — nível de segurança |
| **IACS** | Industrial Automation and Control Systems |
| **OT** | Operational Technology — tecnologia operacional |
| **DMZ** | Demilitarized Zone — zona desmilitarizada (rede intermediária) |
| **Zone** | Grouping of logical or physical assets in IEC 62443 |
| **Conduit** | Communication path between zones in IEC 62443 |
| **NERC CIP** | North American Electric Reliability Corporation Critical Infrastructure Protection |
| **AWIA** | America's Water Infrastructure Act |
| **ICS-CERT** | Industrial Control Systems Cyber Emergency Response Team (CISA) |
| **APT** | Advanced Persistent Threat — ameaça persistente avançada |
| **TTP** | Tactics, Techniques and Procedures — táticas, técnicas e procedimentos |
| **IoC** | Indicator of Compromise — indicador de comprometimento |
| **SAv5** | DNP3 Secure Authentication version 5 |

---

## Recursos Adicionais

### Publicações e Referências

| Recurso | Descrição | URL |
|---------|-----------|-----|
| CISA ICS Advisories | Alertas de vulnerabilidades ICS | https://www.cisa.gov/ics |
| MITRE ATT&CK for ICS | Framework de táticas e técnicas | https://attack.mitre.org/matrices/ics/ |
| ICS-CERT | Resposta a incidentes ICS | https://www.cisa.gov/ics-cert |
| NIST SP 800-82r3 | Guia de segurança ICS | https://doi.org/10.6028/NIST.SP.800-82r3 |
| IEC 62443 | Norma de segurança IACS | https://www.isa.org/iec62443 |
| NERC CIP | Padrões de proteção de infraestrutura crítica | https://www.nerc.com/pa/Stand/Pages/CIPStandards.aspx |

### Comunidades e Listas de Discussão

- **ICS-ISAC**: https://www.ics-isac.org — Information Sharing and Analysis Center para ICS
- **SANS ICS**: https://www.sans.org/industrial-control-systems-security/ — cursos e recursos
- **Dragos Intelligence**: https://www.dragos.com/threat-intelligence/ — inteligência de ameaças ICS

---

*Anterior: [PolyExploit Runner](11-poly-exploit-runner.md) | Voltar ao [Índice](_index.md)*
