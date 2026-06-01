# Assessment e Conformidade

O IXF inclui 18+ módulos de assessment cobrindo IEC 62443, NIST SP 800-82r3, MITRE ATT&CK for ICS, scoring de risco e playbooks de resposta a incidentes.

---

## Executando Módulos de Assessment

Use o comando `assess` para carregar e executar imediatamente um assessment:

```
ixf > assess <caminho_do_modulo>
```

Ou use o fluxo padrão `use` → `set target` → `run`:

```
ixf > use assessment/iec62443/zone_conduit_audit
ixf > set target 192.168.1.0/24
ixf > run
```

---

## IEC 62443 — Auditoria de Zonas e Condutos

```
ixf > assess iec62443/zone_conduit_audit
[*] Executando Auditoria de Zonas e Condutos IEC 62443...

  Auditoria de Zonas e Condutos IEC 62443
  ──────────────────────────────────────────────────────────────────
  Verificação                              Resultado  Notas
  Separação IT/OT                          MANUAL     Verificar regras de firewall Nível 3→2
  Whitelist de protocolos                  MANUAL     Apenas protocolos OT na zona ICS
  Autenticação de acesso remoto            MANUAL     MFA VPN obrigatório para zonas OT
  Servidor jump / DMZ                      MANUAL     Historian na DMZ, não diretamente no OT
  Documentação de zonas/condutos           MANUAL     Zonas definidas no plano de segurança
  ──────────────────────────────────────────────────────────────────
  [i] IEC 62443-3-3: Requisitos de baseline do Nível de Segurança SL2
```

**Níveis de Segurança IEC 62443:**

| Nível | Definição |
|-------|-----------|
| SL 1 | Proteção contra violação não intencional |
| SL 2 | Proteção contra violação intencional por meios simples |
| SL 3 | Proteção contra violação intencional por meios sofisticados |
| SL 4 | Proteção contra violação patrocinada por estados-nação |

---

## NIST SP 800-82r3 — Checklist de Segurança ICS

```
ixf > assess nist_sp800_82/control_checklist
[*] Executando Checklist de Segurança ICS NIST SP 800-82r3...

  Checklist NIST SP 800-82r3
  ──────────────────────────────────────────────────────────────────
  Domínio de Controle      Verificação                         Notas
  Controle de Acesso       AC-2: Gerenciamento de contas       Ciclo de vida OT
  Controle de Acesso       AC-17: Acesso remoto                MFA para todo acesso remoto
  Auditoria e Responsab.   AU-6: Revisão de auditoria          Logs OT coletados e revisados
  Gerenciamento de Config. CM-7: Funcionalidade mínima         Desabilitar protocolos/portas não usados
  Integridade do Sistema   SI-2: Correção de falhas            Gerenciamento de patches para ICS
  ──────────────────────────────────────────────────────────────────
```

---

## Scoring de Risco

```
ixf > assess risk/ics_risk_scorer
  Metodologia de Pontuação de Risco ICS
  ──────────────────────────────────────────────────────────────────
  Fator                      Peso    Avaliação
  Exposição de rede           30%    ICS exposto à internet: CRÍTICO
  Força de autenticação       25%    Sem auth no Modbus: ALTO
  Separação de sistema safety 25%    SIS na mesma rede: ALTO
  Nível de patches            15%    Firmware > 3 anos: ALTO
  Logging/monitoramento        5%    Sem SOC específico para OT: MÉDIO
```

---

## Kill Chain ICS / Inteligência de Ameaças

```
ixf > assess threat_intel/ics_kill_chain
  ICS Cyber Kill Chain — Framework de Resposta a Incidentes
  ──────────────────────────────────────────────────────────────────
  Estágio 1: Identificação do Alvo    OSINT, Shodan, honeypots ICS
  Estágio 2: Acesso Inicial           Spearphishing, abuso VPN, pivot IT→OT
  Estágio 3: Persistência             Backdoor PLC, compromisso historian
  Estágio 4: Descoberta               Scan Modbus, enumeração S7, leitura de tags
  Estágio 5: Movimento Lateral        EWS, servidor jump
  Estágio 6: Escalada de Privilégios  Acesso admin CLP, software de engenharia
  Estágio 7: Condicionamento          Modificação de setpoint, bypass safety
  Estágio 8: Execução do Ataque ICS   Escrita Modbus, EXEC IEC 104, flash firmware
```

---

## Playbook de IR

```
ixf > assess ir/iacs_ir_playbook
  Playbook de Resposta a Incidentes ICS/OT
  ──────────────────────────────────────────────────────────────────
  Fase          Ação                                       Prioridade
  Detecção      Monitorar anomalias rede OT (Modbus FC)    Imediata
  Contenção     Isolar segmento de rede comprometido       < 1 hora
  Evidências    Preservar programas CLP + logs historian   < 2 horas
  Recuperação   Restaurar de backup de programa seguro     < 4 horas
  Pós-IR        Atualizar regras firewall, revisar creds   < 1 semana
  Verticals:
    Energia: proteger relés de proteção, EMS/SCADA
    Água: proteger controles de dosagem, IHMs SCADA
    Petróleo/Gás: proteger RTUs, controladores de compressor
    Manufatura: proteger CLPs, MES, historian
```

---

## Auditorias de Segurança de Protocolo

```
ixf > assess protocols/opcua_security_audit
  Verificação SecurityMode=None         MANUAL  Verificar se aceita sessões anônimas
  Validação de certificado              MANUAL  Verificar verificação de cert cliente
  Browse anônimo                        MANUAL  Testar navegação anônima de namespace

ixf > assess protocols/dnp3_security_audit
  SAv5 challenge-response               MANUAL  Verificar IEC 62351-5
  Proteção contra replay                MANUAL  Chaves de sessão únicas forçadas

ixf > assess protocols/iec61850_security_audit
  Autenticação GOOSE                    MANUAL  IEC 62351-6 HMAC habilitado
  Controle de acesso MMS                MANUAL  Autenticação MMS obrigatória
```

---

## Módulos de Assessment MITRE ATT&CK

```
ixf > use assessment/mitre_ics/t0843_program_upload
ixf > use assessment/mitre_ics/t0836_modify_parameter
ixf > use assessment/mitre_ics/t0880_modify_alarm_settings
ixf > use assessment/mitre_ics/t0851_rootkit
ixf > use assessment/mitre_ics/t0879_damage_to_property
```

Todos os 28 módulos de assessment de técnica executam em modo simulação por padrão e fornecem saídas de análise estruturadas com cenários de ataque passo a passo e recomendações de detecção.

---

## Sessão de Assessment Completo

```bash
ixf assess iec62443/zone_conduit_audit
ixf assess nist_sp800_82/control_checklist
ixf assess risk/ics_risk_scorer
ixf assess threat_intel/ics_kill_chain
ixf assess ir/iacs_ir_playbook
ixf assess network/ics_firewall_audit
ixf assess protocols/opcua_security_audit
ixf mitre-coverage
ixf report json
```

---

*Anterior: [PolyExploit Runner](11-poly-exploit-runner.md) | Voltar ao [Índice](_index.md)*
