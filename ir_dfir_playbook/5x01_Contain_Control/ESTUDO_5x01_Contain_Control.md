# Estudo – Projeto 5x01 Contain and Control

> Guia de estudo do projeto inteiro (tasks 0 a 6): o que cada task pede, o que você deveria aprender, como resolvi e a matéria por trás.

## 0. A história do incidente (o que os logs mostram)

| Hora (UTC) | O que aconteceu | Fonte |
|---|---|---|
| 13/04 18:13:44 | Daniel Marsh (`dmarsh`) abre um e-mail no Outlook | proxy |
| 18:14:02 | Clica no link → `ms0365-support[.]login-verification[.]click/auth` (página falsa do M365) | proxy |
| 18:14:41 | **POST `/auth/submit`** e, no mesmo segundo, **login no Azure AD vindo da Rússia (45.63.9.88)** com MFA aprovado | proxy + auth |
| 18:14:43 | Baixa `update.zip` | proxy + EDR |
| 18:15:02–14 | Extrai `update.xml` + `update.exe`; o `update.exe` cria **Run key `WindowsUpdateSvc`** e **tarefa agendada `{7B4F2D81-…}`** (dispara no logon) | EDR |
| 14/04 02:44:03 | Daniel faz logon para o turno → a tarefa roda o `update.exe` (PID 7204) | auth + EDR |
| 02:46:41 | `update.exe` → `powershell -ep bypass -w hidden -enc …` (PID 7812) | EDR |
| 02:46:57 | `powershell` → **`MSBuild.exe update.xml`** (PID 8104), um LOLBin | EDR |
| 02:47:02 | MSBuild → **C2 185.220.101.47:443** (Tor exit) | EDR + proxy |
| 02:47:11 | **Alerta wz-edr-100041** | SIEM |
| 02:47:14 | Região de memória RWX com cabeçalho MZ dentro do MSBuild: **payload só em memória** | EDR |
| 03:22:47 | **Pass-the-Ticket**: tickets Kerberos do dmarsh usados de WST-WS-031 → WST-WS-017 (ADMIN$, serviço remoto) | auth expansion |
| 03:27:13 | WST-WS-017: MSBuild → **2º C2 91.234.99.107** | EDR |
| 03:41:52–03:43:41 | WST-WS-017 → **LIS-WSIDE-01**, lê **14 PDFs de laudos de pacientes (ePHI)** | auth + file |

Kill chain: **phishing → roubo de credencial → payload → persistência → execução via LOLBin → C2 → movimento lateral (PtT) → acesso a ePHI.**

---

## Task 0 – Triage the First Alert (quiz, já feita ✅)

Decidir severidade, playbook e primeira ação a partir do alerta resumido. Resposta: **SEV2**, playbook **PB-CRED-001**, primeira ação **abrir o incidente e começar a timeline / preservar evidência** (não sair matando processo).

---

## Task 1 – Open the Incident Timeline → `incident_timeline.md`

**Pede:** header (incident_id, declared_at, declared_by, severidades, ir_commander, scribe), legenda dos 5 tipos e entradas `timestamp | tipo | ator | descrição | source= | certainty=`. No mínimo: o alerta, a declaração e a severidade com justificativa.

**Aprender:**
- Abrir a timeline **no momento da declaração**. *"Se não está na timeline, não aconteceu."*
- **Append-only:** nunca reescrever uma entrada. Quando a interpretação muda, entra uma **nova** linha que referencia a antiga. Exemplos no arquivo:
  - 02:54:40 diz "credencial *provavelmente* enviada" (probable). Às 02:58:40 o log do Azure AD **confirma**, e a nova entrada cita a antiga.
  - 02:51:40 diz SEV2. Às 03:44:50 a escalada para SEV1 cita as entradas antigas.
- `certainty` separa **fato** de **suposição**: `confirmed` (está no log) > `high` > `probable` > `possible`.

**Pegadinhas:**
- O alerta só cita o GET da página de phishing. Lendo o proxy inteiro aparece o **POST /auth/submit** e o download do `update.zip`.
- O `-enc` do PowerShell é base64 de **UTF-16LE**: `echo '<b64>' | base64 -d | iconv -f UTF-16LE -t UTF-8`. O de WST-WS-031 aponta para o domínio de phishing; o de WST-WS-017 aponta para `https://91.234.99.107/z`.

**Severidade (matriz da 5x00):** SEV2 = "malware confirmado em uma estação clínica" / "conta clínica comprometida". Não é SEV1 no começo: um host só, sem ePHI acessado, sem queda de serviço, conta não privilegiada.

> Observação: o header `current_severity` agora está **SEV1**, porque o header é o estado *atual*. O que é append-only são as *entradas*. Se o corretor da Task 1 reclamar, volte para SEV2 só no header.

---

## Task 2 – Preserve Evidence Before Containment → `evidence_preservation.md`

**Pede:** um runbook com, para cada artefato, *o quê, como (comando exato), onde fica, hash SHA-256 + comando, e por que vem antes da contenção*. No fim, uma etapa de verificação que recalcula os hashes.

**Aprender: ordem de volatilidade (RFC 3227 / NIST SP 800-86):**

```
RAM → processos → conexões de rede/DNS/ARP → arquivos no disco → logs em servidores
(mais volátil)                                                    (menos volátil)
```

- **Memória primeiro**, porque o payload do MSBuild só existe na RAM (região RWX com MZ). Isolar, matar o processo ou desligar a máquina **destrói** isso. A RAM também guarda os tickets Kerberos (no LSASS), o que depois explica o Pass-the-Ticket.
- **Nunca grave no disco do host suspeito**: rode as ferramentas a partir de um share read-only e escreva direto no share de evidência.
- **Hash nas duas pontas** (`certutil` no host e `sha256sum` no servidor) prova que nada mudou na transferência.
- **Cadeia de custódia**: `hashes.txt`, `chmod 0440`, verificação com `grep -v '^#' hashes.txt | sha256sum -c -`.
- O PB-CRED-001 exige exportar os logs de autenticação **antes** do reset de senha e os do Azure AD **antes** de revogar as sessões.

**Pegadinha achada:** o `evidence_store_init.sh` tem o typo `${INCIDENCE_ID:-…}`. Funciona por causa do fallback, mas uma variável de ambiente perdida desviaria o store. Por isso o runbook manda dar `unset INCIDENCE_ID`.

Os hashes de alert/proxy/auth/EDR no runbook são **reais**, calculados dos arquivos do lab.

---

## Task 3 – Weigh Containment Options → `containment_decision.md`

**Pede:** pelo menos 3 estratégias, cada uma com *ação, efeito no atacante, na evidência, no cuidado ao paciente, tempo e reversibilidade*; a escolha com justificativa de **um parágrafo**; a janela entre preservação e contenção; quem aprova; e o rollback.

| | A. VLAN de quarentena | B. Desligar | C. Matar processo + bloquear egress |
|---|---|---|---|
| Atacante | C2 cortado, sem movimento lateral | Para tudo (mas a persistência volta no logon) | Para o implante visto; o host continua na rede |
| Evidência | **Preservada** | **Destruída** (RAM) | Perde a memória do processo |
| Paciente | 1 estação a menos | 1 estação a menos | Mínimo |
| Reversível | Sim | Não | Parcial |

**Escolha: A + D (reset de conta).** O D vem do PB-CRED-001: conta com acesso a ePHI → **reset imediato**.

**Aprender:**
- Contenção é **trade-off explícito**, e a justificativa fica **ao lado** da decisão.
- **Quem aprova:** James Chen (IR Commander), cujo teto de autoridade é **SEV2**. Em SEV1 a autoridade passa para a **CISO (Patricia Morales)**.
- **Limite importante do D:** trocar a senha **não invalida tickets Kerberos já emitidos** (TGT de 10 h). Isso ficou registrado como risco, e foi exatamente o que o atacante usou na Task 5.

---

## Task 4 – Execute Containment → `containment_execution.md`

**Pede:** cada passo com *timestamp, ator, comando, resultado esperado, resultado observado e desvio*: VLAN, regra de firewall, **prova** de que o C2 caiu (netflow), flag de contenção no EDR e confirmação de que só o jumpbox alcança o host. Cada passo também vira ACTION na timeline.

**Aprender:**
- **Intenção ≠ execução.** Registre o que *realmente* aconteceu, inclusive os desvios. No arquivo, a flag do EDR falhou na 1ª tentativa porque o agente estava reconectando depois da troca de VLAN. Isso foi registrado, com o motivo de não ter havido exposição.
- **Prova, não sensação:** netflow com o último fluxo às 03:24:08 e zero pacotes depois; ping/445 falhando da VLAN de usuário e funcionando do jumpbox.

> Os horários e as saídas de comando das Tasks 2–4 são **simulados** (o lab não traz esses resultados), mas são coerentes com os logs. A lacuna entre o fim da preservação (03:20:40) e o isolamento (03:24:10) explica por que o movimento lateral das 03:22:47 saiu de WST-WS-031 **antes** do isolamento.

---

## Task 5 – Reassess When the Scope Expands (quiz na plataforma)

Você responde na plataforma. Use esta análise:

1. **Técnica:** **Pass-the-Ticket** (MITRE **T1550.003**). Há TGS_REQ do dmarsh vindos de hosts que não são a estação dele, reuso de ticket (`second_request_with_ticket_reuse`) e logon tipo 3 com Kerberos. O PowerShell com pai `services.exe` via ADMIN$ é execução remota no estilo PsExec/Impacket (T1021.002 + T1569.002; ver o alerta CISA AA22-277A).
2. **Por que o reset de senha não segurou o ataque:** tickets já emitidos continuam válidos até expirar.
3. **Nova severidade: SEV1.** O PB-CRED-001 diz *"ePHI confirmed accessed → SEV1"*: 14 laudos de pacientes foram lidos em LIS-WSIDE-01. Além disso, são 3 hosts e um 2º C2.
4. **Quem passa a decidir:** a **CISO Patricia Morales**, porque o teto do IR Commander é SEV2.
5. **Quem avisar (SEV1):** CISO, IR Commander, Technical Lead (Robert Kim), Scribe (Mike Torres) e, por causa do ePHI, **Legal / Helena Reyes, que conduz a avaliação de breach da HIPAA**, além da Comunicação (Marcus Webb).
6. **Regulatório:** acesso a ePHI aciona a **avaliação de breach da HIPAA** (o acesso foi confirmado; a exfiltração ainda não). Não decida sozinho se "é ou não é breach": quem conduz é o Legal.
7. **Ações:** conter WST-WS-017 e LIS-WSIDE-01, bloquear 91.234.99.107, caçar todos os TGS_REQ do dmarsh e planejar o reset do krbtgt.

---

## Task 6 – Plan Eradication with Verification → `eradication_checklist.yaml`

**Pede:** itens com `id, category, target_host, description, command_or_action, verification_command, expected_verification_result, status, executed_at, executed_by`, cobrindo os 3 hosts, a conta dmarsh, o material Kerberos e os 2 IPs de C2.

**Aprender:** *"Erradicação não é sensação."* Cada item tem uma **verificação objetiva**. As categorias cobrem todas as superfícies de persistência:

| Categoria | Exemplos no arquivo |
|---|---|
| `process` | Matar MSBuild/PowerShell (só **depois** da imagem de memória) |
| `malware_artifact` | `update.*`, tarefa `{7B4F2D81…}`, Run key `WindowsUpdateSvc`, serviço remoto no 017, rebuild |
| `credential` | 2º reset do dmarsh, revogar tokens, MFA/inbox rules/OAuth, `klist purge` |
| `machine_account` | `Reset-ComputerMachinePassword` nos 3 hosts |
| `krbtgt` | **Reset duplo**: o AD guarda a chave anterior (n-1), então são 2 resets com replicação completa e espera ≥ vida máxima do TGT (10 h) entre eles |
| `network` | Bloqueio de egress dos 2 C2, segmentação interna (SMB entre estações), bloqueio e purge do phishing |

**Rationale do krbtgt (honesto):** não há evidência de comprometimento do DC/DCSync. O atacante usou tickets *legítimos* do dmarsh. Mesmo assim, o reset duplo é a única forma de invalidar **todos** os TGTs emitidos no domínio durante a janela. Por ser uma ação de impacto no domínio inteiro, precisa da aprovação da CISO.

As verificações usam o `mock_validation_api` (`curl http://127.0.0.1:8080/...`), que provavelmente é a base da Task 7 avançada (`recovery_validation.sh`).

---

## Matéria geral

### NIST SP 800-61r2 (seções 3.3 e 3.4)

```
Preparação → Detecção & Análise → Contenção → Erradicação → Recuperação → Pós-incidente
                     ↑__________________ (volta se o escopo crescer) __________________↓
```

Este projeto inteiro mostra esse "volta": a contenção da Task 4 achou um host, mas a Task 5 mostrou três. Por isso a severidade é **revista a cada nova evidência**.

### Os hábitos que o projeto avalia
1. Timeline aberta na declaração, append-only.
2. **Preservar antes de tocar.**
3. Contenção escolhida com trade-off por escrito.
4. Decisão registrada **na hora**, com quem aprovou.
5. Erradicação = lista + verificação.
6. Recuperação com **prova**.
7. Handoff que outra pessoa consegue assumir sem fazer perguntas.

### Conceitos de ataque
- **LOLBins (LOLBAS):** MSBuild, assinado pela Microsoft, compila e executa C# de dentro de um `.xml`. `signed: true` **não significa seguro**.
- **PowerShell ofuscado:** `-enc` + `-w hidden` + `-ep bypass` é um sinal clássico.
- **MFA não salvou:** o login russo passou com MFA porque o usuário aprovou um push e o risco "impossible travel" não foi promovido (o dispositivo estava marcado como compliant). Lição: usar **MFA resistente a phishing (FIDO2)**.
- **Pass-the-Ticket:** roubar um ticket Kerberos da memória e reutilizá-lo. Trocar a senha não mata o ticket; é preciso purgar tickets e, em último caso, fazer o reset duplo do krbtgt.

## Checklist antes de enviar
- [ ] Todo timestamp em UTC, ISO 8601, terminando em `Z`
- [ ] Toda entrada da timeline tem 6 campos e está em ordem cronológica
- [ ] Toda DECISION tem justificativa + fonte + (quando aplicável) aprovador
- [ ] Nenhuma entrada antiga reescrita (correções = entradas novas que citam a antiga)
- [ ] YAML válido: `python3 -c "import yaml;yaml.safe_load(open('eradication_checklist.yaml'))"`
