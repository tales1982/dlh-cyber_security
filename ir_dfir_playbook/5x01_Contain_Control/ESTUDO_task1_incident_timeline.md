# Estudo – 5x01 Contain and Control · Task 1: Open the Incident Timeline

## 1. O que era o exercício

Você está de plantão no SOC da MedDefense. Às **02:47:11Z** dispara um alerta na estação clínica **WST-WS-031** (usuário Daniel Marsh, `dmarsh`, técnico de laboratório com acesso ao LIS). O IR Commander James Chen manda: *"You own this. Contain it. Document everything."*

A Task 1 pede para criar o `incident_timeline.md`, o **registro oficial (autoritativo)** do incidente, com:

| Parte | O que contém |
|---|---|
| **Header** | `incident_id`, `declared_at`, `declared_by`, `initial_severity`, `current_severity`, `ir_commander`, `scribe` |
| **Legend** | Definição dos 5 tipos de entrada: OBSERVATION, DECISION, ACTION, COMMUNICATION, EVIDENCE |
| **Entries** | Lista cronológica: `timestamp UTC | tipo | ator | descrição em 1 linha | source= | certainty=` |

Entradas mínimas obrigatórias: **o alerta das 02:47:11Z**, **a declaração do incidente** e **a severidade inicial com justificativa**.

Fontes de evidência: `alert_A-20260414-9841.json` e `proxy_24h_dmarsh.log`.

## 2. O que deveria aprender

1. **Abrir a timeline no momento da declaração**, não depois. *"Se não está na timeline, não aconteceu."*
2. **Append-only:** nunca reescrever uma entrada antiga. Se a interpretação mudar, adicione uma **nova** entrada que referencia a antiga. É isso que dá valor legal ao documento (cadeia de custódia, auditoria HIPAA/LGPD).
3. **Separar fato de suposição** usando o campo `certainty`.
4. **Justificar cada decisão no momento em que ela é tomada**, citando a fonte (alerta, log, playbook, matriz de severidade).
5. **Fazer triagem lendo os dados de verdade**, e não só o resumo do alerta.

## 3. Como resolvi, passo a passo

### 3.1 Lendo o alerta (`alert_A-20260414-9841.json`)

| Campo | Valor | Significado |
|---|---|---|
| Regra | `wz-edr-100041` – PowerShell → MSBuild | Árvore de processos suspeita |
| MITRE | **T1059.001** (PowerShell) e **T1127.001** (MSBuild) | Execução + *Trusted Developer Utilities Proxy Execution* |
| Pai | `powershell.exe -ep bypass -w hidden -enc ...` | Ignora a execution policy, janela oculta, comando ofuscado em base64 |
| Filho | `MSBuild.exe C:\Users\dmarsh\AppData\Local\Temp\update.xml` | **LOLBin**: o MSBuild é assinado pela Microsoft, mas compila e executa código C# embutido num `.xml` |
| Rede | `185.220.101.47:443`, 4198 B enviados / 11203 B recebidos | **Tor exit relay** (VT 22/91, AbuseIPDB 84). Comportamento de C2/beacon |

**Decodificando o `-enc`** (é base64 de UTF-16LE):

```bash
echo 'JABzAD0A...' | base64 -d | iconv -f UTF-16LE -t UTF-8
# $s="https://ms0365-support[]login-verification[]click/auth";
```

O próprio comando PowerShell aponta para o domínio de phishing, o que liga a execução ao phishing.

### 3.2 Lendo o proxy (`proxy_24h_dmarsh.log`), a parte mais importante

| Hora (13/04) | Evento | O que prova |
|---|---|---|
| 18:13:44 | Abre o e-mail `AAMkAG` no Outlook | — |
| 18:14:02 | GET `/auth` no domínio falso, **referer = o e-mail** | Clicou no link de phishing (**confirmed**) |
| 18:14:07–09 | Baixa `ms-logo.svg` e `login.css` | Página falsa de login da Microsoft renderizou |
| **18:14:41** | **POST `/auth/submit` → 302** | Enviou o formulário: **credenciais provavelmente entregues** (**probable**, porque não vemos o corpo do POST) |
| 18:14:43 | GET `/auth/drop/update.zip` (421 KB) | Baixou o payload (**probable** que vire o `update.xml`) |
| 14/04 02:46–02:47 | CONNECT 185.220.101.47:443 com **4198/11203 bytes** | Mesmos bytes do alerta: **duas fontes independentes** confirmam o C2 |

> ⚠️ **Pegadinha:** o rascunho anterior dizia *"credential submission is not established"*. O log mostra um **POST para `/auth/submit`**. Ler só a linha que o alerta cita (`supporting_indicators`) faz perder isso. Sempre leia o log inteiro em volta do evento.

### 3.3 Escolhendo a severidade (usando `5x00/severity_matrix.md`)

- **SEV2** = *"Malware confirmed on a single workstation at a clinical site"* e *"Confirmed compromise of a clinical-access account"*. Bate com o caso.
- **Não é SEV1:** um único host, nenhuma exfiltração confirmada, nenhuma queda de serviço clínico, conta não privilegiada.
- **Não é SEV3:** SEV3 é *"phishing clicado, sem credencial confirmada"*. Aqui há código malicioso executando e C2 ativo.
- Gatilhos de escalada registrados: conta privilegiada, outros hosts ou exfiltração do LIS → **SEV1**.

### 3.4 Uso do `certainty`

| Nível | Quando usei |
|---|---|
| `confirmed` | Está literalmente no log/alerta (o alerta disparou, o clique, as conexões) |
| `high` | Decisão bem fundamentada, mas que depende de interpretação (escolha da severidade) |
| `probable` | Forte indício sem prova direta (POST = credenciais; zip = xml) |
| `possible` | Hipótese fraca (não usei na task 1) |

## 4. A matéria: Resposta a Incidentes, contenção e controle

### 4.1 O ciclo NIST SP 800-61r2

```
Preparação → Detecção & Análise → Contenção, Erradicação & Recuperação → Pós-incidente
                                       ↑____________ loop ____________↓
```

O projeto 5x01 cobre a fase 3, e a Task 1 é a ponte entre a detecção e a contenção.

### 4.2 Por que a timeline vem primeiro

- **Memória falha sob pressão.** Às 3 da manhã você não vai lembrar a ordem do que fez.
- **Handoff:** a Dra. Morales e a Helena Reyes vão acordar e ler *só isso*. Precisa ser autoexplicativo.
- **Valor legal:** em saúde (dados de paciente), a timeline vira prova. Por isso ela é *append-only*: editar uma entrada antiga parece adulteração.
- **Decisão registrada na hora** mostra *o que se sabia naquele momento*. Isso protege o analista se, depois, a decisão parecer errada em retrospecto.

### 4.3 Os 5 tipos de entrada

- **OBSERVATION:** fato bruto ("vi X no log Y").
- **DECISION:** escolha + **porquê** ("declarei SEV2 porque...").
- **ACTION:** algo feito num ativo + quem fez ("isolei o host via EDR").
- **COMMUNICATION:** quem avisou quem, por qual canal.
- **EVIDENCE:** artefato preservado + **hash** + **caminho** (cadeia de custódia, Task 2).

### 4.4 Ordem de operações (o que vem nas próximas tasks)

1. **Preservar evidência volátil antes de conter** (RFC 3227, ordem de volatilidade: memória RAM → conexões de rede → processos → disco). Se você isolar ou desligar a máquina primeiro, perde a memória do MSBuild e a sessão de C2.
2. **Contenção**, que pode ser de curto prazo (isolar host no EDR, bloquear IP/domínio, desabilitar a conta, revogar sessões/tokens) ou de longo prazo (reset de senha, MFA, reimagem). Cada opção tem **custo operacional**: isolar uma estação clínica pode atrasar resultados de laboratório.
3. **Reavaliar a severidade quando o escopo mudar** (o `auth_expansion_0334Z.log` sugere movimento lateral para outros hosts como `WST-WS-017` e `LIS-WSIDE-01`).
4. **Erradicação como checklist verificável**: processos, persistência (Run keys, tarefas agendadas, serviços, WMI), credenciais e rede.
5. **Recuperação com prova** (health checks do `lis-api`/`epic-api`), não com "parece ok".
6. **Handoff:** outro analista assume sem precisar fazer perguntas.

### 4.5 Conceitos de ataque deste caso

- **Phishing de credenciais** (T1566.002): link num e-mail leva a uma página falsa de login do M365.
- **LOLBins / LOLBAS:** binários legítimos e assinados (MSBuild, certutil, rundll32) usados para executar código malicioso e burlar a lista de aplicações permitidas. É por isso que `signed: true` **não significa seguro**.
- **PowerShell ofuscado:** `-enc` (base64 UTF-16LE), `-w hidden` e `-ep bypass` juntos são um sinal clássico de ataque.
- **C2 via Tor:** dificulta atribuição e bloqueio. Use as listas de exit nodes para bloquear.

## 5. Checklist de revisão rápida

- [ ] Todo timestamp é UTC, ISO 8601, termina em `Z`?
- [ ] Toda entrada tem os 6 campos (`ts | tipo | ator | descrição | source= | certainty=`)?
- [ ] A descrição cabe numa linha?
- [ ] Toda DECISION tem justificativa e fonte?
- [ ] Separei o que é confirmado do que é provável?
- [ ] Nenhuma entrada antiga foi reescrita? Correções entram como entradas novas que referenciam a antiga.
