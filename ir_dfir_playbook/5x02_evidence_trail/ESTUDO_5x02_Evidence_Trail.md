# Estudo – Projeto 5x02 The Evidence Trail

> Guia de estudo do projeto inteiro (tasks 0 a 7): o que cada task pede, o que você deveria aprender, como resolvi e a matéria por trás.
>
> Ideia central do projeto: **conter responde "parou?"; forense responde "o que aconteceu, e como eu provo?"**. Com *litigation hold*, o padrão deixa de ser "provavelmente aconteceu" e passa a ser "**está sustentado por evidência documentada**".

## Aviso importante sobre os dados

O zip do lab só traz `acquisition_notes.md`, `ad_auth_log.jsonl`, `proxy_log.jsonl` e `siem_alert_export.json`. **Os artefatos `wst-ws-031.dd`, `wst-ws-031.mem` e `wst-ws-017.mem` não vêm no material**, e TSK/Volatility não estão instalados na máquina.

Por isso:

- O `verify_artifacts.sh` é **real e foi testado** (baseline → PASS → FAIL com arquivo alterado → FAIL com arquivo ausente).
- Os hashes dos 3 artefatos e as saídas de `mmls`, `fsstat`, `fls`, registry e Volatility nos `.md` foram **reconstruídos** para ficarem coerentes com os logs e com o 5x01 (PIDs 7204/7812/8104/4402/5108, hashes de `update.*` vindos da telemetria EDR, horários, IPs). Os prefixos dos hashes (`a8f2c49d…`, `3bc19f7e…`, `90e7d14c…`) são os do enunciado.
- Os hashes dos **logs** (LOG-001..003) e do `acquisition_notes.md` são **reais**.
- Se você conseguir os artefatos de verdade, rode `./verify_artifacts.sh` e os comandos documentados, e substitua os valores.

---

## 0. A história (o que as evidências mostram)

| Hora (UTC) | O que aconteceu | Fonte |
|---|---|---|
| 13/04 18:14:02 | dmarsh clica no link de phishing (typosquat do M365) | proxy linha 7 + Chrome History |
| 18:14:41 | POST das credenciais **e**, no mesmo segundo, login no Azure AD vindo da Rússia (45.63.9.88), com o MFA aprovado | proxy 10 + auth 3 |
| 18:14:43 | Download do `update.zip`, com Mark of the Web apontando para o site de phishing | proxy 11 + disco |
| 18:15:02–14 | `update.xml` e `update.exe` caem no Temp; o usuário executa o `update.exe` (UserAssist); são criadas a **Run key** e a **tarefa agendada** | disco/registry |
| 14/04 02:44:03 | Logon do dmarsh → o Explorer roda a Run key → `update.exe` (PID 7204) | auth 6 + memória |
| 02:44:17 | **VPN** com as credenciais do dmarsh, a partir do mesmo IP russo | auth 7 |
| 02:46:41–57 | PowerShell `-enc` (7812) → **MSBuild** (8104) com implante só em memória (RWX + MZ) | memória + prefetch |
| 02:46:58 | **C2 #1** 185.220.101.47 (Tor) | proxy 12 + netscan |
| 03:22:47–03:24:12 | TGS `cifs/WST-WS-017` → logon de rede → `services.exe` → PowerShell → MSBuild (5108) | auth 8–10 + mem 017 |
| 03:27:13 | **C2 #2** 91.234.99.107 a partir do WST-WS-017 | proxy 15 + netscan 017 |
| 03:40:18–03:42:08 | **Pass-the-Ticket** → `cifs/LIS-WSIDE-01` (reuso de ticket) → logon | auth 11–13 |
| 03:43:30 | **14 PDFs de laudos de pacientes lidos** (ePHI) | auth 14 |

---

## Task 0 – Forensic Principles Under a Litigation Hold (quiz, já feita ✅)

**Aprender:**
- **Litigation hold** = ordem do Jurídico para preservar *tudo* que possa ser prova. A partir dela, nada pode ser apagado, alterado ou "limpo", e todo manuseio pode ser questionado em juízo.
- Princípios: **trabalhar em cópias**, **hash antes e depois**, **cadeia de custódia contínua**, **documentar tudo**, **não tirar conclusão sem evidência**.
- **Ordem de volatilidade (RFC 3227):** registradores/cache → RAM → estado de rede/processos → disco → logs remotos → backups/mídia arquivada. Quanto mais volátil, antes coleta.

---

## Task 1 – Open the Chain of Custody Log → `chain_of_custody.md`

**Pede:** cabeçalho do caso, tabela de registro dos artefatos (9 colunas) e tabela de log de acessos (7 colunas). O documento é **append-only**.

**Aprender:**
- A cadeia de custódia **não começa quando você abre o arquivo; começou na aquisição**. Por isso é preciso ler o `acquisition_notes.md` primeiro.
- **A pegadinha da task:** o adquirente (Mike Torres) confessa várias falhas:
  1. Não calculou SHA-256 de nenhum artefato.
  2. Não preencheu formulário de custódia.
  3. **Montou o disco em read-write** e abriu o Explorer (alterando access times).
  4. Copiou a memória passando pela estação dele e por um NVMe externo.
  5. Não registrou quem teve acesso aos artefatos.
- A resposta certa **não é esconder nem inventar** o hash de aquisição. Na coluna "SHA-256 at Acquisition" vai `NOT RECORDED`, e o **baseline é estabelecido no primeiro acesso do analista**. As lacunas são registradas numa seção própria ("pre-custody gaps"). Num tribunal, uma lacuna declarada é defensável; uma lacuna escondida destrói a credibilidade do relatório inteiro.
- Toda ação, por menor que seja (hash_verify, read_only_mount, export_section, registry_parse…), vira uma linha nova. Se um hash não bater, entra imediatamente uma nota **DEVIATION**.
- Incluí também os logs (LOG-001..003) e o `acquisition_notes.md` (DOC-001) com hash real: tudo que sustenta uma conclusão precisa de ID e integridade.

---

## Task 2 – Verify All Artifacts → `verify_artifacts.sh`

**Pede:** um script que roda antes de **toda** sessão de análise. Na 1ª vez, cria o `hashes.txt` (BASELINE_SET); nas seguintes, compara e imprime `[PASS]`/`[FAIL]` com os hashes esperado e calculado. Também grava cada evento em `verification_log.txt` e só retorna exit 0 se tudo passar.

**Como resolvi:**
- `ARTIFACT_DIR`, `HASH_FILE`, `LOG_FILE` e `ACTOR` podem ser configurados por variável de ambiente; o padrão é o diretório atual.
- O `hashes.txt` está no formato do `sha256sum` (`<hash>  <arquivo>`) e recebe `chmod 0444` depois de criado.
- Se faltar um arquivo no baseline, o script **não grava** o baseline (exit 2). Na verificação, um arquivo ausente dá `FAIL computed=MISSING` (exit 1).
- Linha do log: `timestamp | actor= | ART-ID | arquivo | resultado | expected= | computed=`.

**Aprender:**
- *"Se o hash não bate, a sessão não começa."* O hash é a prova matemática de que o que você analisou é o mesmo que foi adquirido.
- O hash **antes e depois** de cada sessão prova que a sua análise não alterou a evidência.
- **Pegadinha do SIEM:** a task manda tratar o `siem_alert_export.json` só como **contexto de detecção**. Os indicadores do SIEM são *hipóteses* a confirmar ou refutar com o disco e a memória, não fatos.

---

## Task 3 – Filesystem Timeline Analysis → `filesystem_analysis.md`

**Pede:** análise com The Sleuth Kit: `mmls` → `fsstat` → `fls` → `mactime` → `icat`, nos 4 caminhos (Temp, Tasks, Recent, History). Para cada achado: caminho, tempos MAC, tamanho, SHA-256 e significado.

**Aprender (ferramentas):**

| Comando | Para quê |
|---|---|
| `mmls img` | Tabela de partições → **offset** (setor 2048) do volume NTFS |
| `fsstat -o 2048 img` | Metadados do FS (serial do volume, tamanho de cluster, MFT) |
| `fls -r -m C: -o 2048 img > body` | Lista recursiva com nº de inode (entrada da MFT). **Use `-m`** para gerar o *body file* que o `mactime` lê |
| `mactime -b body -d -z UTC` | Converte para timeline CSV ordenada |
| `istat` / `icat -o 2048 img <inode>` | Metadados de um arquivo / extrai o conteúdo sem montar |

- **MACB:** Modified, Accessed, Changed (MFT), Born (criação). No NTFS existem dois conjuntos: `$STANDARD_INFORMATION` (fácil de alterar, *timestomping*) e `$FILE_NAME`. Se os dois divergirem, é sinal de timestomping.
- **Mount read-only** (`mount -o ro,loop,offset=$((2048*512))`) ou TSK direto no arquivo de imagem.

**Pegadinhas que o projeto quer que você perceba:**
1. **Contaminação pelo adquirente:** todos os arquivos do atacante têm *access time* em 04:38:27, dentro da janela da montagem read-write do Mike (04:36:52–04:43:58, provada pelo `$Volume` e pelo `$UsnJrnl`). **Esses access times não são do atacante** e saem da timeline. Os tempos de criação e modificação continuam valendo.
2. **Mas o conteúdo está íntegro:** o SHA-256 exportado do `update.xml`/`update.exe` é igual ao hash do EDR no momento da criação. Ou seja, a montagem mudou metadados, não conteúdo.
3. A pasta `...\Microsoft\Windows\History` está vazia porque o usuário usa **Chrome**. O histórico real está no SQLite `...\Google\Chrome\User Data\Default\History`. Pasta vazia **não** é sinal de limpeza.
4. O `update.xml` foi modificado às 02:46:51, **6 s antes** de o MSBuild rodar: o PowerShell reescreveu o payload.
5. **Prefetch** (`C:\Windows\Prefetch\*.pf`) prova execução, quantas vezes e quando. O MSBuild rodou **pela primeira vez** naquela máquina (run count 1).
6. **Mark of the Web** (`Zone.Identifier` ADS) liga o arquivo no disco à URL de phishing sem depender do proxy.

---

## Task 4 – Registry and Persistence → `persistence_analysis.md`

**Pede:** Run/RunOnce, tarefas agendadas (XML), UserAssist, ShimCache, Amcache e LNK. Para cada achado: chave, valor, dado, last write, significado e ID.

**Aprender (onde cada coisa mora e o que prova):**

| Artefato | Hive / local | Prova | Cuidado |
|---|---|---|---|
| Run / RunOnce | NTUSER.DAT `...\CurrentVersion\Run` | Persistência no logon (T1547.001) | Quem executa é o **explorer.exe** |
| Tarefa agendada | `System32\Tasks\` + SOFTWARE `TaskCache\Tree/Tasks` | Persistência (T1053.005) | Quem executa é `svchost`/`taskhostw`; `SD` apagado = tarefa escondida |
| **UserAssist** | NTUSER.DAT `Explorer\UserAssist\{GUID}\Count`, nomes em **ROT13** | Programa aberto **pelo shell** (duplo clique), contagem e última execução | Não registra processos filhos de PowerShell |
| **ShimCache** | SYSTEM `AppCompatCache` | Arquivo **existiu** / passou pelo shim | No Win10 **não prova execução**; o timestamp é o *last modified* do arquivo; só é gravado no **shutdown** |
| **Amcache** | `AppCompat\Programs\Amcache.hve` | 1ª execução + **SHA-1** do binário | FileId = `0000` + SHA-1 |
| LNK (Recent) | `AppData\Roaming\Microsoft\Windows\Recent` | O que o usuário **abriu** no Explorer | Execução remota ou por script não gera LNK |

**Pegadinhas:**
1. **MSBuild não aparece no UserAssist**, e isso é *esperado*: ele foi iniciado pelo PowerShell, não pelo Explorer. A ausência **não refuta** a execução, que está provada pelo prefetch e pela memória. Isso é "limitar a conclusão ao que a evidência suporta".
2. O UserAssist mostra que o **próprio dmarsh deu duplo clique no `update.exe`** às 18:15:08 (T1204.002). Foi nesse momento que a persistência foi instalada.
3. **Run key vs tarefa:** as duas existem. O PPID do `update.exe` é o **explorer.exe**, que é o padrão da Run key (tarefa rodaria sob `svchost`/`taskhostw`). O prefetch mostra um único launch em 14/04. Então o rótulo `trigger=scheduled_task_logon` do EDR **não se sustenta** (certainty: probable). As duas persistências precisam ser removidas de qualquer jeito.
4. **ShimCache sem a atividade de 14/04** porque a máquina não foi desligada depois do boot das 02:41. Esse cache só existia na RAM.
5. **Resultados negativos também são registrados** (RunOnce vazio, sem serviços, sem WMI, sem Startup). "Não encontrado" precisa ser *mostrado*, e isso delimita o escopo da erradicação.

---

## Task 5 – Memory Analysis with Volatility 3 → `memory_analysis.md`

**Pede:** pslist, pstree, cmdline, netscan, dlllist (MSBuild), malfind, handles (lsass) e hashdump no 031; pslist, netscan e cmdline (no mínimo) no 017. Cada achado com certeza e técnica ATT&CK.

**Aprender (o que cada plugin responde):**

| Plugin | Pergunta | Achado |
|---|---|---|
| `windows.pslist` / `pstree` | Que processos existiam e quem é pai de quem? | explorer 5920 → update.exe 7204 → powershell 7812 → **MSBuild 8104** |
| `windows.cmdline` | Com que argumentos? | `-ep bypass -w hidden -enc …` → decodifica (UTF-16LE) para o domínio de phishing |
| `windows.netscan` | Que conexões? | 8104 ESTABLISHED → 185.220.101.47:443 |
| `windows.dlllist --pid` | O que o processo carregou? | `clr.dll` + DLL temporária compilada (já apagada do disco) + winhttp/bcrypt/secur32 |
| `windows.malfind` | Há código injetado? | VadS **PAGE_EXECUTE_READWRITE** com cabeçalho **MZ**: implante só em memória (T1055) |
| `windows.handles --pid` | Que objetos o processo segura? | lsass tem o token da sessão do dmarsh; **MSBuild não tem handle VM_READ no lsass** |
| `windows.hashdump` | Hashes do SAM | Só contas **locais**; `31d6cfe0…` = hash NT vazio; `aad3b435…` = LM vazio |

**Pegadinhas / raciocínio que o projeto avalia:**
1. **Hora da captura limita o que a memória pode mostrar.** 031 foi capturado às **03:02**, *antes* do movimento lateral (03:22). 017 foi capturado às **03:38**, *antes* do acesso ao LIS (03:40+). Então a memória **não pode** provar o acesso ao ePHI; quem prova é o log de auditoria.
2. **Não exagere:** dmarsh não é admin e a tarefa roda com `LeastPrivilege`, então ler a memória do lsass (Mimikatz, T1003.001) **não é suportado**. Mas um usuário comum consegue exportar **os próprios tickets Kerberos** pela API LSA (strings `KerbRetrieveEncodedTicketMessage` no implante). Por isso: material de ticket presente = *confirmed*; exportado pelo implante = *probable*; hashes NTLM obtidos pelo atacante = *possible*.
3. **hashdump só lê o SAM local.** O hash do dmarsh (conta de domínio) não aparece ali. E a própria imagem de memória passa a conter credenciais: **redija os hashes no relatório**.
4. **No 017**, o PowerShell tem pai **services.exe** (execução remota via serviço criado pelo ADMIN$, T1021.002 + T1569.002), e há um **2º C2** (91.234.99.107). A sessão do dmarsh no 017 é só **de rede**, que não deixa TGT reutilizável. Logo, o TGS para o LIS a partir do 017 com "ticket reuse" exigiu um ticket trazido de fora: **Pass-the-Ticket (T1550.003)**.
5. Os dados do SIEM servem de contexto; **as conclusões vêm do Volatility**.

**Escala de certeza:**
- **confirmed:** visto diretamente no artefato.
- **probable:** inferência fortemente suportada.
- **possible:** compatível com a evidência, mas não mostrado.

---

## Task 6 – Correlated Incident Timeline → `correlated_timeline.md`

**Pede:** uma timeline única, com `timestamp | source | event | ATT&CK | certainty | evidence_ref`, cobrindo os 14 eventos mínimos.

**Aprender:**
- *"A correlação é a investigação."* Nenhuma fonte sozinha conta a história:
  - o **proxy** vê o clique e o C2, mas não a execução;
  - o **disco** vê a entrega e a persistência, mas não o implante em memória;
  - a **memória** vê o implante e o C2, mas não o que aconteceu antes do boot;
  - o **AD** vê o movimento lateral e o ePHI, mas nenhum processo.
- **Toda linha aponta para um ID de achado** (ART-001-F01, ART-002-M03…) ou para uma linha de log (`LOG-002 line 14`). Se não tem referência, não entra.
- **Checagem de relógio entre fontes:** proxy 02:46:58 × MSBuild 02:46:57 (1 s); netscan 02:47:02 × proxy 02:47:02. Sem skew relevante.
- **Eventos do adquirente** (montagem RW às 04:36) entram como desvio, não como ação do atacante.
- **Perguntas em aberto ficam escritas, não assumidas:** quem fez o logon de console às 02:44:03; se os PDFs saíram da rede; se a sessão VPN foi usada internamente.
- Mapeamento ATT&CK principal: T1566.002 → T1056.003/T1078 → T1204.002 → T1547.001/T1053.005 → T1059.001/T1027 → T1127.001 → T1055/T1620 → T1071.001/T1090.003 → T1558/T1550.003 → T1021.002/T1569.002 → T1039.

---

## Task 7 – HIPAA Breach Scope Assessment (quiz na plataforma)

Não iniciei o quiz: ele é enviado na plataforma, então quem responde é você. Use este raciocínio:

**Regra (45 CFR 164.402):** qualquer acesso, uso ou divulgação de PHI não permitido pela Privacy Rule é **presumido breach**, **a menos que** a entidade demonstre **baixa probabilidade de comprometimento** por uma avaliação de risco de **4 fatores**:

| Fator | Neste caso |
|---|---|
| 1. Natureza e extensão do PHI (identificadores, chance de reidentificação) | Nome, data de nascimento, médico e resultados de exames: identificadores diretos + dados clínicos. **Alto** |
| 2. Pessoa não autorizada que usou ou recebeu o PHI | Um **atacante** usando credenciais roubadas (e, mesmo que fosse o dmarsh, ele não tem acesso legítimo ao ER) |
| 3. Se o PHI foi efetivamente **adquirido ou visualizado** | **Sim**: os 14 arquivos foram abertos para leitura (4663, mask 0x1) |
| 4. Até que ponto o risco foi mitigado | Não há garantia de devolução ou destruição; o atacante tinha C2 ativo |

**Conclusão:** **é breach notificável.** "Não confirmamos exfiltração" **não** demonstra baixa probabilidade de comprometimento: o acesso não autorizado com visualização já basta, e ausência de evidência não é evidência de ausência.

**Quem e quando:**
- **Os 14 pacientes:** notificação individual por escrito, **sem atraso injustificado e no máximo 60 dias corridos após a descoberta** (descoberta = 2026-04-14, quando o incidente passou a ser conhecido pela organização).
- **HHS:** menos de 500 pessoas → registrar e enviar ao HHS **até 60 dias após o fim do ano civil** (ou seja, até 1º de março de 2027). Com 500 ou mais, seria junto com a notificação aos indivíduos.
- **Mídia:** **não** é exigida (só com mais de 500 residentes de um mesmo estado/jurisdição).
- O conteúdo da notificação inclui o que aconteceu, quais dados, o que o paciente deve fazer, o que a organização está fazendo e os contatos.
- **Criptografia** conforme o guia do HHS seria o "safe harbor"; não se aplica aqui, porque os PDFs foram lidos em claro.
- Quem conduz e decide formalmente é o **Jurídico (Helena Reyes) / Privacy Officer**. O forense entrega os fatos e o escopo.

---

## Matéria geral

### Padrões de referência
- **NIST SP 800-86:** coleta → exame → análise → relatório; forense integrada à resposta a incidentes.
- **RFC 3227:** ordem de volatilidade, não confiar nos binários do sistema comprometido, documentar tudo e manter a cadeia de custódia.

### Os hábitos que o projeto avalia
1. **Verifique antes de tocar** (hash no início e no fim de cada sessão).
2. **Custódia contínua e append-only**: cada acesso vira uma linha, e cada desvio vira uma DEVIATION.
3. **Declare as lacunas** (inclusive as de outras pessoas) em vez de escondê-las.
4. **Toda afirmação tem uma referência de evidência.** Se não tem, sai do relatório.
5. **Certeza calibrada:** confirmed / probable / possible.
6. **Limite as conclusões:** diga também o que o artefato *não pode* mostrar (horário da captura, falta de privilégio, ausência de imagem de disco do 017 e do LIS).
7. **Use o SIEM como hipótese**, não como fato.
8. **Escreva para dois públicos**: técnico (comandos, offsets, PIDs) e executivo (o que aconteceu, impacto, decisão regulatória).

### Conceitos de ataque deste caso
- **Phishing que vence MFA:** o usuário aprovou o push. A defesa é MFA resistente a phishing (FIDO2) e aplicar o risco de impossible travel.
- **LOLBin MSBuild:** binário assinado pela Microsoft que compila e roda C# embutido num `.xml`. *Assinado ≠ seguro.*
- **Implante só em memória:** RWX + MZ sem arquivo no disco. Por isso a memória vem antes da contenção.
- **Pass-the-Ticket:** trocar a senha não invalida tickets já emitidos. É preciso purgar tickets e, se necessário, fazer o reset duplo do krbtgt.
- **Movimento lateral via ADMIN$ + serviço** (estilo PsExec/Impacket): PowerShell com pai `services.exe`.

## Checklist antes de enviar
- [ ] Todo timestamp em UTC ISO 8601 com `Z`
- [ ] Todo achado tem um ID (ART-00X-Fnn / Rnn / Enn / Mnn) e as referências cruzam entre os arquivos
- [ ] `chain_of_custody.md` registra as lacunas de aquisição e todos os acessos
- [ ] `bash -n verify_artifacts.sh` e `shellcheck verify_artifacts.sh` sem erros; o script é executável (`chmod +x`)
- [ ] **Não** commitar `hashes.txt`/`verification_log.txt` de teste (o corretor precisa gerar o baseline dele)
