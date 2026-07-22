# Teoria e Tópicos — 1x00 First Watch

Guia de estudo com teoria + exemplos práticos do cenário MedDefense, para cada exercício do módulo. Este é o **primeiro** módulo da trilha: a pergunta central é **"o que a MedDefense tem, e onde estão as falhas de controle?"** — um levantamento interno (assessment de postura), sem ainda falar de quem quer atacar (isso é o 1x01) ou de vulnerabilidades técnicas escaneadas (isso é o 1x02).

---

## 0. Environment Summary

**O que é:** o levantamento bruto e estruturado do ambiente — sites, infraestrutura, dados, e principalmente os **Known Unknowns** (o que ainda não se sabe). É o ponto de partida de qualquer assessment: não dá para proteger o que não foi mapeado.

**Estrutura usada:** Organization Overview (sites, headcount, estrutura de reporte) → IT Infrastructure (servidores, rede, endpoints, dispositivos médicos) → Data and Services (o que cada sistema guarda e sua criticidade) → **Known Unknowns** (lacunas de conhecimento documentadas explicitamente, por categoria: rede, servidores, autenticação, física, compliance, dispositivos médicos).

**Por que "Known Unknowns" é uma seção formal, não um detalhe:** documentar explicitamente "não sabemos se X" é tão valioso quanto documentar um fato confirmado — transforma um ponto cego silencioso em um item rastreável que alguém pode decidir investigar. Um assessment que só lista certezas esconde exatamente os riscos mais perigosos (o que ninguém verificou ainda).

**Detalhe de governança que já aparece aqui e ecoa o módulo inteiro:** o CISO está vago (James Chen é Deputy, apenas), e James tem autoridade sobre política de segurança mas **não** sobre operações de TI (controladas por Sarah Park, uma colega, não subordinada) — essa fricção organizacional volta a aparecer em praticamente todo exercício de governança dos módulos seguintes.

**Exemplo:** a rede de Central é totalmente plana (`10.10.0.0/16`), dispositivos médicos, estações e servidores compartilham o mesmo domínio de broadcast — esse único fato, registrado aqui como "Known Unknown/planejado mas sem prazo", se torna a causa raiz repetida em praticamente todo gap crítico documentado nos itens seguintes.

---

## 1. Incident Classification

**O que é:** classificar incidentes históricos usando a **Tríade CIA** (Confidentiality, Integrity, Availability) — o vocabulário mais fundamental de segurança da informação, usado para nomear *qual tipo* de dano um evento causou.

**Metodologia correta:** identificar o **pilar primário** (o impacto direto e explícito descrito no relato) e só listar um **pilar secundário** se houver evidência textual explícita — nunca por especulação. Isso evita inflar a gravidade de um incidente com impactos hipotéticos que o registro não sustenta.

**Erro clássico a evitar:** confundir "o sintoma mais visível" com "o pilar realmente violado". Um ransomware que criptografa um servidor parece, à primeira vista, um problema de **Disponibilidade** (o servidor caiu) — mas a criptografia em si é uma modificação não autorizada do dado, o que também é **Integridade**. Já um IDOR que expõe resultado de exame de outro paciente é puramente **Confidencialidade** — nada foi alterado, nada caiu.

**Exemplo:** laptop pessoal não gerenciado na rede por 3 semanas → primário **Confidencialidade** (bypassa a segmentação e alcança o mesmo segmento do compartilhamento de RH), secundário **Disponibilidade** (um cliente de torrent gera tráfego pesado sustentado, podendo degradar a rede clínica/administrativa que compartilha o mesmo link).

---

## 2. Root Cause Analysis

**O que é:** ir além do sintoma óbvio ("a CPU está saturada") até a **causa raiz real** de um incidente técnico — neste caso, um processo de cryptojacking disfarçado de processo legítimo do kernel Linux.

**Técnica central: reconhecer disfarce de processo.** Um `kworker` real roda como `root` e aparece como `[kworker]` entre colchetes; o processo malicioso aqui roda como `www-data`, a partir de um caminho de arquivo (`/var/www/html/.cache/kworker`) — um nome escolhido deliberadamente para se camuflar na lista de processos.

**A cadeia real de comprometimento (na ordem certa):** primeiro **Confidencialidade** foi quebrada (acesso não autorizado através da própria aplicação web), depois **Integridade** (um binário estranho foi enviado e executado), e só **por último**, como sintoma visível, veio a saturação de CPU (**Disponibilidade**). A lição central: o pilar que dispara o alarme nem sempre é o primeiro pilar realmente violado.

**Por que a "solução" do sysadmin (upgrade de hardware) falha:** o minerador está configurado para usar qualquer CPU disponível — uma VM maior só dá mais capacidade de mineração ao atacante, sem tocar em como ele entrou. Trocar o sintoma pelo hardware maior não fecha a porta de entrada.

**Conectando dois incidentes aparentemente não relacionados:** dois comprometimentos diferentes no mesmo servidor, depois de um rebuild completo, significa que o rebuild resetou o **sintoma**, não a **causa** — a mesma vulnerabilidade (Apache 2.4.29 com RCEs conhecidas) provavelmente sobreviveu ao rebuild.

**Exemplo:** a recomendação final não é "aumentar a VM", é confirmar a versão do Apache contra os CVEs conhecidos e auditar outros servidores rodando a mesma versão vulnerável — tratando a causa, não o sintoma.

---

## 3. Physical Assessment

**O que é:** avaliar risco de segurança **física** — como alguém pode causar dano tendo acesso ao prédio, sem tocar em nenhum sistema remotamente.

**Framework de decomposição usado em cada observação (4 componentes formais):**
- **Vulnerability:** a fraqueza física concreta (porta sem trava, credencial exposta, sessão sem timeout).
- **Threat:** quem se beneficiaria de explorar essa fraqueza, e como.
- **Impact:** qual(is) pilar(es) da CIA seriam quebrados.
- **Severity:** justificada em uma frase, pesando facilidade de exploração contra impacto.

**Por que essa decomposição formal importa:** transforma uma observação genérica ("a porta fica aberta") em uma análise de risco defensável, na mesma estrutura usada para vulnerabilidades técnicas — segurança física não é uma categoria à parte, é risco com a mesma anatomia.

**Padrão que se repete nas 5 observações:** a maioria exige **zero habilidade técnica** para explorar (crachá genérico, senha escrita na parede, porta de emergência travada aberta com cunha) — a barreira de entrada para um ataque físico bem-sucedido aqui é quase nula, o que eleva a severidade mesmo quando o "ataque" em si é trivial.

**Exemplo:** o armário de rede (Observação 2) não tem trava, a porta fica entreaberta, e um papel colado na parede lista usuário e senha de gerenciamento do switch — severidade **Crítica**, porque não exige nenhuma habilidade e compromete conectividade/tráfego de um andar inteiro.

---

## 4. Control Inventory

**O que é:** catalogar formalmente **todo controle de segurança já existente** — o inventário que serve de base para toda análise de gap subsequente (não dá para achar o que falta sem primeiro listar o que já existe).

**Duas dimensões de classificação de cada controle (usadas no módulo inteiro daqui em diante):**
- **Category:** Technical / Administrative / Physical — *onde* o controle vive.
- **Function:** Preventive / Detective / Corrective / Compensating / Deterrent — *o que* o controle faz.

**Por que cruzar essas duas dimensões numa matriz:** uma matriz Category × Function revela **padrões de investimento** de forma visual — células vazias saltam aos olhos de um jeito que uma lista linear de controles não revela.

**Padrão que já aparece aqui (e se confirma nos próximos itens):** a matriz do Task 4 mostra controles concentrados quase inteiramente em **Preventive**, com pouquíssima cobertura **Detective** e praticamente nenhuma **Corrective/Compensating/Deterrent** — o mesmo padrão de "prevenção sim, detecção e resposta quase zero" que se torna o tema central de todo o módulo.

**Exemplo:** C-009 (backup noturno Veeam) é Technical/**Corrective** — existe, mas é o único controle corretivo do inventário inteiro, e sozinho não compensa a ausência de qualquer controle Detective ou Compensating.

---

## 5. Control Gaps

**O que é:** a partir do inventário do item 4, identificar formalmente **onde falta cobertura** — cruzando Category × Function e perguntando "que combinação deveria existir e não existe?"

**Metodologia de rigor:** um gap "sem controle Detective E Corrective" só é classificado como tal se **ambas** as funções estiverem genuinamente ausentes — se existe um controle Corrective (ex: backup) mas falta o Detective, o gap é rebaixado de Critical para High. Essa disciplina evita inflar artificialmente a severidade.

**O padrão central que este item formaliza:** MedDefense é fortemente orientada à prevenção; a cobertura detective é fina e não monitorada; corretivo/compensatório/deterrente estão quase totalmente ausentes. Isso significa que, uma vez que um atacante passa de um controle preventivo — o que **já aconteceu duas vezes** no `billing-srv-01` — a organização tem pouquíssima capacidade de perceber, conter ou se recuperar rapidamente: incidentes são descobertos por acidente, não por design.

**Exemplo:** G-002 (logs existem — SSH, firewall — mas nada os revisa ou alerta ativamente) é rated **Critical**, porque a única forma de detecção é "verificamos manualmente quando algo quebra" — exatamente o que permitiu ao cryptominer do item 2 rodar sem ser notado por duas semanas.

---

## 6. Compensating Controls

**O que é:** desenhar uma estratégia de mitigação para um risco que **não pode ser corrigido na origem** — o caso clássico é um sistema legado que não pode ser atualizado, substituído ou desconectado (a estação de controle da ressonância magnética, rodando Windows XP).

**Por que "compensar" é diferente de "corrigir":** um controle compensatório não toca na vulnerabilidade subjacente — ele reduz o **alcance** ou a **probabilidade de exploração** sem eliminar a falha em si. É a resposta correta quando a correção direta (patch, upgrade, substituição) é impossível por restrição de negócio, não de vontade técnica.

**As 3 categorias de estratégia compensatória (aparecem juntas, reforçando-se):**
- **Technical/Compensating:** isolar a rede (segmentação, VLAN dedicada) — não toca o SO, muda apenas onde o dispositivo "vive" na rede.
- **Administrative/Compensating:** um processo formal de aceitação e revisão de risco — não protege tecnicamente nada, garante que o risco continue sendo *ativamente rastreado* em vez de esquecido.
- **Physical/Preventive:** restringir acesso físico e travar portas USB — fecha o caminho que nenhum controle de rede consegue fechar (alguém tocando fisicamente no equipamento).

**Como priorizar entre as três quando só uma pode ser implementada imediatamente:** a segmentação de rede (Technical/Compensating) vence porque ataca a exposição arquitetural raiz (rede plana) em vez de gerenciar o problema administrativamente, é uma mudança técnica pontual que não depende de conformidade humana contínua (ao contrário do processo administrativo), e protege contra o caminho de ataque mais provável e escalável (rede) em vez do menos provável (acesso físico, que já exige o atacante estar dentro do prédio).

**Exemplo:** mesmo com as 3 camadas implementadas, o risco residual continua existindo — se o único host ainda permitido (PACS) for comprometido, ou se houver acesso físico direto, nenhum dos 3 controles oferece proteção. Isso é reconhecido explicitamente, não escondido.

---

## 7. Asset Registry

**O que é:** o inventário formal e único de **todo ativo** no ambiente — servidores, endpoints, dispositivos médicos, aplicações, infraestrutura de rede e física — cada um com ID, localização, dono, criticidade e status.

**Por que isso é a fundação de tudo que vem depois:** você não consegue avaliar criticidade (item 8), mapear dados (item 9), nem calcular risco financeiro (módulo 1x03) sobre um ativo que não está listado. O Asset Registry é o "banco de dados mestre" que todos os outros artefatos do currículo referenciam por ID (A-001, A-002...).

**Passo de reconciliação crucial: cruzar documentação contra um scan independente de rede.** Isso revela três tipos de discrepância, cada um com implicação diferente:
- **Ativo no scan, mas não na documentação (Shadow IT):** ninguém sabe que existe — o risco mais perigoso, porque está fora de qualquer controle.
- **Ativo na documentação, mas não no scan:** pode não existir mais, pode estar desligado, ou pode estar em um sistema não coberto pelo scan (nuvem, por exemplo).
- **Contradição entre fontes:** uma alegação repetida (ex: "a versão do Apache é X") precisa de verificação direta, não repetição confiante.

**Exemplo:** A-012 (`UNKNOWN-01`, 10.10.2.99) é um host Linux não documentado com dois serviços web, no mesmo subnet dos servidores centrais — Sarah não tem registro dele. Esse é exatamente o tipo de achado que só aparece cruzando o scan contra a documentação, nunca confiando em uma fonte isolada.

---

## 8. Criticality Assessment

**O que é:** para cada categoria de ativo do registro (item 7), atribuir uma classificação formal de criticidade usando a **Tríade CIA** — não "isso parece importante", mas uma pontuação C/I/A justificada por evidência.

**Como a criticidade de um ativo médico difere de um ativo de TI comum:** uma falha de Integridade/Disponibilidade num dispositivo médico não é "um problema de dado" — é um problema de **segurança do paciente** (leitura errada de sinais vitais, dosagem interrompida). Isso eleva a categoria inteira de IoT médico a Critical, independentemente de quão "simples" o dispositivo pareça tecnicamente.

**Como a rede plana afeta a criticidade de um ativo aparentemente comum:** um workstation individual tem impacto direto moderado — mas a ausência de segmentação (rastreada separadamente como risco de amplificação) transforma qualquer um deles num ponto de pivô para alcançar ativos muito mais críticos. A criticidade "isolada" de um ativo e seu papel real no risco do ambiente podem divergir.

**Exemplo:** `ehr-db-01` é o ativo #1 do Top 5 — não apenas por guardar PHI de 50.000+ pacientes, mas porque, **no momento da avaliação**, já está alcançável de toda a rede `/16` em vez de restrito ao servidor de aplicação — ou seja, sua exposição real é maior do que a criticidade isolada sugeriria, uma combinação que se repete no módulo 1x02 como o Finding 003.

---

## 9. Data Map

**O que é:** mapear **cada categoria de dado** (não cada sistema) através do seu ciclo de vida completo — em repouso (at rest), em trânsito (in transit) e em uso (in use) — junto com a proteção atual e as lacunas específicas de cada estado.

**Por que separar em 3 estados importa:** um dado pode estar bem protegido em repouso (criptografado no disco) e completamente exposto em trânsito (rede plana, sem TLS) — proteger só um estado dá uma falsa sensação de segurança completa.

**Classificação usada:** **Restricted** (dado de paciente, credenciais de sistema) vs. **Confidential** (financeiro, RH) — a MedDefense usa esses dois níveis, e cada linha do mapa herda o nível mais alto entre tudo que ela contém.

**A descoberta mais importante deste exercício:** a categoria de dado mais crítica em risco não é o prontuário médico em si — é a **credencial de sistema**, porque credencial é "Restricted" por definição (ela destranca acesso a todas as outras categorias), e mesmo assim a senha de gerenciamento do switch está fisicamente escrita numa folha colada na parede, e nenhum sistema no ambiente exige um segundo fator de autenticação. Uma falha na categoria "chave mestra" derruba a proteção de todas as outras categorias de uma vez.

**Exemplo:** dado de pesquisa clínica do Dr. Patel, guardado num NAS pessoal não gerenciado, é completamente **invisível** a qualquer controle do inventário do item 4 — sem backup, sem política de acesso, sem monitoramento, porque nunca foi formalmente reconhecido como um ativo da organização (ver item 11).

---

## 10. Complete Control Matrix

**O que é:** atualizar a matriz de controles do item 4 acrescentando uma nova dimensão — **Effectiveness** (Strong / Adequate / Weak) — e depois cruzar essa matriz contra os Top 5 ativos críticos do item 8, para ver *onde a proteção realmente falha nos lugares que mais importam*.

**Por que "existe" não é a mesma pergunta que "funciona bem":** um controle pode aparecer como presente na matriz do item 4 e ainda assim ser classificado **Weak** aqui — por exemplo, C-004 (SSH key-only) é forte no host onde foi implementado, mas **Adequate**, não Strong, porque nunca foi expandido para o resto da organização. Um controle "correto, mas isolado" não é o mesmo que um controle "correto e abrangente".

**O cruzamento mais revelador do exercício: Control Coverage Map dos Top 5 ativos.** Ele mostra, ativo por ativo, exatamente que função de controle está faltando — e o padrão é consistente: **quase todos os ativos mais críticos não têm nenhum controle Detective**, mesmo tendo algum Preventive/Corrective.

**Exemplo:** a frota de bombas de infusão BD Alaris aparece como **totalmente desprotegida** ("Unprotected") na matriz — nenhum controle de nenhuma categoria a protege diretamente, e o isolamento recomendado pelo fabricante nunca foi implementado — o pior resultado possível cruzando criticidade máxima (segurança do paciente) com cobertura zero.

---

## 11. Shadow Systems Assessment

**O que é:** investigar formalmente cada sistema de **Shadow IT** (tecnologia usada sem aprovação/governança formal de TI) descoberto ao longo do assessment, e decidir a resposta correta para cada um — nem toda Shadow IT merece a mesma resposta.

**As 3 respostas possíveis, e quando cada uma se aplica:**
- **Legitimize and Secure:** quando existe uma necessidade real e legítima por trás da Shadow IT (ex: o compartilhamento de rede era lento demais) — decomissionar sem alternativa só empurra o mesmo comportamento para um lugar ainda menos visível.
- **Migrate:** quando já existe uma alternativa sancionada e já paga, equivalente funcionalmente (ex: O365/SharePoint já licenciado, em vez de um Google Drive pessoal) — o caso mais claro de "por que pagamos por algo que já possuímos, só na sombra".
- **Decommission:** quando não há mais dono de negócio ativo para o sistema (o projeto original terminou quando a pessoa saiu) — não há necessidade legítima atual para legitimar.

**A lição de política mais importante do exercício:** a causa raiz comum aos 3 casos é a **ausência de um processo de intake rápido e de baixa fricção** para novas ferramentas — cada Shadow IT nasceu de uma necessidade real e nenhum caminho sancionado rápido para resolvê-la. Um processo formal com prazo de resposta definido (ex: 48h) remove o incentivo de resolver problemas silenciosamente fora da visão de TI — uma correção mais durável do que qualquer quantidade de detecção após o fato.

**Exemplo:** o Raspberry Pi "monitor de rede" no 2º andar provavelmente é o mesmo host não identificado (A-012) do scan de rede do item 7 — cruzar duas fontes de evidência independentes (a conversa com o helpdesk e o scan técnico) confirma que é o mesmo dispositivo, não um quarto dispositivo desconhecido.

---

## 12. Prioritized Gap Analysis

**O que é:** consolidar tudo dos itens 4-11 numa lista única e priorizada de **gaps de controle**, cada um com ID formal (GAP-XXX), nível de risco e evidência específica — o artefato central que alimenta o resto do currículo (1x01 e 1x02 citam esses GAP-IDs constantemente).

**Regra metodológica explícita (mesma disciplina do item 5, agora formalizada):** "sem controle detective ou corretivo" só justifica **Critical** se ambas as funções estiverem genuinamente ausentes — se uma delas existe (mesmo que fraca), o gap cai para **High**. Essa regra impede inflação de severidade e torna o rating defensável.

**Padrão de distribuição descoberto:** a esmagadora maioria dos gaps se concentra em funções **Detective e Corrective ausentes**, nunca em ausência total de Preventive — confirmando, com dados consolidados, o padrão que já vinha aparecendo desde o item 5: MedDefense nunca teve falta de vontade de bloquear ameaças conhecidas; falta a capacidade de perceber ou se recuperar das que passam mesmo assim.

**Exemplo:** GAP-004 (frota de bombas de infusão sem nenhum controle dedicado) é Critical porque combina um ativo de segurança do paciente com ausência total (Preventive, Detective e Corrective) e uma vulnerabilidade conhecida e sinalizada pelo próprio fabricante, nunca mitigada.

---

## 13. Reality Check

**O que é:** validar (ou refutar) a própria análise de gaps contra **casos reais de violação em outros hospitais** — testar se os gaps documentados batem com como ataques de verdade realmente aconteceram em organizações parecidas.

**Metodologia por breach:** para cada caso real, (1) identificar o vetor de ataque exato, (2) correlacionar cada etapa com os GAPs já documentados da MedDefense, e (3) fazer um **Blind Spot Check** — perguntar explicitamente "existe algo nesse breach que a MedDefense ainda não documentou em lugar nenhum?"

**Por que esse exercício é valioso além de simplesmente "confirmar" os gaps:** ele frequentemente revela gaps **novos**, que passaram despercebidos porque ninguém ainda tinha o caso concreto que os tornasse óbvios — três novos GAPs (017, 018, 019) nascem exatamente desse processo, não da auditoria interna original.

**Como um breach externo pode fazer um gap existente subir de prioridade:** se um caso real mostra um único gap, sozinho, causando uma violação completa e notificável, isso é evidência mais forte do que a análise teórica original — GAP-014 (sem MFA) sobe de High para **Critical** exatamente por essa razão.

**Exemplo de blind spot descoberto:** nenhum gap documentado antes tratava do **tiering de acesso privilegiado no Active Directory** — o Breach 1 mostra uma única credencial de admin de domínio comprometida sendo usada para empurrar ransomware via GPO para toda a organização de uma vez, revelando GAP-017 como um gap real que nunca tinha sido nomeado.

---

## 14. Risk Treatment Decisions

**O que é:** para os gaps de maior prioridade (os 6 Critical + o High mais bem ranqueado), decidir formalmente a **estratégia de tratamento** e propor um controle concreto com custo estimado — transformando "sabemos que isso é ruim" em "aqui está o plano e o preço".

**Estrutura de cada decisão:** nível de risco → estratégia de tratamento (aqui, sempre Mitigate) → justificativa → controle(s) proposto(s) → custo estimado → esforço de implementação → redução de risco esperada → **trade-offs** (o que esse controle *não* resolve, dito explicitamente).

**Por que declarar trade-offs é obrigatório, não opcional:** todo controle tem um limite — SIEM só funciona se alguém de fato monitorar os alertas; segmentar só as bombas de infusão (não o resto do IoT médico) deixa risco residual explícito nos monitores, não uma omissão acidental. Nomear o trade-off evita a falsa sensação de "resolvido por completo".

**Como alocar um orçamento fixo entre múltiplos gaps Critical:** ordenar por relação custo-benefício, e usar o "melhor negócio" (gap trivialmente barato e de altíssimo impacto, como o armário de rede sem trava) como quick win que não compete de verdade com os itens caros — e reservar o saldo remanescente para o próximo gap de maior valor, não deixar sobrando sem propósito.

**Exemplo:** GAP-006 (armário de rede sem trava, credenciais expostas) é o "melhor negócio" da lista inteira — trivialmente explorável, Critical, e corrigível por menos de $1.000 — deve ser feito imediatamente, independente do resto do ciclo orçamentário.

---

## 15. Predecessor Review

**O que é:** comparar formalmente a própria análise contra um rascunho **incompleto** deixado por um analista anterior (Marcus Webb) — uma prática real de handoff/transição de programa de segurança, não uma auditoria adversarial.

**Estrutura de comparação, achado por achado:** Agree (mesma conclusão, evidência independente) / Disagree (razão específica pela qual sua própria classificação diverge) / "Marcus caught something I missed" (reconhecer quando o predecessor viu algo que você não tinha formalizado).

**Por que "discordar" exige justificativa explícita, não apenas uma nota diferente:** cada discordância neste exercício é resolvida com uma razão concreta — por exemplo, discordar do rating "Medium" de Marcus para credencial compartilhada do PACS porque "acesso só local" reduz o **conjunto de atores possíveis**, mas não adiciona nenhum controle detective/corretivo nem muda a classificação do dado.

**A parte mais honesta do exercício: reconhecer o que o predecessor viu e você não tinha.** Isso inclui achados informais (uma nota adesiva dizendo "crítico" que nunca chegou ao documento formal) — evidência de que o próprio Marcus estava documentando descobertas em lugares dispersos e ficou sem tempo de consolidar, não de incompetência.

**Exemplo:** Marcus descontou o risco do login compartilhado do PACS por ser "só acesso local" — mas acesso local não reduzido não muda a ausência de controle detective/corretivo nem a classificação Restricted do dado; reduzir o conjunto de atores não é o mesmo que reduzir a severidade se o evento ocorrer.

---

## 16. Security Posture Assessment

**O que é:** o **relatório consolidado** de todo o módulo 1x00 — reunindo ativos, controles, gaps, decisões de tratamento e a revisão do predecessor num único documento com Executive Summary, Escopo e Metodologia, e Conclusão.

**Por que este documento não é "só juntar os anteriores":** um relatório de postura de segurança precisa **traduzir** artefatos técnicos numa narrativa executiva coerente — a mesma disciplina de tradução técnico → executivo que aparece de novo no Threat Landscape Report (1x01) e no Security Strategy Document (1x03).

**A frase que resume a postura inteira, e por que ela é a formulação certa:** "**prevention-only and effectively blind**" — a organização tem controles razoáveis impedindo *alguns* ataques de começar, mas quase nenhuma capacidade de perceber um que teve sucesso, e quase nenhuma forma testada de se recuperar depois. É a conclusão que amarra os itens 4, 5, 10 e 12 numa única sentença executiva.

**Estrutura do relatório final (modelo reutilizado em todo o currículo):** Executive Summary (achado mais crítico + top 3 ações) → Escopo/Metodologia (o que foi e não foi avaliado, com limitações declaradas) → Asset Landscape → Controles Atuais → Gap Analysis → Recomendações de Tratamento → Conclusão e Próximos Passos.

**Exemplo do fechamento do relatório:** ele termina apontando explicitamente que este assessment respondeu à pergunta interna ("o que temos, e onde estão as falhas"), mas não à pergunta externa ("quem realmente quer atacar organizações como a MedDefense, e como") — a costura direta para o próximo módulo, 1x01.

---

## 17. CISO Briefing

**O que é:** a versão mais comprimida de tudo — uma comunicação executiva de uma página só, para uma reunião de Board, sem jargão técnico.

**Estrutura de um briefing eficaz para o Board:** Estado Atual (o problema, em linguagem simples) → Achado Crítico (um único fato concreto, não uma lista) → Ações Prioritárias (poucas, nomeadas, com custo e prazo) → Caso de Negócio (comparar o custo do programa contra o custo real de um incidente comparável) → Fechamento.

**Por que ancorar em um exemplo real de outro hospital é mais persuasivo que qualquer estatística abstrata:** citar o custo de recuperação e os dias de desvio de ambulância de uma violação real comparável torna o orçamento pedido concreto e comparável, não uma estimativa hipotética que o Board pode descontar mentalmente.

**Regra de estilo, igual à do Board Pitch do 1x03:** toda frase precisa sobreviver sozinha se lida em voz alta numa sala de reunião — zero jargão técnico não traduzido.

**Exemplo:** "se um atacante mais sério tivesse entrado da mesma forma, provavelmente só descobriríamos depois que o atendimento ao paciente já tivesse sido interrompido" — traduz a ausência de detecção (GAP-002) em consequência clínica concreta, sem usar a palavra "SIEM" uma única vez.

---

## Dependency order across the files

```
0 levantamento bruto do ambiente (Known Unknowns)
 └─ 1 classificação CIA de incidentes · 2 causa raiz técnica · 3 avaliação física
     └─ 4 inventário de controles (Category × Function)
         └─ 5 gaps de controle (o que falta na matriz)
             └─ 6 controles compensatórios (caso legado sem correção possível)
                 └─ 7 asset registry (inventário único, reconciliado com scan)
                     └─ 8 criticidade CIA por ativo · 9 mapa de dados (3 estados)
                         └─ 10 matriz completa de controles (+ efetividade, cruzada com Top 5)
                             └─ 11 shadow IT (resposta caso a caso)
                                 └─ 12 gap analysis priorizado (GAP-IDs formais)
                                     └─ 13 reality check (validação contra breaches reais)
                                         └─ 14 risk treatment decisions (custo + estratégia)
                                             └─ 15 predecessor review (comparação com Marcus)
                                                 └─ 16 security posture assessment (relatório consolidado)
                                                     └─ 17 CISO briefing (comunicação final, 1 página)
```

## Framework reference table (revisão rápida antes de repetir o módulo)

| Conceito | Onde é usado | Ideia central |
|---|---|---|
| CIA Triad | Itens 1, 3, 8, 9 | Confidentiality, Integrity, Availability — vocabulário base de todo o currículo |
| Known Unknowns | Item 0 | Documentar explicitamente o que não se sabe, não só o que se sabe |
| Control Category × Function | Itens 4, 5, 10 | Technical/Administrative/Physical × Preventive/Detective/Corrective/Compensating/Deterrent |
| Compensating Control Strategy | Item 6 | Mitigar sem corrigir a causa, quando a correção direta é impossível |
| Asset Registry + reconciliação | Item 7 | Inventário único por ID, cruzado contra scan independente para achar Shadow IT |
| Shadow IT Triage | Item 11 | Legitimize and Secure / Migrate / Decommission — resposta certa por caso |
| GAP-ID formal | Item 12 | Regra: Critical exige ausência de AMBAS Detective e Corrective, não só uma |
| Reality Check / Breach Validation | Item 13 | Validar gaps teóricos contra casos reais; acha blind spots novos |
| Risk Treatment (Mitigate) | Item 14 | Estratégia + custo + trade-off explícito, nunca "resolvido" sem ressalva |
| Predecessor Review | Item 15 | Agree/Disagree com justificativa; reconhecer o que o outro analista viu |
| Executive Report Structure | Itens 16, 17 | Summary → Escopo → Achados → Recomendação, traduzido para não-técnicos |

---

*Guia de estudo — não faz parte da entrega. Use como checklist teórico antes de revisar ou expandir qualquer exercício do módulo.*
