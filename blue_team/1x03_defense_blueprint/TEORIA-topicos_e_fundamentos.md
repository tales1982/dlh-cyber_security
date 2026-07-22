# Teoria e Tópicos — 1x03 Defense Blueprint

Guia de estudo com teoria + exemplos práticos do cenário MedDefense, para cada exercício do módulo. Este módulo é diferente do 1x01 (que mapeava ameaças) e do 1x02 (que escaneava vulnerabilidades): aqui a pergunta muda de "o que pode nos atacar" para **"o que fazemos a respeito, com que orçamento, e como provamos ao Board que a decisão foi racional"**. É o módulo de governança, risco quantitativo e estratégia (GRC).

---

## 0. The Framework Landscape

**O que é:** entender os três grandes frameworks de segurança do mercado — não como concorrentes, mas como ferramentas que operam em **altitudes diferentes** do mesmo problema.

**Os três frameworks:**
- **NIST CSF 2.0:** framework estratégico, voluntário, baseado em **outcomes** ("o que" deve ser alcançado), não em passos técnicos ("como" fazer). Estrutura: 6 Functions (Govern, Identify, Protect, Detect, Respond, Recover) → 22 Categories → 106 Subcategories. Serve para conversar com o Board e montar um gap analysis "Current Profile vs. Target Profile".
- **CIS Controls v8:** framework operacional, prescritivo, baseado em dados reais de ataque. Estrutura: 18 Controls → Safeguards concretos, organizados em 3 Implementation Groups cumulativos — **IG1** (56 safeguards, higiene essencial para qualquer organização), **IG2** (+74, total 130, ambientes mais complexos), **IG3** (+23, total 153, ameaças sofisticadas/nation-state). Responde exatamente à pergunta que o CSF deixa em aberto: "especificamente o que eu implemento, e em que ordem?"
- **ISO/IEC 27001:2022:** norma internacional **certificável**, de governança e garantia (assurance) — não é uma checklist técnica, é um Sistema de Gestão de Segurança da Informação (ISMS). Estrutura: Cláusulas 4-10 (requisitos obrigatórios do sistema de gestão) + Anexo A (93 controles candidatos em 4 temas: Organizacional 37, Pessoas 8, Físico 14, Tecnológico 34). Serve para **provar** a terceiros (auditor, seguradora, regulador) que a segurança é gerida, não só implementada uma vez.

**Metáfora das "três altitudes":** CSF diz **o quê** (estratégico) → CIS Controls diz **como** (operacional) → ISO 27001 garante que isso está sendo **gerido de forma contínua e auditável** (assurance). Uma organização madura tipicamente usa as três juntas.

**Como escolher para uma organização pequena (o exercício MedDefense):** com apenas um analista e um Deputy CISO, sem CISO formal, a recomendação é **CSF 2.0 como espinha dorsal estratégica + CIS Controls (IG1, depois IG2) como camada de implementação**, adiando a certificação ISO 27001 — porque certificar um sistema de gestão antes dos controles que ele certificaria sequer existirem seria certificar um programa que não existe ainda.

**Exemplo:** Sarah Park admite "não seguimos nenhum framework formalmente" → isso não significa começar do zero: os projetos 1x00/1x01/1x02 já geraram evidência (Asset Registry, Threat Actor Matrix, Vulnerability Assessment) que alimenta diretamente o Current Profile do CSF.

---

## 1. NIST CSF Mapping

**O que é:** aplicar as 6 Functions do CSF 2.0 ao ambiente real da MedDefense, avaliando **onde a organização está hoje** (Current Profile) e **onde precisa chegar** (Target Profile).

**As 6 Functions:**
| Function | Pergunta-chave |
|---|---|
| **Govern (GV)** | Existe estratégia, papéis, política e apetite de risco documentados? |
| **Identify (ID)** | Sabemos quais ativos temos e qual o risco de cada um? |
| **Protect (PR)** | Existem salvaguardas (MFA, hardening, controle de acesso)? |
| **Detect (DE)** | Conseguimos perceber um ataque em andamento? |
| **Respond (RS)** | Temos um plano testado para agir durante um incidente? |
| **Recover (RC)** | Conseguimos voltar ao normal depois do incidente? |

**Escala de maturidade usada no exercício:** Not Implemented → Partial → Managed (uma escala simplificada; não confundir com os **CSF Implementation Tiers** oficiais — Tier 1 Partial, Tier 2 Risk Informed, Tier 3 Repeatable, Tier 4 Adaptive — que descrevem a maturidade da *gestão de risco* como um todo, não de cada Function isoladamente).

**Regra de ouro do exercício:** toda avaliação precisa de **evidência concreta** dos projetos anteriores, nunca uma opinião solta.

**Exemplo:** Govern = Not Implemented, evidenciado por "seguimos nenhum framework formalmente" (GV.PO), ausência de CISO (GV.RR) e G-005 do 1x00 (só existe controle Preventivo, nenhum Detective/Corrective/Compensating/Deterrent) → GV.OV (oversight) não existe porque não há mecanismo usando resultado de atividade de segurança para ajustar estratégia.

---

## 2. CIS Controls Audit

**O que é:** auditar cada um dos 18 CIS Controls contra evidência real, atribuindo um score (Implemented / Partial / Not Implemented) — uma segunda lente sobre o mesmo ambiente, mais prescritiva que o CSF.

**Padrão descoberto na auditoria:** **zero controles totalmente Implementados** — 8 Partial, 10 Not Implemented. Isso não é exagero retórico: todo controle que existe de alguma forma (backup, treinamento, antivírus) está incompleto, não verificado, ou cobre só parte do que deveria. É o mesmo padrão do Gap Analysis do 1x00: MedDefense investe em medidas preventivas parciais e quase nada é testado ou monitorado ativamente.

**Como priorizar os 18 controles (Top 5 do exercício):**
1. **Control 6 (Access Control/MFA)** — maior alavancagem, menor custo (licença O365 já paga).
2. **Control 12 (Network Infrastructure/Segmentação)** — amplifica (ou reduz) o risco de *todos* os outros achados por ordens de grandeza.
3. **Control 8 + 13 (Log Management + Network Monitoring)** — o padrão central de falha ("descoberto por acidente, não por design") só se resolve com detecção.
4. **Control 7 (Continuous Vulnerability Management)** — sem processo de remediação recorrente, o scan de vulnerabilidade do 1x02 vira uma foto que expira no dia seguinte.
5. **Control 11 (Data Recovery)** — ransomware é a ameaça #1 e o backup nunca foi testado em escala.

**Exemplo:** Control 4 (Secure Configuration) = Not Implemented, porque 7 de 7 bombas de infusão BD Alaris mantêm credencial padrão nunca trocada, e 13 dos 31 achados do 1x02 são configurações incorretas/permissivas.

---

## 3. Gap-to-Framework Bridge

**O que é:** a "ponte" que conecta tudo o que já foi levantado nos três projetos anteriores — transformando um gap isolado em uma cadeia de rastreabilidade completa.

**A cadeia de rastreabilidade:** `GAP-XXX (1x00) → evidência de vulnerabilidade (1x02) → contexto de ameaça/kill chain (1x01) → Function do NIST CSF → CIS Control → ação recomendada`.

**Por que essa ponte importa:** é o que transforma "eu acho que devíamos ter MFA" em uma frase auditável: "GAP-014 aparece nas Kill Chains #1/#2/#5, viola PR.AA do CSF e o Safeguard 6.3 do CIS Control 6 — e o Finding 009 do 1x02 confirma que a porta continua aberta hoje." Nenhum framework citado sozinho prova nada; a força está na correlação entre os quatro.

**Exemplo:** GAP-002 (nenhuma capacidade de detecção) aparece em **todos os 6 tipos de ator**, em 4 das 5 kill chains, e em todos os 3 cenários de ameaça do 1x01 — o gap mais universal do módulo inteiro — mapeando para a Function Detect (DE.CM/DE.AE) e para os CIS Controls 8 e 13, com ação recomendada: implantar SIEM (Wazuh) com dono nomeado revisando alertas diariamente.

---

## 4. Governance Architecture

**O que é:** desenhar quem decide o quê — a estrutura de governança que faltava completamente antes deste projeto (Govern = Not Implemented no Task 1).

**RACI Matrix — os 4 papéis:**
- **R (Responsible):** quem executa o trabalho.
- **A (Accountable):** quem responde pelo resultado — só uma pessoa por atividade, nunca mais de uma (senão volta a ambiguidade de "quem grita mais alto decide").
- **C (Consulted):** quem é ouvido antes da decisão.
- **I (Informed):** quem é apenas avisado depois.

**Papéis de governança de dados (terminologia de privacidade/GDPR aplicada em contexto HIPAA):**
| Papel | Quem é | Responsabilidade |
|---|---|---|
| **Data Owner** | CEO (org-wide); Dept Heads (domínio específico) | Decide classificação, quem acessa, nível de proteção — autoridade de negócio, não técnica |
| **Data Controller** | A organização (MedDefense) | Determina **por que** e **como** o dado é processado |
| **Data Processor** | Fornecedor (ex: MedTech Solutions) | Processa dado **por conta** do Controller, sem autoridade própria sobre o propósito |
| **Data Custodian/Steward** | IT Director + Security Analyst | Executa a proteção do dia a dia (backup, acesso, criptografia) — **não decide** o que deve ser protegido, só implementa |

**Confusão clássica que esse modelo resolve:** "Sarah acha que é dona da segurança de endpoint porque a TI gerencia os endpoints" — Custódia (Custodian) e Propriedade (Owner) são papéis diferentes; a matriz RACI existe exatamente para tornar essa distinção operacional, não teórica.

**A questão do CISO vacante:** sem CISO, ninguém tem autoridade **e** mandato exclusivo para decisão final de segurança — isso explica por que James, Sarah e o Dr. Patel acham que cada um "possui" pedaços sobrepostos do programa. Solução recomendada: **vCISO (CISO virtual/fracionado)**, tipicamente $3.000-$8.000/mês, em vez de contratação full-time (que custaria $150.000-$200.000/ano — mais que o orçamento técnico inteiro).

**Exemplo:** Vendor Risk Assessment ganha "R" (não só "C") para o Security Analyst, resposta direta ao Cenário 3 do 1x01 ("The MedTech Backdoor") — ninguém avaliava risco de fornecedor antes.

---

## 5. The Risk Equation

**O que é:** o núcleo do módulo — aprender a calcular risco em **dólares**, não em rótulos de cor (Alto/Médio/Baixo), usando a fórmula clássica de análise quantitativa de risco.

**As variáveis:**
- **AV (Asset Value):** o valor em risco — nem sempre o custo do ativo em si, geralmente o **custo do incidente completo** (downtime + recuperação + multa + reputação).
- **EF (Exposure Factor):** que percentual do AV se realiza quando o evento acontece (0-100%). Um evento binário ("o servidor foi encriptado ou não") tem EF = 100%; um evento parcial teria EF menor.
- **SLE (Single Loss Expectancy) = AV × EF:** o custo de **um único** evento.
- **ARO (Annualized Rate of Occurrence):** quantas vezes por ano o evento é esperado (pode ser < 1, ex: 0,25 = uma vez a cada 4 anos; ou > 1, ex: 2,5 = duas vezes e meia por ano).
- **ALE (Annualized Loss Expectancy) = SLE × ARO:** o custo esperado **por ano** — a métrica final usada para comparar riscos e justificar orçamento.

**Regras práticas para não errar a conta:**
- **Nunca contar o mesmo custo duas vezes.** Se uma fonte já inclui detecção+notificação+jurídico num valor "por registro", não some também os itens individuais de notificação/litígio por fora.
- **ARO deve refletir o contexto real da organização, não só a média do setor.** Se o ativo já foi comprometido antes pela mesma falha, o ARO sobe acima da média setorial.
- **Sempre declarar o nível de confiança e qual premissa mudaria mais o resultado.** Isso é o que separa uma estimativa de GRC séria de um "chute com aparência de matemática".

**Exemplo:** Ransomware no billing server → AV = $473.000 (downtime $288k + recuperação $85k + multa HIPAA $100k) → EF 100% (evento binário) → SLE = $473.000 → ARO ajustado para 0,4 (acima da média setorial de 0,29, porque o servidor **já foi comprometido uma vez** e o Apache vulnerável continua sem patch) → **ALE = $189.200**.

---

## 6. The ALE Workshop

**O que é:** aplicar a fórmula do item 5 em risco após risco, e — o passo novo aqui — calcular o **ALE depois do controle proposto**, para medir o valor real de investir em mitigação.

**Fórmula adicional:**
- **Estimated ALE After Control:** recalcula SLE × ARO assumindo que o ARO cai (o controle não elimina o AV, geralmente reduz a probabilidade de o evento acontecer).
- **Net Benefit = ALE(antes) − ALE(depois) − Custo Anual do Controle.**

**Por que ALE(antes) sozinho não basta:** o ranking por ALE bruto não é o mesmo ranking por "qual ativo importa mais" — matemática de likelihood × impact e severidade categórica (ex: segurança do paciente) são **duas lentes diferentes**, e um programa maduro de risco precisa das duas, não só uma.

**Exemplo notável (Risco 4, dispositivos médicos):** o Net Benefit financeiro é baixíssimo ($1.750) porque segmentação é cara relativamente ao ALE puro — mas isso **não** significa que o controle é ruim: achados de segurança do paciente são categóricos, não apenas financeiros. A justificativa aqui é ética/clínica, não só a planilha.

---

## 7. Cost-Benefit Analysis

**O que é:** generalizar o ALE Workshop para **qualquer controle candidato** (não só os 5 riscos-alvo), com um veredito formal.

**Estrutura de cada análise:**
- **Annual Cost:** custo recorrente do controle.
- **ALE Reduction:** quanto risco (em $) o controle remove, somado através de todos os riscos que ele afeta (um controle pode mitigar mais de um risco ao mesmo tempo).
- **Net Value = ALE Reduction − Annual Cost.**
- **Veredito:** **Justified** (positivo e sólido) / **Marginal** (positivo mas fino, ou concorre com opções melhores) / **Not Justified** (negativo — custa mais do que o risco que remove).

**Por que um controle pode ser "Marginal" mesmo com Net Value positivo:** se ele consome o orçamento inteiro e impede outros 4 controles de maior valor, o valor "isolado" positivo não importa — a decisão de orçamento é sempre **relativa**, não absoluta (Control 7, SOC 24/7, é o exemplo clássico disso).

**Exemplo de "Not Justified":** Control 8 (isolamento premium de dispositivo médico com monitoramento dedicado) tem Net Value **negativo** (-$16.300) porque a Control 1 (segmentação básica) já captura a maior parte do valor endereçável a um custo menor — pagar mais por uma melhoria marginal não é gestão de risco racional.

---

## 8. Budget Allocation

**O que é:** resolver o problema clássico de "mochila" (knapsack problem) da segurança — escolher quais controles financiar dentro de um **orçamento fixo** ($120.000), maximizando redução de risco por dólar gasto.

**Método:** ranquear controles por **razão custo-benefício** (ALE Reduction ÷ custo, ou Net Value), financiar em ordem até o orçamento acabar — não por preferência arbitrária ou conveniência.

**Conceito-chave — Opportunity Cost (custo de oportunidade):** ao **não** financiar um controle, a organização aceita implicitamente o risco que aquele controle teria removido. Isso deve ser declarado em dólares, não escondido — "ao adiar o SOC 24/7, aceitamos ~$30.000/ano de exposição adicional que a cobertura contínua removeria além do que o SIEM já cobre."

**Técnica de "escopo cirúrgico":** às vezes um controle mais barato, mirado exatamente no gap documentado, supera a versão "completa" do mesmo controle. Exemplo: EDR em todos os ~387 endpoints custaria $30.000 pelo valor cheio; mas como GAP-005 exclui especificamente **servidores** (workstations já têm Sophos básico), uma versão restrita a ~15 servidores custa $6.000 e captura ~80% do valor — um remédio mirado no problema real supera um remédio genérico que paga parcialmente por uma cobertura que já existe.

**Exemplo:** seleção greedy por Net Value financia MFA, SIEM, backup replication, segmentação e o firewall de Westside por $103.400, deixando $16.600 de reserva — o SOC 24/7 sozinho consumiria o orçamento inteiro e é adiado, não porque não tenha valor, mas porque **cinco** controles de maior valor combinado cabem no mesmo dinheiro.

---

## 9. The CFO Challenge

**O que é:** a habilidade de **defender** as decisões de risco/orçamento contra objeções executivas reais — comunicação de risco, não só cálculo de risco.

**Estrutura recomendada de resposta a cada objeção (4 passos):**
1. **Acknowledgment:** validar a preocupação genuinamente, sem ser defensivo.
2. **Counter-Evidence:** trazer o fato/dado específico que resolve a objeção.
3. **Business Framing:** traduzir para a linguagem que o executivo já usa (ex: seguro, ROI, precedente orçamentário).
4. **Recommendation:** uma ação concreta, não uma reafirmação genérica.

**Objeções clássicas de CFO/Board (e a lógica por trás de cada resposta):**
- *"Nunca fomos violados"* → contra-evidência: já houve dois incidentes reais (ransomware + cryptominer), pela mesma porta ainda aberta.
- *"Seus números de ALE são só estimativas"* → resposta correta não é defender a precisão do número, é mostrar que a decisão **sobrevive** mesmo se o número estiver errado por uma margem larga (teste de sensibilidade).
- *"Seguro é mais barato que controle"* → seguro e controle não competem pelo mesmo dólar: controles ausentes (MFA) são cada vez mais motivo de **negativa de sinistro** pela seguradora — o investimento protege a exequibilidade da própria apólice.
- *"Isso devia ser orçamento normal de TI, não pedido especial"* → é exatamente por segurança nunca ter tido linha própria que os gaps críticos existem; uma linha de orçamento distinta é, em si, um controle de governança.
- *"Pode começar com $60.000?"* → phasing baseado em dados reais: os itens de maior valor já são os mais baratos, então um corte de orçamento captura desproporcionalmente pouco valor perdido.

**Exemplo de closing statement:** ALE combinado de fazer nada = ~$1.097.200/ano; o programa de $103.400 reduz isso em ~$587.750 → **retorno de ~$5,68 para cada $1 investido**, calculado com o mesmo rigor que qualquer outro investimento de capital seria avaliado.

---

## 10. The Risk Register

**O que é:** o documento formal e vivo que consolida **todos** os riscos identificados em um único registro rastreável, com dono, tratamento e indicador de monitoramento — a ferramenta central de GRC (Governance, Risk & Compliance).

**Escalas formais:**
- **Likelihood (1-5):** Rare (>10 anos) → Unlikely (5-10) → Possible (2-5) → Likely (1-2) → Almost Certain (<1 ano ou já em curso).
- **Impact (1-5):** Negligible → Minor → Moderate → Major → Severe/Catastrophic (segurança do paciente ou exposição financeira/regulatória existencial).
- **Inherent Risk Score = Likelihood × Impact** (score bruto, antes de qualquer controle).

**Campos obrigatórios de cada entrada:** descrição, categoria (Strategic/Financial/Operational/Compliance), fonte de ameaça, vulnerabilidade, ativo afetado, likelihood, impact, score, ALE, **Risk Owner** (pessoa nomeada, nunca "a equipe"), **Treatment Decision** (ver item 16), controle planejado, risco residual, **KRI (Key Risk Indicator)**, e data de revisão.

**KRI (Key Risk Indicator):** uma métrica mensurável e específica que **antecipa** a materialização do risco — não é a mesma coisa que um log genérico. Ex: "número de tentativas de MFA falhas por semana" (spike indica ataque de credencial em curso); "contas ativas cuja data de desligamento já passou há mais de 24h" (deveria ser sempre zero).

**Governança do registro:** revisão mensal por dois donos (Deputy CISO + IT Director); qualquer ruptura de KRI dispara revisão **imediata**, não espera o ciclo mensal — o próprio propósito de rastrear um KRI é pegar o risco derivando antes do calendário.

**Exemplo:** RISK-008 (dispositivo shadow-IT não identificado em Westside) não pode ter Treatment Decision formal ainda, porque **não se pode aceitar, transferir ou mitigar formalmente um risco de um ativo que nem está inventariado** — contenção (bloqueio de rede) precede qualquer decisão de tratamento de longo prazo.

---

## 11. The Control Selection

**O que é:** para cada risco do registro (item 10), escolher o controle específico e classificá-lo tecnicamente — a ponte entre "decidimos mitigar" e "aqui está exatamente o mecanismo".

**Tipos de controle (Control Type) — a classificação clássica de segurança:**
| Tipo | O que faz | Exemplo no módulo |
|---|---|---|
| **Preventive** | Impede o evento antes que aconteça | MFA, patch, reset de credencial padrão |
| **Detective** | Percebe o evento acontecendo | SIEM, alerta de exportação em massa |
| **Corrective** | Restaura depois do evento | Backup/replicação imutável |
| **Compensating** | Reduz o risco sem eliminar a vulnerabilidade de base | Segmentação de dispositivo médico (a falha do dispositivo continua existindo, só fica inalcançável) |
| **Deterrent** | Desencoraja a tentativa (mencionado como categoria ausente no 1x00) | Política + treinamento visível |

**Control Category (dimensão ortogonal ao tipo):** **Technical** (tecnologia) vs **Administrative** (processo/política) vs **Physical**.

**Mapeamento cruzado obrigatório:** cada controle escolhido precisa citar **CIS Control/Safeguard** + **NIST CSF Function** — voltando à "ponte" do item 3, agora no nível de controle individual, não de gap.

**Dependency Mapping (camadas de implementação):** alguns controles só funcionam se outro já estiver no ar. Ex: "SIEM depende de inventário de ativos atualizado"; "MFA para contas de fornecedor depende do MFA central já estar ativo". Isso organiza a ordem de rollout em camadas (Layer 0 = sem pré-requisito, Layer 1 = depende de Layer 0, etc.) e revela qual controle é a **fundação arquitetural** de que outros dependem (aqui, o MFA).

**Exemplo:** MFA é marcado como o controle com mais dependentes no mapa — ele é pré-requisito direto para estender MFA a contas de fornecedor e reduz a carga de triagem do SIEM (menos alertas baseados em credencial para revisar).

---

## 12. Acceptable Use Policy (AUP)

**O que é:** a primeira política formal e assinável da organização — transforma "por favor não faça isso" em um padrão documentado e exequível que todo mundo concordou ao entrar.

**Estrutura típica de uma AUP:** Propósito e Escopo → Uso Aceitável → Atividades Proibidas → Dispositivos Pessoais/Mídia Removível → Requisitos de Senha/Autenticação → Tratamento de Dados → Monitoramento e Aplicação → Reconhecimento/Assinatura.

**Princípio de boa prática usado no exercício:** **cada proibição deve mapear para um risco real já documentado**, não ser uma lista genérica copiada de outro lugar — isso torna a política defensável e fácil de justificar para quem pergunta "por que essa regra existe?".

**Aplicação proporcional (enforcement):** uma violação sem intenção e sem exposição real de dado (ex: pendrive perdido, vazio) gera conversa documentada + treinamento; uma violação com exposição real de dado, ou burla deliberada de controle, escala para RH e ação disciplinar; atividade suspeita de má-fé (ex: exportação em massa antes de uma demissão) vai direto para o Deputy CISO como incidente, independente do processo de RH.

**Exemplo:** a proibição de "conectar dispositivo pessoal/de fornecedor à rede clínica ou de servidor sem aprovação prévia" existe porque a MedDefense **já encontrou** um laptop pessoal burlando controles de rede por três semanas e um Raspberry Pi conectado à rede de dispositivos médicos "só para monitorar performance" — nenhum com intenção maliciosa, ambos criando risco real não gerenciado.

---

## 13. The Quick Wins

**O que é:** ações de correção que não exigem orçamento novo, contrato de fornecedor ou dependência de outro projeto — a prova rápida de que o programa de segurança já produz resultado antes das grandes obras (SIEM, segmentação) sequer terminarem a primeira fase.

**Critérios que definem um "quick win" (todos precisam ser verdadeiros):**
1. Custo próximo de zero (usa acesso/licença já existente).
2. Sem dependência de outro controle ainda não implementado.
3. Prazo curto (dias, não meses).
4. Redução de risco desproporcionalmente alta para o esforço.

**Passo que nunca pode faltar: Verification.** Cada quick win do exercício tem um passo explícito de verificação técnica (ex: tentar conectar na porta bloqueada e confirmar que a conexão é recusada) — a disciplina de **confirmar que o fix realmente funcionou**, em vez de assumir que funcionou, é a mesma disciplina que o programa vai precisar em escala muito maior quando o SIEM e a segmentação chegarem.

**Exemplo:** desabilitar o conector AJP do Tomcat no `ehr-srv-01` (Quick Win #1) custa $0, leva 2 dias, e fecha sozinho a vulnerabilidade mais severa (CVSS 9,8, Ghostcat) de todo o scan do 1x02 — o maior retorno de risco por esforço de todo o programa.

---

## 14. The Segmentation Architecture

**O que é:** o projeto de rede que substitui o `/16` totalmente plano da MedDefense por **zonas isoladas com política default-deny** entre elas — o oposto do "aberto por omissão em todo lugar" que existia antes.

**Princípio central: default-deny.** Qualquer caminho zona-a-zona não explicitamente permitido é **negado por padrão** — a lista de regras é a lista completa de exceções permitidas, não uma lista de bloqueios sobre uma base aberta.

**As 5 zonas típicas (VLANs):** Server Zone, Clinical Workstation Zone, Medical Device Zone, Management Zone (a única zona com alcance amplo, porque é o plano administrativo confiável — todo acesso ali é obrigatoriamente autenticado com MFA), e Guest/IoT Zone.

**Conceito relacionado — Zero Trust:** nunca confiar automaticamente em nada, nem em tráfego interno; toda comunicação precisa ser explicitamente permitida.

**Metodologia de avaliação: Kill Chain Disruption Analysis.** Depois de desenhar a arquitetura, você **percorre cada passo de cada kill chain já documentada** (do 1x01) e pergunta: "esse passo específico ainda funciona contra essa nova arquitetura?" Isso prova (ou desmente) o valor da segmentação com evidência concreta, não com uma alegação genérica de "melhoramos a segurança".

**Limite honesto da segmentação:** ela é um controle de **rede**. Ela não impede phishing (Step 1) nem C2 via DNS/egress (Step 2) de uma kill chain — e não pode, por definição, deter um insider usando acesso **já legitimamente autorizado** dentro da própria zona (Kill Chain #3) — isso é um problema de governança de acesso, não de arquitetura de rede, e exige um controle diferente (item 11).

**Exemplo:** a Kill Chain #1 (ransomware) quebra decisivamente no Step 3 (Discovery) — a estação de trabalho comprometida, agora presa na Clinical Workstation Zone, só alcança a porta 443 do Server Zone; o mapeamento de rede que alimentava os passos seguintes simplesmente não encontra nada para mapear.

---

## 15. Red Team Your Blueprint

**O que é:** o exercício de **autocrítica adversarial** — vestir o chapéu do próprio atacante e perguntar "com tudo que acabamos de construir, o que ainda funciona contra nós?"

**Por que isso é uma etapa formal, não um extra:** todo blueprint de defesa tem pontos cegos que só aparecem quando alguém tenta ativamente furá-lo — a mesma lógica por trás de um pentest, aplicada ao próprio plano em vez de ao sistema já implantado.

**Distinção crítica que esse exercício ensina:** existe diferença entre um gap **fechado**, um gap **nunca financiado** (identificado, custeado, mas nunca competiu de fato pelo orçamento) e um gap **estruturalmente inalcançável** por um determinado tipo de controle (ex: segmentação de rede não pode, por natureza, impedir alguém que já tem acesso legítimo dentro da própria zona). Confundir essas três categorias leva a uma falsa sensação de segurança.

**Como se chega a um veredito de risco residual:** não é "tudo foi resolvido, risco Low" nem "nada foi resolvido, risco Critical" — é uma leitura honesta de **quais caminhos, especificamente, continuam abertos** depois dos controles propostos, e por quê.

**Exemplo:** mesmo depois de MFA, SIEM e segmentação, a Kill Chain #3 (exfiltração por insider) continua **completamente intacta**, porque o controle específico para ela (RISK-004, $8.000) foi identificado e custeado no Task 6, mas nunca de fato competiu pelo orçamento no processo do Task 7/8 — apesar de sobrarem $16.600 que cobririam esse controle duas vezes. Esse é o achado mais afiado do exercício: nem todo gap conhecido acaba sendo financiado, mesmo quando há dinheiro sobrando.

---

## 16. The Risk Appetite Debate

**O que é:** formalizar **quanto risco a organização está disposta a tolerar**, e quem tem autoridade para aceitar cada nível — sem isso, "aceitar o risco" vira uma desculpa informal em vez de uma decisão de governança registrada.

**As 4 estratégias formais de tratamento de risco (Risk Treatment):**
- **Mitigate:** reduzir a probabilidade ou o impacto com um controle.
- **Accept:** tolerar o risco como está, conscientemente e com aprovação no nível certo.
- **Transfer:** repassar o custo financeiro a terceiros (ex: seguro cibernético).
- **Avoid:** eliminar a atividade/ativo que gera o risco por completo.

**Estrutura de um Risk Appetite Statement:** define limiares numéricos de autoridade — por exemplo, qualquer aceitação de risco acima de um valor de ALE, ou que toque um ativo Crítico, exige assinatura do Deputy CISO; acima de um valor maior, ou que toque **segurança do paciente**, exige assinatura pessoal do CEO. **Segurança do paciente é tratada como limite absoluto:** pode ser aceita temporariamente, mas nunca sem uma medida compensatória mensurável — "aceitar e seguir em frente" sem nenhum controle associado não é uma decisão de governança, é negligência disfarçada de decisão.

**Todo risco aceito precisa de 3 elementos, sem exceção:** autoridade de assinatura no nível certo, uma **Compensating Measure** nomeada, e um **Review Trigger** específico (evento que força reavaliação imediata, não uma data fixa distante).

**Exemplo (Decisão 1, Windows XP na estação de controle da ressonância):** aceitar o risco por um período limitado (18 meses, até o fim do contrato de leasing do equipamento) é justificável porque romper o contrato custaria mais que o próprio risco mitigado — mas a aceitação só é válida com a segmentação **verificada operacional** (não apenas financiada) como medida compensatória, e com gatilho de revisão imediata em caso de falha de segmentação confirmada.

---

## 17. Security Strategy Document

**O que é:** o documento executivo final que **consolida** todo o trabalho dos Tasks 0-16 em um único relatório voltado ao Board — governança, risco quantitativo, seleção de controles, arquitetura e política, tudo amarrado.

**Estrutura recomendada:** Executive Summary (retorno sobre investimento em uma frase) → Governance Framework → Quantitative Risk Analysis → Control Strategy → Architecture Recommendations → Policy Foundation → Residual Risk Assessment → Implementation Roadmap → Next Steps.

**Por que isso não é "só juntar os arquivos anteriores":** um relatório executivo precisa **traduzir** artefatos técnicos (RACI, ALE, CIS scorecard) em uma narrativa que o Board consegue avaliar e aprovar em uma reunião — a mesma disciplina do Threat Landscape Report do item 18 do 1x01, agora aplicada à camada de estratégia e orçamento em vez de à camada de ameaça.

**Elemento que não pode faltar: honestidade sobre risco residual.** Um relatório de estratégia que promete "resolvemos tudo" perde credibilidade na primeira auditoria; incluir explicitamente o que o Red Team (item 15) encontrou como ainda aberto é o que torna o documento confiável.

**Exemplo do "Next Steps":** o documento termina explicitamente conectando este projeto ao próximo do currículo (1x04, Cryptographic Foundation) — mostrando que "dados Restritos devem ser criptografados" (uma frase de política do item 12) ainda precisa virar um padrão técnico específico implementado, não é o fim da jornada.

---

## 18. The 6-Month Security Roadmap

**O que é:** transformar a estratégia (item 17) em um **cronograma executável** mês a mês, com dono, dependência e critério de conclusão explícitos para cada ação — sem isso, uma estratégia aprovada morre na gaveta.

**Elementos obrigatórios de cada mês:** Ações → Owner (pessoa nomeada) → Dependencies (o que precisa estar pronto antes) → Completion Criteria (como saber, de forma objetiva, que o mês foi cumprido — nunca "achamos que está bom").

**Cadeia de dependências (Dependency Chain) como ferramenta de sequenciamento:** alguns trabalhos **têm que** vir antes de outros por razões estruturais, não de preferência — ex: a arquitetura de zonas de rede (Mês 3) precisa existir antes que uma zona específica (dispositivo médico) possa ser isolada dentro dela (Mês 4); um SIEM recém-implantado gera ruído, não sinal, então simulações de resposta a alerta só fazem sentido depois de meses de ajuste fino.

**Marcos (Milestones) vs. ações do dia a dia:** um milestone é um ponto de verificação de alto nível com um indicador de sucesso binário e mensurável (ex: "0 testes de alcançabilidade falhos em todas as zonas"), diferente da lista de tarefas — serve para o Board acompanhar progresso sem entrar no detalhe operacional.

**Gestão de risco do próprio cronograma (Risk to Timeline):** um roadmap maduro antecipa **o que pode atrasá-lo** (resistência da equipe clínica à mudança de fluxo de trabalho; atraso de fornecedor/procurement) e já embute a contingência (rollout em piloto pequeno antes do mandatório; iniciar toda ação sem dependência já no Mês 1, com folga de tempo reservada para atraso de hardware).

**Exemplo:** a autenticação por crachá do PACS já foi rejeitada uma vez por reclamação de fluxo de trabalho — a contingência é reaproveitar o mesmo padrão de piloto de 48h usado no GPO de USB, e usar a responsabilidade de treinamento já atribuída aos chefes de departamento (item 4) para construir adesão **antes** de anunciar uma data obrigatória.

---

## 19. Board Pitch

**O que é:** a versão mais comprimida de tudo — uma comunicação executiva de uma página, feita para durar poucos minutos de uma reunião de aprovação de orçamento.

**Estrutura de um board pitch eficaz:** Estado Atual (o problema, sem jargão) → O Risco (um único número de ALE que o Board reconhece como já ter acontecido, não hipotético) → O Plano (poucas ações nomeadas, não "mais segurança" genérica) → O Retorno (ROI em uma frase, comparável a qualquer outra decisão de capital que o Board já avalia).

**Por que "já aconteceu" é mais persuasivo que "pode acontecer":** um número de risco ancorado em um incidente real já vivido pela organização (não uma estatística de setor genérica) é muito mais difícil de descartar como alarmismo — é a mesma lógica usada no Objection 1 do item 9.

**Regra de estilo:** zero jargão técnico não traduzido, zero grandes tabelas — cada frase precisa sobreviver sozinha se lida em voz alta numa sala de reunião.

**Exemplo:** "não somos azarados — somos desprotegidos, e isso já nos custou duas vezes" resume, em uma frase, o achado central de todo o módulo (zero controles totalmente implementados, dois incidentes reais pela mesma porta) sem precisar de nenhuma tabela.

---

## Dependency order across the files

```
0 panorama dos 3 frameworks (CSF, CIS, ISO)
 └─ 1 CSF Current/Target Profile · 2 CIS Controls Audit  (duas lentes sobre o mesmo ambiente)
     └─ 3 gap-to-framework bridge (conecta 1x00/1x01/1x02 aos frameworks)
         └─ 4 governança (RACI, papéis de dado, CISO/vCISO)
             └─ 5 risk equation (AV/EF/SLE/ARO/ALE) · 6 ALE workshop (5 riscos + controle)
                 └─ 7 cost-benefit (todo controle candidato) · 8 budget allocation (orçamento fixo)
                     └─ 9 CFO challenge (defender a decisão)
                         └─ 10 risk register formal (consolida tudo com likelihood×impact)
                             └─ 11 control selection (tipo/categoria/dependência por risco)
                                 └─ 12 AUP · 13 quick wins · 14 segmentação  (execução concreta)
                                     └─ 15 red team (autocrítica do blueprint)
                                         └─ 16 risk appetite (aceitar/mitigar/transferir/evitar, formalmente)
                                             └─ 17 security strategy (documento executivo consolidado)
                                                 └─ 18 roadmap de 6 meses (execução, mês a mês)
                                                     └─ 19 board pitch (comunicação final, 1 página)
```

## Framework reference table (revisão rápida antes de repetir o módulo)

| Framework/Conceito | Onde é usado | Ideia central |
|---|---|---|
| NIST CSF 2.0 | Itens 0, 1, 17 | 6 Functions, outcome-based, "o quê" estratégico |
| CIS Controls v8 | Itens 0, 2, 11 | 18 Controls + Safeguards, IG1/IG2/IG3, "como" operacional |
| ISO/IEC 27001 | Item 0 | ISMS certificável, garantia/assurance contínua |
| RACI Matrix | Item 4 | Responsible/Accountable/Consulted/Informed — um só "A" por atividade |
| Data Owner/Controller/Processor/Custodian | Item 4 | Quem decide vs. quem processa vs. quem executa a proteção |
| SLE / ARO / ALE | Itens 5, 6 | AV×EF=SLE; SLE×ARO=ALE — risco em dólares por ano |
| Net Value / Verdict | Itens 6, 7 | ALE Reduction − Custo = valor líquido; Justified/Marginal/Not Justified |
| Budget Allocation (knapsack) | Item 8 | Maximizar redução de risco dentro de orçamento fixo; opportunity cost |
| Acknowledge-Counter-Frame-Recommend | Item 9 | Estrutura de resposta a objeção executiva |
| Likelihood × Impact (1-5) | Item 10 | Inherent Risk Score; KRI como alarme antecipado |
| Control Type (Preventive/Detective/Corrective/Compensating/Deterrent) | Item 11 | Classificação funcional de qualquer controle |
| Default-deny / Zero Trust | Item 14 | Segmentação de rede, nunca confiar por omissão |
| Kill Chain Disruption Analysis | Item 14 | Testar a arquitetura passo a passo contra kill chains já mapeadas |
| Risk Treatment: Mitigate/Accept/Transfer/Avoid | Item 16 | As 4 estratégias formais, com autoridade de assinatura por limiar |
| Risk Appetite Statement | Item 16 | Limites numéricos + limite absoluto de segurança do paciente |

---

*Guia de estudo — não faz parte da entrega. Use como checklist teórico antes de revisar ou expandir qualquer exercício do módulo.*
