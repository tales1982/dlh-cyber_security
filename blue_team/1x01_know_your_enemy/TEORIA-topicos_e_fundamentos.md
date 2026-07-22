# Teoria e Tópicos — 1x01 Know Your Enemy

Guia de estudo com teoria + exemplos práticos do cenário MedDefense, para cada exercício do módulo.

---

## 0. Threat Landscape Summary

**O que é:** o retrato geral de quem pode atacar sua organização, por quê, e com que capacidade — o ponto de partida antes de detalhar cada ameaça individualmente.

**Conceitos-base:**
- **Ameaça (Threat):** alguém ou algo com intenção e capacidade de causar dano (ex: um grupo de ransomware).
- **Vulnerabilidade:** uma fraqueza que pode ser explorada (ex: servidor sem patch).
- **Risco:** a combinação das duas coisas com o impacto se acontecer. Fórmula mental: `Risco = Ameaça × Vulnerabilidade × Impacto`. Sem uma das três partes, não há risco real (uma vulnerabilidade sem ninguém interessado em explorá-la é risco baixo).

**Por que hospital é alvo específico:**
1. Dados de paciente valem muito no mercado negro.
2. Sistemas antigos (dispositivos médicos que não podem ser atualizados).
3. Urgência clínica — não dá pra "esperar" resolver um incidente, o que aumenta pressão pra pagar resgate.
4. Regulação (HIPAA) — vazamento gera multa e obrigação de notificação pública.

**Exemplo:** MedDefense tem EHR com dados de milhares de pacientes + firewall exposto sem MFA + já viu 3 hospitais da região sofrerem ransomware → ameaça real, vulnerabilidade real, impacto alto = risco crítico.

---

## 1. Threat Actor Taxonomy

**O que é:** processo de classificar um agente de ameaça a partir de evidências técnicas (não suposição) — como um perito monta um perfil a partir de pistas.

**Critérios formais de classificação:**
- **Actor Type:** Nation-State/APT, Organized Crime, Insider, Hacktivist, Unskilled/Opportunistic.
- **Interno vs Externo:** o ataque partiu de dentro (funcionário) ou de fora?
- **Recursos:** ferramentas customizadas e caras (indício de grupo bem financiado) vs ferramentas públicas/gratuitas (indício de atacante casual).
- **Sophistication (nível técnico):** baixo (usa exploit pronto), médio (adapta ferramentas), alto (desenvolve exploit próprio), muito alto (zero-day + operação sem ser detectado por meses).
- **Motivação:** financeira, espionagem (roubo de propriedade intelectual/pesquisa), ideológica (hacktivismo), vingança pessoal, curiosidade.
- **Confidence Level:** o quão certo você está da atribuição, e por quê — sempre justificado com evidência (ex: "certificado de assinatura de código roubado + DNS criptografado para C2 + 14 meses sem detecção" aponta pra nação-estado, não crime comum, porque crime comum quer lucro rápido, não paciência de 14 meses).

**Exemplo prático:** Relatório mostra exploração de zero-day, malware customizado, nenhum pedido de resgate, alvo foi dado de pesquisa clínica (não dinheiro). Conclusão: Nation-State/APT, motivação espionagem, confiança alta — porque crime organizado não investe tanto esforço sem cobrar resgate.

**Framework de apoio — Diamond Model:** toda intrusão pode ser descrita por 4 pontos conectados: **Adversário** (quem) — **Capacidade** (ferramentas/técnica) — **Infraestrutura** (servidores/domínios usados) — **Vítima** (alvo). Ajuda a organizar o raciocínio de atribuição.

---

## 2. Ransomware Assessment

**O que é:** entender ransomware como **modelo de negócio criminoso**, não só como "vírus que criptografa arquivo".

**RaaS (Ransomware-as-a-Service) — os papéis:**
| Papel | Função | Ganho |
|---|---|---|
| Developers | criam e mantêm o malware, operam o site de vazamento | 20-30% do resgate |
| Affiliates | executam a invasão de fato | 70-80% do resgate |
| Initial Access Brokers (IAB) | vendem acesso já comprometido (VPN, RDP) | US$500 a US$10.000 por acesso |
| Negotiators | conversam com a vítima no portal de extorsão | comissão |

**Double extortion (dupla extorsão):** o atacante rouba os dados **antes** de criptografar. Assim, mesmo que a vítima tenha backup e recupere sozinha, ainda existe a ameaça "pague ou publicamos seus dados". É por isso que destruir o backup também virou passo padrão do ataque — sem essa segunda alavanca, a vítima simplesmente restaura e ignora o pedido de resgate.

**Linha do tempo típica de um ataque (para referência ao montar kill chains):**
1. Dias -30 a 0: acesso inicial (compra de IAB, phishing, ou exploração direta).
2. Dias 1-2: mapeamento da rede, Active Directory, e principalmente **onde está o backup**.
3. Dias 2-3: escalonamento de privilégio até Domain Admin.
4. Dias 3-5: exfiltração de dados (15-50GB é típico em alvo hospitalar).
5. Dia 5+: deploy simultâneo do ransomware em toda a rede, geralmente via GPO (Group Policy Object) disparado de um Domain Controller comprometido.

**Por que hospital é alvo lógico (4 razões):**
1. Urgência clínica = pressão pra pagar rápido.
2. Prontuário vale US$250-1.000 no mercado negro (cartão de crédito vale US$5-50, porque pode ser cancelado; dado médico não).
3. Tecnologia legada = mais fácil de invadir e se mover lateralmente.
4. Seguro cibernético paga o resgate com frequência, o que os atacantes já sabem e usam pra fixar o valor pedido.

**Exemplo:** afiliado compra acesso VPN por US$5.000 de um IAB, passa 2 dias mapeando a rede, encontra e apaga o job de backup do NAS, exfiltra a base de pacientes, e só então dispara o ransomware via GPO — atingindo todos os servidores ao mesmo tempo.

---

## 3. Insider Threat Assessment

**O que é:** ameaça originada de alguém com acesso legítimo — nem toda ameaça interna é intencional, e a classificação certa muda totalmente a mitigação.

**As 3 classificações:**
- **Malicious (malicioso):** intenção clara de causar dano ou lucrar (ex: funcionário vende dado de paciente).
- **Negligent (negligente):** não há intenção, é falha de processo ou cultura organizacional (ex: conta compartilhada porque "sempre foi assim").
- **Compromised (comprometido):** a conta é legítima, mas está sendo usada por um terceiro que roubou a credencial (a pessoa não fez nada errado, mas o efeito é o mesmo).

**Indicadores que ajudam a diferenciar:**
- **Comportamentais:** horário estranho de acesso, volume de dados incomum, acesso fora do escopo do cargo.
- **Técnicos:** múltiplas sessões simultâneas da mesma conta, login de contas já desligadas, ausência de log individual.

**Controles associados a cada tipo:**
- Malicious → monitoramento de comportamento (UEBA), DLP (Data Loss Prevention), segregação de funções.
- Negligent → treinamento, login individual (não compartilhado), timeout automático de sessão.
- Compromised → MFA, detecção de anomalia de login.

**Exemplo 1:** login compartilhado entre técnicos do PACS, sem timeout de sessão → classificação **negligente** (falha de processo, não má intenção individual). Mitigação: login individual + timeout automático.

**Exemplo 2:** conta de ex-contratado autenticando 3 vezes fora do horário, 2 meses após o desligamento, sem chamado aberto → classificação **negligente (sistêmica)**, causa raiz é falha de offboarding — mas exige investigação individual porque também pode indicar uso malicioso da credencial por terceiro.

---

## 4. Social Engineering Analysis

**O que é:** ataque que manipula uma **pessoa**, não um sistema, pra obter acesso ou informação.

**Vetores (terminologia oficial CompTIA Security+ 2.2):**
| Vetor | Descrição | Exemplo |
|---|---|---|
| Phishing | e-mail fraudulento em massa | link falso de "reset de senha" |
| Spear phishing | phishing direcionado a uma pessoa específica | e-mail citando o nome do diretor de TI |
| Whaling | spear phishing em executivo de alto escalão | e-mail falso pro CFO pedindo transferência |
| Vishing | golpe por voz/telefone | ligação fingindo ser o suporte técnico |
| Smishing | golpe por SMS | SMS "sua entrega está retida, clique aqui" |
| Pretexting | criar uma história falsa pra ganhar confiança | "sou da auditoria, preciso da sua senha" |
| Baiting | isca física ou digital | pendrive "esquecido" no estacionamento |
| Tailgating/Piggybacking | seguir alguém por uma porta sem crachá | entrar atrás de um funcionário sem bater ponto |
| Watering hole | comprometer um site que a vítima costuma visitar | site de associação médica infectado |

**Gatilhos psicológicos (Cialdini) que tornam o golpe eficaz:**
- **Autoridade** ("sou do suporte técnico oficial").
- **Urgência** ("sua conta será bloqueada em 1 hora").
- **Medo** ("detectamos acesso suspeito à sua conta").
- **Prova social** ("todos os outros departamentos já atualizaram").
- **Curiosidade/simpatia** (isca genérica, ex: "veja quem visualizou seu perfil").

**Como resolver cada cenário do exercício:** identificar o vetor exato (tabela acima) + o gatilho psicológico dominante + 3 red flags concretas no texto (remetente estranho, urgência artificial, link não corresponde ao domínio oficial) + 1 controle técnico + 1 controle administrativo.

**Exemplo:** e-mail "atualização urgente de firmware FortiGate" assinado como suporte técnico, pedindo clique em link externo → vetor: spear phishing; gatilho: autoridade + urgência; controle técnico: banner "e-mail externo" + bloqueio de link; controle administrativo: treinamento pra verificar por telefone antes de clicar.

---

## 5. Supply Chain / Third-Party Risk Assessment

**O que é:** todo fornecedor com acesso à sua rede é, na prática, uma extensão da sua superfície de ataque — a segurança da organização é tão forte quanto o elo mais fraco entre seus parceiros.

**Conceitos-chave:**
- **TPRM (Third-Party Risk Management):** processo formal de avaliar e monitorar o risco de cada fornecedor.
- **BAA (Business Associate Agreement):** em ambiente de saúde (HIPAA), contrato obrigatório definindo responsabilidade do fornecedor sobre dados de paciente.
- **Right to audit:** cláusula contratual que permite auditar a segurança do fornecedor.
- **Least privilege para terceiros:** o fornecedor só deve ter acesso ao que realmente precisa, nada além.

**O que avaliar em cada vendor:**
1. Escopo de acesso concedido (o que ele pode ver/tocar).
2. Tipo de conexão (VPN dedicada, acesso remoto, API).
3. Existência de MFA na conta do fornecedor.
4. Caminho de comprometimento: se o fornecedor for hackeado, o que o atacante ganha na sua rede?

**Exemplo real de referência (fora do exercício, mas didático):** o ataque à SolarWinds (2020) comprometeu um único fornecedor de software e, por causa disso, atingiu milhares de clientes — prova de como um elo fraco na cadeia de suprimentos vira porta de entrada em massa.

**Exemplo MedDefense:** empresa de manutenção do EHR (MedTech Solutions) tem VPN de acesso remoto sem MFA e sem restrição de horário → se essa empresa for comprometida, o atacante entra direto no EHR do hospital como se fosse um usuário legítimo.

---

## 6. Threat Actor Matrix

**O que é:** uma tabela única comparando os 6 tipos de ator lado a lado — não é teoria nova, é consolidação do que foi levantado nos itens 1 a 5.

**Estrutura esperada por ator:** motivação, capacidade técnica, TTPs (Tactics, Techniques, Procedures) típicos, e qual ativo da MedDefense esse ator provavelmente mira.

**Exemplo de linha da matriz:**
| Ator | Motivação | Sofisticação | Alvo preferencial |
|---|---|---|---|
| Ransomware (RaaS) | Financeira | Média-Alta | EHR + backup (dupla extorsão) |
| Nation-State APT | Espionagem | Muito Alta | Dados de pesquisa clínica |
| Insider Malicioso | Financeira/vingança | Baixa-Média | Dados que ele já tem acesso |
| Hacktivista | Ideológica | Baixa-Média | Site público, vazamento pra exposição |
| Oportunista | Curiosidade/lucro fácil | Baixa | Qualquer sistema exposto e sem patch |

---

## 7. Attack Surface Map

**O que é:** listar **todo ponto de entrada** possível pra dentro da organização, organizado por camada.

**As 4 camadas clássicas:**
- **Externa:** tudo acessível pela internet (VPN, e-mail, site, portal do paciente, DNS).
- **Interna:** rede local, segmentação (ou ausência dela), Active Directory.
- **Humana:** funcionários, terceiros — qualquer pessoa que pode ser enganada.
- **Física:** acesso físico ao datacenter, a um dispositivo médico, a uma sala de servidores.

**Para cada ponto de entrada, documentar:** o ativo por trás dele, o controle que já existe, e o gap (se houver) que deixa ele exposto.

**Conceitos relacionados:**
- **Attack Surface Reduction (ASR):** prática de eliminar ou desligar tudo que não é estritamente necessário, reduzindo pontos de entrada.
- **Zero Trust:** princípio de nunca confiar automaticamente em nada, nem em tráfego interno — sempre verificar.

**Exemplo:** VPN FortiGate 100F exposta na internet, sem MFA (GAP-014) → ponto de entrada externo de alto risco, porque uma única credencial vazada já basta pra entrar na rede.

---

## 8. Technical Vectors Assessment

**O que é:** vetores técnicos de invasão — diferente do vetor humano do item 4, aqui o alvo é o sistema em si.

**Categorias principais:**
- **Software vulnerável/desatualizado:** versão com CVE conhecida, fim de suporte (EOL/End-of-Support).
- **Configuração incorreta:** porta aberta sem necessidade, permissão excessiva, serviço rodando com privilégio de admin sem precisar.
- **Credenciais fracas ou padrão:** senha default de fábrica nunca trocada, senha simples.
- **Protocolo legado inseguro:** SMBv1, Telnet, ou no caso hospitalar, protocolo DICOM sem autenticação em dispositivo médico.
- **Zero-day vs exploit conhecido:** zero-day exige atacante sofisticado (nação-estado); exploit público de CVE antiga pode ser usado até por iniciante.

**Ligação com a taxonomia (item 1/6):** o tipo de vetor indica o tipo de atacante mais provável — CVE pública e antiga atrai oportunista; zero-day indica ator avançado.

**Exemplo:** Apache 2.4.29 rodando em billing-srv-01, sem suporte desde junho/2023, com RCE (Remote Code Execution) conhecido e público → qualquer atacante oportunista com um exploit baixado da internet consegue comprometer o servidor, sem precisar de habilidade avançada.

---

## 9. Vector-to-Asset Matrix

**O que é:** matriz cruzando **vetor de ataque (linhas) × ativo crítico (colunas)**, pra visualizar onde a exposição se concentra.

**Como escolher os ativos críticos:** usar a Tríade CIA (Confidencialidade, Integridade, Disponibilidade) — qual ativo, se comprometido, causa maior dano em uma dessas três dimensões. Ex: EHR = alta confidencialidade (dado de paciente) + alta disponibilidade (precisa estar sempre acessível pro atendimento).

**Como preencher uma célula da matriz:** "esse vetor consegue atingir esse ativo? De que forma, especificamente?" — não é só sim/não, é explicar o caminho.

**Exemplo:** linha "VPN sem MFA" cruzando com coluna "Active Directory" → célula de risco crítico, porque uma credencial de VPN roubada permite login direto na rede, e a partir daí escalar até o Domain Controller.

**Por que importa:** essa matriz é a base direta pra montar os Kill Chains do item seguinte — cada célula de alto risco vira o ponto de partida de uma cadeia de ataque completa.

---

## 10. Kill Chains

**O que é:** o **Cyber Kill Chain** (modelo da Lockheed Martin) descreve as fases sequenciais de um ataque completo, do reconhecimento até o objetivo final.

**As 7 fases:**
1. **Reconnaissance:** coletar informação sobre o alvo (funcionários no LinkedIn, tecnologia exposta via scan).
2. **Weaponization:** preparar o payload (malware, exploit, e-mail malicioso).
3. **Delivery:** entregar o payload (enviar o e-mail, explorar o serviço exposto).
4. **Exploitation:** a vulnerabilidade é de fato explorada (o clique acontece, o exploit roda).
5. **Installation:** o atacante instala persistência (backdoor, malware residente).
6. **Command & Control (C2):** canal de comunicação remoto entre o atacante e a máquina comprometida.
7. **Actions on Objectives:** o objetivo final é executado (exfiltração de dados, criptografia, sabotagem).

**Conceitos complementares:**
- **MITRE ATT&CK** (item 13) é uma evolução mais granular do kill chain.
- **Unified Kill Chain** (Paul Pols) combina os dois modelos numa cadeia só.

**Exemplo de kill chain completa:** phishing pro diretor de TI (Delivery) → credencial roubada usada na VPN (Exploitation) → malware instalado na máquina (Installation) → atacante se comunica via C2 encriptado (C2) → GPO distribui ransomware pra rede inteira (Actions on Objectives).

---

## 11 e 12. STRIDE (na EHR e na Arquitetura)

**O que é:** framework de *threat modeling* da Microsoft, com 6 categorias fixas de ameaça, aplicado sistema por sistema.

| Letra | Categoria | Pergunta-chave | Exemplo |
|---|---|---|---|
| S | Spoofing | Alguém pode fingir ser outra pessoa/sistema? | login com credencial roubada, sem MFA |
| T | Tampering | Alguém pode alterar dado sem permissão? | editar prontuário sem autorização |
| R | Repudiation | Alguém pode negar uma ação por falta de prova? | sem log, ninguém comprova quem acessou o quê |
| I | Information Disclosure | Alguém pode ver dado que não devia? | exportação não autorizada da base de pacientes |
| D | Denial of Service | Alguém pode derrubar o serviço? | ransomware trava bomba de infusão médica |
| E | Elevation of Privilege | Alguém pode virar admin sem ser? | bug de permissão vira caminho pra Domain Admin |

**Como aplicar:** para cada categoria, documentar um Threat ID, descrição, vetor de ataque associado (relacionando com os itens 4 e 8) e impacto no negócio.

**Diferença entre os dois exercícios:** o item 11 aplica STRIDE só no sistema EHR (foco único); o item 12 repete o processo pra cada sistema da arquitetura (PACS, dispositivos médicos, rede) — mesma metodologia, escopo mais amplo.

**Frameworks complementares (contexto, não usados diretamente aqui):**
- **DREAD:** método de pontuação de risco (Damage, Reproducibility, Exploitability, Affected users, Discoverability).
- **PASTA / VAST:** outras metodologias de threat modeling, mais focadas em risco de negócio ou escala ágil.

**Exemplo (EHR):** login sem MFA no sistema EHR (GAP-014) → categoria **Spoofing** → atacante autentica como se fosse um médico legítimo → impacto: acesso completo a prontuários sem verificação real de identidade.

---

## 13. ATT&CK Mapping

**O que é:** matriz da MITRE que documenta comportamentos reais de adversários, observados em campanhas reais (não teórico), com nomenclatura padronizada.

**Estrutura:**
- **Tactic (Tática):** o "porquê" — a fase do objetivo do atacante (Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Impact).
- **Technique (Técnica):** o "como" — a ação específica, com código no formato T####  (ex: T1190) ou sub-técnica T####.### (ex: T1566.001 = phishing via anexo).

**Diferença pro Kill Chain:** o ATT&CK é mais granular (dezenas de técnicas por tática) e não precisa seguir ordem linear — um atacante pode voltar pra "Discovery" várias vezes durante o ataque.

**Exemplo de mapeamento:**
| Passo do ataque | Tactic | Technique |
|---|---|---|
| Compra de acesso de um IAB | Resource Development | Acquire Access (T1650) |
| FortiGate exposta explorada | Initial Access | Exploit Public-Facing Application (T1190) |
| Dump de credenciais de memória | Credential Access | OS Credential Dumping (T1003) |
| Ransomware via GPO | Impact | Data Encrypted for Impact (T1486) |

**Como resolver o exercício:** para cada passo do cenário, identificar a Tactic, a Technique/código correspondente, e o "fator MedDefense" — o motivo organizacional específico que torna aquela técnica viável ali (ex: "FortiGate exposta à internet" é o que habilita T1190).

---

## 14. Threat Scenarios

**O que é:** consolidar ator + vetor + kill chain + STRIDE + ATT&CK numa **narrativa única e plausível**, contada do início ao fim.

**Os três eixos de cenário a cobrir:**
- **Externo:** ex: campanha de ransomware (ator de fora explorando vetor técnico ou humano).
- **Interno:** ex: exfiltração de dado por insider.
- **Terceiro/cadeia de suprimentos:** ex: fornecedor comprometido usado como ponte.

**Estrutura de um cenário bem escrito:** título, ator, motivação, vetor inicial, superfície de ataque explorada, progressão passo a passo, impacto final.

**Exemplo:** "Operação Flatline" — afiliado de ransomware (ator) manda phishing se passando por suporte Fortinet (vetor inicial, vetor humano) pro diretor de TI; credencial cai; atacante entra na VPN (superfície externa); mapeia rede e apaga backup; exfiltra base de pacientes; dispara criptografia via GPO em todos os sistemas de domínio (impacto final: parada total + vazamento de dados).

---

## 15. Gap-Threat Correlation

**O que é:** ligar cada **gap de controle** identificado no assessment anterior (1x00) às ameaças específicas que exploram exatamente aquele gap — uma matriz de rastreabilidade.

**Lógica da correlação:** um gap nunca é abstrato — ele sempre habilita uma ou mais cadeias de ataque concretas. Documentar: `GAP-XXX → qual Kill Chain usa esse gap → em qual Cenário aparece → qual controle fecha o gap`.

**Por que essa correlação importa na prática:** é o que transforma "recomendo comprar MFA" (opinião) em "GAP-014 permite Kill Chain 2, que leva à tomada total do domínio, então MFA é obrigatório" (justificativa baseada em ameaça real) — essa é a lógica usada em GRC (Governance, Risk & Compliance) pra aprovar orçamento de segurança.

**Exemplo:** GAP-014 (sem MFA na VPN) → habilita a Kill Chain 2 (credencial de VPN comprometida leva à tomada do domínio inteiro) → aparece no Cenário 1 (ransomware) → controle recomendado: MFA obrigatório em toda VPN e conta administrativa.

---

## 16. Threat Priority Assessment

**O que é:** ranquear as ameaças do Top 5 usando o critério formal de risco: **Likelihood (probabilidade) × Impact (impacto)**.

**O que aumenta Likelihood:**
- Superfície de ataque exposta e fácil de encontrar (scan público).
- Facilidade técnica de exploração (exploit pronto disponível).
- Evidência de atividade real no setor (inteligência contextual: "3 hospitais da região já foram atingidos pelo mesmo grupo nos últimos 8 meses").

**O que aumenta Impact:**
- Criticidade do ativo (usa a Tríade CIA do item 9).
- Presença de dado regulado (PHI sob HIPAA = multa e obrigação legal).
- Dependência operacional crítica (dispositivo médico comprometido pode custar vida, não só dinheiro).

**Regra de ouro:** toda posição no ranking precisa citar evidência concreta dos artefatos anteriores (kill chain, STRIDE, gap correlacionado) — não pode ser opinião solta tipo "acho que é o mais perigoso".

**Exemplo:** ransomware fica em 1º lugar porque tem Likelihood alta (grupo já ativo na região, vetor de entrada já mapeado e sem MFA) e Impact altíssimo (para o hospital inteiro, incluindo atendimento a paciente, além de vazar dado regulado).

---

## 17. Threat Evolution — What-If Analysis

**O que é:** análise prospectiva (scenario planning) — testar como o panorama de ameaça inteiro muda se um fator do negócio mudar.

**5 perguntas obrigatórias por cenário hipotético:**
1. **New Threat Actors:** que tipo de ator passa a se interessar?
2. **Changed Vectors:** que vetor novo fica disponível ou mais atrativo?
3. **Shifted Priorities:** como o ranking do item 16 se reordena?
4. **New Gaps:** que controle passa a faltar nesse novo contexto que antes não era necessário?
5. **Net Assessment:** conclusão executiva — o risco líquido aumentou, diminuiu, ou mudou de natureza?

**Por que isso é uma habilidade valiosa:** decisões de negócio (parceria nova, expansão, nova tecnologia) mudam o *threat model* inteiro, não só um ponto isolado — pensar nisso antecipadamente evita ser pego de surpresa.

**Exemplo:** MedDefense fecha parceria com universidade pra pesquisa clínica → passa a interessar nação-estado (antes só interessava crime organizado) → vetor muda de "phishing genérico" pra "espionagem direcionada e paciente"; prioridade se desloca; novo gap: dado de pesquisa não tinha classificação de sigilo antes.

---

## 18. Threat Landscape Report

**O que é:** o documento final — traduzir toda a análise técnica em comunicação executiva, pra quem decide (diretoria/board), que não tem tempo nem vocabulário técnico.

**Estrutura recomendada:**
1. **Executive Summary:** 3-5 frases, direto ao ponto, sem jargão, com a ameaça mais crítica e as 3 principais recomendações.
2. **Corpo do relatório:** organizado em seções lógicas reaproveitando os artefatos anteriores (atores → superfície → cenários → gaps → priorização).
3. **Recomendações:** específicas, priorizadas, e vinculadas a um gap concreto — nunca genéricas.

**Boas práticas de relatório de inteligência de ameaças:**
- Separar **fato observado** de **inferência/suposição**.
- Indicar **nível de confiança** de cada afirmação.
- Ser específico: "ativar MFA na VPN até 30/09" em vez de "melhorar segurança".

**Exemplo de resumo executivo bem escrito:** "MedDefense corresponde ao perfil ideal de alvo de ransomware: dado de paciente valioso, equipe de segurança enxuta, e gaps que já foram explorados em 3 hospitais da região nos últimos 8 meses. A ameaça mais crítica é um ataque de ransomware que criptografa o EHR inteiro e destrói o backup antes de pedir resgate. As 3 prioridades: detecção de intrusão funcional, MFA em todo lugar (incluindo fornecedores), e fechar os 4 gaps que permitem um único phishing virar comprometimento total."

---

## Ordem de dependência entre os arquivos

```
0 panorama geral
 └─ 1,2,3,4,5 perfis de ameaça por categoria (ator, ransomware, insider, humano, fornecedor)
     └─ 6 matriz consolidada de atores
         └─ 7,8,9 superfície de ataque, vetores técnicos, matriz vetor×ativo
             └─ 10 kill chains · 11,12 STRIDE · 13 ATT&CK  (mesma camada, se alimentam do passo anterior)
                 └─ 14 cenários de ameaça consolidados
                     └─ 15 correlação gap × ameaça
                         └─ 16 priorização de risco
                             └─ 17 análise what-if
                                 └─ 18 relatório final
```

## Tabela de frameworks (revisão rápida antes de repetir o módulo)

| Framework | Onde é usado | Ideia central |
|---|---|---|
| Diamond Model | Item 1 | Adversário – Infraestrutura – Capacidade – Vítima |
| CIA Triad | Itens 0, 9, 16 | Confidencialidade, Integridade, Disponibilidade |
| RaaS / Double Extortion | Item 2 | Ransomware é negócio dividido em papéis, com 2 formas de pressão |
| Classificação de Insider | Item 3 | Malicious vs Negligent vs Compromised |
| Sec+ 2.2 (Social Engineering) | Item 4 | Vocabulário padrão de golpes + gatilhos psicológicos |
| TPRM / BAA | Item 5 | Gestão formal de risco de fornecedor em ambiente regulado |
| Cyber Kill Chain (Lockheed Martin) | Item 10 | 7 fases, do reconhecimento ao objetivo final |
| STRIDE | Itens 11, 12 | 6 categorias de ameaça, aplicadas por sistema |
| MITRE ATT&CK | Item 13 | Tactics (porquê) + Techniques (como), com código padronizado |
| Risk Matrix | Item 16 | Probabilidade × Impacto = prioridade de risco |
| Scenario Planning | Item 17 | Antecipar como mudança de contexto muda o threat model |
| Threat Intel Reporting | Item 18 | Fato vs inferência, nível de confiança, recomendação específica |

---

*Guia de estudo — não faz parte da entrega. Use como checklist teórico antes de revisar ou expandir qualquer exercício do módulo.*
