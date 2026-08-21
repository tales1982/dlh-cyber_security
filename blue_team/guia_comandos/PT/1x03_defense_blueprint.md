# 1x03 – Defense Blueprint

## Task - 0-framework_landscape.md
Conceito: Compara os três grandes frameworks de segurança da informação — NIST CSF, CIS Controls e ISO/IEC 27001 — e explica que cada um opera em uma "altitude" diferente: NIST CSF é estratégico (o quê alcançar), CIS Controls é operacional (como implementar, em ordem de prioridade) e ISO 27001 é de governança/certificação (como provar formalmente que o programa é gerenciado). Organizações maduras costumam usar os três em conjunto, não como concorrentes.

## Task - 1-nist_csf_mapping.md
Conceito: O NIST CSF 2.0 organiza a cibersegurança em seis Funções (Govern, Identify, Protect, Detect, Respond, Recover), cada uma decomposta em Categorias e Subcategorias que descrevem resultados desejados, não passos técnicos prescritivos. O exercício aplica uma análise de maturidade "Current Profile vs. Target Profile", avaliando o nível atual (Not Implemented, Partial, Managed) de cada função com evidências e definindo metas realistas de melhoria.

## Task - 2-cis_controls_audit.md
Conceito: O CIS Controls v8 é um conjunto prescritivo de 18 controles defensivos, priorizados a partir de dados reais de ataques, organizados em três Grupos de Implementação cumulativos (IG1, IG2, IG3) conforme a maturidade e o porte da organização. O exercício audita cada controle atribuindo uma nota de maturidade (Implemented, Partial, Not Implemented) baseada em evidências concretas do ambiente.

## Task - 3-gap_framework_bridge.md
Conceito: Demonstra como conectar falhas técnicas específicas (achados de scans de vulnerabilidade, cenários de ameaça) às categorias formais dos frameworks (Funções do NIST CSF e Controles do CIS), traduzindo descobertas brutas de segurança em uma estrutura de remediação organizada e rastreável, ligando evidência técnica a linguagem de governança.

## Task - 4-governance_architecture.md
Conceito: Estrutura de governança de segurança usando uma matriz RACI (Responsible, Accountable, Consulted, Informed) para definir quem decide e quem executa cada atividade de segurança, além dos papéis formais de dados (Data Owner, Data Controller, Data Processor, Data Custodian). Também aborda a decisão entre contratar um CISO em tempo integral versus um vCISO (CISO virtual/fracionado) conforme a maturidade e o orçamento da organização.

## Task - 5-risk_equation.md
Conceito: Introduz o cálculo quantitativo de risco clássico: SLE (Single Loss Expectancy) = AV (Asset Value) × EF (Exposure Factor), e ALE (Annualized Loss Expectancy) = SLE × ARO (Annualized Rate of Occurrence). Esse modelo transforma risco qualitativo ("alto/médio/baixo") em um valor monetário anual esperado, permitindo comparar riscos e justificar investimentos com base em números.

## Task - 6-ale_workshop.md
Conceito: Aprofunda a aplicação prática da fórmula ALE a cenários de risco reais, incluindo o cálculo do ALE residual após a aplicação de um controle proposto e o "Net Benefit" (ALE evitado menos custo do controle) — a lógica central por trás de qualquer decisão de investimento em segurança baseada em risco.

## Task - 7-cost_benefit_analysis.md
Conceito: Análise custo-benefício de controles de segurança: compara o custo anual de implementar um controle com a redução de ALE que ele proporciona, calculando o "Net Value" para determinar se o investimento se justifica (Verdict: Justified/Not Justified) e priorizar controles por retorno.

## Task - 8-budget_allocation.md
Conceito: Alocação orçamentária sob restrição de capital — ranquear controles pela razão custo-benefício (redução de ALE por dólar gasto) e financiá-los em ordem até o orçamento se esgotar, maximizando a redução total de risco. Inclui o conceito de custo de oportunidade: o risco que permanece exposto ao adiar ou rejeitar um controle.

## Task - 9-cfo_challenge.md
Conceito: Comunicação executiva de risco para stakeholders não técnicos (CFO/financeiro), respondendo a objeções comuns sobre investimento em segurança — histórico sem incidentes, incerteza das estimativas, seguro cibernético como substituto de controles, e orçamento fracionado. Ensina a traduzir risco técnico em linguagem de negócio e ROI.

## Task - 10-risk_register.md
Conceito: O Risk Register (registro de riscos) é uma ferramenta formal de gestão de riscos que documenta cada risco com fonte, ativo afetado, probabilidade, impacto, score de risco inerente, ALE, dono do risco, decisão de tratamento (Mitigate/Accept/Transfer/Avoid) e KRI (Key Risk Indicator) para monitoramento contínuo.

## Task - 11-control_selection.md
Conceito: Seleção formal de controles para cada risco do registro, classificando-os por tipo (Preventive, Detective, Corrective, Compensating) e categoria (Technical, Administrative, Physical), e mapeando cada um a uma referência específica do CIS Controls e do NIST CSF — conectando decisão de risco a implementação concreta.

## Task - 12-acceptable_use_policy.md
Conceito: Elaboração de uma Política de Uso Aceitável (Acceptable Use Policy), documento formal de governança que define como sistemas, dados e credenciais podem ser usados pelos colaboradores, lista atividades proibidas, requisitos de senha/MFA e as consequências proporcionais de violações — transformando expectativas de segurança em um padrão exigível e documentado.

## Task - 13-quick_wins.md
Conceito: "Quick wins" são correções de segurança de baixo custo (ou custo zero) e alto impacto que podem ser implementadas rapidamente, sem necessidade de aprovação orçamentária, priorizando velocidade de remediação para fechar as vulnerabilidades mais críticas antes mesmo do plano orçamentário maior entrar em ação.

## Task - 14-segmentation_architecture.md
Conceito: Segmentação de rede — dividir a infraestrutura em zonas isoladas (VLANs) com uma política de "default-deny" entre elas, permitindo apenas o tráfego explicitamente necessário. É uma técnica central de defesa em profundidade que limita o raio de propagação (blast radius) de um invasor mesmo após um comprometimento inicial.

## Task - 15-red_team_blueprint.md
Conceito: Exercício de red team / pensamento adversarial — assumir a perspectiva de um atacante para testar criticamente o próprio plano de defesa e identificar caminhos de ataque que os controles orçados não cobrem (tipicamente ameaças internas e confiança em terceiros/fornecedores), revelando lacunas que uma auditoria puramente técnica não enxergaria.

## Task - 16-risk_appetite.md
Conceito: O apetite de risco (risk appetite) é uma declaração formal de quanto risco a organização está disposta a aceitar, com limites definidos (ex: ALE acima de determinado valor exige aprovação de um executivo específico), aplicada a decisões concretas de aceitação de risco com medidas compensatórias e gatilhos de revisão obrigatórios.

## Task - 17-security_strategy.md
Conceito: Documento de estratégia de segurança que sintetiza todo o trabalho anterior (framework, governança, análise de risco, controles, orçamento) em um único relatório executivo voltado ao Board, conectando decisões técnicas a resultados de negócio e retorno sobre investimento.

## Task - 18-roadmap.md
Conceito: Roadmap de implementação — sequenciamento de iniciativas de segurança ao longo do tempo (por mês), com donos, dependências explícitas entre etapas e critérios de conclusão mensuráveis, transformando uma estratégia em um plano de execução realista.

## Task - 19-board_pitch.md
Conceito: Comunicação executiva condensada (pitch) para aprovação orçamentária pelo Board — reduzir um programa de segurança complexo a uma narrativa curta e de alto impacto, focada em risco de negócio, retorno financeiro (ROI) e urgência, adequada para uma audiência de tomadores de decisão não técnicos.
