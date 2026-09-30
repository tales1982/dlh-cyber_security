# 1x00 – First Watch

## Task - 0-environment_summary.md

Conceito: Levantamento de ambiente (environment/asset discovery) é a etapa inicial de qualquer avaliação de segurança: mapear sites, infraestrutura, sistemas, dados e estrutura organizacional antes de analisar riscos. Sem esse baseline documentado, é impossível saber o que precisa ser protegido nem identificar lacunas. O exercício também introduz o conceito de "known unknowns" — reconhecendo explicitamente o que ainda não foi verificado, em vez de presumir segurança onde não há evidência.

## Task - 1-incident_classification.md

Conceito: A Tríade CIA (Confidencialidade, Integridade, Disponibilidade) é o modelo fundamental para classificar o impacto de um incidente de segurança. Cada incidente deve ser avaliado quanto a qual pilar foi violado primariamente, podendo haver um impacto secundário quando há evidência textual explícita — nunca especulação. Essa classificação orienta a priorização e a resposta ao incidente.

## Task - 2-root_cause_analysis.md

Conceito: Root Cause Analysis (RCA) é a técnica de investigar a causa raiz de um incidente em vez de tratar apenas o sintoma visível (como alto uso de CPU). O exercício também trabalha o conceito de cryptojacking (mineração de criptomoeda não autorizada usando recursos comprometidos) e reforça que corrigir o sintoma sem eliminar a vulnerabilidade de entrada (ex.: uma falha RCE não corrigida) permite que o mesmo ataque se repita.

## Task - 3-physical_assessment.md

Conceito: Avaliação de segurança física decompõe cada observação em quatro componentes formais de risco — Vulnerabilidade, Ameaça, Impacto (mapeado aos pilares da Tríade CIA) e Severidade. Esse framework mostra que segurança física e segurança lógica estão interligadas: acesso físico não controlado a um armário de rede ou sala de servidores pode comprometer confidencialidade, integridade e disponibilidade de sistemas críticos.

## Task - 4-control_inventory.md

Conceito: Inventário de controles de segurança organiza controles existentes em duas dimensões: Categoria (Técnico, Administrativo, Físico) e Função (Preventivo, Detectivo, Corretivo, Compensatório, Dissuasivo). Essa matriz é a base para qualquer análise de maturidade de segurança, pois permite visualizar rapidamente onde a organização investe proteção e onde não investe.

## Task - 5-control_gaps.md

Conceito: Análise de lacunas de controle (gap analysis) compara a matriz de controles existente contra o que deveria existir, revelando combinações Categoria x Função vazias ou insuficientes. O exercício demonstra um padrão comum em organizações reais: excesso de investimento em controles preventivos e escassez de controles detectivos, corretivos e compensatórios — o que significa que ataques bem-sucedidos passam despercebidos por muito tempo.

## Task - 6-compensating_controls.md

Conceito: Controles compensatórios são medidas alternativas aplicadas quando um sistema não pode ser corrigido, atualizado ou substituído diretamente (por exemplo, um equipamento médico legado rodando um sistema operacional sem suporte). Em vez de eliminar a vulnerabilidade, o controle compensatório reduz a exposição ao risco — tipicamente por segmentação de rede, processo de governança formal, ou restrição de acesso físico — e deve ser priorizado pelo controle que mais reduz o vetor de ataque mais provável.

## Task - 7-asset_registry.md

Conceito: Registro de ativos (asset registry / CMDB) é o inventário formal de todos os sistemas, dispositivos e serviços de uma organização, com dono, localização, criticidade e status. O exercício introduz a prática de reconciliação — comparar a documentação existente contra um scan de rede independente — que expõe discrepâncias reais, como Shadow IT (sistemas não documentados) e ativos documentados que na prática não existem mais.

## Task - 8-criticality_assessment.md

Conceito: Avaliação de criticidade de ativos aplica a Tríade CIA a cada categoria de ativo para determinar seu nível de importância geral (Crítico, Alto, Médio, Baixo). Esse ranking orienta a priorização de investimentos e esforços de proteção, concentrando recursos limitados nos ativos cujo comprometimento traria o maior impacto ao negócio ou à segurança dos pacientes.

## Task - 9-data_map.md

Conceito: Mapeamento de dados (data mapping) identifica onde cada categoria de dado reside, como trafega e como é usada — dados em repouso, em trânsito e em uso — além de sua classificação de sensibilidade (Restrito, Confidencial, etc.). Esse mapeamento é essencial para identificar lacunas de proteção específicas por tipo de dado, já que dados diferentes exigem controles diferentes conforme seu valor e risco.

## Task - 10-complete_control_matrix.md

Conceito: Avaliação de efetividade de controles vai além de apenas inventariar controles — atribui um nível de maturidade (Forte, Adequado, Fraco) a cada um e mapeia sua cobertura sobre os ativos mais críticos. Esse cruzamento revela ativos "parcialmente protegidos" ou "desprotegidos" mesmo quando controles existem no papel, mostrando que ter um controle documentado não equivale a ter proteção real.

## Task - 11-shadow_systems.md

Conceito: Shadow IT são sistemas, dispositivos ou serviços implantados por usuários ou departamentos sem aprovação ou visibilidade da equipe de TI/segurança. Cada caso de Shadow IT exige uma resposta proporcional ao risco e à necessidade legítima por trás dele: legitimar e proteger, migrar para uma alternativa já sancionada, ou descomissionar — sendo que a causa raiz normalmente é um processo de TI lento demais para atender necessidades reais.

## Task - 12-gap_analysis.md

Conceito: Análise de lacunas priorizada combina criticidade do ativo, classificação do dado e cobertura de controle para atribuir um nível de risco (Crítico, Alto, Médio, Baixo) a cada lacuna identificada. Essa metodologia estruturada evita priorização subjetiva, aplicando regras consistentes (por exemplo, a ausência de controle detectivo E corretivo eleva o risco a Crítico) para decidir onde agir primeiro.

## Task - 13-reality_check.md

Conceito: Validar uma avaliação interna contra casos reais de violação de dados (threat intelligence / lessons learned) serve para confirmar se as lacunas identificadas realmente levam a incidentes graves, e para descobrir "pontos cegos" — riscos reais que a análise original não capturou. Esse processo de correlação com incidentes externos aumenta a confiança nas prioridades definidas e frequentemente revela novas lacunas (como falta de gestão de acesso privilegiado ou de desprovisionamento de contas).

## Task - 14-risk_decisions.md

Conceito: Tratamento de risco é a decisão formal sobre como lidar com cada risco identificado, seguindo estratégias padrão: Mitigar, Transferir, Aceitar ou Evitar. Cada decisão deve vir acompanhada de controles propostos, custo estimado, esforço de implementação e redução de risco esperada, permitindo priorização orçamentária racional dentro de um orçamento de segurança limitado.

## Task - 15-predecessor_review.md

Conceito: Revisão por pares (peer review) de uma avaliação de segurança compara conclusões independentes sobre os mesmos achados, resolvendo concordâncias, discordâncias e lacunas que um analista capturou e o outro não. Esse processo de validação cruzada fortalece a qualidade da avaliação final e evidencia como diferentes analistas podem discordar sobre severidade mesmo diante dos mesmos fatos — exigindo justificativa explícita para cada divergência.

## Task - 16-security_posture_assessment.md

Conceito: Uma avaliação de postura de segurança (security posture assessment) é o relatório formal que consolida todo o trabalho anterior — ativos, dados, controles, lacunas e decisões de risco — em um documento estruturado com sumário executivo, escopo, metodologia, achados e recomendações. É o produto final que transforma análises técnicas fragmentadas em uma narrativa coerente sobre o estado de segurança da organização.

## Task - 17-ciso_briefing.md

Conceito: Um briefing executivo (para CISO/board) traduz achados técnicos complexos em linguagem de negócio, focando em impacto financeiro, risco operacional e ações prioritárias com custo e prazo claros. A comunicação com liderança exige remover jargão técnico e usar comparações de custo-benefício (ex.: custo da correção vs. custo de um incidente real) para justificar investimento em segurança.
