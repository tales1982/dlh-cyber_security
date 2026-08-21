# 1x01 – Know Your Enemy

## Task - 0-threat_landscape_summary.md
Conceito: Perfilamento de atores de ameaça (threat actor profiling) é a prática de categorizar quem pode atacar uma organização segundo tipo (crime organizado, estado-nação, insider, hacktivista, oportunista), motivação, sofisticação técnica e recursos disponíveis. Esse perfil não é genérico: ele é cruzado com a lógica específica do setor (por exemplo, por que hospitais são alvos atrativos) para estimar a probabilidade real de cada ator mirar a organização avaliada.

## Task - 1-threat_actor_taxonomy.md
Conceito: Atribuição de ameaças (threat attribution) é o processo de classificar um incidente observado em um tipo de ator com base em evidências indiretas — sofisticação da técnica, motivação aparente, recursos usados, padrão de comportamento — em vez de identificar a pessoa exata. O exercício também ensina que a atribuição tem níveis de confiança (alto, médio, baixo) e que evidências ambíguas podem apontar igualmente para mais de um tipo de ator.

## Task - 2-ransomware_assessment.md
Conceito: Ransomware-as-a-Service (RaaS) é um modelo operacional onde desenvolvedores, afiliados e "Initial Access Brokers" dividem papéis e lucro em uma cadeia de crime industrializada. O conceito central de "dupla extorsão" (double extortion) é a combinação de criptografar dados e ameaçar vazá-los publicamente, criando duas alavancas de pressão independentes sobre a vítima — o que torna a simples restauração de backups insuficiente para neutralizar o ataque.

## Task - 3-insider_assessment.md
Conceito: Ameaça interna (insider threat) é o risco representado por pessoas que já possuem acesso legítimo a sistemas, dividida em duas categorias: negligente (erro ou atalho sem intenção maliciosa) e maliciosa (abuso deliberado de acesso por vingança, ganho financeiro ou curiosidade). A classificação correta depende de indicadores comportamentais específicos, não apenas do dano causado.

## Task - 4-social_engineering_analysis.md
Conceito: Engenharia social é a manipulação de pessoas — em vez de sistemas — para obter acesso ou informação, explorando alavancas psicológicas como urgência, autoridade, familiaridade e prestatividade. O exercício cobre os vetores específicos da certificação Security+ (phishing, vishing, smishing, BEC, watering hole, typosquatting, tailgating), reforçando que cada vetor tem sinais de alerta e controles técnicos/administrativos próprios.

## Task - 5-supply_chain_assessment.md
Conceito: Risco de cadeia de suprimentos (supply chain / third-party risk) reconhece que o acesso concedido a fornecedores e prestadores de serviço estende a superfície de ataque da organização além do seu próprio perímetro. Avaliar esse risco exige mapear o escopo exato do acesso de cada vendor e o "caminho de comprometimento" que um invasor percorreria caso aquele fornecedor específico fosse violado.

## Task - 6-threat_actor_matrix.md
Conceito: Uma matriz de atores de ameaça consolida, para cada tipo de ator, sua probabilidade, capacidade, motivação, vetor preferido e alvo provável, permitindo comparar e priorizar ameaças lado a lado. É o passo que transforma perfis individuais de atores em uma lista ordenada de prioridades defensivas.

## Task - 7-attack_surface_map.md
Conceito: Mapeamento de superfície de ataque é a identificação sistemática de todos os pontos por onde um atacante pode tentar entrar, organizados tipicamente em três camadas — externa (internet), interna (rede) e humana (pessoas). O exercício reforça que, em uma rede não segmentada ("flat network"), qualquer ponto de entrada pode se tornar um atalho direto até os ativos mais críticos.

## Task - 8-technical_vectors.md
Conceito: Vetores técnicos de ataque são categorias recorrentes de fraqueza que um atacante explora — software vulnerável, sistemas fora de suporte (EOL), portas de serviço abertas, credenciais padrão, redes inseguras e dispositivos removíveis não gerenciados. Cada categoria é analisada junto ao tipo de ator mais provável de explorá-la, ligando a fraqueza técnica ao adversário real.

## Task - 8-threat_landscape_report.md
Conceito: Um relatório de panorama de ameaças (threat landscape report) é o documento consolidado que sintetiza atores, vetores, superfície de ataque, kill chains, STRIDE, cenários e correlação de gaps em uma narrativa única voltada a decisão executiva. Ele representa a etapa final de inteligência de ameaças, traduzindo análise técnica dispersa em recomendações priorizadas e acionáveis.

## Task - 9-vector_asset_matrix.md
Conceito: Uma matriz de vetor-versus-ativo cruza cada vetor de ataque possível contra cada ativo crítico, mapeando o caminho de exploração (ou a ausência dele) célula a célula. Isso permite identificar os "ativos mais conectados" (alcançáveis por múltiplos vetores) e os "vetores mais versáteis" (que alcançam múltiplos ativos), revelando onde o investimento defensivo tem maior alavancagem.

## Task - 10-kill_chains.md
Conceito: A Cyber Kill Chain é um modelo que descreve um ataque como uma sequência de etapas — acesso inicial, estabelecimento de presença, movimento lateral/escalação, execução do objetivo e impacto. Mapear um ataque nessas etapas permite identificar "break points": estágios específicos onde um controle de segurança poderia ter interrompido toda a cadeia antes do impacto final.

## Task - 11-stride_ehr.md
Conceito: STRIDE é um modelo de modelagem de ameaças que categoriza riscos em seis tipos — Spoofing (falsificação de identidade), Tampering (adulteração), Repudiation (repúdio/falta de rastreabilidade), Information Disclosure (vazamento), Denial of Service (indisponibilidade) e Elevation of Privilege (escalação de privilégio). Aplicar STRIDE em profundidade a um único sistema crítico gera uma lista sistemática de ameaças por categoria, em vez de depender de brainstorming ad-hoc.

## Task - 12-stride_architecture.md
Conceito: STRIDE também pode ser aplicado em nível de arquitetura, cobrindo múltiplos sistemas de forma mais superficial (survey level) para identificar rapidamente a ameaça dominante de cada componente. Isso mostra como o mesmo framework se adapta tanto a uma análise profunda de um único ativo quanto a uma varredura ampla de vários sistemas.

## Task - 13-attck_mapping.md
Conceito: O MITRE ATT&CK é uma matriz de táticas (o "porquê" de cada etapa, como Acesso Inicial ou Movimento Lateral) e técnicas (o "como" específico, como Pass-the-Hash ou Phishing por Anexo) usadas por atacantes reais. Mapear uma narrativa de ataque a técnicas ATT&CK cria um vocabulário comum e comparável entre diferentes cenários de ataque, revelando táticas recorrentes onde a defesa deve investir primeiro.

## Task - 14-threat_scenarios.md
Conceito: Um cenário de ameaça é uma narrativa completa que une ator, motivação, vetor inicial, sequência de ataque, categorias STRIDE, ativos impactados e impacto de negócio em uma única história coerente. Construir cenários realistas (em vez de listas abstratas de riscos) ajuda a comunicar consequências concretas a stakeholders não técnicos.

## Task - 15-gap_threat_correlation.md
Conceito: Correlação entre gaps e ameaças é o processo de recalibrar a prioridade de vulnerabilidades já identificadas (numa análise interna) cruzando-as com evidências externas de quem realmente as exploraria e como. Um gap pode subir ou descer de prioridade quando se descobre que ele é (ou não é) um passo central em múltiplos kill chains e cenários de ataque reais.

## Task - 16-threat_priority_assessment.md
Conceito: Priorização de ameaças combina probabilidade (likelihood) e impacto em uma classificação de risco composta, ordenando as ameaças da mais para a menos crítica. O conceito central é que nem sempre o impacto mais severo define o primeiro lugar — a combinação de probabilidade alta e impacto alto juntos é que determina a prioridade final.

## Task - 17-threat_evolution.md
Conceito: Análise "e se" (what-if / threat evolution) avalia como o panorama de ameaças mudaria diante de eventos hipotéticos futuros — uma nova parceria, uma migração para nuvem, exposição na mídia. O conceito ensina que mudanças no ambiente não apenas alteram o nível de risco, mas podem ativar atores de ameaça antes irrelevantes e criar categorias inteiramente novas de gap.

## Task - 18-threat_landscape_report.md
Conceito: Um relatório de panorama de ameaças (threat landscape report) é o documento consolidado que sintetiza atores, vetores, superfície de ataque, kill chains, STRIDE, cenários e correlação de gaps em uma narrativa única voltada a decisão executiva. Ele representa a etapa final de inteligência de ameaças, traduzindo análise técnica dispersa em recomendações priorizadas e acionáveis.
