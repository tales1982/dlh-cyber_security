# 1x05 – Board Briefing

## Task - 0-advisory_analysis.md
Conceito: Mostra como transformar um advisory de threat intelligence (linguagem genérica de CISA/CTI) em uma análise concreta, mapeando cada fase do ataque para ativos, vulnerabilidades e gaps específicos do próprio ambiente. É a base da contextualização de inteligência de ameaças: uma campanha ativa só é útil ao negócio quando traduzida em "isso nos afeta, aqui, assim". O resultado é um placar de exposição fase a fase, não uma leitura teórica do relatório.

## Task - 1-cve_deep_dive.md
Conceito: Ensina o processo de pesquisa aprofundada de uma CVE — descrição técnica (NVD/CWE), cálculo do CVSS base e seus ajustes ambientais e temporais, e verificação de exploração pública (KEV, Exploit-DB, Metasploit). O ponto central é que a ausência de exploit público não reduz a urgência quando a CVE já está sendo explorada ativamente por atores sofisticados; a pontuação real de risco deve refletir o contexto da organização, não apenas o número da NVD.

## Task - 2-kill_chain_overlay.md
Conceito: Compara uma kill chain hipotética, construída antecipadamente, com a cadeia de ataque real observada em uma campanha ativa, identificando onde o modelo original acertou e onde divergiu (ex.: vetor de entrada previsto vs. real). Essa sobreposição também mapeia quais controles planejados de fato interceptam cada fase do ataque real, revelando lacunas entre o plano de segurança e a proteção efetiva.

## Task - 3-emergency_plan.md
Conceito: Trata de planejamento de resposta a incidentes sob restrição severa de tempo e pessoal, organizando ações em camadas (imediato, curto prazo, médio prazo) com donos, pré-requisitos e uma análise explícita de risco-da-ação vs. risco-da-inação. Também aborda como resolver conflitos de recursos quando poucas pessoas precisam executar múltiplas mudanças críticas simultaneamente sem gerar uma nova instabilidade.

## Task - 4-crypto_emergency.md
Conceito: Conecta fraquezas criptográficas específicas (falta de criptografia em trânsito/repouso, algoritmos quebrados) às técnicas reais de um ataque ativo, e repriotiza a correção com base em inteligência de ameaça atual em vez da ordem original planejada. Reforça um princípio central de defesa em profundidade: criptografia sozinha não impede um atacante que já possui privilégios suficientes no host — ela precisa ser combinada com controles de acesso e segmentação.

## Task - 5-ale_update.md
Conceito: Demonstra como a Expectativa de Perda Anualizada (ALE) deve ser recalculada quando chega nova inteligência de ameaça, ajustando a Taxa de Ocorrência Anual (ARO) e o Fator de Exposição (EF) para refletir uma campanha ativa e confirmada em vez de uma taxa genérica de setor. Mostra também como essa atualização de risco financeiro pode mudar decisões orçamentárias, transformando controles antes "marginais" em claramente justificados.

## Task - 6-technical_proof.md
Conceito: Reúne verificações técnicas práticas que sustentam uma análise de segurança: inspeção de certificados TLS via OpenSSL, verificação de integridade por hash SHA-256 (efeito avalanche), pesquisa de exploits públicos e auditoria de hardening de sistema (Lynis). A lição central é que afirmações de segurança devem ser comprovadas com comandos e evidências reais, não apenas descritas.

## Task - 7-risk_register_update.md
Conceito: Explica a governança de um registro de riscos vivo — como atualizar uma entrada existente com nova inteligência, criar uma nova entrada de risco específica, definir Indicadores-Chave de Risco (KRIs) e aplicar formalmente os gatilhos que obrigam uma revisão fora do ciclo normal. O registro de riscos não é estático; ele deve reagir a eventos como uma nova CVE crítica ou um incidente confirmado.

## Task - 8-comprehensive_assessment.md
Conceito: Consolida múltiplas avaliações anteriores (ativos, ameaças, vulnerabilidades, risco, criptografia) em um relatório executivo único e coerente, destacando a lacuna entre o que foi planejado/aprovado e o que de fato foi implementado. É o exercício de síntese que transforma semanas de análise técnica dispersa em uma narrativa de postura de segurança compreensível para a liderança.

## Task - 9-board_presentation.md
Conceito: Foca na comunicação de risco técnico para um conselho executivo — condensar tudo em um briefing de uma página e adaptar a mensagem para diferentes stakeholders (CEO, CFO, jurídico, presidente do conselho) usando a linguagem e as prioridades de cada um. É a habilidade de traduzir achados técnicos em decisões de negócio acionáveis e financiáveis.
