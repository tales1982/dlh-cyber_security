# 1x02 – The Weak Links

## Task - 0-first_impressions.md
Conceito: Um relatório de scan de vulnerabilidades é um documento produzido por humanos e ferramentas, e como tal pode conter inconsistências (cabeçalho vs. corpo, contagens erradas, achados adicionados manualmente sem atualizar o resumo). A disciplina de ler e contar cada achado individualmente, em vez de confiar apenas no sumário executivo, é uma habilidade central de análise de vulnerabilidades. Também introduz a diferença entre scan autenticado e não autenticado: dispositivos escaneados sem credenciais só revelam o que está exposto na rede, não o que está mal configurado internamente, o que deve reduzir a confiança nesses achados específicos.

## Task - 1-cve_ecosystem.md
Conceito: CVE (Common Vulnerabilities and Exposures) é um sistema de identificadores únicos e padronizados para vulnerabilidades conhecidas, mantido por CNAs (CVE Numbering Authorities) sob o Programa CVE do MITRE/CISA. Cada CVE tem um ciclo de vida (Reserved, Published, Rejected) e uma estrutura de ID (CVE-AAAA-NNNN) onde o ano reflete a atribuição, não necessariamente a descoberta. Entender esse ecossistema descentralizado explica por que nem toda CVE tem uma classificação CWE, por que CVEs podem ser rejeitadas (duplicatas) e por que a data de "última modificação" não significa que a vulnerabilidade ainda está sob análise ativa.

## Task - 2-cvss_analysis.md
Conceito: CVSS (Common Vulnerability Scoring System) é um framework padronizado para pontuar a severidade técnica de uma vulnerabilidade, combinando métricas de Explorabilidade (Vetor de Ataque, Complexidade, Privilégios Necessários, Interação do Usuário, Escopo) e Impacto (Confidencialidade, Integridade, Disponibilidade) em uma nota de 0 a 10. Decompor manualmente um vetor CVSS e recalcular a fórmula ensina quais métricas pesam mais na nota final - o impacto (C/I/A) costuma separar High de Critical, enquanto Vetor de Ataque e Privilégios Necessários controlam quem consegue sequer tentar o ataque.

## Task - 3-cwe_analysis.md
Conceito: CWE (Common Weakness Enumeration) é uma taxonomia hierárquica de categorias de falhas de software (a "causa raiz" por trás de uma CVE específica), organizada do mais genérico (Classe) ao mais específico (Variante). A lista CWE Top 25 do MITRE ranqueia as categorias mais frequentes e perigosas do ecossistema, mas frequência não é o mesmo que perigo por instância - uma CWE rara pode gerar uma CVE tão crítica quanto uma comum. Rastrear CVEs até sua CWE ajuda a identificar padrões repetidos de causa raiz que uma lista de CVEs isoladas esconderia.

## Task - 4-exploit_hunt.md
Conceito: Exploit-DB (e a ferramenta `searchsploit`) e o catálogo CISA KEV (Known Exploited Vulnerabilities) são fontes que medem a maturidade e a exploração real de uma vulnerabilidade, complementando a severidade teórica do CVSS. Uma vulnerabilidade com CVSS alto mas sem exploit público disponível representa um risco diferente de uma com módulo Metasploit armado e confirmada na lista KEV de exploração ativa - essa maturidade de exploração é um eixo essencial de priorização, separado da nota de severidade.

## Task - 5-exploit_check.sh
O que faz: Lê uma lista de serviços/versões de um arquivo texto e roda `searchsploit` para cada linha, contando quantos exploits públicos existem para cada serviço e listando os resultados.
Como usar: `./5-exploit_check.sh <arquivo_de_serviços>`
Comandos:
- `searchsploit -j <termos>` — busca exploits no Exploit-DB local para os termos informados (cada palavra funciona como filtro AND) e retorna o resultado em formato JSON.
- `searchsploit --colour=never <termos>` — mesma busca, mas em modo texto puro (sem cores ANSI), usado como alternativa quando `jq` não está instalado.

## Task - 6-misconfiguration_analysis.md
Conceito: Nem toda vulnerabilidade tem um CVE - configurações incorretas (portas abertas demais, autenticação ausente, criptografia desativada) são falhas humanas de operação, não defeitos de software, e por isso nunca recebem um identificador CVE ou pontuação CVSS oficial. Achados sem CVE podem ser tão ou mais perigosos que CVEs pontuadas, já que costumam exigir zero sofisticação técnica para explorar (só alcance de rede). Um programa de gestão de vulnerabilidades baseado apenas em contagem de CVE/CVSS é cego para essa categoria inteira de risco.

## Task - 7-vulnerability_taxonomy.md
Conceito: Vulnerabilidades podem ser classificadas em categorias amplas (Aplicação, OS-based, Misconfiguration, Criptográfica, Hardware/Firmware/EOL, Web-based, Supply Chain, Cloud, Virtualização, Mobile, Zero-day), como no domínio Sec+ 2.3. Construir essa taxonomia sobre um conjunto real de achados revela o perfil de maturidade de segurança de uma organização - por exemplo, predomínio de misconfiguration indica falha de disciplina operacional, não de sofisticação técnica dos atacantes. Categorias ausentes na taxonomia não significam ausência de risco: podem refletir apenas um ponto cego da ferramenta de scan (ex.: zero-day nunca aparece em um scanner baseado em assinaturas).

## Task - 8-lynis_audit.md
Conceito: Lynis é uma ferramenta de auditoria de hardening de sistemas Linux que avalia dezenas de categorias (autenticação, permissões de arquivo, logging, rede, pacotes) e produz um Hardening Index junto com sugestões acionáveis. Rodar uma auto-auditoria sem privilégios de root demonstra como o nível de acesso muda a visibilidade dos achados - testes que exigem root (firewall, permissões de sudo, criptografia de disco) ficam invisíveis sem privilégio elevado, o mesmo princípio de "acesso reduzido = visibilidade reduzida" observado em scans não autenticados de dispositivos médicos.

## Task - 9-osint_hunt.md
Conceito: OSINT (Open Source Intelligence) aplicado à segurança significa buscar ativamente, em fontes públicas (NVD, avisos de fabricante, boletins CISA), vulnerabilidades que afetam a pilha de tecnologia de uma organização mas que um scanner interno nunca detectaria - seja por estar fora do escopo do scan (nuvem, dispositivos móveis) ou por atingir uma camada que o scanner não alcança (firmware de um firewall de perímetro, por exemplo). Isso reforça que um relatório de scan é sempre uma visão parcial, e pesquisa proativa é necessária para cobrir os pontos cegos.

## Task - 10-critical_cves.md
Conceito: Uma análise completa de uma vulnerabilidade crítica combina duas dimensões: a análise técnica (CVSS, CWE, disponibilidade de exploit, status no CISA KEV) e a análise contextual (exposição de rede, posição em uma kill chain, ator de ameaça relevante, controles existentes). Só a combinação das duas permite chegar a uma prioridade ajustada de fato - um achado tecnicamente "só" High pode ser o mais urgente do relatório inteiro quando o contexto do ativo e da ameaça é levado em conta.

## Task - 11-false_positives.md
Conceito: Falsos positivos são achados de scanner que, após validação manual, não representam risco real no contexto específico do ambiente - geralmente porque a pré-condição de exploração não se aplica (ex.: uma CVE que exige um comportamento de uso que o servidor nunca realiza). Validar antes de agir é essencial porque o esforço de remediação é um recurso finito: tempo gasto corrigindo um falso positivo é tempo tirado de um achado verdadeiro e crítico. A taxa esperada de falsos positivos de uma ferramenta de scan (tipicamente 5-10%) serve como checagem de sanidade sobre o processo de validação.

## Task - 12-legacy_systems.md
Conceito: Um sistema "End-of-Life" (EOL) é qualitativamente diferente de um sistema apenas "desatualizado" - "não corrigido" descreve uma falha com correção disponível mas não aplicada (um problema temporário), enquanto EOL significa que nenhuma correção futura jamais será produzida para nenhuma vulnerabilidade nova, por mais grave que seja (uma exposição permanente e crescente). Quando um sistema EOL não pode ser migrado por razões técnicas ou regulatórias (ex.: um dispositivo médico certificado), controles compensatórios como segmentação de rede tornam-se a única mitigação viável, em vez de aplicar patches.

## Task - 13-web_exposure.md
Conceito: Achados de divulgação de informação (como uma página de erro revelando número de versão) parecem de baixa severidade isoladamente, mas devem ser tratados como pistas de investigação, não como conclusões finais - eles indicam exatamente o que verificar em seguida. Combinar múltiplos achados de um mesmo host (exposição à internet, cadeia de exploração, criticidade do ativo) produz um cenário de ataque mais realista do que analisar cada achado isoladamente.

## Task - 14-network_posture.md
Conceito: Uma rede "flat" (sem segmentação/VLANs) funciona como um multiplicador de risco uniforme: ela não cria nenhuma vulnerabilidade individual, mas amplia o raio de alcance de todas elas simultaneamente, convertendo um risco departamental isolado em um risco organizacional completo. Diferente de aplicar um patch (que fecha exatamente uma vulnerabilidade), a segmentação de rede reduz o impacto de tudo que ainda não foi descoberto - inclusive vulnerabilidades futuras e configurações incorretas nunca cobertas por CVE.

## Task - 15-medical_iot.md
Conceito: Dispositivos médicos IoT (bombas de infusão, monitores de pacientes) exigem um modelo de risco diferente de servidores de TI comuns, porque uma falha de integridade ou disponibilidade ali não é um problema de dados - é um problema físico de segurança do paciente em tempo real, sem possibilidade de "restaurar backup" depois do fato. Corrigir esses dispositivos é estruturalmente mais difícil que corrigir TI comum por três razões: regulação (recertificação da FDA), operação (uso clínico contínuo sem janela de manutenção) e dependência total do fabricante para qualquer atualização de firmware.

## Task - 16-triage.md
Conceito: Triagem é o processo de classificar rapidamente todos os achados de um scan em categorias de ação (ex.: Crítico Acionável, Padrão Acionável, Informativo, Falso Positivo) antes de investir tempo em pesquisa profunda em qualquer um deles individualmente. Esse filtro inicial evita que um analista gaste esforço de pesquisa em ruído (falsos positivos, itens puramente informativos) antes mesmo de saber quais achados realmente merecem atenção prioritária.

## Task - 17-cvss_contextualizer.md
Conceito: As Métricas Ambientais (Environmental Metrics) do CVSS v3.1 permitem ajustar a pontuação base de uma vulnerabilidade considerando a criticidade real do ativo afetado (Confidentiality/Integrity/Availability Requirements), produzindo uma "pontuação ajustada" mais fiel ao risco real do que a pontuação base genérica. Esse recálculo é mais revelador quando a pontuação base ainda não está saturada no teto da escala - é aí que fatores como criticidade do ativo, posição em uma cadeia de ataque e ausência de controles compensatórios podem elevar drasticamente a prioridade de um achado que uma triagem baseada só em CVSS teria ignorado.

## Task - 18-threat_vuln_correlation.md
Conceito: Correlacionar vulnerabilidades técnicas com inteligência de ameaças (atores, vetores de ataque, cadeias de ataque documentadas) transforma uma lista de falhas isoladas em uma visão de quais delas efetivamente convergem com um caminho de ataque real e plausível. Quando uma mesma vulnerabilidade aparece, de forma independente, em múltiplas narrativas de ameaça diferentes, isso é um sinal mais forte de inevitabilidade de exploração do que qualquer pontuação CVSS isolada poderia expressar.

## Task - 19-remediation_map.md
Conceito: Um plano de remediação formal especifica não apenas o que corrigir, mas como (mudança de configuração, patch, ou controle compensatório), com avaliação de impacto, plano de rollback, prazo, responsável e custo estimado. Diferenciar os três tipos de resposta é essencial: mudanças de configuração costumam ser rápidas e baratas, patches exigem testes e plano de reversão, e controles compensatórios (como segmentação) mitigam o risco de acesso sem eliminar a vulnerabilidade subjacente - deixando um risco residual que precisa ser reconhecido explicitamente.

## Task - 20-priority_matrix.md
Conceito: Uma matriz de priorização organiza todos os achados acionáveis por horizonte de tempo (imediato, curto, médio e longo prazo), com custo estimado, permitindo comparar o esforço total de remediação contra o orçamento de segurança real disponível. Esse exercício frequentemente revela que os itens mais urgentes e de maior impacto custam pouco (mudanças de configuração), enquanto os itens mais caros (segmentação de rede, substituição de hardware) tendem a ser de prazo mais longo - uma informação decisiva para decisões orçamentárias e para negociar verba suplementar.

## Task - 21-vulnerability_assessment.md
Conceito: Um relatório executivo de avaliação de vulnerabilidades consolida escopo, metodologia, achados críticos, falsos positivos, perfil de vulnerabilidades, priorização orientada por ameaça e roteiro de remediação em um único documento voltado para tomada de decisão gerencial. A habilidade central aqui é síntese: traduzir dezenas de achados técnicos individuais em uma narrativa coerente e priorizada que um executivo (não técnico) consegue usar para decidir orçamento e prazos.

## Task - 22-patch_briefing.md
Conceito: Comunicação executiva de segurança exige tradução de achados técnicos complexos (CVEs, CVSS, CWE) para uma linguagem que um conselho ou diretoria não técnica entenda e possa agir imediatamente - focando em impacto de negócio, custo e prazo, não em jargão técnico. Um briefing eficaz é curto, concreto e orientado à ação, deixando claro o que vai acontecer se nada for feito.

## Task - 23-validation_plan.md
Conceito: Remediação não está completa até ser verificada de forma independente - uma correção não testada é uma alegação, não um fato. Um plano de validação define testes específicos e reproduzíveis para cada tipo de correção (reconexão negada após uma mudança de configuração, verificação de versão após um patch, teste de alcance de rede após um controle compensatório) e estabelece um ciclo de vida contínuo (scan, triagem, priorização, remediação, validação, repetição) em vez de tratar o scan como um evento único.
