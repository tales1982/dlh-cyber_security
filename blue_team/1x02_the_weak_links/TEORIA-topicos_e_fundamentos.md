# Teoria e Tópicos — 1x02 The Weak Links

Guia de estudo com teoria + exemplos práticos do cenário MedDefense, para cada exercício do módulo. Se o 1x00 mapeou "o que temos e onde faltam controles" e o 1x01 mapeou "quem quer nos atacar", o 1x02 traz o **scan técnico de vulnerabilidades** — a pergunta central é **"os grupos de ransomware que já mapeamos têm, de fato, algo para explorar aqui?"**. É o módulo mais técnico da trilha: CVE, CVSS, CWE, exploits reais, triagem e priorização orientada a ameaça.

---

## 0. First Impressions Summary

**O que é:** a primeira leitura crítica e cética de um relatório de scan de vulnerabilidades — antes de analisar qualquer finding individual, verificar se o **relatório em si** é confiável.

**A disciplina central deste exercício: nunca confiar no resumo, sempre contar manualmente.** O cabeçalho do relatório afirmava 4 Critical/7 High/11 Medium/5 Low/4 Informational — mas contar finding por finding revela 4/**8**/10/5/4. A causa: um finding (031) foi adicionado manualmente depois que o cabeçalho já tinha sido escrito, e ninguém atualizou o resumo. Um relatório é, ele mesmo, um documento que pode conter erro — a disciplina de contar em vez de confiar no resumo pegou algo que o resumo escondia.

**Por que isso importa além de pedantismo aritmético:** o Finding 031 tem CVSS 9,8, confirmado ativo, no servidor de aplicação do ativo mais valioso do ambiente — um leitor que confiasse no "7 High, sem mudanças" do cabeçalho e fosse direto aos 4 Critical perderia exatamente o finding que mais precisava de atenção.

**Cobertura de autenticação não é uniforme — e isso muda a confiança em cada achado.** Servidores Linux/Windows foram escaneados **autenticados**; dispositivos médicos foram escaneados **não autenticados**, porque não havia credenciais disponíveis. Isso deveria **reduzir a confiança** nos achados de dispositivo médico em relação aos achados de servidor — um scan sem credenciais só vê o que está exposto na rede, não o que está mal configurado por baixo.

**Asset Heat Map:** ranquear hosts por número de findings distintos que os nomeiam revela onde o risco se concentra — mas contagem bruta não é a única lente: um host pode ganhar prioridade por **densidade de severidade** em vez de contagem (um único finding pode empacotar 3 CVEs weaponizadas, como no caso do MRI).

**O que o relatório explicitamente NÃO cobriu (limitações declaradas):** nuvem (O365), dispositivos móveis (iPads), qualquer ativo offline durante a janela do scan, e nenhuma exploração ativa foi tentada — apenas detecção de versão/configuração. Isso não é uma falha do scan, é um limite de escopo que precisa ser lembrado ao interpretar "limpo" como "seguro".

**Exemplo:** o Finding 031 (Ghostcat) só existe porque um analista humano verificou manualmente uma pista "Medium" (Finding 017) que o scanner sozinho não conseguiu confirmar — prova de que um scan totalmente automatizado, sozinho, teria perdido a vulnerabilidade mais perigosa do relatório inteiro.

---

## 1. The CVE Ecosystem

**O que é:** entender a infraestrutura formal por trás de um identificador CVE — quem o atribui, que estados ele pode ter, e por que o sistema existe do jeito que existe.

**Estrutura do ID:** `CVE-AAAA-NNNN...` — o ano é quando o ID foi **reservado/atribuído**, não necessariamente quando a falha foi descoberta, divulgada ou corrigida (um CNA pode reservar um ID de 2021 e só publicá-lo em 2023 se o fornecedor pedir embargo). O número sequencial tem tamanho variável desde 2014, especificamente para o ecossistema nunca ficar sem espaço.

**CNA (CVE Numbering Authority):** uma organização autorizada a atribuir CVE IDs dentro do seu próprio escopo (um fornecedor, uma organização de pesquisa, uma plataforma de bug bounty). É um modelo **deliberadamente descentralizado**: o MITRE não precisa revisar pessoalmente cada vulnerabilidade do planeta antes de ela ganhar um ID — quem está em melhor posição para saber sobre o próprio produto faz a triagem inicial.

**Os 3 estados de ciclo de vida de um CVE:**
- **Reserved:** um CNA reivindicou o ID para uma divulgação futura, mas nenhum detalhe público existe ainda.
- **Published:** descrição, produtos afetados e (geralmente) um score CVSS já foram publicados — o estado normal e completo.
- **Rejected:** o Programa CVE retirou o ID — geralmente por ser duplicata de outro CVE, ter sido retirado a pedido, ter sido atribuído por engano, ou não descrever uma vulnerabilidade real de fato.

**Por que um CVE Rejected importa:** ele mostra que o próprio sistema de identificação pode errar e se autocorrigir — dois relatórios independentes do mesmo bug (`libwebp`) geraram dois IDs diferentes antes de alguém perceber, e o mais novo foi rejeitado em favor do original, para que ferramentas de gestão de patch não tratem o mesmo bug como duas falhas diferentes.

**Exemplo:** CVE-2021-44790 (Finding 001) tem CVSS 9,8, CWE-787 (Out-of-bounds Write), e referências categorizadas como Vendor Advisory / Exploit / Third-Party Advisory — cada tipo de referência serve a um propósito diferente na investigação.

---

## 2. The CVSS Deconstruction

**O que é:** desmontar (e depois recalcular manualmente) o **CVSS v3.1** — o padrão de pontuação de severidade de vulnerabilidades mais usado do mundo — componente por componente, para entender *por que* um número é o que é, não apenas aceitá-lo.

**Os 8 componentes do vetor Base:** AV (Attack Vector: Network/Adjacent/Local/Physical) · AC (Attack Complexity: Low/High) · PR (Privileges Required: None/Low/High) · UI (User Interaction: None/Required) · S (Scope: Unchanged/Changed) · C/I/A (Impact: None/Low/High) — os quatro primeiros formam a **Exploitability** (quão fácil é alcançar/disparar a falha), os três últimos formam o **Impact** (o que acontece se disparar).

**A fórmula manual (Scope Unchanged):** `Exploitability = 8.22 × AV × AC × PR × UI`; `ISC_Base = 1 − (1−C)(1−I)(1−A)`; `Impact = 6.42 × ISC_Base`; `BaseScore = Roundup(min(Impact + Exploitability, 10))`.

**Por que mudar um único componente pode derrubar o score inteiro:** trocar AV de Network (0,85) para Local (0,55) derruba o score de 9,8 para 8,4 — o Impact fica idêntico (nada mudou sobre "o que acontece"), mas a Exploitability cai, porque o atacante precisa de um ponto de apoio local primeiro, não apenas uma requisição pela internet.

**A lição mais importante ao comparar dois vetores lado a lado:** se todos os componentes de Exploitability (AV/AC/PR/UI) são idênticos entre dois CVEs, a diferença de score inteira vem do **Impact** — e o inverso também é verdade. Isso ensina onde procurar quando dois scores parecidos ou diferentes precisam de explicação.

**Exemplo:** CVE-2021-44790 (9,8) e CVE-2020-25165 (7,5) têm Exploitability idêntica (mesmos AV/AC/PR/UI) — a diferença de 2,3 pontos vem inteiramente do Impact: um compromete C/I/A por completo (RCE), o outro só afeta Availability (negação de serviço na conectividade wireless da bomba).

---

## 3. The Weakness Beneath (CWE)

**O que é:** ir de um CVE específico (uma instância de falha, num produto e versão específicos) até a **CWE** correspondente (Common Weakness Enumeration — a categoria genérica de erro de programação/configuração que torna aquele CVE possível).

**Hierarquia CWE:** Class (categoria ampla) → Base (categoria específica o bastante para mapear a vulnerabilidades reais) → Variant (ainda mais específica). Por exemplo, CWE-416 (Use After Free) é filha de CWE-825 (Expired Pointer Dereference), que é filha da Class CWE-672.

**CWE Top 25 mede frequência no ecossistema, não perigo de uma instância única.** CWE-428 (Unquoted Search Path) não está no Top 25 — é uma categoria mais rara — mas o CVE construído sobre ela (CVE-2023-38408) tem o mesmo score 9,8 das categorias "famosas". Raridade no ranking não significa menor severidade quando ocorre.

**Padrões de misconfiguration se repetem mais do que CVEs únicos.** Duas bases de dados diferentes (PostgreSQL, MySQL), em hosts diferentes, sem CVE algum, são a **mesma** categoria de erro (CWE-1327, Binding to an Unrestricted IP Address) — o mesmo padrão aparece de novo em 4 sistemas EOL (CWE-1104) e em 2 pares de cifra fraca nunca desativada (CWE-327). A conclusão central: misconfigurações repetidas contam uma história de disciplina operacional, não de código malfeito.

**Como decidir em qual CWE treinar desenvolvedores primeiro:** não pela frequência *neste* scan específico, mas pela combinação de (a) ranking de perigo na indústria como um todo (CWE-787 é #2 no Top 25 2024), (b) ser a causa direta do pior finding do relatório, e (c) ser **prevenível por construção** (linguagem memory-safe, fuzzing) de um jeito que revisão de código pontual não detecta de forma confiável.

**Exemplo:** Finding 001 (CVE-2021-44790) mapeia para CWE-787 (Out-of-Bounds Write), ranking #2 do CWE Top 25 2024, com 3.842 CVEs associados e CVSS médio 7,3 — não é uma categoria rara e acadêmica, é uma das causas-raiz mais comuns de vulnerabilidades sérias publicadas hoje.

---

## 4. The Exploit Hunt

**O que é:** para os CVEs mais críticos, pesquisar se um **exploit funcional já existe publicamente** — a diferença entre "teoricamente perigoso" e "qualquer um pode baixar e rodar isso agora".

**As 3 fontes de verificação, em ordem de rigor crescente:**
1. **searchsploit / Exploit-DB:** existe um PoC (proof-of-concept) ou módulo público? De que tipo — script Python isolado, ou módulo Metasploit (muito mais fácil de operacionalizar)?
2. **CISA KEV (Known Exploited Vulnerabilities):** existe evidência confirmada de exploração **ativa no mundo real** — não apenas "existe um exploit", mas "gente está realmente usando isso agora"?
3. **Contexto do ambiente:** mesmo com exploit disponível, a precondição de exploração se aplica *aqui*? (Ex: um CVE que exige agent forwarding SSH não se aplica a um servidor que nunca faz isso.)

**Escala de Exploitability Score (1-5) usada no exercício:** combina maturidade do exploit (PoC isolado vs. Metasploit) + status KEV + confirmação de exploração ativa no host específico. Um score 5 exige: módulo weaponizado, listado no KEV, e idealmente confirmado ativo no ambiente avaliado.

**Nem todo CVE tem uma entrada no Exploit-DB — e isso não é evidência de segurança.** CVE-2023-38408 (score NVD 9,8) não tem listagem no Exploit-DB, mas tem um advisory técnico detalhado (Qualys) e PoCs no GitHub — ausência de uma fonte específica não significa ausência de exploit funcional, só significa que ele vive em outro lugar.

**Uma misconfiguração sem CVE pode ser "mais explorável" que um CVE com score alto.** O Finding 003 (PostgreSQL aberto) não tem CVE nem CVSS, mas na prática se comporta como um 5/5 de exploitability — nenhum exploit é necessário, apenas alcançabilidade de rede e uma senha.

**Exemplo:** Windows XP no MRI (Finding 004) empacota três CVEs com Exploitability 5/5 cada — MS08-067 (Conficker), EternalBlue (WannaCry/NotPetya) e BlueKeep — todas com módulo Metasploit weaponizado e listadas no CISA KEV, no dispositivo com o pior perfil de disponibilidade de exploit do relatório inteiro.

---

## 5. Exploit Check Script

**O que é:** um script bash (`5-exploit_check.sh`) que automatiza a consulta ao `searchsploit` para uma lista de serviços/versões — transformando a pesquisa manual do item 4 num processo repetível e em lote.

**Por que automatizar essa etapa específica:** consultar `searchsploit` serviço por serviço, à mão, não escala para um relatório de 31 findings, e pior, não escala para o ciclo contínuo de reavaliação que um programa de vulnerabilidades de verdade exige (rescans mensais, por exemplo).

**Detalhe técnico digno de nota: o script preserva word-splitting deliberado.** A variável `$service` não é citada entre aspas ao ser passada para `searchsploit` — de propósito, porque `searchsploit` faz correspondência **E** (AND) entre argumentos posicionais separados (`"apache" "2.4.29"`), igual ao comando manual equivalente.

**Fallback sem `jq`:** o script detecta se `jq` está disponível e, se não estiver, faz parsing manual da saída colorida do `searchsploit` usando `awk`, contando separadores de tabela — uma lição prática de engenharia defensiva de scripts: nunca assumir que toda dependência opcional está instalada.

**Saída do script:** para cada serviço, quantos exploits foram encontrados e seus títulos/caminhos; ao final, um resumo "Services with known exploits: X / Y" — uma métrica agregada única que dá uma primeira leitura de exposição do ambiente inteiro antes de mergulhar finding por finding.

**Como isso se conecta ao restante do módulo:** o script é a ferramenta; o item 4 é a análise manual e interpretada dos resultados mais críticos — automação encontra candidatos, mas a decisão de priorização (item 4, 16, 17) ainda exige julgamento humano sobre contexto.

---

## 6. The Misconfiguration Findings

**O que é:** analisar em profundidade findings que **não têm CVE** — porque o software está funcionando exatamente como projetado, a falha é uma decisão administrativa (ou um default nunca alterado), não um defeito de código.

**Por que misconfiguração não recebe CVE:** um CVE descreve uma falha no *produto*; uma misconfiguração é uma falha em *como o produto foi configurado* por um humano (ou deixado no default). PostgreSQL aceitando conexões de toda a rede está fazendo exatamente o que foi mandado fazer via `pg_hba.conf` — não há defeito para atribuir um identificador.

**Por que isso é perigoso apesar de "não ter CVE":** um processo de priorização construído puramente em torno de números CVE/CVSS classificaria a exposição direta e não autenticada do banco de dados de pacientes como **invisível** — enquanto um finding com CVE, mas de consequência bem menor, recebe toda a atenção só por produzir um número para ordenar. O MongoDB Ransomware Wave (28.000 bancos, zero CVEs) e a violação da Capital One (100 milhões de registros, uma regra de WAF malconfigurada) não são casos raros — são a forma **normal** de como violações reais acontecem.

**Comparação de risco (CVE Risk Comparison):** cada misconfiguração é comparada a um CVE de severidade equivalente para calibrar intuição — ajuda a internalizar que "sem CVE" não significa "sem risco".

**Exemplo:** Finding 003 (PostgreSQL aberto ao `/16` inteiro) é comparável ao Ghostcat (CVSS 9,8) em risco prático — ambos dão acesso direto aos dados do `ehr-db-01` sem precisar de uma cadeia de exploração sofisticada; Ghostcat pelo menos exige que o atacante saiba que a vulnerabilidade existe — essa misconfiguração não exige nada além de curiosidade.

---

## 7. The Vulnerability Taxonomy

**O que é:** classificar cada um dos 31 findings numa das categorias formais da CompTIA Security+ 2.3 — Application, OS-based, Web-based, Hardware/Firmware/EOL, Cryptographic, Misconfiguration, Supply chain, Cloud-specific, Mobile device, Virtualization, Zero-day.

**Por que essa taxonomia é diferente do CWE (item 3):** CWE descreve o *mecanismo* técnico da falha (buffer overflow, use-after-free); a taxonomia Sec+ descreve a *superfície* onde a falha vive (é um problema de aplicação? de configuração de nuvem? de dispositivo móvel?) — são lentes complementares, não concorrentes.

**Distribuição descoberta: Misconfiguration domina (13 de 31, 42%) — mais que as duas próximas categorias somadas.** Somado com Cryptographic (5) — que é essencialmente o mesmo modo de falha com outra roupa (opção fraca deixada ligada ao lado da forte, nunca removida) — mais da metade do relatório (58%) não tem nada a ver com código malfeito e tudo a ver com disciplina de configuração.

**Categorias ausentes por 3 razões diferentes (e distinguir a razão importa muito):**
- **Cloud-specific / Mobile device (0):** ausentes porque o **escopo do scan excluiu** O365 e iPads explicitamente — é um gap de escopo, não um fato de segurança.
- **Virtualization (0):** genuinamente uma pergunta em aberto — nada documenta se existe ou não uma camada de hipervisor.
- **Zero-day (0):** ausente por razão **estrutural**, não específica da MedDefense — um scanner de vulnerabilidades funciona identificando versões conhecidas contra bancos de dados conhecidos; por definição, um zero-day verdadeiro não pode aparecer nesse tipo de relatório, esteja ele presente no ambiente ou não.

**Exemplo:** ausência de achados em uma categoria nunca deve ser lida como "sem risco" para 3 das 4 categorias vazias — significa "fora do que este instrumento consegue enxergar", não "não presente".

---

## 8. The Self-Audit (Lynis)

**O que é:** rodar uma ferramenta real de auditoria de hardening Linux (**Lynis**) contra a própria máquina do analista, para ganhar julgamento de primeira mão sobre o que um scanner *host-based* de fato verifica — e depois **projetar** o que ele provavelmente encontraria no `billing-srv-01`, sem acesso direto ao servidor.

**Rodar sem privilégio root é um modo real e suportado, não uma falha — mas tem uma consequência honesta.** O Lynis reporta explicitamente quais testes pulou por falta de privilégio (permissões de arquivo de autenticação, regras de iptables, detecção de criptografia de disco) — a mesma distinção autenticado-vs-não-autenticado já vista no item 0 para dispositivos médicos se repete aqui, agora sobre a própria máquina do analista.

**Hardening Index é um número único (0-100), não uma nota por categoria.** Como o Lynis não imprime pontuação por categoria, usa-se uma proxy honesta: **testes executados** (amplitude de cobertura) cruzado com **densidade de sugestão** (quantos desses testes viraram um achado acionável) — isso revela onde a categoria está fraca sem inventar um número que a ferramenta não fornece.

**A projeção para o `billing-srv-01` é o exercício mais valioso aqui:** sem acesso direto ao servidor, usar o que já foi estabelecido nos relatórios anteriores (SSH com senha habilitado, Sophos excluindo servidores, Ubuntu 18.04 sem ESM, MySQL exposto) para prever com alta confiança exatamente quais módulos do Lynis disparariam — e por quê, citando a evidência específica que sustenta cada previsão em vez de adivinhar no vácuo.

**Exemplo:** a previsão SSH-7408 ("PasswordAuthentication yes") não é uma suposição — o Finding 009 já confirma diretamente que autenticação por senha está habilitada nesse host, então o Lynis marcaria isso com certeza absoluta, não como possibilidade.

---

## 9. The OSINT Hunt

**O que é:** pesquisar vulnerabilidades em componentes do ambiente da MedDefense que o **scan interno nunca poderia ter visto** — porque estão fora do escopo por natureza (nuvem, firmware de appliance de perímetro) — usando fontes públicas (OSINT: Open Source Intelligence).

**Por que um scan de rede interno nunca alcançaria essas 3 vulnerabilidades:** o FortiGate é um dispositivo de perímetro cujo próprio firmware não foi versionado pelo scan (que mirava hosts *atrás* do firewall, não o firewall em si); o O365/Entra ID vive inteiramente na infraestrutura de nuvem da Microsoft, fora de qualquer scanner on-premise; o Synology DSM teve sua *exposição* confirmada pelo scan, mas nunca teve seu **número de versão** capturado — o scanner viu a porta aberta, mas não o que rodava atrás dela.

**A lição estrutural mais importante:** identidade e infraestrutura hospedadas em nuvem são uma superfície de ataque controlada pelo **fornecedor**, inteiramente fora do programa de scan/patch da própria organização — a ação prática não é "corrigir", é garantir que os boletins de segurança do fornecedor cheguem a uma pessoa nomeada, já que nenhuma ferramenta interna vai revelar esse risco sozinha.

**Como isso muda a leitura do relatório de scan como um todo:** "nosso scan não achou nada crítico no perímetro/nuvem" não significa "não há risco crítico ali" — significa "fora do que este instrumento específico consegue enxergar", reforçando a mesma lição do item 7.

**Exemplo:** CVE-2026-24858 no FortiGate (CVSS 9,8, listado no CISA KEV com prazo de 3 dias, um dos mais agressivos já emitidos) é um bypass de autenticação que não exige phishing nem compra de credencial — e o relatório de 31 findings tem **zero** menções ao FortiGate, porque o scan nunca mirou o próprio appliance de perímetro.

---

## 10. The Critical CVEs

**O que é:** para os 5 findings mais críticos, montar uma análise completa em duas camadas — **Technical Analysis** (o que a falha é, tecnicamente) e **Contextual Analysis** (o que ela significa *neste* ambiente específico) — culminando numa prioridade final ajustada.

**A estrutura de Contextual Analysis tem 4 componentes fixos:** Network Exposure (quem alcança isso?) → Kill Chain Position (em que passo de qual cadeia de ataque já documentada isso se encaixa?) → Threat Actor (que tipo de atacante, do módulo 1x01, mais provavelmente usaria isso?) → Related Findings (que outros achados deste mesmo relatório se conectam a este?).

**Por que "não está numa kill chain nomeada" é uma lacuna a ser sinalizada, não um sinal de que o risco é menor.** Alguns findings críticos (031, 004) não aparecem explicitamente em nenhuma das kill chains do 1x01 — isso é reconhecido como um **gap de documentação real**, e o finding é posicionado estruturalmente como equivalente a um passo já existente em vez de ser descartado por "não estar formalmente citado".

**A prioridade final combina evidência técnica e de negócio numa única justificativa coesa** — nunca apenas "CVSS alto = prioridade alta". Um finding de CVSS mais baixo, mas nomeado explicitamente numa kill chain e sem nenhum controle compensatório, pode justificar prioridade igual ou maior que um CVSS puro mais alto.

**Exemplo:** Finding 004 (Windows XP no MRI) é único no conjunto por ser **impossível de corrigir por patch** — a única estratégia viável é isolamento de rede, e os controles compensatórios propostos para esse cenário exato (1x00, item 6) continuam apenas propostos, nunca implementados — o que o torna, na prática, tão urgente quanto qualquer CVE weaponizado.

---

## 11. The False Positives

**O que é:** investigar formalmente findings suspeitos de serem **falsos positivos** — validar antes de agir, porque agir sobre um falso positivo desperdiça recursos escassos de remediação que deveriam ir para um achado real.

**Metodologia de validação para cada suspeito:** por que é um falso positivo (a precondição de exploração não se aplica ao papel real deste host) → método de validação concreto (inspecionar configuração, revisar logs, entrevistar quem opera o sistema) → risco de agir sobre o falso positivo (desperdiçar uma janela de mudança limitada) → risco de **não** validar (e se a suposição de "falso positivo" estiver errada?).

**A assimetria de risco que justifica sempre validar, nunca apenas descartar por suspeita:** o custo de agir sobre um falso positivo é limitado e recuperável (algumas horas de trabalho desperdiçadas); o custo de descartar incorretamente algo que só *parece* falso positivo, sem checar, pode deixar um Critical real sentado sob a etiqueta "já tratado".

**Taxa esperada de falso positivo como sanity check do próprio processo.** SecurePoint declara uma taxa típica de 5-10% para essa configuração de scan — aplicado a 31 findings, prevê 1,5 a 3 falsos positivos. Achar exatamente 3 é uma confirmação saudável do processo (achar zero seria mais suspeito que achar alguns; achar dez sugeriria problema na própria configuração do scan).

**Exemplo:** Finding 022 (clock skew de 47 segundos) é falso positivo porque a tolerância padrão do Kerberos é 300 segundos — quase 400 vezes maior que o desvio medido — mas a validação certa não é apenas "descartar", é checar o histórico de sincronização NTP para confirmar se é um artefato momentâneo estável ou um sintoma de um daemon NTP que parou de sincronizar e vai crescer até um dia realmente importar.

---

## 12. The Legacy Systems

**O que é:** analisar 3 sistemas em fim de vida (EOL — End of Life) em profundidade, e depois tomar uma **decisão de negócio real**: com orçamento para migrar só um sistema neste trimestre, qual deve ser?

**A distinção mais importante do exercício: "sem patch" vs. "EOL" não são a mesma coisa.** "Sem patch" descreve uma vulnerabilidade com correção conhecida ainda não aplicada — um gap temporário e fechável. "EOL" descreve um sistema operacional para o qual **nenhuma correção jamais será produzida de novo**, para nenhuma vulnerabilidade futura, não importa a gravidade — a exposição cresce todo ano, sem possibilidade de fechamento via patch.

**Por que a pesquisa de novos CVEs para Windows XP retorna zero resultados recentes — e por que isso é péssima notícia, não boa:** significa que o próprio ecossistema de CVE **parou de olhar** para esse SO, não que ele ficou seguro. Ninguém mais confirma nem nega novas falhas nele.

**Como decidir qual sistema migra primeiro (a lição central de negócio):** não pela criticidade isolada do ativo (o MRI venceria por criticidade pura, sendo um dispositivo de segurança do paciente), mas por qual "migração" é **operacionalmente realista dentro do prazo dado**. O MRI não pode ser "migrado" num trimestre — é um dispositivo médico regulado pela FDA que exige recertificação do fabricante; sua resposta certa é *implementar* a segmentação já desenhada, não migrar. O `billing-srv-01`, por outro lado, tem uma migração real e viável (assinatura ESM ou upgrade de SO), exposição comprovada (dois comprometimentos reais) e está acumulando CVEs Críticos novos agora mesmo no mesmo componente vulnerável.

**Exemplo:** duas novas vulnerabilidades Críticas em `mod_rewrite` do Apache (CVE-2024-38474, CVE-2024-38475), publicadas em julho de 2024, aplicam-se diretamente e permanentemente ao Apache 2.4.29 do `billing-srv-01` — prova de que este host específico está acumulando dívida técnica crítica *ativamente*, não apenas carregando dívida histórica.

---

## 13. The Web Exposure

**O que é:** analisar os 4 hosts com exposição web/aplicação, comparando risco combinado por host — não cada finding isoladamente, mas o que a **combinação** de findings no mesmo host conta como história.

**Por que analisar por host, e não por finding isolado, revela mais:** um host pode ter um finding real (Critical) diretamente precedido pela pista exata que o revelou (Medium) — a história completa (`ehr-srv-01`: Finding 017 revelando a versão do Tomcat, que levou à verificação manual do Finding 031) só aparece quando os findings do mesmo host são lidos juntos, não em uma lista plana ordenada por severidade.

**A lição central sobre findings de "Medium" que revelam versão/configuração: eles são pistas, não conclusões.** Um número de versão sozinho não faz nada a ninguém — seu valor inteiro está no que ele permite checar *em seguida*. Descartar findings Medium de disclosure de informação só porque "não são diretamente exploráveis" teria significado que a vulnerabilidade confirmada mais perigosa deste scan nunca teria sido verificada manualmente.

**Priorização entre hosts expostos considera mais do que "está na internet":** `web-srv-01` (Patient Portal) é internet-facing, mas fica em **último** lugar na priorização entre os 4 hosts, porque nenhum finding ali, isolado ou combinado, oferece um caminho direto de execução de código ou acesso a dado — são deficiências de hardening (defesa em profundidade), não uma porta aberta.

**Exemplo:** `NAS-01` tem apenas um finding (015), mas ocupa o 3º lugar de prioridade porque essa exposição é a interface de **gerenciamento** do único backup da organização — coincide exatamente com o Passo 4 da Kill Chain #1, tornando esse um achado de consequência última, não de acesso inicial.

---

## 14. The Network Posture

**O que é:** para 3 CVEs críticos, comparar explicitamente o **Cenário A (rede plana atual)** contra o **Cenário B (rede hipoteticamente segmentada)** — medindo o "fator de amplificação de risco" que a topologia de rede aplica sobre cada vulnerabilidade.

**A descoberta central e mais importante do módulo inteiro:** a exploitabilidade CVSS de cada CVE **não muda nada** entre os dois cenários (9,8 continua 9,8) — o que muda, por uma ou duas ordens de grandeza, é **quantos dispositivos conseguem alcançar a vulnerabilidade** e **quanto do ambiente fica alcançável depois da exploração**.

**Por que isso torna segmentação potencialmente mais impactante que corrigir qualquer CVE individual:** corrigir um CVE fecha exatamente **uma** vulnerabilidade. Segmentar a rede reduz simultaneamente o raio de explosão de **todos os 31 findings ao mesmo tempo** — incluindo os que ainda não foram descobertos, as misconfigurações que nunca receberão um CVE, e o próximo zero-day que aparecer em qualquer host, sem custo de engenharia marginal por finding. Um patch corrige o que você já encontrou; segmentação reduz a consequência de tudo que você ainda não encontrou.

**O caso mais urgente do exercício, por uma razão específica: exploits auto-propagáveis (worms).** EternalBlue não exige que um atacante decida manualmente pivotar em direção ao MRI — ele se espalha sozinho. Numa rede plana, uma única estação phishada em qualquer lugar dos ~320 endpoints comuns alcança e infecta o MRI automaticamente; numa rede segmentada, o MRI só seria alcançável comprometendo primeiro o PACS (um alvo separado, com suas próprias credenciais e controles).

**Exemplo:** o Finding 001 (Apache RCE no `billing-srv-01`) muda de "risco crítico e imediato" (Cenário A: qualquer um dos ~350+ dispositivos alcança tudo depois do shell) para "alto, porém contido" (Cenário B: apenas hosts na mesma VLAN "Finance/Billing" são alcançáveis) — a exploitabilidade não muda, o raio de explosão sim.

---

## 15. The Medical IoT

**O que é:** um aprofundamento específico nos achados de dispositivos médicos (BD Alaris, Philips IntelliVue) — cruzando cada um contra o advisory **real** do fabricante/CISA, e discutindo por que remediar dispositivo médico é categoricamente mais difícil que remediar um servidor de TI comum.

**A disciplina de nunca aceitar um número sem checar contra a fonte primária, aplicada aqui duas vezes:** (1) o CVSS do relatório do scan (7,5) diverge do CVSS oficial do próprio fabricante BD (6,5) para o mesmo CVE — uma discrepância que precisa ser resolvida diretamente com o advisory original, não aceita silenciosamente. (2) o firmware real da frota MedDefense (12.1.2) é **mais recente** que a versão documentada como corrigida (12.1.1) — sugerindo que os dispositivos podem já estar corrigidos contra esse CVE específico, mas isso precisa de validação direta antes de ser descartado *ou* aceito.

**Recomendação do fabricante e o que a organização realmente fez são duas coisas separadas.** Mesmo que o firmware esteja corrigido, a recomendação do fabricante de **isolamento de rede** como mitigação primária não foi seguida — e o relatório confirma, sem ambiguidade, que 7 de 7 bombas escaneadas ainda usam credenciais padrão de fábrica (`admin/admin`), um achado totalmente independente da versão de firmware.

**A dimensão de segurança do paciente muda a régua de comparação por completo.** Um workstation de TI comprometido é, na pior das hipóteses, um problema de confidencialidade/integridade de dado — recuperável restaurando um estado conhecido. Uma bomba de infusão ou monitor comprometido é um problema físico **direto** para uma pessoa específica naquele momento: uma leitura de sinais vitais falsificada pode atrasar a resposta clínica a uma deterioração real; uma dosagem manipulada não é "dado corrompido", é medicação entregue incorretamente na corrente sanguínea, sem "restaurar do backup" depois.

**As 3 razões pelas quais remediar dispositivo médico é categoricamente mais difícil:** (1) **Regulatório** — mudança de firmware pode exigir revalidação/recertificação da FDA; (2) **Operacional** — o dispositivo está em uso clínico ativo, sem janela de manutenção equivalente à de um servidor; (3) **Dependência de fornecedor** — a MedDefense não pode corrigir firmware BD/Philips por conta própria, sob nenhuma circunstância; todo fix vem no cronograma do próprio fabricante.

**Exemplo:** os monitores Philips carregam vulnerabilidades documentadas (CISA ICSMA-18-156-01) descrevendo acesso **de leitura e escrita** não autenticado à memória do dispositivo pela rede — um atacante com o acesso de rede que a topologia plana da MedDefense já fornece não precisaria descobrir uma falha nova; a capacidade documentada já é suficiente para ler sinais vitais reais, falsificar valores, ou derrubar o monitor.

---

## 16. The Noise Filter (Triage)

**O que é:** triar **todos os 31 findings** numa passagem única, atribuindo cada um a uma de 4 categorias — o filtro que separa sinal de ruído antes de qualquer análise mais profunda consumir tempo limitado da equipe.

**As 4 categorias de triagem:**
- **AC (Actionable Critical):** remediação imediata (24-48h) — risco real e urgente.
- **AS (Actionable Standard):** remediação agendada (7-30 dias) — real, mas não exige ação de emergência.
- **I (Informational):** vale monitorar/documentar, mas não representa um caminho de ataque direto por si só.
- **FP (False Positive):** validado como não aplicável a este ambiente (ver item 11).

**Por que a categoria de um finding às vezes contradiz sua própria etiqueta de severidade do scanner:** o Finding 031 tem etiqueta "High" do scanner, mas é classificado como o item #1 da lista Actionable Critical — porque é o único achado confirmado ativo, listado no CISA KEV, com Exploitability 5/5, no servidor de aplicação do ativo mais valioso do ambiente. A etiqueta do scanner é um input, não a palavra final.

**A justificativa de cada linha da triagem cita evidência específica, nunca apenas repete a severidade.** Cada finding triado carrega uma razão de uma frase que aponta para o fato concreto que sustenta aquela categoria — essa é a disciplina que transforma uma lista de 31 severidades soltas numa lista priorizada e defensável.

**Exemplo:** o Finding 029 (Grafana em Westside) é rotulado apenas "Informational" pelo scanner, mas entra na lista Actionable Critical porque combina um CVE público e trivial de explorar com um dispositivo **completamente sem monitoramento** — ninguém notaria a exploração acontecendo, o que é, por si só, uma razão para tratá-lo com urgência, não menos.

---

## 17. The CVSS Contextualizer

**O que é:** recalcular o **CVSS Environmental Score** (a terceira camada da métrica CVSS, além de Base e Temporal) para os 8 findings mais críticos, incorporando formalmente 4 fatores contextuais — o exercício mais avançado de priorização orientada a risco do módulo.

**Os 4 fatores contextuais aplicados a cada finding:** Asset Criticality (a classificação CIA do 1x00) → Kill Chain Position (em que passo de qual cadeia documentada isso aparece) → Exploitability (maturidade do exploit + status KEV) → Compensating Controls (que proteção já existe, e será que ela realmente cobre esta superfície específica?).

**Environmental Metrics do CVSS (CR/IR/AR):** Confidentiality/Integrity/Availability Requirements — o quanto a organização *precisa* que cada pilar seja protegido para este ativo específico, ajustando o Impact score para refletir o contexto de negócio, não apenas a matemática abstrata do vetor Base.

**A descoberta metodológica mais importante: o "cap" de Impact às vezes esconde a diferença real entre findings.** Vários findings já estão saturados no teto matemático do CVSS (0,915 de Impact subscore) na pontuação Base — recalcular o Environmental não muda o número, só **confirma** que já estava no limite. Mas para findings que **não** começam saturados, o ajuste Environmental pode mover o score de forma dramática e reveladora.

**Os dois casos mais reveladores do exercício:** Finding 029 (Grafana shadow IT) sobe de CVSS Base 7,5 para Environmental **9,3** — um salto de 1,8 pontos, invisível a qualquer processo de triagem baseado só em CVSS, porque o driver real de risco (ausência total de visibilidade sobre um dispositivo com alta exigência de confidencialidade) só aparece quando pesado explicitamente. Finding 007 (LDAP/SMBv1) sobe de ~7,4 para 8,1 pela mesma razão, em escala menor.

**Uma nota de integridade de dado que aparece no próprio exercício:** o vetor CVSS do Finding 031 no relatório do scan continha um erro de transcrição (`A:N` em vez de `A:H`) que, matematicamente, não bateria com o score 9,8 declarado — a verificação direta contra o NVD (em vez de confiar na transcrição do relatório) corrigiu isso antes de prosseguir com o recálculo.

**Exemplo:** um finding rotulado "Informational" pelo scanner, num dispositivo que ninguém formalmente possui, com CVSS Base de apenas 7,5, recalcula para 9,3 uma vez que o verdadeiro driver de risco — ausência total de visibilidade sobre um dispositivo com exposição de alta confidencialidade documentada — é devidamente pesado. Exatamente o tipo de achado que um processo de triagem puramente orientado a CVSS, sem esse peso, despriorizaria até a irrelevância.

---

## 18. The Threat-Vulnerability Correlation

**O que é:** para 8 findings-chave, cruzar formalmente cada um contra os artefatos do módulo 1x01 (Threat Actor, Vector, Kill Chain, Scenario) e contra o GAP correspondente do 1x00 — a matriz de correlação que amarra os três módulos anteriores numa única visão.

**Por que "não aparece numa kill chain nomeada" precisa ser registrado explicitamente, não escondido:** vários findings críticos genuinamente não têm uma citação direta em nenhuma kill chain do 1x01 — isso é reconhecido como gap de documentação real, não inventado ou forçado para caber numa narrativa existente.

**O critério de desempate para "qual vulnerabilidade causaria mais dano" não é apenas criticidade de ativo isolada.** Vários findings estão igualmente ligados a ativos Críticos — o critério decisivo é o **número de caminhos de ameaça independentes que convergem no mesmo gap**. Quando um único gap não remediado é nomeado explicitamente, por dois tipos de atores completamente diferentes, em dois artefatos de ameaça escritos independentemente, isso é evidência muito mais forte de inevitabilidade no mundo real do que uma única citação em kill chain.

**Exemplo:** o Finding 003 (PostgreSQL aberto) vence esse critério porque a Kill Chain #5 (um vendor comprometido) e o Scenario 3 (um atacante externo via MedTech) chegam **independentemente** ao mesmo detalhe técnico exato — "o banco não está restrito ao `ehr-srv-01`" — para dois perfis de atacante completamente diferentes, tornando esse o caminho mais curto, mais agnóstico de ator, e mais provável para o pior resultado do ambiente inteiro.

---

## 19. The Remediation Map

**O que é:** para cada um dos 8 findings críticos correlacionados no item 18, produzir um plano de remediação concreto e executável — não apenas "o que corrigir", mas **como**, com prazo, dono, custo e avaliação de impacto operacional.

**Os 3 tipos de resposta de remediação, e quando cada um se aplica:**
- **Configuration Change:** quando o problema é uma configuração incorreta — barato, rápido, geralmente sem dependência externa.
- **Patch:** quando existe uma correção de fornecedor disponível — exige avaliação de pré-requisitos (backup, teste em staging) e plano de rollback.
- **Compensating Control:** quando o problema não pode ser corrigido na origem (dispositivo EOL, sistema regulado) — a mesma lógica do item 6 do 1x00, agora aplicada a achados de scan específicos.

**Elementos obrigatórios de cada plano:** descrição da mudança → avaliação de impacto (o que pode quebrar, e como confirmar que não quebrou) → timeline → dono → custo estimado. Um plano sem avaliação de impacto é uma receita para causar um incidente ao tentar corrigir outro.

**Por que "impacto zero esperado" ainda precisa de confirmação prévia com o dono do sistema:** mesmo quando o registro de ativos não mostra nenhum outro consumidor legítimo de um serviço, a recomendação é sempre confirmar com o dono da aplicação/DBA antes do corte — a diferença entre "não documentado" e "não existe" é exatamente o tipo de suposição que causa incidentes.

**Exemplo:** para o Finding 029 (Grafana shadow IT), a resposta correta não é "corrigir o CVE" diretamente — é **bloquear o acesso de rede imediatamente**, como contenção, enquanto uma investigação de propriedade acontece em paralelo, porque remediar tecnicamente um sistema cujo propósito e dono são desconhecidos é agir antes de entender o que realmente está em jogo.

---

## 20. The Priority Matrix

**O que é:** consolidar os 24 findings acionáveis (Actionable Critical + Actionable Standard, do item 16) num plano por **horizonte de tempo** (Imediato/24-48h, Curto prazo/7 dias, Médio prazo/30 dias, Longo prazo/90 dias), cada um com custo estimado — e então confrontar o total contra o orçamento real disponível.

**Por que agrupar por horizonte, e não apenas por severidade individual:** um plano de remediação real precisa responder "o que fazemos esta semana com a equipe e o orçamento que já temos?", não apenas "o que é mais grave em teoria?" — horizonte de tempo é uma dimensão de planejamento tão importante quanto severidade.

**A descoberta orçamentária mais importante do exercício:** os horizontes Imediato + Curto Prazo juntos custam apenas ~$10.000 — cabendo confortavelmente dentro do que sobrou do orçamento anual (já que boa parte foi comprometida em decisões anteriores do 1x00). Esse é o número mais importante do resumo: fechar **todo** achado genuinamente urgente e ativamente explorável deste scan **não exige** dinheiro novo.

**Como recomendar realocação quando o Longo Prazo não tem fonte de financiamento:** em vez de simplesmente reportar "não há dinheiro", a recomendação move orçamento já planejado para outra prioridade (cobertura de antivírus em servidor) para a prioridade que este scan específico prova ser mais urgente (segmentação do MRI) — e pede orçamento suplementar explicitamente para o resto, em vez de esperar o próximo ciclo anual.

**Exemplo:** o Finding 004 (segmentação do MRI, ~$30.000) domina sozinho o horizonte de Médio Prazo — e a recomendação argumenta que ele merece prioridade sobre o item de antivírus de servidor já planejado, porque envolve três RCEs weaponizadas listadas no KEV, num dispositivo de segurança do paciente impossível de corrigir, contra o valor de defesa em profundidade de um item já coberto por backup.

---

## 21. Vulnerability Assessment Summary

**O que é:** o **relatório executivo consolidado** de todo o módulo 1x02 — a versão traduzida para liderança de tudo desenvolvido nos itens 0-20, seguindo a mesma disciplina de tradução técnico → executivo do 1x00 e do 1x03.

**Estrutura:** Executive Summary → Escopo e Metodologia (com limitações declaradas) → Findings Overview (distribuição real, não a do cabeçalho com erro) → Critical Findings (os 5 do item 10) → False Positive Report (item 11) → Vulnerability Profile (item 7) → Threat-Informed Prioritization (itens 17-18) → Remediation Roadmap (item 20) → Validation Plan (item 23) → Next Steps.

**A frase de abertura que resume o achado mais importante do relatório inteiro:** "labels alone are misleading" — o item mais perigoso do relatório inteiro foi rotulado apenas "High" pelo scanner, e só foi descoberto porque um analista seguiu manualmente uma pista "Medium". Essa é a tese central que todo o módulo 1x02 defende, do início ao fim.

**Como a seção "Next Steps" conecta este módulo ao próximo:** vulnerabilidades foram identificadas, priorizadas e mapeadas contra ameaças — o próximo passo é desenhar a **estratégia de defesa formal**: selecionar controles usando frameworks da indústria, montar um registro de risco quantitativo, e produzir um roadmap de 6 meses que o Board vai financiar. Essa é exatamente a ponte para o módulo 1x03.

**Exemplo:** o resumo executivo evita jargão técnico ao comunicar o achado mais crítico para a liderança — em vez de "CVSS 9,8 no AJP connector", a formulação é "o item mais perigoso deste relatório foi rotulado só 'High' pela ferramenta, e só foi achado porque alguém verificou manualmente uma pista que a ferramenta não conseguiu resolver sozinha."

---

## 22. Patch Briefing

**O que é:** a versão mais comprimida de tudo — uma comunicação de uma página para o Board, cobrindo apenas os 3 achados mais urgentes e seus custos, sem nenhum jargão técnico não traduzido.

**Estrutura:** Estado Atual (o que sabíamos vs. o que sabemos agora, em uma frase) → os 3 problemas mais urgentes, cada um em 2-3 frases com um "Fix" nomeado, prazo e custo → "Se não fizermos nada" (consequência concreta, não abstrata) → fechamento com o progresso do programa em 3 semanas.

**Por que cada item usa uma metáfora de "porta" em vez de terminologia técnica:** "a mesma porta, pela terceira vez" comunica o padrão de comprometimento repetido do `billing-srv-01` de um jeito que qualquer pessoa entende, sem precisar explicar o que é um RCE ou um CVE — a mesma disciplina de tradução do Board Pitch do 1x03 e do CISO Briefing do 1x00.

**Regra de estilo idêntica aos outros documentos executivos do currículo:** toda frase precisa sobreviver sozinha se lida em voz alta numa sala de reunião; nenhuma tabela grande; nenhum número sem contexto de comparação.

**Exemplo:** "não é uma teoria; é a mesma porta, pela terceira vez" resume, numa frase, a história real e comprovada de que o `billing-srv-01` já foi comprometido duas vezes através do mesmo Apache não corrigido — tornando o pedido de orçamento concreto em vez de hipotético.

---

## 23. The Validation Plan

**O que é:** o encerramento formal do ciclo de vulnerabilidade — garantir que toda remediação seja **verificada de fato**, não apenas assumida como concluída, e desenhar o processo contínuo (não pontual) que mantém o programa vivo depois deste relatório.

**A disciplina central, repetida do início ao fim do módulo:** "**Validate é uma etapa distinta e obrigatória, não uma suposição**" — a mesma lição do enquadramento "analista júnior vs. sênior" do início do projeto se aplica no fim do ciclo tanto quanto no início: uma correção que não foi testada de forma independente é uma alegação, não um fato.

**Verificação específica por tipo de remediação (nunca um "parece bom" genérico):** mudanças de configuração exigem reexecutar o plugin específico do OpenVAS ou um teste manual direcionado (não um rescan completo); patches exigem confirmar a versão do pacote pós-patch e reexecutar a busca de CVE/exploit para confirmar que não corresponde mais; controles compensatórios exigem um **teste de alcançabilidade real** a partir de fora do segmento restrito — uma regra de firewall que parece correta na configuração, mas não está de fato bloqueando tráfego, é uma falsa sensação de segurança pior que nenhum controle.

**Cronograma de rescan não é uniforme — ativos de maior risco comprovado merecem cadência mais apertada.** Um scan completo mensal é a linha de base razoável, mas `billing-srv-01` e o FortiGate merecem varredura **semanal** dedicada — porque um tem histórico real e repetido de comprometimento, e o outro é o único ponto de estrangulamento de perímetro por onde toda kill chain do 1x01 passa.

**Inteligência contínua não pode depender de "o time de TI" genericamente.** Assinaturas de boletins (CISA KEV, PSIRT do Fortinet, MSRC da Microsoft, avisos do Ubuntu, páginas de advisory dos fabricantes de dispositivo médico) precisam ter **um dono nomeado** — não fazer isso é exatamente a mesma difusão de responsabilidade que já deixou alertas sem revisão antes (GAP-002 do 1x00).

**Exemplo do diagrama de ciclo de vida (Scan → Triage → Prioritize → Remediate → Validate → Repeat):** o Continuous Intelligence pode disparar uma entrada **fora de ciclo** na Triagem a qualquer momento do mês, independente do calendário regular — qualquer advisory que corresponda a um ativo do Registro (1x00) deve disparar um scan direcionado dentro de 48 horas, não esperar o próximo ciclo mensal agendado.

---

## Dependency order across the files

```
0 primeira leitura crítica do relatório (contar, não confiar no resumo)
 └─ 1 ecossistema CVE (CNA, ciclo de vida) · 2 desconstrução CVSS (matemática do score)
     └─ 3 CWE (a fraqueza por trás do CVE) · 7 taxonomia Sec+ (a superfície da falha)
         └─ 4 caça a exploits (searchsploit/KEV) · 5 script de automação
             └─ 6 misconfigurações (findings sem CVE, igualmente perigosos)
                 └─ 8 self-audit Lynis (projeção prática sobre um host real)
                     └─ 9 OSINT (o que o scan não podia ver: nuvem, firmware de perímetro)
                         └─ 10 os 5 CVEs críticos (técnico + contextual completo)
                             └─ 11 falsos positivos (validar antes de agir)
                                 └─ 12 sistemas legados (decisão de negócio: qual migra primeiro)
                                     └─ 13 exposição web (risco combinado por host)
                                         └─ 14 postura de rede (rede plana como amplificador universal)
                                             └─ 15 IoT médico (segurança do paciente muda a régua)
                                                 └─ 16 triagem (AC/AS/I/FP para os 31 findings)
                                                     └─ 17 CVSS contextualizado (Environmental Score)
                                                         └─ 18 correlação ameaça-vulnerabilidade (liga aos módulos 1x00/1x01)
                                                             └─ 19 mapa de remediação (plano concreto por finding)
                                                                 └─ 20 matriz de prioridade (horizonte × orçamento)
                                                                     └─ 21 relatório executivo consolidado
                                                                         └─ 22 patch briefing (Board, 1 página)
                                                                             └─ 23 plano de validação (fecha o ciclo, começa o próximo)
```

## Framework reference table (revisão rápida antes de repetir o módulo)

| Conceito | Onde é usado | Ideia central |
|---|---|---|
| Contar, não confiar no resumo | Item 0 | O relatório em si pode conter erro; verificar a estrutura antes de confiar no conteúdo |
| CVE / CNA / lifecycle | Item 1 | Reserved / Published / Rejected; atribuição descentralizada por CNA |
| CVSS v3.1 (Base Score) | Item 2 | Exploitability (AV/AC/PR/UI) × Impact (C/I/A); Scope Unchanged/Changed |
| CWE (Common Weakness Enumeration) | Item 3 | A causa-raiz genérica por trás de um CVE específico; Top 25 mede frequência, não perigo |
| Exploit maturity (searchsploit/KEV) | Itens 4, 5 | PoC vs. Metasploit vs. exploração ativa confirmada — 3 níveis de confiança diferentes |
| Misconfiguration sem CVE | Item 6 | Falha de configuração humana, não de produto — igualmente ou mais perigosa |
| Sec+ 2.3 Vulnerability Taxonomy | Item 7 | Categoriza pela superfície (Application/Web/OS/Hardware/Crypto/Misconfig...) |
| Host-based audit (Lynis) | Item 8 | Ferramenta real de hardening; projeção informada sobre um host sem acesso direto |
| OSINT para superfícies fora de escopo | Item 9 | Nuvem e firmware de perímetro são superfície do fornecedor, não do scan interno |
| Contextual/Environmental CVSS | Itens 10, 17 | Asset Criticality + Kill Chain + Exploitability + Controles compensatórios |
| False Positive validation | Item 11 | Sempre validar antes de descartar ou agir; assimetria de risco |
| EOL vs. Unpatched | Item 12 | EOL nunca mais recebe correção; decisão de migração pesa viabilidade, não só criticidade |
| Flat network as amplifier | Item 14 | Segmentação não muda exploitability, muda blast radius de TODOS os findings |
| Patient safety severity | Item 15 | Dispositivo médico comprometido é dano físico direto, não recuperável via backup |
| Triage categories (AC/AS/I/FP) | Item 16 | A etiqueta do scanner é um input, não a palavra final sobre prioridade |
| Threat-Vulnerability Correlation | Item 18 | Convergência de múltiplos atores/artefatos no mesmo gap = maior probabilidade real |
| Remediation horizon + budget | Itens 19, 20 | Configuration Change / Patch / Compensating Control; horizonte × custo real disponível |
| Validate as mandatory step | Item 23 | Uma correção não testada é uma alegação, não um fato |

---

*Guia de estudo — não faz parte da entrega. Use como checklist teórico antes de revisar ou expandir qualquer exercício do módulo.*
