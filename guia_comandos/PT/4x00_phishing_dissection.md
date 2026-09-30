# 4x00 – Phishing Dissection

Toda task deste módulo é um entregável de análise escrita (Markdown), não um script — uma investigação de mesa de 8 e-mails brutos (phishing e legítimos) coletados depois de um relato de funcionário e quarentena no gateway. Regras de manuseio seguro valem o tempo todo: nenhuma URL suspeita é visitada, nenhum anexo é aberto, todo valor citado é "defangeado" (`http` → `hxxp`, `.` → `[.]`), e toda conclusão precisa citar evidência específica em vez de intuição.

## Task - 0-initial_triage.md
O que faz: Uma tabela de triagem de primeira passada pelos 8 e-mails brutos (E1-E8), pontuando SPF/DKIM/DMARC, classificando cada um em SPAM/SUSPICIOUS/LEGITIMATE, e atribuindo uma prioridade — com E2 fixado em P1-URGENT especificamente porque o lote de evidência já registra um clique confirmado de usuário nele. Resultado: 1 SPAM, 4 SUSPICIOUS, 3 LEGITIMATE.
Como usar: leia `0-initial_triage.md` (também disponível em `PT/`)
Comandos:
- Fazer o parsing dos valores do header `Authentication-Results` (`spf=pass/fail`, `dkim=pass/none`, `dmarc=pass/fail`) direto do código-fonte bruto do e-mail, antes de ler qualquer conteúdo do corpo — vereditos de autenticação são checados primeiro porque são objetivos e não podem ser falsificados tão facilmente quanto uma linha de assunto.
- Uma rubrica de triagem fixa (SPAM/SUSPICIOUS/LEGITIMATE × prioridade) aplicada uniformemente aos 8 e-mails numa única tabela, em vez de um parágrafo sob medida por e-mail — a mesma disciplina da fila de triagem real de um analista Tier 1, onde consistência entre itens importa tanto quanto acurácia em qualquer um deles.
- Sobrescrever a pontuação de prioridade mecânica do E2 com base em evidência externa (um clique confirmado) já presente no lote — triagem não é uma função pura de pontuação de header; impacto real conhecido reprioriza independente do que os headers sozinhos sugerem.

## Task - 1-header_analysis.md
O que faz: Uma análise profunda da cadeia de headers SMTP pros quatro e-mails SUSPICIOUS (E2, E3, E5, E7): `From` visível vs `Return-Path`, o IP de envio real a partir do salto externo (não um alegado), string `X-Mailer`, formato do `Message-ID`, e uma lista ranqueada de anomalias por e-mail. Resultado: os quatro se originam diretamente de hosts externos usando PHPMailer 6.6.0 com um padrão de Message-ID `PHP-<8 hex>` correspondente — sem IP ou domínio compartilhado, mas uma impressão digital de toolchain compartilhada os liga.
Como usar: leia `1-header_analysis.md`
Comandos:
- Ler a cadeia de header `Received:` de baixo pra cima (a ordem em que os saltos de e-mail foram realmente adicionados) pra achar o primeiro salto externo, em vez de confiar no campo `From:` visível — a técnica padrão pra recuperar a infraestrutura de envio real por trás de um nome de exibição falsificado.
- Comparar `From:` contra `Return-Path:` — um descompasso entre quem uma mensagem alega ser e pra onde as devoluções realmente vão é um dos indícios de falsificação mais baratos e de maior sinal disponíveis sem nenhuma consulta externa.
- Colher a impressão digital do próprio toolchain de envio (`X-Mailer: PHPMailer 6.6.0`, o formato de `Message-ID` que ele gera) como um sinal de *ligação* entre e-mails que de resto não compartilham infraestrutura nenhuma — a mesma ideia do fingerprinting JA3/JA3S de TLS, aplicada a headers de e-mail em vez de um handshake TLS.

## Task - 2-authentication_analysis.md
O que faz: Interpretação formal de SPF/DKIM/DMARC pros 8 e-mails — o que cada protocolo realmente verifica (SPF: o IP de envio está autorizado pro domínio do envelope; DKIM: uma assinatura criptográfica sobre a mensagem não foi adulterada; DMARC: aplicação de política quando SPF/DKIM discordam do domínio From visível) — com um veredito por e-mail. Resultado: a autenticação sozinha sinaliza corretamente E2/E5/E6/E7, mas o E3 *passa* porque autentica como `outlook-protection.com`, um domínio que o atacante legitimamente possui e configurou corretamente — provando que autenticação válida não é o mesmo que remetente seguro.
Como usar: leia `2-authentication_analysis.md`
Comandos:
- Tratar SPF/DKIM/DMARC como três checagens separadas, falháveis independentemente, em vez de um único sinal pass/fail — uma mensagem pode passar SPF e DKIM e ainda falhar no alinhamento DMARC (ou vice-versa), e cada combinação tem um significado diferente que vale a pena detalhar.
- O achado específico "E3 passa porque é genuinamente `outlook-protection.com`, não `microsoft.com`" — a lição central de que um domínio parecido pode legitimamente configurar SPF/DKIM/DMARC pra *si mesmo*, então um resultado de autenticação verde só prova que o domínio é quem diz ser, nunca que o domínio é confiável.

## Task - 3-social_engineering.md
O que faz: Uma análise não-técnica da manipulação psicológica dos quatro e-mails suspeitos — o pretexto usado, a ação específica pedida, o quão individualmente direcionado cada um é, red flags na própria linguagem, e o que o pretexto revela sobre o conhecimento prévio do atacante sobre o MedDefense. Resultado: E2 é avaliado como TARGETED (usa o nome e cargo reais da funcionária); E3, E5 e E7 são SEMI-TARGETED (apropriados pra indústria/empresa mas não personalizados individualmente); os quatro combinam um prazo com uma consequência e levam o leitor a um domínio externo parecido.
Como usar: leia `3-social_engineering.md`
Comandos:
- Um conjunto fixo de dimensões de análise (pretexto, ação pedida, nível de direcionamento, red flags, conhecimento do atacante) aplicado identicamente aos quatro e-mails — transforma "esse e-mail parece suspeito" numa avaliação estruturada e comparável em vez de uma reação de estômago.
- Distinguir "targeted" de "semi-targeted" especificamente por se o pretexto só poderia funcionar contra essa única pessoa nomeada, versus funcionar contra qualquer funcionário de uma empresa de saúde — uma distinção que importa operacionalmente, já que uma isca direcionada implica que o atacante fez reconhecimento real especificamente sobre o MedDefense.
- Nomear a estrutura prazo-mais-consequência como a única alavanca de manipulação que os quatro e-mails compartilham, independente dos pretextos diferentes — o mecanismo psicológico de verdade (urgência suprimindo verificação cuidadosa) é a constante; a história em volta dele é o que varia.

## Task - 4-url_attachment_autopsy.md
O que faz: Uma autópsia de indicador totalmente segura de toda URL, IP e anexo nos e-mails suspeitos (12 indicadores no total) — todo valor tirado só da evidência bruta, toda URL/IP "defangeada" (`hxxps://`, `[.]`), e um "método de investigação seguro" escrito em prosa pra cada um (nomeando WHOIS, `dig`/`nslookup`, crt.sh, VirusTotal, urlscan.io) sem nunca rodar um comando ao vivo contra infraestrutura do atacante. Resultado: 12 indicadores catalogados, incluindo um anexo PDF cujo timestamp de criação embutido é um segundo antes do horário de envio do e-mail (evidência de que foi gerado especificamente pra esse envio, não um chamariz reaproveitado).
Como usar: leia `4-url_attachment_autopsy.md`
Comandos:
- Uma regra de manuseio estrita contra até mesmo uma requisição HEAD-only `curl -I` pra um domínio suspeito — explicitamente documentada como ainda sendo uma conexão real com a infraestrutura do atacante, que pode vazar o IP do analista ou disparar um pixel de rastreamento, a mesma disciplina de segurança operacional que um engajamento de IR ao vivo exigiria.
- "Defangear" todo valor no momento de escrever (`http` → `hxxp`, `.` → `[.]`) pra que o próprio documento nunca possa ser colado num navegador por acidente — uma convenção que não custa nada e previne um erro específico e comum de analista.
- Remover o parâmetro de query `token` por destinatário antes de nomear qualquer URL pra consulta — o token identifica unicamente a Diane Marsh pro rastreamento do atacante, então até uma consulta passiva "segura" da URL nua (não só visitá-la) precisa ter o token removido primeiro pra evitar confirmar o clique dela pra infraestrutura do atacante.
- Extrair metadado de anexo (timestamp de criação do PDF) da cópia em base64 do lote de evidência em vez de abrir o arquivo — prova um fato sobre o anexo (foi gerado na hora) sem nunca renderizar conteúdo controlado pelo atacante numa máquina de analista.

## Task - 7-click_investigation.md
O que faz: Uma avaliação estruturada do que se sabe e do que não se sabe sobre o clique confirmado da Diane Marsh no link do E2 a partir de `WS-NURSE-04` — separando fatos confirmados (o clique em si, seu timestamp) de incógnitas (se credenciais foram inseridas, se o endpoint foi comprometido), listando as checagens de endpoint e conta que *deveriam* acontecer em seguida (sem realizá-las, já que essa é uma investigação de mesa), uma matriz de decisão, e recomendações de contenção. Resultado: clique confirmado, impacto posterior indeterminado — a suposição de trabalho assume por padrão possível exposição de credencial até prova em contrário.
Como usar: leia `7-click_investigation.md`
Comandos:
- Uma separação rígida entre "fatos confirmados" e "incógnitas" como duas seções rotuladas distintas, em vez de uma narrativa misturando as duas — a disciplina de nunca deixar uma inferência plausível ser relatada com a mesma confiança que um fato diretamente observado.
- Listar ações de acompanhamento recomendadas (histórico de processo EDR em `WS-NURSE-04`, um reset forçado de senha, checar logins anômalos da conta da Diane Marsh) como *recomendações*, explicitamente não realizadas aqui — essa task é revisão de evidência, não resposta a incidente ao vivo, e o relatório é honesto sobre esse limite em vez de dar a entender que ações foram tomadas.
- Assumir por padrão a suposição de trabalho de pior caso (possível exposição de credencial) quando a evidência é genuinamente inconclusiva — a mesma postura "culpado até prova em contrário" usada em outros pontos deste currículo pra achados de alta importância e baixa certeza.

## Task - 8-verdict_matrix.md
O que faz: Revisita cada um dos 8 e-mails com um veredito final, totalmente baseado em evidência (versus a triagem inicial mecânica da Task 0), explicando todo caso em que a classificação final difere da inicial, mais uma autoavaliação da acurácia da triagem inicial. Resultado: a triagem inicial acertou 8/8 no nível grosseiro malicioso/legítimo/spam, mas não tinha mecanismo pra distinguir phishing direcionado de oportunista — uma distinção que só a análise mais profunda das Tasks 1-4 conseguiu revelar — e um e-mail de aparência legítima (E1) é rebaixado pra LEGITIMATE-WITH-ISSUE.
Como usar: leia `8-verdict_matrix.md`
Comandos:
- Avaliar explicitamente a triagem *inicial* contra a *final*, não só reportar a resposta final — torna visível exatamente o que a análise mais profunda comprou em cima de uma checagem de header de primeira passada, em vez de descartar silenciosamente o trabalho anterior.
- Separar "o julgamento grosseiro estava certo" (spam/phishing/legítimo) de "a nuance estava certa" (direcionado vs. oportunista) como duas perguntas de acurácia diferentes — um processo de triagem pode estar mecanicamente correto e ainda perder o detalhe que realmente determina a resposta.
- A categoria de veredito `LEGITIMATE-WITH-ISSUE` pro E1 — um rótulo que não cabe num binário limpo, usado deliberadamente em vez de forçar um achado ambíguo em "seguro" ou "malicioso".

## Task - 9-campaign_thread.md
O que faz: Testa se E2, E5 e E7 (e separadamente E3) formam uma campanha coordenada em vez de três ataques não relacionados, comparando indicadores compartilhados, um mapa de direcionamento, um mapa de tempo, e uma comparação direta contra as características nomeadas no alerta setorial da HC3 — parando explicitamente antes de nomear um ator de ameaça específico, já que atribuição exige evidência que essa revisão de mesa não tem. Resultado: confiança MÉDIA de que E2/E5/E7 são uma campanha direcionada ao MedDefense de 14 a 16 de abril, batendo com as quatro características que o alerta HC3 descreve; E3 compartilha o mesmo toolchain mas é avaliado como uma operação separada e mais genérica.
Como usar: leia `9-campaign_thread.md`
Comandos:
- Construir uma matriz explícita de indicador compartilhado (infraestrutura, tempo, direcionamento, toolchain) entre os membros candidatos da campanha — a mesma lógica de comparação "A se relaciona com B" da própria correlação de anomalia entre fontes deste projeto (Task 13 do 3x01), só que aplicada a e-mails de phishing em vez de telemetria de segurança.
- Tratar "compartilha o mesmo toolchain PHPMailer/Message-ID" e "faz parte da mesma campanha direcionada" como duas alegações *diferentes* que precisam de evidência separada — E3 compartilha uma mas não a outra, e o relatório diz isso explicitamente em vez de juntar os quatro só porque parecem iguais.
- Um nível de confiança (MÉDIO) anexado à conclusão de ligação de campanha em vez de um sim/não puro — espelha como o outro trabalho de correlação deste projeto (`10-campaign_correlation.sh` do 3x05) sempre entrega uma confiança junto com um veredito de ligação, nunca o veredito sozinho.

## Task - 11-ioc_extraction.md
O que faz: Converte todo achado das Tasks 1-9 numa única tabela de IOC estruturada e categorizada (33 entradas: domínios, IPs, endereços de remetente, URLs, mais impressões digitais de toolchain e as próprias notas de hospedagem/palavra-chave do alerta HC3) marcada por fase de ataque e por qualidade de IOC, com um destaque explícito de quais indicadores são seguros pra bloquear diretamente versus quais são só contexto e causariam falso positivo se bloqueados isoladamente. Resultado: 4 domínios, 4 IPs, 8 endereços de remetente e 6 URLs são candidatos de bloqueio de alta confiança; impressões digitais de toolchain e as notas genéricas de hospedagem/palavra-chave da HC3 são explicitamente marcadas como só-contexto.
Como usar: leia `11-ioc_extraction.md`
Comandos:
- Marcar todo IOC com um rótulo de fase de ataque E um nível de qualidade/confiança na mesma tabela — um indicador ser *real* (apareceu em evidência confirmadamente maliciosa) é uma pergunta diferente de um indicador ser *seguro pra agir unilateralmente* (bloqueá-lo não vai quebrar colateralmente algo legítimo).
- Sinalizar explicitamente indicadores de baixa especificidade (uma impressão digital de mailer, um padrão de palavra-chave genérico do alerta HC3) como só-contexto em vez de omiti-los — ainda úteis pra engenharia de detecção (batendo com a própria filosofia de regra Sigma deste projeto de campos de assinatura estáveis e de baixa cardinalidade do `0-detection_matrix.sh` do 3x02) mesmo sendo errado colocá-los direto numa lista de bloqueio.
- Estruturar a tabela como saída compartilhável com a HC3 desde o início — uma lista de IOC feita pra sair da organização (compartilhada com um ISAC setorial) precisa de uma barra diferente pra "confirmado" do que uma usada só pra bloqueio interno, e o formato da tabela reflete isso.

## Task - 13-phishing_investigation_report.md
O que faz: O entregável de síntese final — junta os achados de toda task anterior num único relatório feito pra revisão do SOC lead e compartilhamento externo com a HC3: resumo executivo, linha do tempo, veredito por e-mail, análise de campanha, avaliação do clique, resumo de IOC, gaps de detecção/controle encontrados no caminho, e recomendações em fases (24h / 7 dias / 30 dias). Documenta explicitamente onde o próprio raciocínio teve que divergir de um plano: um arquivo de ideias de detecção referenciado como "Task 12" não existe nesse lote, então essas ideias são propostas direto no relatório em vez de citadas de uma fonte externa.
Como usar: leia `13-phishing_investigation_report.md`
Comandos:
- Estruturar recomendações em três horizontes de tempo explícitos (24h / 7 dias / 30 dias) em vez de uma lista plana — separa "bloqueie esses IOCs hoje" de "conserte a política de SPF essa semana" de "reconsidere o fluxo de aprovação de fatura de fornecedor esse mês", cada um exigindo um dono e uma urgência diferentes.
- Um documento de síntese que reaproveita, não repete, a conclusão de toda task anterior por referência — o relatório é tanto um grafo de ponteiros sobre os próprios artefatos da investigação quanto prosa nova, a mesma disciplina "cite sua evidência, não a reafirme" que as Regras de Manuseio Seguro do módulo inteiro exigem.
- Nomear o gap da "Task 12" explicitamente no texto em vez de contornar silenciosamente — um exemplo pequeno mas real de documentar uma limitação da própria investigação (uma entrada planejada ausente) em vez de absorvê-la quietamente.
