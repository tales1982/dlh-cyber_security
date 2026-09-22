# Revisão 17 — Identificação de Campanha

**Pergunta:** Uma analista investiga 5 e-mails de phishing recebidos ao longo de 48 horas. Três deles compartilham:

- domínios registrados no mesmo dia no mesmo registrador
- o mesmo software de envio de e-mail, PHPMailer 6.6.0
- alvos em departamentos diferentes: clínico, financeiro, RH
- o mesmo padrão de engenharia social: urgência com um prazo

Explique por que esses indicadores sugerem fortemente uma campanha de phishing coordenada, em vez de e-mails de spam não relacionados.

## Resposta

Nenhum indicador isolado aqui provaria coordenação por si só, mas os quatro juntos descartam coincidência, porque não seria esperado que operadores de spam não relacionados compartilhassem nenhum deles, muito menos os quatro ao mesmo tempo.

1. **Domínios registrados no mesmo dia no mesmo registrador.** Este é um sinal de padrão de provisionamento, não um sinal de conteúdo — aponta para um único evento de registro (um ator ou um lote de compra) em vez de três spammers independentes que cada um, separadamente, decidiu registrar um domínio parecido. Campanhas de spam não relacionadas usam domínios de idades variadas de registradores variados, frequentemente comprados em massa ao longo do tempo através de revendedores diferentes; uma data de registro *e* um registrador compartilhados significam que esses três domínios muito provavelmente foram adquiridos juntos, como uma preparação deliberada pré-campanha.

2. **Software de envio idêntico — PHPMailer 6.6.0, exatamente a mesma versão.** O PHPMailer em si é uma biblioteca comum e legítima, então isso sozinho é fraco. Mas uma *correspondência exata de versão* entre três remetentes de resto não relacionados é uma impressão digital de conjunto de ferramentas: significa que o mesmo script, modelo ou kit construiu e enviou as três mensagens. Esperar-se-ia que operadores de spam independentes rodando botnets ou kits de afiliados diferentes mostrassem assinaturas de mailer mais variadas, não uma versão idêntica.

3. **Direcionamento combinado por cargo entre departamentos (clínico, financeiro, RH).** Este é o sinal mais forte. Spam comum é amplo e genérico — a mesma mensagem disparada para todo mundo, independente de quem seja. Aqui, três pretextos *diferentes* foram cada um combinado com a função real de um departamento *diferente* dentro da *mesma* organização. Isso exige que o remetente já conheça a estrutura departamental da organização e tenha escolhido os destinatários de acordo — um reconhecimento que o spam aleatório não envolve.

4. **O mesmo modelo de engenharia social — urgência com um prazo — reutilizado nos três.** Uma estrutura psicológica compartilhada aplicada de forma consistente, apenas reformulada para o contexto de cada departamento, é um manual (playbook), não três pessoas chegando independentemente à mesma ideia.

**Por que isso aponta para uma única campanha coordenada em vez de spam não relacionado:** cada indicador é individualmente explicável por acaso, mas a probabilidade conjunta de três remetentes independentes e não relacionados coincidentemente compartilharem uma data de registro e um registrador, uma versão idêntica de mailer, direcionamento apropriado por cargo dentro de uma organização, e o mesmo modelo de urgência — tudo dentro de uma janela de 48 horas — é extremamente pequena. A explicação muito mais parcimoniosa é um único operador (ou um único kit de ferramentas) rodando uma campanha de múltiplos pretextos, informada por reconhecimento prévio, especificamente contra esta organização. Essa é exatamente a lógica de agrupamento que analistas de inteligência de ameaças usam para agrupar incidentes separados em uma única campanha para rastreamento e resposta, mesmo antes de um ator específico poder ser nomeado: provisionamento de infraestrutura compartilhado, ferramentas/TTPs compartilhados, e agrupamento temporal, somados a um direcionamento que só funcionaria com conhecimento prévio do alvo.

Este é o mesmo raciocínio aplicado a E2, E5 e E7 em `9-campaign_thread.md` desta investigação.
