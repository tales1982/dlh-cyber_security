# 4x00 - Dissecção de Phishing

Investigação de phishing do sistema MedDefense Health Systems. Oito e-mails brutos (cabeçalhos SMTP completos) foram coletados após relatos de funcionários e quarentena do gateway entre 2026-04-14 e 2026-04-16. O objetivo é fazer a triagem, decidir se os maliciosos pertencem a uma campanha coordenada e determinar se a usuária que clicou (Diane Marsh, `WS-NURSE-04`) foi comprometida.

## Regras de manuseio seguro

- Nunca navegue diretamente para uma URL suspeita. Use desmascaramento, serviços de sandbox e ferramentas de linha de comando.
- Nunca abra um anexo no workstation do analista. Use extração de metadados e sandboxes online apenas.
- Toda conclusão deve citar evidências específicas a partir de cabeçalhos, resultados de autenticação ou descobertas de OSINT.

## Tarefas

### 0 - 0-initial_triage.md

Tabela de triagem inicial para E1 a E8 (SPF, DKIM, DMARC, classe, prioridade, evidência) mais um resumo. E2 está fixado como P1-URGENT porque o lote registra o clique em 2026-04-14 às 15:02:33 CDT.

Resultado: 1 SPAM (E6), 4 SUSPEITOS (E2, E3, E5, E7), 3 LEGÍTIMOS (E1, E4, E8).

### 1 - 1-header_analysis.md

Análise da cadeia de cabeçalhos SMTP para E2, E3, E5 e E7: From visível, Return-Path, IP de envio a partir do salto externo, X-Mailer, formato do Message-ID, remetente alegado versus infraestrutura de envio, e anomalias classificadas por severidade.

Resultado: os quatro chegam diretamente de hosts externos (`91.234.99.107`, `51.38.42.17`, `185.176.43.22`, `164.90.218.73`) usando PHPMailer 6.6.0 e um Message-ID no formato `PHP-<8 hex>`. Nenhum IP ou domínio é compartilhado, então o elo entre eles é a impressão digital do conjunto de ferramentas.

### 2 - 2-authentication_analysis.md

Resultados de SPF, DKIM e DMARC para os 8 e-mails, o que cada um significa, e um veredito por e-mail.

Resultado: a autenticação sozinha sinaliza E2, E5, E7 e E6, mas deixa passar o E3 junto com os legítimos E1, E4 e E8, porque `outlook-protection.com` (não `microsoft.com` nem `outlook.com`) autentica para si mesmo.

### 3 - 3-social_engineering.md

Alavancas psicológicas, pretexto, ação solicitada, nível de direcionamento, sinais de alerta no conteúdo e conhecimento necessário pelo atacante para E2, E3, E5 e E7.

Resultado: E2 é DIRECIONADO; E3, E5 e E7 são SEMI-DIRECIONADOS. Todos os quatro combinam um prazo com uma consequência e enviam o leitor a um domínio externo parecido.

### 4 - 4-url_attachment_autopsy.md

Indicadores de URL, IP e anexo desmascarados, com comandos de investigação seguros e achados a partir da evidência de e-mail. Nenhuma consulta ao vivo foi executada.

Resultado: 12 indicadores, incluindo o PDF de fatura do E5 (gerado um segundo antes do envio, com link embutido para a URL de pagamento). A única reutilização de IP no lote é o E6 (`203.0.113.228`, host de envio e do link).

### 7 - 7-click_investigation.md

Avaliação do clique de Diane Marsh no E2 a partir do `WS-NURSE-04`: fatos confirmados, incógnitas, verificações de endpoint e conta (acompanhamento recomendado, não realizado), matriz de decisão e contenção.

Resultado: clique confirmado, impacto indeterminado. A suposição de trabalho é de possível exposição de credenciais.

### 8 - 8-verdict_matrix.md

Veredito final baseado em evidências para os 8 e-mails (classe inicial, classe final, confiança, evidência-chave, ação recomendada), onde a final difere da inicial, e uma avaliação de precisão da triagem.

Resultado: E1 vira LEGITIMATE-WITH-ISSUE, E2/E5/E7 viram PHISHING-TARGETED, E3 vira PHISHING-OPPORTUNISTIC; a triagem inicial acertou 8/8 na decisão grosseira malicioso/legítimo/spam, mas não tinha como separar phishing direcionado de oportunista.

### 9 - 9-campaign_thread.md

Indicadores compartilhados, mapa de direcionamento, mapa de tempo e comparação com o HC3 para E2, E5 e E7, mais uma avaliação de atribuição que evita nomear um ator.

Resultado: confiança MÉDIA de que E2/E5/E7 são uma única campanha coordenada e direcionada à MedDefense (14-16 de abril), combinando com os quatro traços do alerta do HC3. O E3 compartilha ferramentas, mas é avaliado como uma operação separada e mais genérica.

### 11 - 11-ioc_extraction.md

Tabela estruturada de IOC (33 entradas) cobrindo E2, E3, E5, E7, o anexo do E5 e os padrões do alerta do HC3, categorizada por fase de ataque, com uma análise de qualidade de IOC e um resumo pronto para o HC3.

Resultado: 4 domínios, 4 IPs, 8 endereços de remetente e 6 URLs têm alta confiança e são seguros para bloquear; impressões digitais de PHPMailer/Message-ID/X-Priority e as notas de hospedagem/palavra-chave do HC3 são apenas contexto e causariam falsos positivos se bloqueadas isoladamente.

### 13 - 13-phishing_investigation_report.md

Relatório final de síntese para revisão do líder do SOC e compartilhamento com o HC3: resumo executivo, linha do tempo, veredito por e-mail, análise de campanha, avaliação do clique, resumo de IOC, lacunas de detecção/controle, e recomendações por fase (24h / 7 dias / 30 dias).

Nota: a Seção 7 referencia ideias de detecção que o enunciado chama de "Tarefa 12"; esse arquivo não existe neste lote, então essas ideias são propostas diretamente no relatório, e não citadas a partir de um arquivo externo.

## Notas sobre o lote de evidências

- A data e hora do clique (2026-04-14 15:02:33 CDT) fica cerca de 66 horas antes da coleta do lote (2026-04-17 09:15 CDT), não aproximadamente 36 horas citadas no briefing. As tarefas posteriores devem usar a marca de tempo do NTP do workstation como referência.
- Os timestamps do DKIM `t=` nos e-mails assinados (E1, E4, E8) caem em 2025, e vários cabeçalhos `Date` contêm nomes de dias da semana que não coincidem com 2026 (2026-04-14 foi uma terça-feira). Isso afeta mensagens legítimas e maliciosas, então foi tratado como artefato do lote e não como sinal de triagem.
