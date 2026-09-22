# Análise de Autenticação de E-mail

Resultados de SPF, DKIM e DMARC para os 8 e-mails no lote de evidências, e o que cada resultado significa para a investigação. Os valores são os vereditos registrados no cabeçalho `Authentication-Results` pelo `mx01.meddefense.com`. Nenhum registro DNS foi consultado novamente e nenhuma assinatura foi reverificada; esta tarefa usa apenas o lote de evidências de e-mail.

## O que cada resultado responde

| Mecanismo | Pergunta que responde | O que não informa |
|---|---|---|
| SPF | O IP de conexão está listado no registro SPF do domínio do envelope (`smtp.mailfrom`)? | Não verifica o endereço visível `From:`, e não diz nada sobre quem é o dono do domínio. |
| DKIM | A mensagem foi assinada com uma chave publicada pelo domínio assinante (`d=`), e permanece inalterada desde a assinatura? | Uma assinatura válida prova que o assinante controla o DNS daquele domínio, não que o domínio é confiável. |
| DMARC | SPF ou DKIM passaram e estão alinhados com o domínio visível em `From:`? O que a política desse domínio diz para fazer em caso de falha? | Protege apenas o domínio exato em `From:`. Um domínio parecido (lookalike) é um domínio diferente com seu próprio registro DMARC. |

`action=none` no resultado do DMARC significa que nenhuma ação de aplicação foi tomada sobre a mensagem. Ou o domínio remetente publica uma política somente de monitoramento, ou o gateway não aplicou uma; o cabeçalho não diz qual. Em ambos os casos, uma falha de DMARC com `action=none` é entregue na caixa de entrada.

---

## Email 1 — healthcare-education-weekly.com

- SPF: `pass`. O IP remetente `198.51.100.42` está autorizado no registro SPF de `healthcare-education-weekly.com`. O servidor de conexão é um que o dono do domínio listou.
- DKIM: `pass` (`d=healthcare-education-weekly.com`, `s=mail01`). A mensagem foi assinada com uma chave que aquele domínio publica e não foi alterada após a assinatura.
- DMARC: `pass`, `action=none`. SPF (`smtp.mailfrom`) e DKIM (`d=`) coincidem com o domínio visível em `From:`, então o alinhamento é completo.
- Veredito de autenticação: sustenta a legitimidade. Totalmente alinhado em um único domínio.
- Significado para a investigação: o domínio remetente é quem alega ser. Se Jennifer Moore realmente se inscreveu em 2024-08-11 é uma verificação separada contra o histórico da caixa de correio dela. Um detalhe solto: o `X-Mailer` menciona MailChimp enquanto a cadeia Received mostra o próprio Postfix do remetente, o que vale uma olhada, mas não muda o veredito dada a autenticação alinhada e o conteúdo benigno.
- Veredito final: LEGÍTIMO (newsletter graymail), P4-LOW.

## Email 2 — meddefense-portal.com

- SPF: `fail`. O IP remetente `91.234.99.107` não está autorizado para `meddefense-portal.com`. O próprio registro SPF do domínio não lista o servidor que enviou a mensagem. Note que o domínio que falha é o lookalike, não o `meddefense.com`, então isso não é uma falsificação do nosso domínio.
- DKIM: `none` (mensagem não assinada, `header.d=none`). Não há nada para validar. Ausência não é uma falha, mas significa que não há elo criptográfico entre a mensagem e nenhum domínio.
- DMARC: `fail`, `action=none`. Nem SPF nem DKIM produziram um pass alinhado para `meddefense-portal.com`. Nenhuma aplicação foi feita, então a mensagem foi entregue.
- Veredito de autenticação: contradiz a legitimidade. Não há evidência de autenticação que ligue esta mensagem à `meddefense.com`.
- Significado para a investigação: confirma que o E2 não veio da TI da MedDefense. Também mostra por que o usuário o viu: o gateway deixou passar uma mensagem que falha em tudo sob `action=none`. Vale revisar o tratamento do gateway para falhas de DMARC vindas de domínios lookalike desconhecidos.
- Veredito final: SUSPEITO (phishing de coleta de credenciais), P1-URGENT por causa do clique confirmado.

## Email 3 — outlook-protection.com

- SPF: `pass`. O IP remetente `51.38.42.17` está listado no registro SPF de `outlook-protection.com`. Isso significa apenas que quem controla o DNS de `outlook-protection.com` listou esse IP. Não diz nada sobre a Microsoft.
- DKIM: `pass` (`d=outlook-protection.com`, `s=default`). A mensagem foi assinada com uma chave publicada na zona DNS de `outlook-protection.com`. Isso prova integridade e controle daquele domínio, não identidade ou marca.
- DMARC: `pass`, `action=none`, `header.from=outlook-protection.com`. SPF e DKIM estão alinhados com o domínio visível em `From:`. Isso responde "este e-mail pertence a `outlook-protection.com`?" com sim. Não pode responder "`outlook-protection.com` é a Microsoft?".
- Veredito de autenticação: válido, mas não é evidência de legitimidade. As três verificações passam para o domínio errado.
- Significado para a investigação:
  - `outlook-protection.com` não é `microsoft.com` e não é `outlook.com`. É um domínio separado que qualquer pessoa pode registrar por alguns dólares, e SPF, DKIM e DMARC para ele podem ser configurados corretamente em minutos. As palavras "outlook" e "protection" foram escolhidas para parecerem certas à primeira vista; a confiança vem do nome Microsoft no nome de exibição e no corpo, não do domínio.
  - O DMARC protege exatamente o domínio no cabeçalho `From:`. Qualquer política que `microsoft.com` ou `outlook.com` publique só se aplica a e-mails que usem esses domínios em `From:`. Esta mensagem nunca usa, então essas políticas nunca são consultadas.
  - Tudo está alinhado: `From:`, `Return-Path`, SPF `smtp.mailfrom` e DKIM `d=` são todos `outlook-protection.com`. Isso é consistência de propriedade, o que não é o mesmo que ser legítimo.
  - Um filtro que trate `dmarc=pass` como sinal de confiança entregaria o E3 como e-mail bom. A autenticação sozinha pega E2, E5 e E7, mas não o E3. A decisão precisa vir da discrepância marca-versus-domínio, da idade de registro do domínio (o alerta HC3 descreve domínios lookalike com menos de 30 dias), da impressão digital de envio PHPMailer e `wp-admin`, e do conteúdo (falso login em Lagos, ameaça de bloqueio em 48 horas).
  - Ressalva de evidência: o valor `b=` do DKIM está truncado no lote, e no E3, E4 e E8 contém texto de preenchimento legível em vez de dados de assinatura. Os valores `t=` do E1, E3, E4 e E8 também caem em 2025, um ano antes de seus cabeçalhos `Date`. O mesmo padrão aparece em e-mails legítimos e maliciosos, então é tratado como artefato do lote. O veredito `pass` vem do gateway e não pôde ser reverificado offline.
- Veredito final: SUSPEITO (personificação da Microsoft), P2-HIGH. A autenticação é válida apenas para o próprio domínio do atacante.

## Email 4 — meddefense.com

- SPF: `pass` (IP remetente `10.10.1.15`, `smtp.mailfrom=meddefense.com`). O IP é o hub interno do Exchange `exchange-hub.meddefense.local`. É um endereço privado, então o pass reflete o caminho interno confiável, não uma consulta SPF pública.
- DKIM: `pass` (`d=meddefense.com`, `s=selector1`). Assinado para o nosso próprio domínio.
- DMARC: `pass`, `action=none`. Alinhado com `header.from=meddefense.com`.
- Veredito de autenticação: sustenta a legitimidade.
- Significado para a investigação: autenticação, o caminho de relay interno, o `X-Mailer` Exchange 2019, o `List-ID` de lista de distribuição e o conteúdo (sem links, sem anexo, sem pedido de credenciais) concordam entre si. Um remetente interno ainda pode ser uma conta comprometida, então o conteúdo também importa; nada aqui está fora do padrão. O E4 é a referência para e-mail interno genuíno, e sua afirmação de que a TI nunca envia links de senha por e-mail e de que o portal é apenas interno ou via VPN contradiz o pretexto do E2.
- Veredito final: LEGÍTIMO, P4-LOW.

## Email 5 — medequip-supplies.net

- SPF: `softfail`. O IP remetente `185.176.43.22` tem softfail para `medequip-supplies.net`. O registro SPF do domínio termina em uma regra de soft-fail e não lista esse IP. Softfail é um negativo mais fraco que `fail`, mas o próprio sistema de faturamento de um fornecedor normalmente estaria listado.
- DKIM: `none` (mensagem não assinada).
- DMARC: `fail`, `action=none`. Nada se alinhou para `medequip-supplies.net`, e a mensagem foi entregue mesmo assim.
- Veredito de autenticação: contradiz a legitimidade.
- Significado para a investigação: pequenos fornecedores realmente configuram o SPF de forma errada, então o softfail sozinho não provaria fraude. O peso vem da combinação: não assinado, DMARC fail, envio via PHPMailer, uma cobrança de pagamento em 7 dias, e um destinatário de Contas a Pagar que não reconhece a fatura. A autenticação também não pode dizer se a MedEquip Supplies é um fornecedor real. Isso deve ser verificado contra o cadastro de fornecedores e um número de contato que a MedDefense já possui, não o número no e-mail.
- Veredito final: SUSPEITO (fraude de fatura e coleta de credenciais), P2-HIGH.

## Email 6 — canadian-pharma-discount.org

- SPF: `softfail`. O resultado não mostra o IP remetente.
- DKIM: `none` (sem `header.d`).
- DMARC: `fail`, `action=quarantine`. Esta é a única mensagem no lote em que o cabeçalho mostra uma ação de quarentena, significando que a política ou o gateway pediu para a mensagem ser retida. O lote não diz quais dois e-mails foram retirados da quarentena do Proofpoint, então não está estabelecido que o E6 foi um deles.
- Veredito de autenticação: contradiz a legitimidade do remetente, da forma comum de um domínio de spam em massa descartável.
- Significado para a investigação: consistente com a classificação de SPAM (`X-Spam-Score: 9.8` contra um limite de 5.0). Não personifica a MedDefense nem solicita credenciais, e sua autenticação, mailer (`XPedia Bulk Mailer 4.2`) e host de envio não compartilham nada com E2, E3, E5 ou E7 nesta evidência.
- Veredito final: SPAM, P4-LOW.

## Email 7 — meddefense-benefits.org

- SPF: `fail`. O IP remetente `164.90.218.73` não está autorizado para `meddefense-benefits.org`. Como no E2, o domínio que falha é o lookalike, não o `meddefense.com`.
- DKIM: `none` (mensagem não assinada).
- DMARC: `fail`, `action=none`. Entregue sem aplicação.
- Veredito de autenticação: contradiz a legitimidade. Nada liga a mensagem a `meddefense.com`, o domínio que o RH genuíno usaria.
- Significado para a investigação: o padrão de falha é idêntico ao E2. Um aviso real de RH da MedDefense seria retransmitido pelo hub interno do Exchange e passaria para `meddefense.com`, como o E4 faz. A afirmação da destinatária de que nunca se inscreveu para nada é consistente com o quadro de autenticação.
- Veredito final: SUSPEITO (isca de RH em domínio parecido), P2-HIGH.

## Email 8 — hhs.gov

- SPF: `pass`. O IP remetente `134.174.47.82` está autorizado para `hhs.gov`.
- DKIM: `pass` (`d=hhs.gov`, `s=hhs2026`).
- DMARC: `pass`, `action=none`. Alinhado com `header.from=hhs.gov`.
- Veredito de autenticação: sustenta a legitimidade.
- Significado para a investigação: o e-mail é autenticado para o domínio que afirma ser. Isso não prova que o conteúdo do alerta é preciso, e um remetente legítimo comprometido também passaria. Outras evidências concordam: TLS 1.3, texto simples, sem links para agir, sem anexo, sem pedido de credenciais. Como o alerta pede ao SOC para enviar indicadores, o pedido deve ser verificado com o contato do ISAC ou um contato HC3 conhecido, não com os detalhes dentro da mensagem.
- Veredito final: LEGÍTIMO, P3-MEDIUM (gera acompanhamento).

---

## Resumo

| Email | Domínio remetente | SPF | DKIM | DMARC | Autenticação sustenta legitimidade? | Veredito final |
|---|---|---|---|---|---|---|
| E1 | `healthcare-education-weekly.com` | pass | pass | pass | Sim | LEGÍTIMO |
| E2 | `meddefense-portal.com` | fail | none | fail (`none`) | Não | SUSPEITO |
| E3 | `outlook-protection.com` | pass | pass | pass | Válida, mas apenas para o domínio do atacante | SUSPEITO |
| E4 | `meddefense.com` | pass | pass | pass | Sim | LEGÍTIMO |
| E5 | `medequip-supplies.net` | softfail | none | fail (`none`) | Não | SUSPEITO |
| E6 | `canadian-pharma-discount.org` | softfail | none | fail (`quarantine`) | Não | SPAM |
| E7 | `meddefense-benefits.org` | fail | none | fail (`none`) | Não | SUSPEITO |
| E8 | `hhs.gov` | pass | pass | pass | Sim | LEGÍTIMO |

## O que o padrão mostra

- A autenticação sozinha separaria três dos quatro e-mails suspeitos (E2, E5, E7 falham no DMARC), mas colocaria o E3 junto dos legítimos E1, E4 e E8.
- Três e-mails suspeitos falharam no DMARC e ainda assim foram entregues porque o resultado foi `action=none`.
- Nenhum dos quatro e-mails suspeitos autentica como `meddefense.com` ou `microsoft.com`. Eles usam domínios parecidos (lookalike), então uma regra baseada nos domínios reais nunca teria disparado.
- Acompanhamento que vale considerar: tratar falhas de DMARC vindas de domínios lookalike desconhecidos como quarentena, adicionar uma verificação que compare a marca do nome de exibição com o domínio remetente, e usar a idade do domínio como entrada, para que um `dmarc=pass` de um domínio recém-registrado não seja tratado como sinal de confiança.
