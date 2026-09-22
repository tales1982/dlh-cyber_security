# Análise de Cabeçalhos

Análise da cadeia de cabeçalhos SMTP dos quatro e-mails classificados como SUSPEITOS na triagem: E2, E3, E5 e E7. A fonte é apenas o lote de evidências de e-mail bruto (coletado em 2026-04-17 09:15 CDT). Nenhum dado ao vivo de Wazuh, Sysmon, Suricata ou endpoint foi usado, nenhum link foi visitado e nenhum anexo foi aberto. Domínios, endereços e IPs são exibidos em formatação de código para permanecerem exatamente como aparecem nos cabeçalhos.

## Como a cadeia de Received foi lida

- As linhas `Received:` são adicionadas no topo por cada servidor, então a cadeia é lida de baixo para cima para acompanhar a mensagem em ordem cronológica. Cada resumo abaixo está listado do mais antigo para o mais recente.
- Apenas o salto escrito pelo nosso próprio `mx01.meddefense.com` é evidência confiável, porque nosso servidor registrou o IP de conexão diretamente. A linha abaixo dele, escrita pelo próprio host do remetente, é o que o remetente afirma e pode ser forjado.
- As quatro mensagens chegaram diretamente do próprio host de e-mail do remetente para o `mx01.meddefense.com`. Não há relay de terceiros ou provedor de e-mail em nenhuma cadeia.

## Referência: como é um e-mail genuíno neste lote

| Item | E4 (interno) | E1 (externo, legítimo) | E8 (externo, legítimo) |
|---|---|---|---|
| Host de envio | `exchange-hub.meddefense.local` (`10.10.1.15`) | `mail-out.healthcare-education-weekly.com` (`198.51.100.42`) | `mail.hhs.gov` (`134.174.47.82`) |
| MTA / X-Mailer | Microsoft Exchange Server 2019 | Postfix / MailChimp Mailer v12.4 | HHS Secure Mail Gateway |
| Message-ID | `<20260415100010.2D7A3F9B@meddefense.com>` | `<20260414072210.8F3D4E1A@healthcare-education-weekly.com>` | `<HC3-20260416-0847@hhs.gov>` |
| DKIM | pass, `d=meddefense.com` | pass, domínio próprio | pass, `d=hhs.gov` |
| TLS no salto | relay interno | TLS 1.3 | TLS 1.3 |

Os quatro e-mails suspeitos não compartilham nenhuma dessas características. E-mails reais da MedDefense são retransmitidos pelo Exchange na rede interna, então qualquer mensagem que afirme ser da TI ou do RH da MedDefense e chegue de um IP externo já está fora do padrão.

---

## Email 2 — meddefense-portal.com

### Evidência de Cabeçalho

- From: `"MedDefense IT Security" <noreply@meddefense-portal.com>`
- Return-Path: `<noreply@meddefense-portal.com>` (mesmo domínio do From)
- IP de envio: `91.234.99.107` (`mail.meddefense-portal.com`, ESMTP simples, sem TLS, registrado pelo `mx01` em 2026-04-14 14:47:51 -0500)
- X-Mailer: `PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)`
- Message-ID: `<PHP-5D7E2F4A@meddefense-portal.com>`
- Reply-To: `<no-reply@meddefense-portal.com>`
- Authentication-Results: SPF `fail`, DKIM `none`, DMARC `fail` (`action=none`), todos contra `meddefense-portal.com`
- Cabeçalhos de prioridade: `X-Priority: 1 (Highest)`, `X-MSMail-Priority: High`, `Importance: High`

### Resumo da Cadeia Received

1. Origem (afirmada pelo remetente): `from localhost (localhost [127.0.0.1]) by mail.meddefense-portal.com (PHPMailer 6.6.0) id PHP-5D7E2F4A`, 2026-04-14 19:47:48 +0000. Um script PHP no host do remetente entregou a mensagem ao próprio serviço de e-mail.
2. Salto externo (registrado pela MedDefense): `from mail.meddefense-portal.com ([91.234.99.107]) by mx01.meddefense.com with ESMTP id 6E4A1B23`, 14:47:51 -0500 (19:47:51 UTC). Este é o indicador de origem confiável.
3. Repasse interno: `mx01.meddefense.com ([10.10.1.20])` para `inbound-relay.meddefense.com`, id `7F8D3C9B`, para `dmarsh@meddefense.com`, 14:47:52 -0500. Três a quatro segundos do início ao fim, o remetente conectou diretamente ao nosso MX.

### Remetente Alegado vs. Infraestrutura de Envio

A mensagem se apresenta como a TI Security interna da MedDefense (nome de exibição, logo, número de chamado no corpo). A infraestrutura é um host externo `91.234.99.107` operando sob `meddefense-portal.com`, que não é `meddefense.com`. Nada na cadeia toca `meddefense.com` ou `*.meddefense.local`, exceto o nosso próprio MX. O remetente interno genuíno neste lote (E4) usa Exchange 2019 em `10.10.1.15` e assina como `d=meddefense.com`.

### Anomalias

- [HIGH] Domínio remetente parecido (lookalike): `meddefense-portal.com` imita `meddefense.com` adicionando uma palavra plausível. From, Return-Path e Reply-To usam todos esse domínio.
- [HIGH] Afirma ser TI interna, mas se origina de um IP externo, sem nenhum relay interno na cadeia, ao contrário do padrão de referência do E4.
- [HIGH] Nenhuma identidade autenticada: SPF `fail` (IP não autorizado para o próprio domínio do remetente), DKIM `none`, DMARC `fail`. Entregue porque o DMARC retornou `action=none`.
- [MEDIUM] `PHPMailer 6.6.0` aparece tanto na cláusula `by ... (PHPMailer 6.6.0)` do `Received:` quanto no `X-Mailer:`. PHPMailer é uma biblioteca PHP usada por aplicações web, não um servidor de e-mail, e não é o que a TI da MedDefense usa. A mesma string aparece em E3, E5 e E7.
- [MEDIUM] O formato do Message-ID `PHP-<8 hex>@domínio` não tem timestamp e repete o `id` da linha `Received:` do remetente. Postfix (E1) e Exchange (E4) usam `<AAAAMMDDHHMMSS.IDDAFILA@domínio>`.
- [MEDIUM] Três sinalizadores de alta prioridade empilhados (`X-Priority`, `X-MSMail-Priority`, `Importance`), consistente com a urgência de 24 horas no corpo. Apenas o E2 carrega os três.
- [LOW] Reply-To (`no-reply@`) difere do From (`noreply@`) por um hífen, dois endereços diferentes para um remetente supostamente "automatizado".
- [LOW] Sem TLS no salto externo, enquanto os remetentes externos legítimos E1 e E8 negociaram TLS 1.3.

### Conclusão

O E2 não foi enviado pela MedDefense. A origem real é `91.234.99.107` rodando `mail.meddefense-portal.com` com PHPMailer 6.6.0, entregue diretamente ao nosso MX sem autenticação. A evidência de cabeçalho sozinha já é suficiente para classificá-lo como phishing, o que sustenta a classificação P1 dado o clique registrado em 2026-04-14 15:02:33 CDT (14 min 41 s após a entrega). Quem registrou o domínio e qual provedor hospeda o IP não podem ser determinados pelos cabeçalhos, e ficam para as consultas em `4-url_attachment_autopsy.md`.

---

## Email 3 — outlook-protection.com

### Evidência de Cabeçalho

- From: `"Microsoft Account Protection" <security@outlook-protection.com>`
- Return-Path: `<security@outlook-protection.com>` (mesmo domínio do From)
- IP de envio: `51.38.42.17` (`mail.outlook-protection.com`, ESMTPS TLS 1.2 `ECDHE-RSA-AES128-GCM-SHA256`, registrado pelo `mx01` em 2026-04-15 09:13:43 -0500)
- X-Mailer: `PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)`
- Message-ID: `<PHP-9F2D7E1B@outlook-protection.com>`
- Reply-To: `<no-reply@outlook-protection.com>`
- Authentication-Results: SPF `pass`, DKIM `pass` (`d=outlook-protection.com`, `s=default`), DMARC `pass` (`action=none`), todos para `outlook-protection.com`
- Cabeçalhos de prioridade: `X-Priority: 1 (Highest)`

### Resumo da Cadeia Received

1. Origem (afirmada pelo remetente): `from wp-admin.outlook-protection.com (localhost [127.0.0.1]) by mail.outlook-protection.com (PHPMailer 6.6.0) id PHP-9F2D7E1B`, 2026-04-15 14:13:40 +0000.
2. Salto externo (registrado pela MedDefense): `from mail.outlook-protection.com ([51.38.42.17]) by mx01.meddefense.com with ESMTPS (TLS1.2) id 5D7A2B1C`, 09:13:43 -0500 (14:13:43 UTC).
3. Repasse interno: `mx01` para `inbound-relay.meddefense.com`, id `8A2B4E7C`, para `rmendez@meddefense.com`, 09:13:44 -0500.

### Remetente Alegado vs. Infraestrutura de Envio

O nome de exibição, o texto do corpo, o logo e o rodapé (`© 2026 Microsoft Corporation ... One Microsoft Way, Redmond`) afirmam ser da Microsoft. A infraestrutura pertence a `outlook-protection.com`, que não é `microsoft.com` e não é `outlook.com`. Todos os campos de identidade se alinham nesse único domínio: From, Return-Path, SPF `smtp.mailfrom` e DKIM `d=`. A mensagem é internamente consistente, e ela é consistente em ser de `outlook-protection.com`, não da Microsoft. O logo é carregado de `outlook-protection.com/img/ms_logo.png`, não de um host da Microsoft.

### Anomalias

- [HIGH] Personificação de marca: um nome de exibição "Microsoft Account Protection" em um domínio que a Microsoft não possui. A autenticação passa apenas para o próprio domínio do atacante, então essa discrepância aparece nos cabeçalhos e no conteúdo, não no resultado de autenticação.
- [HIGH] Alertas de segurança da Microsoft não são enviados via PHPMailer a partir de um domínio de terceiros. `PHPMailer 6.6.0` no `X-Mailer` e na cláusula `by` do `Received:` é a mesma impressão digital do E2, E5 e E7.
- [MEDIUM] O host de origem se chama `wp-admin.outlook-protection.com`, um nome de host no estilo painel de administração do WordPress. Sugere um site WordPress/PHP usado para injetar e-mail, não uma plataforma de e-mail. Também visto no E7 como `wp-portal.meddefense-benefits.org`.
- [MEDIUM] Message-ID `PHP-9F2D7E1B@...` segue o mesmo padrão `PHP-<8 hex>` sem timestamp.
- [LOW] Reply-To (`no-reply@`) difere do From (`security@`), ambos no domínio do remetente.
- [LOW] TLS 1.2 e uma assinatura DKIM válida mostram um remetente configurado com mais cuidado que E2, E5 e E7. TLS e DKIM não dizem nada sobre quem é o dono do domínio.
- [INFO] O corpo lista um IP de "login" `41.203.72.188` (Lagos, Nigéria). É conteúdo da isca, não infraestrutura de envio, e não tem lugar na cadeia Received.

### Conclusão

O E3 foi enviado a partir de `51.38.42.17` em infraestrutura de `outlook-protection.com`, não pela Microsoft. É o único dos quatro que autentica de forma limpa, então seu valor de cabeçalho está em mostrar a discrepância remetente-versus-alegação, não em uma falha de autenticação. Combinado com a impressão digital PHPMailer e `wp-admin`, isso é phishing de personificação de marca.

---

## Email 5 — medequip-supplies.net

### Evidência de Cabeçalho

- From: `"MedEquip Supplies Billing" <invoices@medequip-supplies.net>`
- Return-Path: `<invoices@medequip-supplies.net>` (mesmo domínio do From)
- IP de envio: `185.176.43.22` (`mail.medequip-supplies.net`, ESMTP simples, sem TLS, registrado pelo `mx01` em 2026-04-16 11:28:37 -0500)
- X-Mailer: `PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)`
- Message-ID: `<PHP-7C2D4E1A@medequip-supplies.net>`
- Reply-To: `<billing@medequip-supplies.net>`
- Authentication-Results: SPF `softfail`, DKIM `none`, DMARC `fail` (`action=none`), todos contra `medequip-supplies.net`
- Cabeçalhos de prioridade: `X-Priority: 1 (Highest)`
- MIME: `multipart/mixed` com corpo HTML e um anexo PDF em base64 chamado `INV-2026-04891.pdf`

### Resumo da Cadeia Received

1. Origem (afirmada pelo remetente): `from billing-svc.medequip-supplies.net (localhost [127.0.0.1]) by mail.medequip-supplies.net (PHPMailer 6.6.0) id PHP-7C2D4E1A`, 2026-04-16 16:28:35 +0000.
2. Salto externo (registrado pela MedDefense): `from mail.medequip-supplies.net ([185.176.43.22]) by mx01.meddefense.com with ESMTP id 1E4F2B8D`, 11:28:37 -0500 (16:28:37 UTC).
3. Repasse interno: `mx01` para `inbound-relay.meddefense.com`, id `6B3E7A2C`, para `arivera@meddefense.com`, 11:28:39 -0500.

### Remetente Alegado vs. Infraestrutura de Envio

A mensagem afirma ser o departamento de faturamento de um fornecedor de equipamentos médicos. Angela Rivera (Contas a Pagar) relata que a fatura parece errada, e nada na evidência estabelece a MedEquip Supplies como fornecedor existente. O sistema de faturamento de um fornecedor normalmente enviaria a partir de uma plataforma assinada e listada no SPF. Aqui, o "serviço" de faturamento (`billing-svc`) é um script PHPMailer em um host cujo próprio registro SPF não o lista, e a mensagem não é assinada.

### Anomalias

- [HIGH] SPF `softfail`, DKIM `none`, DMARC `fail`: nada autentica a mensagem para `medequip-supplies.net`, e um sistema de faturas de um fornecedor real normalmente faria ambos.
- [HIGH] Relação de remetente não verificada: o destinatário de Contas a Pagar não reconhece a fatura, e o domínio tem um nome no estilo lookalike com terminação `.net`, sem histórico de fornecedor estabelecido na evidência.
- [MEDIUM] `PHPMailer 6.6.0` como X-Mailer e no `Received:`, o mesmo conjunto de ferramentas de E2, E3 e E7.
- [MEDIUM] Message-ID `PHP-7C2D4E1A@...` usa o mesmo padrão `PHP-<8 hex>`.
- [MEDIUM] Timing do anexo: os metadados do PDF registram criação em 2026-04-16 16:28:34 UTC, um segundo antes do `Date` desta mensagem (16:28:35 +0000), enquanto o corpo diz que as mercadorias foram entregues em 9 de abril. O anexo foi gerado no momento do envio (detalhes em `4-url_attachment_autopsy.md`).
- [MEDIUM] `X-Priority: 1 (Highest)` em uma fatura de fornecedor, alinhado com a pressão de pagamento de 7 dias no corpo.
- [LOW] Reply-To (`billing@`) difere do From (`invoices@`), ambos no domínio do remetente.
- [LOW] Sem TLS no salto externo.

### Conclusão

O E5 se origina de `185.176.43.22` sob `medequip-supplies.net`, usando a mesma impressão digital PHPMailer das outras iscas. Ele falha ou apenas tem softfail em cada verificação de autenticação e vem de um remetente que o destinatário não consegue identificar. Os cabeçalhos sustentam a classificação da triagem como isca de fraude de pagamento e coleta de credenciais.

---

## Email 7 — meddefense-benefits.org

### Evidência de Cabeçalho

- From: `"MedDefense HR Benefits" <hr-notifications@meddefense-benefits.org>`
- Return-Path: `<hr-notifications@meddefense-benefits.org>` (mesmo domínio do From)
- IP de envio: `164.90.218.73` (`mail.meddefense-benefits.org`, ESMTP simples, sem TLS, registrado pelo `mx01` em 2026-04-16 15:22:05 -0500)
- X-Mailer: `PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)`
- Message-ID: `<PHP-2E4A7B1C@meddefense-benefits.org>`
- Reply-To: `<no-reply@meddefense-benefits.org>`
- Authentication-Results: SPF `fail`, DKIM `none`, DMARC `fail` (`action=none`), todos contra `meddefense-benefits.org`
- Cabeçalhos de prioridade: `X-Priority: 1 (Highest)`

### Resumo da Cadeia Received

1. Origem (afirmada pelo remetente): `from wp-portal.meddefense-benefits.org (localhost [127.0.0.1]) by mail.meddefense-benefits.org (PHPMailer 6.6.0) id PHP-2E4A7B1C`, 2026-04-16 20:22:02 +0000.
2. Salto externo (registrado pela MedDefense): `from mail.meddefense-benefits.org ([164.90.218.73]) by mx01.meddefense.com with ESMTP id 7D2F4B9A`, 15:22:05 -0500 (20:22:05 UTC).
3. Repasse interno: `mx01` para `inbound-relay.meddefense.com`, id `3C8E4A7B`, para `lpatterson@meddefense.com`, 15:22:07 -0500.

### Remetente Alegado vs. Infraestrutura de Envio

A mensagem afirma ser do Recursos Humanos da MedDefense. Vem de um host externo sob `meddefense-benefits.org`, um domínio de topo diferente do real `meddefense.com`. O e-mail interno de RH real seguiria o padrão do E4 (Exchange em `10.10.1.15`, assinado para `meddefense.com`). Linda Patterson (Billing) relata que nunca se inscreveu para nada, o que não bate com a alegação de "seus registros mostram que você ainda não completou sua re-inscrição".

### Anomalias

- [HIGH] Domínio parecido com a própria marca da empresa: `meddefense-benefits.org` adiciona uma palavra-chave de benefícios e troca `.com` por `.org`.
- [HIGH] SPF `fail` (IP não autorizado para o próprio domínio do remetente), DKIM `none`, DMARC `fail`; entregue sob `action=none`.
- [MEDIUM] O host de origem é `wp-portal.meddefense-benefits.org`, um nome de host no estilo WordPress, comparável ao `wp-admin` no E3.
- [MEDIUM] `PHPMailer 6.6.0` e Message-ID `PHP-<8 hex>`, a mesma impressão digital de E2, E3 e E5.
- [MEDIUM] `X-Priority: 1 (Highest)` em um aviso de RH, consistente com o prazo "encerra amanhã".
- [LOW] Reply-To (`no-reply@`) difere do From (`hr-notifications@`).
- [LOW] Sem TLS no salto externo.

### Conclusão

O E7 foi enviado a partir de `164.90.218.73` sob `meddefense-benefits.org`, não pelo RH da MedDefense. Falha em toda verificação de autenticação e compartilha a impressão digital PHPMailer, Message-ID e prioridade de E2, E3 e E5. Os cabeçalhos sustentam a classificação como isca de credenciais em domínio parecido.

---

## Comparação Entre os E-mails

| Campo | E2 | E3 | E5 | E7 |
|---|---|---|---|---|
| Domínio remetente | `meddefense-portal.com` | `outlook-protection.com` | `medequip-supplies.net` | `meddefense-benefits.org` |
| IP de envio | `91.234.99.107` | `51.38.42.17` | `185.176.43.22` | `164.90.218.73` |
| Nome do MTA remetente em `Received:` | `mail.meddefense-portal.com` | `mail.outlook-protection.com` | `mail.medequip-supplies.net` | `mail.meddefense-benefits.org` |
| Host interno (origem) | `localhost` | host `wp-admin.` | host `billing-svc.` | host `wp-portal.` |
| TLS no salto externo | nenhum | TLS 1.2 | nenhum | nenhum |
| SPF / DKIM / DMARC | fail / none / fail | pass / pass / pass | softfail / none / fail | fail / none / fail |
| X-Mailer | PHPMailer 6.6.0 | PHPMailer 6.6.0 | PHPMailer 6.6.0 | PHPMailer 6.6.0 |
| Message-ID | `PHP-5D7E2F4A@` | `PHP-9F2D7E1B@` | `PHP-7C2D4E1A@` | `PHP-2E4A7B1C@` |
| Fuso do cabeçalho Date | +0000 | +0000 | +0000 | +0000 |
| Prioridade | 1 + High + High | 1 | 1 | 1 |

Observações:

- Nenhum IP ou domínio de envio é compartilhado entre os quatro e-mails. Os cabeçalhos não mostram reutilização de infraestrutura.
- O elo entre eles é a impressão digital do conjunto de ferramentas: PHPMailer 6.6.0, o Message-ID `PHP-<8 hex>` que repete o id do `Received`, a nomenclatura `mail.<domínio>`, `X-Priority: 1` e um fuso `+0000`. Os remetentes legítimos no lote não mostram nenhum desses traços juntos.
- O E3 está configurado com mais cuidado que os outros (DKIM, SPF e TLS válidos), enquanto E2, E5 e E7 não são assinados e falham no SPF contra seus próprios domínios. Isso pode indicar esforço de configuração ou operadores diferentes. Os cabeçalhos sozinhos não resolvem essa questão.

## Notas e Limitações

- Os timestamps de Date e Received são internamente consistentes nas quatro mensagens: o `Date` do remetente bate com o salto do `mx01` dentro de um a três segundos uma vez aplicados os fusos +0000 e -0500, então a linha do tempo é utilizável.
- Alguns nomes de dias da semana no lote não coincidem com o calendário de 2026 (por exemplo, o E5 diz quarta-feira para 16 de abril de 2026, que é uma quinta-feira) e os valores `t=` do DKIM caem em 2025. Como nas notas de triagem, isso é tratado como artefato do lote que afeta mensagens legítimas e maliciosas igualmente, e não como sinal.
- DNS reverso, WHOIS, idade de registro, provedor de hospedagem e geolocalização não estão na evidência e não foram consultados. Estão listados como métodos de acompanhamento em `4-url_attachment_autopsy.md`.
