# Revisão 15 — O Paradoxo da Autenticação de E-mail

**Pergunta:** Uma analista investiga um e-mail suspeito enviado ao CFO do hospital. O e-mail alega ser da "Microsoft 365 Security" e avisa sobre atividade incomum de login. O cabeçalho Authentication-Results mostra SPF: pass, DKIM: pass, DMARC: pass. O domínio remetente é `outlook-protection.com`, não `microsoft.com` nem `outlook.com`.

Explique por que o e-mail ainda pode ser malicioso mesmo com todas as verificações de autenticação passando.

## Resposta

SPF, DKIM e DMARC verificam apenas o *controle* de um domínio, não a *identidade* organizacional. Cada protocolo checa se a infraestrutura de envio está autorizada a mandar e-mail em nome do domínio específico nomeado na mensagem — o SPF verifica o registro DNS do domínio do envelope (envelope-from), o DKIM valida uma assinatura criptográfica contra uma chave pública publicada no próprio DNS do domínio assinante, e o DMARC checa se esses dois resultados se alinham com o domínio visível em From. Os três protocolos foram projetados para impedir a *falsificação* de domínio (spoofing) — alguém enviando e-mail forjando um domínio que não controla —, não para impedir a *personificação* de domínio (impersonation), em que alguém registra e controla legitimamente um domínio novo e parecido.

Neste caso, o atacante é dono de fato de `outlook-protection.com`. Ele pode configurar um registro SPF correto, gerar seu próprio par de chaves DKIM e publicá-lo na própria zona DNS, e publicar uma política DMARC que se alinha perfeitamente com o próprio endereço From — porque é o domínio dele e ele controla o DNS dele. Toda verificação passa honestamente, exatamente como os protocolos deveriam funcionar, para aquele domínio. Nada no SPF, DKIM ou DMARC jamais pergunta "este domínio pertence à Microsoft?" ou "esta organização é quem alega ser?" — isso está totalmente fora do escopo deles. `outlook-protection.com` não é `microsoft.com` nem `outlook.com`; é um domínio separado que qualquer pessoa poderia registrar por alguns dólares, sem nenhuma checagem de marca registrada envolvida.

O engano é, portanto, social e visual, não técnico: o nome de exibição ("Microsoft 365 Security"/"Microsoft Account Protection"), o logo e o rodapé copiados, e o tom de urgência são o que criam a falsa impressão de legitimidade — não o resultado da autenticação. Um "pass" em SPF/DKIM/DMARC só prova que a mensagem é autenticamente de `outlook-protection.com`; não diz nada sobre se esse domínio tem qualquer relação com a Microsoft. É por isso que os resultados de autenticação sempre precisam ser combinados com uma checagem de identidade de domínio (o domínio em From/DKIM realmente combina com a marca alegada?), além de reputação, idade do domínio e análise de conteúdo — a autenticação sozinha não consegue pegar um domínio parecido bem configurado.

Este é o mesmo paradoxo documentado para o Email 3 nesta investigação, em `2-authentication_analysis.md`.
