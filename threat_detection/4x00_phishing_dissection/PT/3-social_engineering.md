# Análise de Engenharia Social

Análise de conteúdo dos quatro e-mails suspeitos (E2, E3, E5, E7): o que cada um pede ao leitor para fazer, como tenta induzir isso, e quanto o remetente precisou saber sobre o destinatário. Cabeçalhos e autenticação explicam como o e-mail foi enviado; este arquivo explica como ele tenta influenciar quem o recebe. A fonte é apenas o lote de evidências; nenhum link foi visitado e nenhum anexo foi aberto.

## Escala de direcionamento usada

| Nível | Significado |
|---|---|
| GENÉRICO | A mesma mensagem poderia ser enviada a qualquer pessoa. Nenhum detalhe específico do destinatário. |
| SEMI-DIRECIONADO | Personalizado com dados públicos ou facilmente deduzíveis, como nome, e-mail, organização, departamento ou um processo de negócio comum. Sem conhecimento interno. |
| DIRECIONADO | Contém informação específica do indivíduo ou interna à organização, como um token por usuário, sistemas ou fluxos de trabalho internos nomeados, que não são trivialmente públicos. |

---

## Email 2 — Isca de re-verificação do portal de funcionários

- Alavanca psicológica primária: urgência (prazo de 24 horas), reforçada por autoridade (enviado como "MedDefense IT Security" com um número de chamado de TI) e medo de perder acesso ao sistema de escalas, ao gateway do EHR e às trocas de plantão.
- Pretexto: uma atualização de política de segurança "lançada neste fim de semana" exige que todo funcionário faça a re-verificação do acesso ao portal. O rodapé acrescenta uma referência de chamado, `INC-2026-04-14-7741`, e uma linha de confidencialidade para parecer um aviso real de TI.
- Ação solicitada: clicar em **VERIFY MY ACCESS NOW**, que leva a `meddefense-portal.com/verify/staff` com o nome de usuário do destinatário e um token na query string, e verificar (fazer login) ali.
- Nível de direcionamento: DIRECIONADO.
- Sinais de alerta no conteúdo:
  - "Dentro de 24 horas" e "re-verificação imediata" com ameaça de suspensão.
  - As consequências são escolhidas para uma enfermeira: escalas, gateway do EHR, solicitações de troca de plantão.
  - O link vai para `meddefense-portal.com`, não `meddefense.com`, e o texto do botão esconde o destino.
  - A URL carrega `id=dmarsh` e `token=a8f3e2d1`, um link por destinatário que também permite ao remetente ver quem clicou.
  - "Esta é uma mensagem automática. Não responda." desencoraja perguntas.
  - O logo é carregado do próprio domínio do atacante.
  - Contradiz o aviso genuíno do E4: a TI nunca envia links de senha por e-mail, e o portal só é acessível de dentro da rede ou via VPN.
  - Três cabeçalhos de alta prioridade em um "aviso de TI".
- Conhecimento necessário pelo atacante:
  - O nome completo de Diane Marsh e o formato do nome de usuário dela (inicial do primeiro nome mais sobrenome, `dmarsh`).
  - Que ela trabalha na MedDefense e tem acesso ao portal e ao gateway do EHR.
  - Os nomes de fluxos de trabalho internos: um sistema de escalas, um gateway de EHR e solicitações de troca de plantão.
  - A marca da MedDefense (nome, logo, azul de marca `#0a4d8c`) e a aparência de um número de chamado interno de TI.
  - O lote não mostra como isso foi obtido. Um diretório de funcionários, redes sociais, uma violação anterior ou reconhecimento prévio seriam suficientes.
- Conclusão: o mais personalizado dos quatro. Combina uma pessoa nomeada, o nome de usuário dela, consequências específicas de enfermagem e um número de chamado com aparência interna, por isso também é o único com um clique confirmado. Um clique não prova que a personalização aumentou a taxa de sucesso, mas é consistente com isso. Tratado como coleta de credenciais.

## Email 3 — Isca de alerta de segurança da Microsoft

- Alavanca psicológica primária: medo (uma tentativa de login não reconhecida em Lagos, Nigéria, significando "sua conta pode ter sido comprometida"), com autoridade via personificação da Microsoft e uma urgência secundária (bloqueio em 48 horas).
- Pretexto: a Microsoft detectou uma tentativa de login de um dispositivo Windows desconhecido (IP `41.203.72.188`, "15 de abril de 2026 às 10h47 UTC") na conta `rmendez@meddefense.com`.
- Ação solicitada: clicar em **Verify account**, que leva a `outlook-protection.com/verify`, e confirmar a conta (fazer login).
- Nível de direcionamento: SEMI-DIRECIONADO (extremidade inferior).
- Sinais de alerta no conteúdo:
  - O remetente é `outlook-protection.com`, não um domínio Microsoft, apresentado sob o nome de exibição "Microsoft Account Protection".
  - Uma cidade estrangeira e um dispositivo desconhecido são escolhidos para alarmar. A localização, o IP e o dispositivo não podem ser verificados a partir da mensagem.
  - A solução oferecida é um link no mesmo e-mail, quando uma preocupação real de conta é resolvida indo diretamente ao serviço.
  - Ameaça de bloqueio em 48 horas por não verificar.
  - O rodapé copia "© 2026 Microsoft Corporation" e o endereço de Redmond, e o logo é carregado de `outlook-protection.com/img/ms_logo.png`.
  - O texto é um alerta de "conta Microsoft" no estilo consumidor, para um endereço corporativo.
  - O link não tem token por usuário: uma URL genérica para todo destinatário.
- Conhecimento necessário pelo atacante:
  - O primeiro nome e o endereço de e-mail de Rafael Mendez.
  - Que a organização provavelmente usa contas Microsoft. Essa é uma suposição segura para quase qualquer empresa, e a isca funciona sem conhecer o tenant real. O lote mostra um hub Exchange 2019 on-premises (E4), então se a MedDefense realmente usa Microsoft 365 para caixas de correio não está estabelecido por esta evidência.
  - Nada interno: nenhum sistema, pessoa, cargo ou processo da MedDefense é mencionado.
- Conclusão: um modelo de personificação de marca com personalização por mala direta (nome e endereço). Depende de o destinatário confiar no nome Microsoft e reagir a um gatilho de medo, não de conhecimento sobre a MedDefense. É o mais genérico dos quatro, e nenhum clique foi relatado. Tratado como coleta de credenciais.

## Email 5 — Isca de fatura

- Alavanca psicológica primária: pressão financeira (USD 24.716,38 vencendo em 7 dias, multa de 2% por atraso e suspensão de entregas futuras), com personificação de fornecedor e a autoridade rotineira de um processo de negócio comum.
- Pretexto: um fornecedor, "MedEquip Supplies", fatura a MedDefense por suprimentos médicos "entregues em 9 de abril de 2026", fatura `INV-2026-04891`, vencimento em 23 de abril de 2026.
- Ação solicitada: pagar através do portal de faturas vinculado (`medequip-supplies.net/invoices/pay`), ou, se o anexo não for visualizável, fazer login em `medequip-supplies.net/portal/login` para obter uma cópia. Há também um anexo PDF, `INV-2026-04891.pdf`, que carrega o mesmo link de pagamento. O e-mail oferece três caminhos para o mesmo domínio: clicar, fazer login ou abrir o PDF.
- Nível de direcionamento: SEMI-DIRECIONADO.
- Sinais de alerta no conteúdo:
  - Saudação genérica "Dear Accounts Payable" apesar de um destinatário nomeado.
  - O destinatário de Contas a Pagar não reconhece a fatura nem o fornecedor.
  - Nenhum número de pedido de compra, referência de contrato ou dados de remessa. O único contato é um número de telefone de vaidade (`1-800-MED-EQUIP`).
  - O pagamento é solicitado por um link no e-mail, não por um canal de remessa do cadastro de fornecedores.
  - O fallback "faça login para obter uma cópia" direciona o leitor a um prompt de credenciais.
  - Ameaças de multa por atraso e suspensão de entregas em um prazo de 7 dias, e `X-Priority: 1` em uma fatura.
  - O remetente é um domínio `.net` no estilo lookalike sem histórico estabelecido.
- Conhecimento necessário pelo atacante:
  - Que a MedDefense compra suprimentos médicos, o que é verdade para qualquer organização de saúde.
  - Que existe uma função de Contas a Pagar e como se dirigir a ela (`arivera@`, inicial do primeiro nome mais sobrenome).
  - Um número de fatura, faixa de valor e data de entrega plausíveis.
  - Não necessário: nomes de fornecedores reais, pedidos de compra ou contratos. O relato de Contas a Pagar de que a fatura "parece errada" sugere que o remetente não tinha esses dados.
- Conclusão: fraude de fatura direcionada por função, voltada à função de Contas a Pagar, combinada com coleta de credenciais através do fallback de login. Depende de um funcionário de AP ocupado pagando um valor plausível sem checar o cadastro de fornecedores. A fatura não deve ser paga nem aberta, e o fornecedor deve ser verificado usando um contato já registrado.

## Email 7 — Isca de inscrição em benefícios

- Alavanca psicológica primária: escassez (uma janela de inscrição que "encerra à meia-noite de amanhã"), mais medo de perda (a cobertura expira e o funcionário é padronizado para um plano básico até novembro de 2026) e autoridade (RH).
- Pretexto: "Nossos registros mostram que você ainda não completou sua re-inscrição de benefícios de 2026." O aviso é rotulado **AVISO FINAL** com prazo de 17 de abril de 2026.
- Ação solicitada: clicar em **COMPLETE ENROLLMENT**, que leva a `meddefense-benefits.org/enroll`, e fazer login ou fornecer informações para se inscrever. O e-mail acrescenta que quem acredita já ter se inscrito deve "ainda assim verificar no portal".
- Nível de direcionamento: SEMI-DIRECIONADO (extremidade superior).
- Sinais de alerta no conteúdo:
  - "AVISO FINAL" em cabeçalho vermelho e prazo para o dia seguinte, enviado à tarde do dia anterior, deixando pouco tempo para checar.
  - Ameaça de expiração de cobertura.
  - "Ainda assim verifique" remove a desculpa de quem já se inscreveu.
  - O link vai para `meddefense-benefits.org`, um lookalike `.org`, não para o sistema real de RH ou benefícios.
  - A destinatária, Linda Patterson, do Billing, diz que nunca se inscreveu para nada, o que conflita com a alegação de que os registros dela mostram uma re-inscrição pendente.
  - Nenhum nome de plano, contato de RH ou número de referência.
  - O rodapé repete o endereço da destinatária para parecer pessoal.
- Conhecimento necessário pelo atacante:
  - O primeiro nome e o endereço de e-mail de Linda.
  - Que a MedDefense tem um programa de benefícios com um período de inscrição, e o nome da função de RH.
  - A marca da MedDefense.
  - Se uma janela de inscrição realmente estava aberta naquelas datas não está estabelecido pelo lote e deve ser confirmado com o RH. Uma isca temática de RH chegando a uma caixa de correio do Billing sugere um pretexto para toda a força de trabalho, não um feito sob medida para o cargo dela.
- Conclusão: uma isca temática organizacional com personalização por primeiro nome e prazo, dependendo de informação pública e de um processo de benefícios que todo funcionário conhece. É mais específica da MedDefense que o E3, menos individualmente talhada que o E2. Tratado como coleta de credenciais.

---

## Comparação

| Email | Alavanca primária | Ação solicitada | Prazo na isca | Direcionamento |
|---|---|---|---|---|
| E2 | Urgência, autoridade, medo de bloqueio | Clicar e fazer login | 24 horas | DIRECIONADO |
| E3 | Medo, personificação da Microsoft | Clicar e fazer login | 48 horas | SEMI-DIRECIONADO (baixo) |
| E5 | Pressão financeira, personificação de fornecedor | Clicar, fazer login ou abrir PDF, pagar | 7 dias | SEMI-DIRECIONADO |
| E7 | Escassez, medo de perda, autoridade de RH | Clicar e fazer login | Cerca de 1 dia | SEMI-DIRECIONADO (alto) |

- Todos os quatro anexam um prazo a uma consequência e enviam o leitor a um domínio externo parecido (lookalike). Isso corresponde ao padrão descrito no alerta do HC3 (E8): prazos de 24 a 48 horas, ameaças de bloqueio, prazos finais de inscrição e iscas com sabor de cargo.
- Cada e-mail usa uma família de pretexto diferente: TI interna, segurança Microsoft, fatura de fornecedor, benefícios de RH. Iscas diferentes com o mesmo conjunto de ferramentas PHPMailer (ver `1-header_analysis.md`) apontam para um único playbook aplicado entre cargos, com a personalização ajustada aos dados que o remetente tinha para cada destinatário.
- O lote mostra um destinatário por e-mail, então o número de funcionários que receberam cada isca é desconhecido.
