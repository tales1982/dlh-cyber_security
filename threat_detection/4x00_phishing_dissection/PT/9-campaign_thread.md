## Análise do Fio da Campanha

Avaliação sobre se E2, E5 e E7 formam uma única campanha de phishing coordenada contra a MedDefense, usando infraestrutura compartilhada, tempo e padrões de direcionamento extraídos de `1-header_analysis.md`, `3-social_engineering.md` e `4-url_attachment_autopsy.md`, comparados com o alerta do setor de saúde no E8. E3 e E6 são referenciados para contraste, mas não são tratados como parte do trio E2/E5/E7 (ver Avaliação de Atribuição).

### Indicadores Compartilhados

| Indicador | E2 | E5 | E7 |
|---|---|---|---|
| Domínio relacionado à marca ou cadeia de suprimentos da MedDefense | `meddefense-portal.com` (parecido com a marca) | `medequip-supplies.net` (parecido no estilo de fornecedor) | `meddefense-benefits.org` (parecido com a marca) |
| X-Mailer / software de envio | PHPMailer 6.6.0 | PHPMailer 6.6.0 | PHPMailer 6.6.0 |
| Formato do Message-ID | `PHP-<8 hex>@meddefense-portal.com` | `PHP-<8 hex>@medequip-supplies.net` | `PHP-<8 hex>@meddefense-benefits.org` |
| Padrão do nome de host remetente | `mail.meddefense-portal.com` | `mail.medequip-supplies.net` | `mail.meddefense-benefits.org` |
| Cabeçalhos de prioridade | `X-Priority: 1` + `X-MSMail-Priority: High` + `Importance: High` | `X-Priority: 1` | `X-Priority: 1` |
| Autenticação | SPF fail, DKIM none, DMARC fail (`action=none`) | SPF softfail, DKIM none, DMARC fail (`action=none`) | SPF fail, DKIM none, DMARC fail (`action=none`) |
| TLS na entrega | Não | Não | Não |
| Reply-To difere do From por uma pequena variação | `no-reply@` vs `noreply@` | `billing@` vs `invoices@` | `no-reply@` vs `hr-notifications@` |
| Urgência combinada com uma consequência concreta | Bloqueio em 24h → perde acesso a escalas/EHR/troca de plantão | Prazo de 7 dias → multa de 2%, suspensão de entrega | "Encerra amanhã" → perda de cobertura, reduzido a um plano básico |
| Isca combina com um processo de negócio real da MedDefense | Acesso ao portal/pessoal de TI | Pagamento de fatura de fornecedor | Inscrição aberta de benefícios |

Nenhum IP de envio é compartilhado entre os três (`91.234.99.107`, `185.176.43.22`, `164.90.218.73` são todos diferentes), então isso não é reutilização de infraestrutura no sentido estrito. O elo é uma impressão digital consistente de conjunto de ferramentas e modelo — mesma versão de mailer, mesmas convenções de Message-ID e nome de host, mesmo hábito de cabeçalho de prioridade, mesma estrutura de "urgência mais uma consequência nomeada", cada uma redirecionada a um processo real diferente da MedDefense — o que se lê como um único manual aplicado três vezes, e não três remetentes não relacionados que coincidentemente se parecem.

### Mapa de Direcionamento

| Email | Destinatária | Departamento / Cargo | Tema do Pretexto | Processo de Negócio Referenciado |
|---|---|---|---|---|
| E2 | Diane Marsh (`dmarsh@meddefense.com`) | Equipe clínica / enfermagem (workstation `WS-NURSE-04`) | Re-verificação do portal de TI | Sistema de escalas, gateway do EHR, solicitações de troca de plantão |
| E5 | Angela Rivera (`arivera@meddefense.com`) | Contas a Pagar / Finanças | Pagamento de fatura de fornecedor | Compra e pagamento de suprimentos médicos |
| E7 | Linda Patterson (`lpatterson@meddefense.com`) | Billing | Inscrição aberta de benefícios de RH | Re-inscrição anual de benefícios |

O *conteúdo* de cada isca é apropriado ao departamento que ela nomeia (fluxos clínicos para E2, uma fatura para AP), o que combina com a descrição do HC3 de iscas direcionadas por cargo. O E7 é a única inconsistência digna de nota: seu conteúdo aborda um processo de RH da empresa toda (inscrição de benefícios), não um específico de Billing, mas mesmo assim chegou a uma caixa de correio do Billing. Isso é consistente com uma isca pensada para qualquer pessoa na folha de pagamento, e não escrita especificamente para a função de Linda Patterson — o direcionamento é por *lista de destinatários*, não necessariamente por *conteúdo combinado com departamento*, nesta mensagem específica. Isso não enfraquece o elo da campanha; apenas mostra que o pretexto do E7 é organizacional, não específico de cargo, ao contrário de E2 e E5.

### Mapa de Tempo

| Email | Data (lote de evidências) | Horário de entrega (CDT) | Intervalo desde o anterior |
|---|---|---|---|
| E2 | 2026-04-14 | 14:47:51 | — (primeiro dos três) |
| E5 | 2026-04-16 | 11:28:37 | +44 h 41 min após o E2 |
| E7 | 2026-04-16 | 15:22:05 | +3 h 54 min após o E5 (mesmo dia) |

O E2 foi entregue em 14 de abril; E5 e E7 foram entregues em 16 de abril, cerca de quatro horas de diferença, conforme os timestamps de `Received:` registrados pelo `mx01.meddefense.com`. Não há entrega em 15 de abril entre esses três na evidência — um intervalo de um dia separa o E2 do par E5/E7, que então chegam próximos na mesma tarde. (O E3 cai dentro dessa lacuna, em 15 de abril, mas é avaliado separadamente — ver Avaliação de Atribuição.) O agrupamento de dois por dia em 16 de abril é consistente com um único remetente trabalhando em uma lista curta de alvos em uma única sessão, em vez de três remetentes não relacionados e independentemente cronometrados.

### Comparação Com o Alerta do HC3

O E8 (HC3, recebido em 2026-04-16 08:47 CDT — depois do E2, antes de E5 e E7) descreve uma campanha regional do setor de saúde com quatro padrões observados. Todos os quatro estão presentes em E2, E5 e E7:

| Padrão descrito pelo HC3 | Correspondência em E2 / E5 / E7 |
|---|---|
| Domínios `.com`/`.net`/`.org` recém-registrados usando "portal", "benefits", "supplies" ou "login" no hostname | `meddefense-**portal**.com` (E2), `medequip-**supplies**.net` (E5), `meddefense-**benefits**.org` (E7) — todas as três categorias de palavra-chave que o HC3 cita estão representadas exatamente |
| Envio via PHPMailer em hospedagem VPS de baixo custo | PHPMailer 6.6.0 confirmado nos três cabeçalhos `X-Mailer` e cláusulas `Received:`; os IPs de envio (`91.234.99.107`, `185.176.43.22`, `164.90.218.73`) são consistentes com hosts externos pequenos/estilo VPS, embora o provedor de hospedagem específico não tenha sido consultado ao vivo neste exercício apenas de evidência |
| Prazos de 24–48 horas, ameaças de bloqueio de conta, prazos finais de inscrição aberta | E2: bloqueio em 24 horas; E7: inscrição "encerra amanhã"; E5 usa um prazo mais longo de 7 dias, mas a mesma estrutura de ameaça de multa por atraso/suspensão |
| Iscas apropriadas por cargo para equipe clínica, de billing e ligada ao RH | E2 → clínica/enfermagem; E5 → Contas a Pagar/Finanças ("billing staff" do HC3); E7 → conteúdo temático de RH, entregue a uma destinatária de Billing |

A correspondência é próxima o suficiente em cada um dos quatro traços observados pelo HC3 para que E2, E5 e E7 sejam lidos como instâncias locais do mesmo padrão regional que o HC3 está rastreando, não como uma semelhança coincidente. O próprio E8 ainda estava TLP:CLEAR e "não confirmado por IOC" no momento em que chegou, então a evidência própria da MedDefense (este lote) é um dado concreto e específico da organização que reforçaria o padrão do HC3 se enviado (ver `11-ioc_extraction.md`).

### Avaliação de Atribuição

**O que pode ser inferido:** E2, E5 e E7 muito provavelmente foram construídos e enviados usando o mesmo manual operacional — versão idêntica de mailer e convenção de Message-ID, padrão de hostname idêntico (`mail.<domínio-parecido>`), hábito idêntico de cabeçalho de prioridade, e um modelo consistente de "urgência mais uma consequência nomeada, ligada a um processo real da MedDefense", aplicado a três pretextos diferentes visando três departamentos diferentes dentro de uma janela de aproximadamente 48 horas. As escolhas de domínio (a própria marca da empresa duas vezes, um fornecedor com nome plausível uma vez) mostram que quem enviou tinha pesquisado a MedDefense especificamente — seu nome, pelo menos um processo interno por alvo, e os nomes, endereços de e-mail e departamentos de pelo menos dois funcionários reais.

**O que não pode ser provado apenas com esta evidência:**
- **Um único humano ou grupo, em vez de um kit compartilhado.** PHPMailer é uma biblioteca de código aberto amplamente disponível, e "o mesmo conjunto de ferramentas" é evidência mais fraca que "a mesma infraestrutura". Nenhum IP de envio, conta de hospedagem ou registrador é compartilhado entre E2, E5 e E7 na evidência, então a atribuição no nível de infraestrutura não é possível aqui.
- **Propriedade ou identidade do provedor de hospedagem.** WHOIS, registrador e dados de provedor de hospedagem não foram consultados ao vivo para esta tarefa; sem eles, alegações sobre quem registrou esses domínios ou qual provedor os hospeda não são confirmadas.
- **Um grupo de ator de ameaça nomeado.** Nada nos cabeçalhos ou no conteúdo é uma impressão digital única o suficiente para anexar o nome de um grupo conhecido. O próprio alerta do HC3 (E8) descreve o padrão regional mais amplo como "não confirmado por IOC" e também não nomeia um ator.
- **Se o E3 pertence à mesma operação.** O E3 compartilha alguns traços com o trio (PHPMailer 6.6.0, Message-ID `PHP-<8 hex>`, `X-Priority: 1`), mas foi enviado de um IP diferente, está melhor configurado (SPF/DKIM/DMARC válidos, TLS 1.2), não visa nenhum processo específico da MedDefense, e não exigiu reconhecimento além de um nome e endereço de e-mail (ver `8-verdict_matrix.md`, classificado PHISHING-OPPORTUNISTIC). Pode ser o mesmo operador rodando um segundo kit, mais genérico, contra uma lista de alvos mais ampla, ou pode ser um remetente completamente não relacionado. A evidência não resolve isso de nenhuma forma, então o E3 é tratado como possivelmente relacionado, mas não contado como parte do fio confirmado E2/E5/E7.

**Avaliação:** confiança MÉDIA de que E2, E5 e E7 são uma única campanha coordenada e direcionada à MedDefense, com base em consistência de ferramentas, modelo e tempo. Nenhum ator de ameaça, grupo ou país específico é nomeado ou implicado — essa alegação iria além do que a evidência de cabeçalho e conteúdo consegue sustentar.

### Conclusão

A evidência sustenta tratar E2, E5 e E7 como uma única campanha de phishing coordenada contra a MedDefense: a mesma impressão digital de mailer e modelo de mensagem, domínios deliberadamente escolhidos para referenciar a própria marca da organização ou sua cadeia de suprimentos, pretextos apropriados por cargo combinados com três departamentos diferentes, e entrega concentrada dentro de uma janela de aproximadamente 48 horas (14–16 de abril) sem lacuna não relacionada. O padrão também se alinha ponto a ponto com o alerta regional do setor de saúde do HC3 (E8), o que reforça o caso de que isso não é um incidente isolado e único na MedDefense, mas uma instância local de uma campanha mais ampla já rastreada. O E3 é plausivelmente conectado por meio de ferramentas compartilhadas, mas é avaliado separadamente como phishing oportunista e genérico, e não parte do fio confirmado, e o E6 é spam em massa não relacionado. Esta conclusão deve ser lida como "campanha coordenada, operador não identificado" — forte o suficiente para justificar o compartilhamento de IOC e o monitoramento contínuo, não forte o suficiente para nomear um ator.
