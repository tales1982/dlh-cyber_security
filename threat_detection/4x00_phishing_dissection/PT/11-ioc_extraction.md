# Extração de IOC

Indicadores de comprometimento extraídos do lote de evidências para E2, E3, E5 e E7, o anexo do E5, e o padrão do alerta do HC3 no E8, estruturados para compartilhamento com outros defensores. Nem toda linha é igualmente acionável: domínios, IPs, URLs e endereços de remetente ligados diretamente a uma mensagem maliciosa específica têm alta confiança e são seguros para bloquear; impressões digitais de ferramentas e notas de nível de hospedagem são contexto que ajuda na correlação, mas causariam falsos positivos se bloqueadas isoladamente (ver Qualidade de IOC abaixo). Todos os valores estão desmascarados. O E6 (spam de farmácia em massa) está fora do escopo deste relatório — não está relacionado à campanha direcionada (ver `9-campaign_thread.md`) e já foi tratado como spam de baixa prioridade em `8-verdict_matrix.md`.

## 1. Tabela Estruturada de IOC

| # | Tipo de IOC | Valor do IOC (desmascarado) | E-mail de Origem | Contexto | Confiança | Ação Recomendada |
|---|---|---|---|---|---|---|
| 1 | Domínio | `meddefense-portal[.]com` | E2 | Parecido com o próprio domínio da MedDefense; hospeda a página de coleta de credenciais em que Diane Marsh clicou | HIGH | Bloquear |
| 2 | IP | `91[.]234[.]99[.]107` | E2 | Servidor de e-mail externo (`mail.meddefense-portal.com`) que entregou o E2; SPF fail | HIGH | Bloquear |
| 3 | URL | `hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1` | E2 | Link personalizado de coleta de credenciais; o `token` é por destinatário e será diferente para outras vítimas | HIGH (domínio/caminho); token de uso único | Bloquear o domínio e o caminho `/verify/staff`; não esperar que o token exato se repita |
| 4 | URL | `hxxps://meddefense-portal[.]com/assets/logo[.]png` | E2 | Imagem de logo carregada remotamente; funciona como indicador de abertura/rastreamento | MEDIUM | Monitorar (coberto ao bloquear #1) |
| 5 | Endereço de e-mail | `noreply@meddefense-portal[.]com` | E2 | Endereço From | HIGH | Bloquear / alertar sobre o remetente |
| 6 | Endereço de e-mail | `no-reply@meddefense-portal[.]com` | E2 | Endereço Reply-To (note a diferença do hífen em relação ao endereço From) | HIGH | Bloquear / alertar sobre o remetente |
| 7 | Domínio | `outlook-protection[.]com` | E3 | Personifica a Microsoft; autentica de forma limpa apenas para si mesmo, não para a Microsoft | HIGH | Bloquear |
| 8 | IP | `51[.]38[.]42[.]17` | E3 | Servidor de e-mail externo (`mail.outlook-protection.com`) que entregou o E3; SPF/DKIM/DMARC passam apenas para este domínio | HIGH | Bloquear |
| 9 | URL | `hxxps://outlook-protection[.]com/verify` | E3 | Link genérico (sem token) de coleta de credenciais | HIGH | Bloquear |
| 10 | URL | `hxxps://outlook-protection[.]com/img/ms_logo[.]png` | E3 | Logo falso da Microsoft carregado remotamente; indicador de rastreamento | MEDIUM | Monitorar (coberto ao bloquear #7) |
| 11 | Endereço de e-mail | `security@outlook-protection[.]com` | E3 | Endereço From | HIGH | Bloquear / alertar sobre o remetente |
| 12 | Endereço de e-mail | `no-reply@outlook-protection[.]com` | E3 | Endereço Reply-To | HIGH | Bloquear / alertar sobre o remetente |
| 13 | Domínio | `medequip-supplies[.]net` | E5 | Parecido no estilo de fornecedor; hospeda tanto a página de pagamento de fatura quanto uma página de login alternativa | HIGH | Bloquear |
| 14 | IP | `185[.]176[.]43[.]22` | E5 | Servidor de e-mail externo (`mail.medequip-supplies.net`) que entregou o E5; SPF softfail | HIGH | Bloquear |
| 15 | URL | `hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891` | E5 | Link de fraude de pagamento / captura de credenciais; a mesma URL também está embutida no anexo PDF | HIGH (domínio/caminho); id da fatura específico deste lote | Bloquear o domínio e o caminho `/invoices/pay` |
| 16 | URL | `hxxps://medequip-supplies[.]net/portal/login` | E5 | Página de login alternativa de coleta de credenciais | HIGH | Bloquear |
| 17 | Endereço de e-mail | `invoices@medequip-supplies[.]net` | E5 | Endereço From | HIGH | Bloquear / alertar sobre o remetente |
| 18 | Endereço de e-mail | `billing@medequip-supplies[.]net` | E5 | Endereço Reply-To | HIGH | Bloquear / alertar sobre o remetente |
| 19 | Nome de arquivo | `INV-2026-04891[.]pdf` | Anexo do E5 | Nome do arquivo PDF de fatura entregue como anexo MIME em base64 | LOW | Apenas monitorar — um nome de arquivo é trivialmente renomeável |
| 20 | URL (embutida no arquivo) | `hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891` | Anexo do E5 | Anotação de link `/URI` dentro do PDF, mesmo destino do #15 | HIGH | Bloquear (mesmo que #15) |
| 21 | Hash de arquivo (SHA-256) | `49558e1500b82d6758379f44ce6104442ec3a5cc08912737db5584640f4b9cad` | Anexo do E5 | Hash do fluxo do anexo decodificado **conforme reproduzido no lote de evidências**; pode não corresponder byte a byte ao arquivo original se o lote foi normalizado (ver `4-url_attachment_autopsy.md`, Indicador 8) | LOW | Apenas pista de investigação/monitoramento — não tratar uma não-correspondência como "seguro" |
| 22 | Nota de ferramenta/infraestrutura | `Producer: wkhtmltopdf 0.12.6` (metadado do PDF) | Anexo do E5 | Mostra que a fatura foi gerada por máquina a partir de HTML no momento do envio, um segundo antes do `Date` da mensagem | LOW | Apenas contexto — uma ferramenta de código aberto comum, não exclusiva deste atacante |
| 23 | Domínio | `meddefense-benefits[.]org` | E7 | Parecido com o próprio domínio da MedDefense; hospeda a página de coleta de credenciais de inscrição | HIGH | Bloquear |
| 24 | IP | `164[.]90[.]218[.]73` | E7 | Servidor de e-mail externo (`mail.meddefense-benefits.org`) que entregou o E7; SPF fail | HIGH | Bloquear |
| 25 | URL | `hxxps://meddefense-benefits[.]org/enroll` | E7 | Link de coleta de credenciais e informações pessoais | HIGH | Bloquear |
| 26 | Endereço de e-mail | `hr-notifications@meddefense-benefits[.]org` | E7 | Endereço From | HIGH | Bloquear / alertar sobre o remetente |
| 27 | Endereço de e-mail | `no-reply@meddefense-benefits[.]org` | E7 | Endereço Reply-To | HIGH | Bloquear / alertar sobre o remetente |
| 28 | Ferramenta | `X-Mailer: PHPMailer 6.6.0` | E2, E3, E5, E7 | Impressão digital de mailer idêntica nos quatro; também aparece em cada cláusula `Received:` | LOW | Apenas contexto — não alertar apenas com esta string (ver Qualidade de IOC) |
| 29 | Nota de infraestrutura | Padrão de Message-ID `PHP-<8 hex>@<domínio-remetente>` | E2, E3, E5, E7 | Convenção de nomenclatura compartilhada, repete o id de fila do `Received:`, sem timestamp | LOW | Apenas contexto — auxílio de correlação, não um valor bloqueável |
| 30 | Nota de infraestrutura | `X-Priority: 1 (Highest)` nos quatro; o E2 também adiciona `X-MSMail-Priority: High` e `Importance: High` | E2, E3, E5, E7 | Hábito compartilhado de cabeçalho de urgência | LOW | Apenas contexto — comum também em e-mails urgentes legítimos |
| 31 | Nota de infraestrutura (padrão HC3) | Domínios `.com`/`.net`/`.org` recém-registrados contendo "portal", "benefits", "supplies" ou "login" | E8 (alerta HC3) | Combina exatamente com #1, #13, #23; útil como heurística de monitoramento de registro de domínio | LOW | Apenas contexto — alimentar uma regra de pontuação, não bloquear apenas por correspondência de palavra-chave |
| 32 | Nota de infraestrutura (padrão HC3) | Envio via PHPMailer em hospedagem VPS de baixo custo (nível de preço Hostinger/DigitalOcean) | E8 (alerta HC3) | Consistente com os IPs de envio acima, mas o provedor de hospedagem específico não foi confirmado por WHOIS ao vivo neste exercício apenas de evidência | LOW | Apenas contexto — nunca bloquear uma faixa inteira de um provedor de hospedagem apenas por isso |
| 33 | Nota de infraestrutura (padrão HC3) | Prazos de urgência de 24–48 horas, ameaças de bloqueio, prazos finais de inscrição, iscas direcionadas por cargo | E8 (alerta HC3) | Combina com os pretextos em E2, E5 e E7 (ver `9-campaign_thread.md`) | LOW | Apenas contexto — um padrão de engenharia social para conteúdo de conscientização de usuários, não um IOC técnico |

## 2. Checagem de Cobertura

As fontes mínimas exigidas estão todas representadas: E2 (#1–6), E3 (#7–12), E5 (#13–18), o anexo do E5 (#19–22), E7 (#23–27), e os padrões do alerta do HC3 a partir do E8 (#31–33).

## 3. Categorização por Fase do Ataque

**Entrega (Delivery)** — a infraestrutura de envio e as identidades de remetente que levaram cada mensagem à caixa de correio: #2, #5, #6 (E2); #8, #11, #12 (E3); #14, #17, #18 (E5); #24, #26, #27 (E7).

**Coleta de credenciais (Credential harvesting)** — as páginas de destino para as quais as iscas tentam levar um clique: #3, #9, #15, #16, #20, #25.

**Artefato de anexo ou isca (Attachment or lure artifact)** — indicadores ligados especificamente ao PDF do E5: #19, #21, #22 (mais o #20, também listado em coleta de credenciais por ser a URL embutida dentro do arquivo).

**Infraestrutura (Infrastructure)** — os domínios registrados em si, como infraestrutura durável de campanha separada de qualquer caminho de URL específico: #1, #7, #13, #23; mais as imagens de rastreamento/logo #4, #10, que carregam da mesma infraestrutura quando a mensagem é renderizada.

**Indicadores apenas de contexto (Context-only)** — sinais úteis para correlação, pontuação ou conteúdo de conscientização, mas não seguros para agir isoladamente: #28, #29, #30, #31, #32, #33.

## 4. Qualidade dos IOC

**Alta confiança, seguro para bloquear:** os quatro domínios (#1, #7, #13, #23), os quatro IPs de envio (#2, #8, #14, #24), as URLs primárias de coleta de credenciais por domínio-mais-caminho (#3, #9, #15, #16, #25, #20), e os oito endereços de remetente From/Reply-To (#5, #6, #11, #12, #17, #18, #26, #27). Cada um é exclusivo de uma mensagem maliciosa confirmada neste lote, e nenhum tráfego legítimo da MedDefense tem motivo para alcançar um domínio parecido, então o risco de dano colateral ao bloqueá-los é efetivamente zero.

**Apenas monitorar, não um bloqueio isolado:**
- O parâmetro `token` da URL do E2 (#3) e o id da fatura do E5 na query string (#15) são específicos deste lote e serão diferentes para outras vítimas ou envios futuros; bloqueie o domínio e o caminho, mas não espere que a query string literal reapareça.
- As imagens de rastreamento/logo (#4, #10) são colateral de simplesmente renderizar o e-mail de phishing e não acrescentam nada além do que bloquear o domínio já cobre.
- O nome do arquivo PDF (#19) é trivialmente renomeado pelo atacante e não prova nada por si só.
- O hash SHA-256 (#21) foi calculado a partir da reprodução do anexo no lote, que pode não ser idêntica byte a byte ao arquivo original real (ver `4-url_attachment_autopsy.md`). Use-o como pista de caça, não como prova de que um arquivo não correspondente é seguro.

**Não deve ser usado isoladamente — risco de falso positivo:**
- `X-Mailer: PHPMailer 6.6.0` (#28) e o padrão de Message-ID `PHP-<8 hex>` (#29) são padrões de uma biblioteca de código aberto amplamente usada e inteiramente legítima. Inúmeros sites benignos e pequenas empresas enviam e-mail assim; alertar apenas com essa string geraria alto volume de falsos positivos. É útil apenas combinado com outros sinais (um domínio parecido ou recém-registrado, um resultado de DMARC com falha).
- `X-Priority: 1` (#30) é comum em e-mails urgentes legítimos (avisos de interrupção de TI, prazos de RH) e não é um indicador de ameaça por si só.
- O padrão de palavra-chave de domínio do HC3 (#31) — "portal", "benefits", "supplies", "login" — combina com muitos domínios legítimos também; pertence a uma regra de monitoramento de registro de domínio ou de pontuação, não a uma lista de bloqueio direta.
- A nota de "hospedagem VPS de baixo custo" (#32) descreve um nível de hospedagem usado por uma quantidade enorme de sites pequenos legítimos; bloquear faixas inteiras de IP de um provedor com base nisso causaria bloqueio colateral amplo.
- O padrão de urgência/direcionamento por cargo (#33) descreve estilo de engenharia social, não um artefato técnico — serve para informar treinamento de conscientização de usuários e design de regras de detecção (ver `13-phishing_investigation_report.md`), não para alimentar uma lista de bloqueio.

## 5. Resumo Pronto para o HC3

Para envio junto com o relatório da MedDefense ao alerta regional de phishing do HC3 (referenciando o E8, referência de aviso `HC3-2026-PRELIM-001`):

**Domínios:** `meddefense-portal[.]com`, `outlook-protection[.]com`, `medequip-supplies[.]net`, `meddefense-benefits[.]org`

**IPs:** `91[.]234[.]99[.]107`, `51[.]38[.]42[.]17`, `185[.]176[.]43[.]22`, `164[.]90[.]218[.]73`

**Endereços de remetente:** `noreply@meddefense-portal[.]com`, `security@outlook-protection[.]com`, `invoices@medequip-supplies[.]net`, `hr-notifications@meddefense-benefits[.]org`

**URLs:** `hxxps://meddefense-portal[.]com/verify/staff`, `hxxps://outlook-protection[.]com/verify`, `hxxps://medequip-supplies[.]net/invoices/pay`, `hxxps://medequip-supplies[.]net/portal/login`, `hxxps://meddefense-benefits[.]org/enroll`

**Referência de arquivo:** `INV-2026-04891[.]pdf`, URL de pagamento embutida conforme acima, SHA-256 `49558e1500b82d6758379f44ce6104442ec3a5cc08912737db5584640f4b9cad` (rotulado como não verificado — calculado a partir de uma reprodução em lote do anexo, não do arquivo original)

**Narrativa para o HC3:** a MedDefense Health Systems observou quatro e-mails de phishing entre 2026-04-14 e 2026-04-16 que combinam com o padrão descrito em HC3-2026-PRELIM-001: domínios parecidos recém-estilizados usando palavras-chave "portal", "benefits" e "supplies", envio via PHPMailer consistente com infraestrutura VPS de baixo custo, prazos de urgência de 24 horas a um dia com ameaças de bloqueio de conta ou perda de cobertura, e iscas direcionadas por cargo visando equipe clínica, financeira e ligada a RH. Uma destinatária (equipe clínica, baseada em workstation) clicou no link de coleta de credenciais na mais urgente das quatro mensagens; o comprometimento de credenciais ainda não está confirmado e está sob investigação ativa (ver `7-click_investigation.md`). Nenhuma infraestrutura de envio compartilhada foi encontrada entre as três mensagens específicas da MedDefense, sugerindo infraestrutura VPS rotativa ou múltiplos operadores usando o mesmo kit.
