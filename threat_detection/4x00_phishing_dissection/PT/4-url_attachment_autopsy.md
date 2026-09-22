# Autópsia de URL e Anexo

Investigação segura das URLs, endereços IP e indicadores de anexo encontrados nos quatro e-mails suspeitos (E2, E3, E5, E7), mais o indicador de spam `203.0.113.228` do E6. Todos os valores foram retirados do lote de evidências de e-mail bruto. Nenhum link foi visitado, nenhum anexo foi aberto ou renderizado, e nenhuma consulta ao vivo de DNS, WHOIS ou reputação foi executada para este relatório. Os comandos listados em cada indicador são os métodos que um analista usaria; eles não foram executados aqui, e as conclusões se apoiam no arquivo de evidências.

## Regras de manuseio

Nenhum comando deste arquivo foi executado contra a internet ao produzir este relatório. Nenhum domínio ou IP suspeito foi contatado, navegado, pingado, resolvido ou varrido; todo achado abaixo vem apenas do lote de evidências bruto. Os comandos são documentados para um analista autorizado executar depois, a partir de um ambiente controlado, e não como etapas realizadas aqui.

- Os valores são desmascarados (defanged): `http` vira `hxxp` e cada `.` vira `[.]`. Os valores originais ficam em formatação de código para permanecerem não clicáveis e exatamente como aparecem na evidência.
- Trate cada método abaixo como algo a ser executado a partir de um host de análise isolado ou de um sandbox de fornecedor, nunca de um workstation com sessão de navegador, cliente de e-mail ou credenciais corporativas, e nunca a partir da rede corporativa.
- Prefira fontes passivas e somente leitura: WHOIS, respostas de DNS de um resolvedor público, logs de transparência de certificados (crt.sh), e resultados já existentes do VirusTotal ou urlscan.io para o domínio ou IP. Essas consultas atingem um registro ou banco de dados de terceiros, não o próprio servidor do atacante.
- Não envie nenhuma requisição HTTP(S) diretamente aos domínios ou IPs suspeitos a partir da infraestrutura do analista, incluindo uma requisição apenas HEAD como `curl -I`. Mesmo uma requisição HEAD entrega uma conexão real, e possivelmente um pixel de rastreamento, redirecionamento ou exploit, à infraestrutura controlada pelo atacante, e revela o IP do analista. Se uma renderização ao vivo da página for genuinamente necessária, envie o domínio puro a um scanner em sandbox (urlscan.io) e leia o resultado lá; não se conecte ao site diretamente.
- Não solicite nem envie a URL do E2 com o valor de `token`. O token é por destinatário e permite ao remetente ver quem clicou. Para qualquer consulta externa, use o domínio puro ou a URL sem a query string.
- Configure as varreduras do urlscan.io como `unlisted` ou `private` para que o envio não divulgue a investigação.
- Não abra o anexo do E5 em um desktop. O PDF foi inspecionado apenas como texto base64 dentro da evidência (ver Indicador 8).

## Escala de classificação de risco

| Classificação | Significado |
|---|---|
| CRITICAL | Malicioso conforme a evidência e ligado a uma interação confirmada do usuário. |
| HIGH | Malicioso conforme a evidência (URL, anexo ou servidor de e-mail de phishing), sem interação relatada. |
| MEDIUM | Infraestrutura de apoio ou um indicador cujo papel não é claro. |
| LOW | Spam ou conteúdo informativo, não infraestrutura do atacante. |

## Resumo dos indicadores

| # | Email | Tipo | Valor desmascarado | Risco |
|---|---|---|---|---|
| 1 | E2 | URL | `hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1` | CRITICAL |
| 2 | E2 | Endereço IP | `91[.]234[.]99[.]107` | HIGH |
| 3 | E3 | URL | `hxxps://outlook-protection[.]com/verify` | HIGH |
| 4 | E3 | Endereço IP | `51[.]38[.]42[.]17` | HIGH |
| 5 | E3 | Endereço IP (conteúdo da isca) | `41[.]203[.]72[.]188` | LOW |
| 6 | E5 | URL | `hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891` | HIGH |
| 7 | E5 | URL | `hxxps://medequip-supplies[.]net/portal/login` | HIGH |
| 8 | E5 | Anexo | `INV-2026-04891[.]pdf` | HIGH |
| 9 | E5 | Endereço IP | `185[.]176[.]43[.]22` | HIGH |
| 10 | E7 | URL | `hxxps://meddefense-benefits[.]org/enroll` | HIGH |
| 11 | E7 | Endereço IP | `164[.]90[.]218[.]73` | HIGH |
| 12 | E6 | Endereço IP e URL | `hxxp://203[.]0[.]113[.]228/shop?ref=pwhite` | LOW |

---

## Indicador 1

- E-mail de origem: E2, "ACTION REQUIRED: Portal re-verification needed within 24 hours", entregue a `dmarsh@meddefense.com`
- Valor original: `https://meddefense-portal.com/verify/staff?id=dmarsh&amp;token=a8f3e2d1` (como escrito no `href` do HTML; `&amp;` decodifica para `&`)
- Valor desmascarado: `hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1`
- Domínio ou IP: `meddefense-portal.com`
- Tipo de indicador: URL, avaliada como página de coleta de credenciais
- Evidência do e-mail:
  - O link é o botão "VERIFY MY ACCESS NOW". O mesmo domínio é usado no endereço do remetente, no `Return-Path` e no logo (`hxxps://meddefense-portal[.]com/assets/logo[.]png`).
  - `meddefense-portal.com` é um domínio parecido (lookalike) com `meddefense.com`. O aviso interno genuíno (E4) diz que o portal é apenas interno ou via VPN e que a TI nunca envia links de senha por e-mail.
  - O caminho é `/verify/staff` e a query string carrega `id=dmarsh` e um `token`, então o link é único para Diane Marsh.
  - O e-mail foi enviado com SPF `fail`, sem DKIM e DMARC `fail` a partir de `91.234.99.107`.
  - O clique de Diane Marsh neste link está registrado em 2026-04-14 15:02:33 CDT (ver `7-click_investigation.md`).
  - O logo é uma imagem remota no mesmo domínio. Se o cliente de e-mail a carregou, a requisição chegou ao servidor do atacante no momento da renderização da mensagem.
- Método de investigação seguro:
  ```
  whois meddefense-portal.com                        # registrador, data de criação, titular
  dig +short A meddefense-portal.com                 # IP do host web (pode diferir do host de e-mail)
  dig +short NS meddefense-portal.com
  dig +short TXT meddefense-portal.com               # registro SPF
  dig +short TXT _dmarc.meddefense-portal.com
  curl -s "https://crt.sh/?q=meddefense-portal.com&output=json"     # datas de primeiro avistamento do certificado
  curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/domains/meddefense-portal.com"
  curl -s "https://urlscan.io/api/v1/search/?q=domain:meddefense-portal.com"   # apenas varreduras existentes
  # Não faça curl nem navegue diretamente para esta URL, e nunca com o token.
  # Para uma renderização ao vivo, envie o domínio puro como uma nova varredura
  # unlisted no urlscan.io.
  ```
  Também pesquise logs de proxy, DNS e firewall por `meddefense-portal.com` e por requisições a `/assets/logo.png`, para encontrar todo host que carregou a mensagem ou a página.
- Achado: a URL é um link personalizado de coleta de credenciais em um domínio parecido, entregue por um remetente que falha em toda verificação de autenticação. O domínio é avaliado como infraestrutura controlada pelo atacante. O que a página exibe, e se credenciais foram inseridas, não está na evidência.
- Classificação de risco: CRITICAL

## Indicador 2

- E-mail de origem: E2
- Valor original: `91.234.99.107` (salto externo `Received:`, `mail.meddefense-portal.com`)
- Valor desmascarado: `91[.]234[.]99[.]107`
- Domínio ou IP: `91.234.99.107`
- Tipo de indicador: Endereço IP, servidor de e-mail de envio
- Evidência do e-mail:
  - Registrado pelo `mx01.meddefense.com` em 2026-04-14 14:47:51 -0500 via ESMTP simples, sem TLS.
  - SPF `fail`: o IP não está autorizado para `meddefense-portal.com`.
  - O remetente identifica o host como `mail.meddefense-portal.com`, rodando PHPMailer 6.6.0.
  - O IP não é compartilhado com nenhum outro e-mail no lote.
- Método de investigação seguro:
  ```
  whois 91.234.99.107                                # dono da rede, contato de abuso, data de alocação
  dig -x 91.234.99.107 +short                        # DNS reverso, comparar com mail.meddefense-portal.com
  curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/ip_addresses/91.234.99.107"
  curl -s "https://urlscan.io/api/v1/search/?q=ip:91.234.99.107"
  ```
  Pesquise logs do gateway de e-mail por outras mensagens deste IP, e logs de firewall ou proxy por qualquer conexão a ele.
- Achado: o servidor de e-mail que entregou o e-mail de phishing com clique confirmado. Se o host web de `meddefense-portal.com` é a mesma máquina é desconhecido até que o DNS seja checado, então este IP não deve ser presumido como o destino do clique.
- Classificação de risco: HIGH

## Indicador 3

- E-mail de origem: E3, "Unusual sign-in activity detected on your Microsoft 365 account", entregue a `rmendez@meddefense.com`
- Valor original: `https://outlook-protection.com/verify`
- Valor desmascarado: `hxxps://outlook-protection[.]com/verify`
- Domínio ou IP: `outlook-protection.com`
- Tipo de indicador: URL, avaliada como página de coleta de credenciais (personificação da Microsoft)
- Evidência do e-mail:
  - O botão "Verify account" aponta para esta URL. O logo é carregado de `hxxps://outlook-protection[.]com/img/ms_logo[.]png`.
  - `outlook-protection.com` não é `microsoft.com` nem `outlook.com`, embora o e-mail se apresente como Microsoft.
  - SPF, DKIM e DMARC todos passam, mas apenas para `outlook-protection.com` (ver `2-authentication_analysis.md`).
  - A URL não tem token por usuário, então o mesmo link serviria a todo destinatário.
  - Nenhum clique neste link foi relatado.
- Método de investigação seguro:
  ```
  whois outlook-protection.com                       # data de criação: o HC3 descreve lookalikes com menos de 30 dias
  dig +short A outlook-protection.com
  dig +short MX outlook-protection.com
  dig +short TXT outlook-protection.com
  dig +short TXT _dmarc.outlook-protection.com
  dig +short TXT default._domainkey.outlook-protection.com   # seletor DKIM da mensagem
  curl -s "https://crt.sh/?q=outlook-protection.com&output=json"
  curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/domains/outlook-protection.com"
  curl -s "https://urlscan.io/api/v1/search/?q=domain:outlook-protection.com"
  # Não faça curl nem navegue diretamente para esta URL. Para uma renderização
  # ao vivo, envie o domínio puro como uma nova varredura unlisted no urlscan.io.
  ```
  Pesquise logs de proxy e DNS pelo domínio para checar se alguém já o visitou.
- Achado: uma isca de login com personificação de marca em um domínio que autentica de forma limpa, mas que não é da Microsoft. A consulta deve confirmar a idade de registro e o titular. Até lá, a classificação da evidência permanece.
- Classificação de risco: HIGH

## Indicador 4

- E-mail de origem: E3
- Valor original: `51.38.42.17` (salto externo `Received:`, `mail.outlook-protection.com`)
- Valor desmascarado: `51[.]38[.]42[.]17`
- Domínio ou IP: `51.38.42.17`
- Tipo de indicador: Endereço IP, servidor de e-mail de envio
- Evidência do e-mail:
  - Registrado pelo `mx01` em 2026-04-15 09:13:43 -0500 via ESMTPS (TLS 1.2).
  - SPF `pass`: o IP está listado para `outlook-protection.com`, o que mostra que o dono do domínio e o operador do IP estão conectados. Não torna o remetente a Microsoft.
  - O e-mail foi gerado por um processo PHPMailer em um host chamado `wp-admin.outlook-protection.com`.
  - O IP não é compartilhado com nenhum outro e-mail no lote.
- Método de investigação seguro:
  ```
  whois 51.38.42.17
  dig -x 51.38.42.17 +short
  curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/ip_addresses/51.38.42.17"
  curl -s "https://urlscan.io/api/v1/search/?q=ip:51.38.42.17"
  ```
- Achado: infraestrutura de envio da isca de personificação da Microsoft. Se outros domínios estão hospedados neste IP (um sinal comum de hospedagem compartilhada de atacante) precisa de checagens de DNS passivo ou urlscan.io.
- Classificação de risco: HIGH

## Indicador 5

- E-mail de origem: E3
- Valor original: `41.203.72.188` (linha da tabela no corpo, "IP address", rotulado "Lagos, Nigeria (approximate)")
- Valor desmascarado: `41[.]203[.]72[.]188`
- Domínio ou IP: `41.203.72.188`
- Tipo de indicador: Endereço IP, conteúdo da isca
- Evidência do e-mail:
  - Aparece apenas no corpo, como a suposta origem de um login não reconhecido, junto com um "dispositivo Windows desconhecido" e um horário de 10h47 UTC em 15 de abril de 2026.
  - Não aparece em nenhum cabeçalho `Received:`, então não faz parte do caminho de envio.
  - Nada na evidência confirma que algum login a partir deste IP realmente ocorreu.
- Método de investigação seguro:
  ```
  whois 41.203.72.188
  curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/ip_addresses/41.203.72.188"
  ```
  Como verificação de acompanhamento, pesquise logs de login de identidade por este IP para `rmendez@meddefense.com` em 2026-04-15. Um resultado positivo sugeriria uma tentativa real e mudaria a avaliação; nenhum resultado é o esperado para um alerta fabricado.
- Achado: um detalhe não verificável escolhido para criar medo, não infraestrutura do atacante. Não deve ser usado como entrada de lista de bloqueio apenas com base neste e-mail.
- Classificação de risco: LOW

## Indicador 6

- E-mail de origem: E5, "Invoice INV-2026-04891 - Payment required within 7 days", entregue a `arivera@meddefense.com`
- Valor original: `https://medequip-supplies.net/invoices/pay?id=INV-2026-04891`
- Valor desmascarado: `hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891`
- Domínio ou IP: `medequip-supplies.net`
- Tipo de indicador: URL, portal de pagamento de fatura (fraude de pagamento e coleta de credenciais)
- Evidência do e-mail:
  - Aparece duas vezes no corpo HTML (como destino do link e como texto visível) e uma terceira vez dentro do anexo PDF (Indicador 8).
  - A fatura é de USD 24.716,38, vencendo em 2026-04-23, com multa de 2% por atraso.
  - Autenticação do remetente: SPF `softfail`, DKIM `none`, DMARC `fail`.
  - O destinatário de Contas a Pagar diz que a fatura parece errada e o fornecedor não é verificado.
  - O e-mail oferece receber o pagamento "diretamente através do nosso portal de faturas", sem nenhum dado de remessa.
- Método de investigação seguro:
  ```
  whois medequip-supplies.net
  dig +short A medequip-supplies.net
  dig +short MX medequip-supplies.net
  dig +short TXT medequip-supplies.net               # registro SPF; espera-se um final de soft-fail
  dig +short TXT _dmarc.medequip-supplies.net
  curl -s "https://crt.sh/?q=medequip-supplies.net&output=json"
  curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/domains/medequip-supplies.net"
  curl -s "https://urlscan.io/api/v1/search/?q=domain:medequip-supplies.net"
  # Não faça curl nem navegue diretamente para este domínio, e nunca com o id
  # da fatura na requisição. Para uma renderização ao vivo, envie o domínio
  # puro como uma nova varredura unlisted no urlscan.io.
  ```
  Verifique o fornecedor separadamente no cadastro de fornecedores e por telefone usando um número que a MedDefense já possui, não o número no e-mail.
- Achado: a URL é a etapa de pagamento de uma fatura não verificada de um remetente que falha na autenticação. Combina com fraude de fatura e possível captura de dados de pagamento ou credenciais.
- Classificação de risco: HIGH

## Indicador 7

- E-mail de origem: E5
- Valor original: `https://medequip-supplies.net/portal/login`
- Valor desmascarado: `hxxps://medequip-supplies[.]net/portal/login`
- Domínio ou IP: `medequip-supplies.net`
- Tipo de indicador: URL, página de login (coleta de credenciais)
- Evidência do e-mail:
  - Oferecida como fallback: "If the attached invoice is not viewable, please log in to retrieve a copy". Uma página de login para uma fatura que um cliente nunca pediu é uma etapa padrão de captura de credenciais.
  - Mesmo domínio e remetente do Indicador 6.
- Método de investigação seguro: as mesmas consultas de domínio do Indicador 6, mais uma pesquisa no urlscan.io restrita a este caminho (`page.url:"medequip-supplies.net/portal/login"`) por resultados existentes.
  ```
  curl -s "https://urlscan.io/api/v1/search/?q=page.domain:medequip-supplies.net"
  ```
- Achado: uma segunda rota para o mesmo domínio que leva a um prompt de credenciais. Mesmo que a fatura fosse ignorada, um leitor que não conseguisse abrir o PDF é enviado para cá.
- Classificação de risco: HIGH

## Indicador 8

- E-mail de origem: E5, parte MIME `Content-Type: application/pdf; name="INV-2026-04891.pdf"`, `Content-Disposition: attachment; filename="INV-2026-04891.pdf"`, base64
- Valor original: `INV-2026-04891.pdf`
- Valor desmascarado: `INV-2026-04891[.]pdf` (link embutido `hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891`)
- Domínio ou IP: `medequip-supplies.net` (o link dentro do arquivo)
- Tipo de indicador: Anexo (PDF) com uma URL embutida
- Evidência do e-mail: o corpo base64 foi decodificado como um fluxo de bytes simples e lido apenas como texto. Não foi salvo como `.pdf`, aberto em um visualizador nem interpretado por uma biblioteca de PDF. O que mostra:
  - Cabeçalho `%PDF-1.4` com `Producer (wkhtmltopdf 0.12.6)`. Esta é uma ferramenta que converte páginas HTML em PDF, típica de uma aplicação web gerando documentos.
  - `CreationDate` e `ModDate` são ambos `D:20260416162834+00'00'`, ou seja, 2026-04-16 16:28:34 UTC. O `Date` do e-mail é 16:28:35 +0000, um segundo depois. O anexo foi gerado no momento do envio da mensagem, enquanto o corpo afirma entrega em 9 de abril.
  - Uma anotação de link (objeto 10, retângulo `[175 185 450 205]`) com uma ação `/URI` apontando para `hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891`, a mesma URL de pagamento do corpo.
  - Nenhuma palavra-chave `/JavaScript`, `/OpenAction`, `/Launch` ou de arquivo embutido aparece no texto decodificado. O arquivo é curto (622 bytes conforme reproduzido) e incompleto: os objetos 7 (fonte) e 9 (conteúdo da página) são referenciados mas ausentes, e não há tabela de referência cruzada nem trailer. A ausência de uma palavra-chave em uma reprodução incompleta não mostra que o original é inofensivo.
  - Após o último objeto há uma string de texto extra começando com `xxxSHA-256:` seguida de 62 caracteres hexadecimais em um padrão ascendente regular. Um SHA-256 tem 64 caracteres e um arquivo não pode conter seu próprio hash, então isso é texto não verificado e não é um indicador utilizável.
  - SHA-256 do fluxo decodificado conforme reproduzido no lote: `49558e1500b82d6758379f44ce6104442ec3a5cc08912737db5584640f4b9cad`. Pode diferir do arquivo original se o lote foi normalizado.
- Método de investigação seguro:
  ```
  # Extrair sem abrir, apenas em uma VM de análise isolada
  ripmime -i E5.eml -d ./out
  sha256sum ./out/INV-2026-04891.pdf
  file ./out/INV-2026-04891.pdf
  exiftool ./out/INV-2026-04891.pdf                  # Producer, CreationDate
  pdfid.py ./out/INV-2026-04891.pdf                  # contagens de /JS /JavaScript /OpenAction /Launch /URI
  pdf-parser.py --search URI ./out/INV-2026-04891.pdf
  strings -a ./out/INV-2026-04891.pdf | grep -i -E 'http|uri|javascript'
  # Reputação por hash, sem necessidade de enviar o arquivo
  curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/files/<sha256>"
  ```
  Nunca dê duplo clique nem visualize o arquivo. Pesquise o gateway de e-mail e os endpoints por este nome de arquivo e hash.
- Achado: um PDF de fatura gerado sob demanda cuja única função visível é carregar o link de pagamento, com uma string de hash embutida não verificada. Reforça o pretexto da fatura e dá um terceiro caminho de clique para o mesmo domínio. Também importa para filtragem: URLs dentro de anexos são inspecionadas com menos frequência do que URLs no corpo da mensagem.
- Classificação de risco: HIGH

## Indicador 9

- E-mail de origem: E5
- Valor original: `185.176.43.22` (salto externo `Received:`, `mail.medequip-supplies.net`)
- Valor desmascarado: `185[.]176[.]43[.]22`
- Domínio ou IP: `185.176.43.22`
- Tipo de indicador: Endereço IP, servidor de e-mail de envio
- Evidência do e-mail:
  - Registrado pelo `mx01` em 2026-04-16 11:28:37 -0500 via ESMTP simples, sem TLS.
  - SPF `softfail` para `medequip-supplies.net`.
  - O e-mail foi gerado por um processo PHPMailer em um host chamado `billing-svc.medequip-supplies.net`.
  - O IP não é compartilhado com nenhum outro e-mail no lote.
- Método de investigação seguro:
  ```
  whois 185.176.43.22
  dig -x 185.176.43.22 +short
  curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/ip_addresses/185.176.43.22"
  curl -s "https://urlscan.io/api/v1/search/?q=ip:185.176.43.22"
  ```
- Achado: infraestrutura de envio da isca de fatura. Sua relação com o host web de `medequip-supplies.net` é desconhecida até que o DNS seja checado.
- Classificação de risco: HIGH

## Indicador 10

- E-mail de origem: E7, "Open Enrollment closes TOMORROW - action required", entregue a `lpatterson@meddefense.com`
- Valor original: `https://meddefense-benefits.org/enroll`
- Valor desmascarado: `hxxps://meddefense-benefits[.]org/enroll`
- Domínio ou IP: `meddefense-benefits.org`
- Tipo de indicador: URL, avaliada como página de coleta de credenciais e informações pessoais
- Evidência do e-mail:
  - O botão "COMPLETE ENROLLMENT" aponta para cá. O domínio visível do remetente é o mesmo.
  - `meddefense-benefits.org` é um domínio parecido (lookalike) com `meddefense.com`: palavra-chave de benefícios, `.org` no lugar de `.com`.
  - SPF `fail`, DKIM `none`, DMARC `fail`.
  - A destinatária, do Billing, diz que nunca se inscreveu para nada, e o e-mail diz a quem já se inscreveu para "ainda assim verificar no portal".
  - Nenhum clique neste link foi relatado.
- Método de investigação seguro:
  ```
  whois meddefense-benefits.org
  dig +short A meddefense-benefits.org
  dig +short MX meddefense-benefits.org
  dig +short TXT meddefense-benefits.org
  dig +short TXT _dmarc.meddefense-benefits.org
  curl -s "https://crt.sh/?q=meddefense-benefits.org&output=json"
  curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/domains/meddefense-benefits.org"
  curl -s "https://urlscan.io/api/v1/search/?q=domain:meddefense-benefits.org"
  # Não faça curl nem navegue diretamente para esta URL. Para uma renderização
  # ao vivo, envie o domínio puro como uma nova varredura unlisted no urlscan.io.
  ```
  Confirme com a equipe real de RH se uma janela de inscrição estava aberta e qual URL ela usa.
- Achado: um domínio parecido com a própria marca da empresa usado para uma isca de RH. A URL é a etapa de inscrição de uma mensagem que falha em toda a autenticação.
- Classificação de risco: HIGH

## Indicador 11

- E-mail de origem: E7
- Valor original: `164.90.218.73` (salto externo `Received:`, `mail.meddefense-benefits.org`)
- Valor desmascarado: `164[.]90[.]218[.]73`
- Domínio ou IP: `164.90.218.73`
- Tipo de indicador: Endereço IP, servidor de e-mail de envio
- Evidência do e-mail:
  - Registrado pelo `mx01` em 2026-04-16 15:22:05 -0500 via ESMTP simples, sem TLS.
  - SPF `fail`: não autorizado para `meddefense-benefits.org`.
  - O e-mail foi gerado por um processo PHPMailer em um host chamado `wp-portal.meddefense-benefits.org`.
  - O IP não é compartilhado com nenhum outro e-mail no lote.
- Método de investigação seguro:
  ```
  whois 164.90.218.73
  dig -x 164.90.218.73 +short
  curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/ip_addresses/164.90.218.73"
  curl -s "https://urlscan.io/api/v1/search/?q=ip:164.90.218.73"
  ```
- Achado: infraestrutura de envio da isca de RH. O alerta do HC3 (E8) descreve envio via PHPMailer a partir de hospedagem VPS de baixo custo; uma consulta WHOIS mostraria se este e os outros IPs de envio são faixas de provedores de hospedagem.
- Classificação de risco: HIGH

## Indicador 12

- E-mail de origem: E6, "90% OFF Viagra, Cialis, Xanax - No prescription needed!!!", entregue a `pwhite@meddefense.com`
- Valor original: `http://203.0.113.228/shop?ref=pwhite` (link no corpo) e `203.0.113.228` (salto externo `Received:`, `bulk-mail-07.canadian-pharma-discount.org`)
- Valor desmascarado: `hxxp://203[.]0[.]113[.]228/shop?ref=pwhite` e `203[.]0[.]113[.]228`
- Domínio ou IP: `203.0.113.228` (domínio remetente `canadian-pharma-discount.org`)
- Tipo de indicador: Endereço IP e URL, página de spam de farmácia
- Evidência do e-mail:
  - O link usa um IP puro em vez de um domínio. Os testes de spam `NORMAL_HTTP_TO_IP` e `NUMERIC_HTTP_ADDR` dispararam, com um `X-Spam-Score` geral de 9.8 contra um limite de 5.0.
  - O IP do link é o mesmo do host de envio: o remetente envia e-mail e serve a loja a partir de um único endereço, a única reutilização de IP neste lote.
  - O parâmetro `ref=pwhite` marca o destinatário, então um clique confirma um endereço ativo.
  - SPF `softfail`, DKIM `none`, DMARC `fail` com `action=quarantine`. O mailer é `XPedia Bulk Mailer 4.2`.
  - Sem personificação da MedDefense, sem pedido de credenciais, sem anexo.
  - A faixa `203.0.113.0/24` é reservada para documentação (RFC 5737, TEST-NET-3). Um WHOIS ou DNS reverso ao vivo não retornaria um operador real, e em uma rede de produção este endereço não seria roteável. O mesmo se aplica ao `198.51.100.42` da newsletter legítima (E1, TEST-NET-2), então partes do lote parecem sanitizadas.
- Método de investigação seguro:
  ```
  whois 203.0.113.228                                # espera-se resposta de faixa de documentação da IANA
  dig -x 203.0.113.228 +short
  whois canadian-pharma-discount.org
  dig +short A bulk-mail-07.canadian-pharma-discount.org
  dig +short TXT _dmarc.canadian-pharma-discount.org
  curl -s "https://urlscan.io/api/v1/search/?q=domain:canadian-pharma-discount.org"
  ```
  Não busque a URL. Se as consultas ao vivo não retornarem nada útil, registre isso e apoie-se na evidência acima.
- Achado: spam em massa comum, baixo risco para a organização além do incômodo. Nada na evidência liga este IP ou domínio a E2, E3, E5 ou E7. Está listado para que a lista de bloqueio o cubra, e para que não seja confundido com infraestrutura da campanha.
- Classificação de risco: LOW

---

## Achados entre indicadores

- Padrão de domínio parecido (lookalike): três dos quatro domínios da campanha reutilizam a marca da empresa ou a marca Microsoft mais uma palavra-chave de segurança ou negócio: `meddefense-portal.com`, `meddefense-benefits.org`, `outlook-protection.com`. O quarto, `medequip-supplies.net`, imita o nome de um fornecedor.
- Reutilização de IP de envio: nenhum IP é compartilhado entre E2, E3, E5 e E7. A única reutilização no lote é o E6, onde o host de envio e o destino do link são o mesmo endereço. A ausência de IPs compartilhados não descarta um operador comum: os quatro e-mails da campanha compartilham o mesmo conjunto de ferramentas PHPMailer 6.6.0, Message-IDs `PHP-<8 hex>` e `X-Priority: 1` (ver `1-header_analysis.md`).
- Rastreamento de link por destinatário: o E2 carrega `id` e `token` na URL, e o E6 carrega `ref=pwhite`, então os remetentes conseguem identificar quem clicou. E3, E5 e E7 usam URLs genéricas.
- Múltiplas rotas para um domínio: o E5 envia o leitor a `medequip-supplies.net` pelo link do corpo, pelo fallback de login e pelo PDF.
- Ainda não conhecido: datas de registro, provedores de hospedagem, se os hosts web coincidem com os hosts de e-mail, e se algum outro host da MedDefense contatou esses domínios. Esses são resultados das consultas acima e de buscas em logs que não fizeram parte desta tarefa.

## Indicadores para bloqueio e caça (desmascarados)

Domínios:

- `meddefense-portal[.]com`
- `outlook-protection[.]com`
- `medequip-supplies[.]net`
- `meddefense-benefits[.]org`
- `canadian-pharma-discount[.]org`

IPs de envio:

- `91[.]234[.]99[.]107`
- `51[.]38[.]42[.]17`
- `185[.]176[.]43[.]22`
- `164[.]90[.]218[.]73`
- `203[.]0[.]113[.]228` (spam, baixa prioridade)

Nome de arquivo: `INV-2026-04891[.]pdf`

Não bloquear: `41[.]203[.]72[.]188` (apenas conteúdo da isca).

Antes de bloquear IPs em nível de rede, verifique se o endereço é hospedagem compartilhada, para evitar bloquear sites não relacionados.
