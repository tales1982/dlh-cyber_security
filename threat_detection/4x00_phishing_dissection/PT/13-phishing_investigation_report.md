# Relatório de Investigação de Campanha de Phishing

**MedDefense Health Systems — Operações de Segurança**
**Preparado para:** revisão do líder do SOC; adequado para compartilhamento com o HC3
**Base de evidências:** lote de evidências SMTP brutas de 8 e-mails, coletado em 2026-04-17 09:15 CDT por Mike Torres (Engenheiro de Redes)
**Escopo:** apenas análise baseada em evidências — nenhum log ao vivo de Wazuh, Sysmon, Suricata, Windows Security, proxy, DNS ou provedor de identidade foi consultado para este relatório. Toda verificação de acompanhamento citada abaixo é uma recomendação, claramente rotulada como ainda não realizada.

---

## 1. Resumo Executivo

Entre 14 e 16 de abril de 2026, funcionários da MedDefense receberam quatro e-mails de phishing coordenados que personificaram a TI interna, a Microsoft, um fornecedor de suprimentos médicos e os benefícios de RH para roubar credenciais de login ou informações de pagamento. Uma funcionária, da equipe clínica, clicou no mais urgente desses links cerca de 15 minutos após ele chegar; se sua senha foi de fato inserida ou sua conta comprometida ainda não está confirmado e está sob investigação ativa. Três dos quatro e-mails de phishing mostram sinais claros de fazerem parte de uma única campanha deliberadamente direcionada à MedDefense, e combinam de perto com um alerta regional do setor de saúde emitido pelo Health Sector Cybersecurity Coordination Center (HC3) federal durante a mesma janela. Nenhum malware ou comprometimento de sistema foi confirmado; o risco imediato é roubo de credenciais e possível acesso não autorizado a sistemas que tocam dados de pacientes. Este relatório recomenda etapas de contenção imediatas que não dependem de revisão adicional de logs, junto com uma lista curta de lacunas de detecção e processo a fechar nos próximos 30 dias.

## 2. Linha do Tempo da Investigação

| Item | Valor |
|---|---|
| Janela de coleta | 2026-04-14 07:22 CDT → 2026-04-16 15:22 CDT (cerca de 57 horas) |
| Lote coletado | 2026-04-17 09:15 CDT |
| E1 (newsletter legítima) enviado | 2026-04-14 07:22 CDT |
| **E2 (phishing, clicado) enviado** | **2026-04-14 14:47 CDT** |
| **Clique relatado de Diane Marsh no E2** | **2026-04-14 15:02:33 CDT (14 min 41 s após a entrega, conforme NTP do workstation)** |
| E3 (phishing, personificação da Microsoft) enviado | 2026-04-15 09:13 CDT |
| E4 (legítimo, TI interna) enviado | 2026-04-15 10:00 CDT |
| E5 (phishing, fraude de fatura) enviado | 2026-04-16 11:28 CDT |
| E6 (spam) enviado | 2026-04-16 13:04 CDT |
| E7 (phishing, benefícios de RH) enviado | 2026-04-16 15:22 CDT |
| E8 (alerta do setor do HC3) recebido | 2026-04-16 08:47 CDT |

O clique é cerca de 66 horas antes de o lote ser coletado, não as aproximadamente 36 horas mencionadas em relatos iniciais; este relatório usa o timestamp de NTP do workstation como autoritativo, consistente com `0-initial_triage.md`. O escopo da investigação cobre análise de cabeçalho, autenticação, conteúdo, URL/anexo e clique dos 8 e-mails, mais uma passada de vinculação de campanha e extração de IOC; não inclui nenhuma revisão de log de endpoint ou de provedor de identidade, o que é recomendado como acompanhamento (Seções 5 e 7).

## 3. Análise E-mail por E-mail

Detalhe completo e raciocínio em `8-verdict_matrix.md`; resumido aqui.

| Email | Classificação | Confiança | Evidência-Chave |
|---|---|---|---|
| E1 | LEGITIMATE-WITH-ISSUE | HIGH | SPF/DKIM/DMARC alinhados para `healthcare-education-weekly.com`; conteúdo de newsletter benigno; alegação de assinatura não verificada, vale uma checagem rápida. |
| **E2** | **PHISHING-TARGETED** | **HIGH** | Parecido `meddefense-portal.com`; SPF fail/DKIM none/DMARC fail; link personalizado `/verify/staff?id=dmarsh&token=...` citando os fluxos de trabalho reais de Diane Marsh; **clique confirmado**. |
| E3 | PHISHING-OPPORTUNISTIC | MEDIUM | Personifica a Microsoft a partir de `outlook-protection.com`; autentica de forma limpa apenas para o próprio domínio; modelo genérico, não personalizado; nenhum clique relatado. |
| E4 | LEGITIMATE | HIGH | Relay interno do Exchange, autenticação alinhada para `meddefense.com`, lembrete de política em texto simples sem links. |
| E5 | PHISHING-TARGETED | HIGH | Fraude de fatura de `medequip-supplies.net`; SPF softfail/DKIM none/DMARC fail; PDF gerado no momento do envio; destinatária de AP sinaliza a fatura como não reconhecida. |
| E6 | SPAM | HIGH | Spam de farmácia em massa, `X-Spam-Score 9.8`, sem direcionamento à MedDefense. |
| E7 | PHISHING-TARGETED | HIGH | `meddefense-benefits.org` imita a própria marca da MedDefense; SPF fail/DKIM none/DMARC fail; destinatária nega ter se inscrito para qualquer coisa. |
| E8 | LEGITIMATE | HIGH | Autenticação alinhada para `hhs.gov`; alerta genuíno do setor do HC3 descrevendo um padrão que combina com E2, E3, E5 e E7. |

## 4. Análise de Campanha

Detalhe completo em `9-campaign_thread.md`; resumido aqui.

**Por que E2, E5 e E7 estão provavelmente conectados:** os três usam PHPMailer 6.6.0 com uma convenção de Message-ID `PHP-<8 hex>@<domínio>` idêntica e nomenclatura de host de envio `mail.<domínio-parecido>`; os três falham na autenticação do próprio domínio da mesma forma (não assinados, DMARC `action=none`); os três combinam um prazo de urgência com uma consequência nomeada ligada a um processo real da MedDefense (acesso ao portal, uma fatura, inscrição de benefícios); e os três foram enviados dentro de uma janela de aproximadamente 48 horas (14–16 de abril), com entregas concentradas em 16 de abril. Nenhum IP de envio é reutilizado entre eles, então isso é um manual e conjunto de ferramentas compartilhados, não infraestrutura compartilhada no sentido estrito.

**Como o E8 sustenta a hipótese de campanha:** o alerta do HC3 descreve, quase ponto a ponto, os mesmos quatro traços encontrados em E2/E5/E7 — domínios parecidos recém-estilizados usando palavras-chave "portal", "benefits" e "supplies"; envio via PHPMailer em hospedagem estilo VPS de baixo custo; prazos de urgência de 24–48 horas com ameaças de bloqueio ou perda de cobertura; e iscas direcionadas por cargo para equipe clínica, de billing e ligada a RH. O E8 chegou em 16 de abril às 08:47 CDT, entre as entregas do E2 e do par E5/E7, o que significa que os próprios três e-mails da MedDefense são um dado concreto e local para o mesmo padrão regional que o HC3 ainda chamava de "não confirmado por IOC".

**Como o E3 deve ser interpretado:** o E3 compartilha traços de ferramentas com o trio (PHPMailer, o mesmo formato de Message-ID, `X-Priority: 1`), mas foi enviado de um IP diferente, autentica de forma limpa para o próprio domínio, não exige conhecimento específico da MedDefense, e não carrega token por destinatário. É avaliado como uma operação de phishing separada, mais genérica — possivelmente o mesmo operador usando um segundo kit, mais polido, contra uma lista de alvos mais ampla, possivelmente não relacionado — e não deve ser presumido como parte do fio confirmado direcionado à MedDefense. Ainda assim deve ser bloqueado e reportado; a distinção afeta a confiança da atribuição, não a resposta.

## 5. Avaliação do Incidente de Clique

Detalhe completo em `7-click_investigation.md`; resumido aqui.

**O que se sabe:** Diane Marsh (`dmarsh@meddefense.com`, workstation `WS-NURSE-04`, `10.10.2.15`) clicou no link do E2 em 2026-04-14 15:02:33 CDT, cerca de 15 minutos após a entrega. O link (`hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1`) é uma página personalizada de coleta de credenciais em um domínio parecido, entregue por um remetente que falhou em toda verificação de autenticação.

**O que não pode ser concluído apenas com o lote de evidências:** se a página realmente carregou, o que ela exibia, se Diane inseriu um usuário ou senha, se ela aprovou algum prompt de MFA, e se algo foi baixado ou executado no workstation dela. O lote registra um clique, não um envio de credenciais ou um evento de endpoint, e nenhum log de endpoint ou identidade foi revisado para este relatório.

**Próximas ações seguras recomendadas** (não exigem evidência adicional para começar):
1. Redefinir a senha de Diane Marsh a partir de um dispositivo conhecidamente limpo, fora de banda, e revogar suas sessões ativas e tokens de atualização.
2. Revisar e, onde não reconhecidos, remover os métodos de MFA registrados dela.
3. Entrevistá-la sem culpabilizar sobre o que ela viu e fez após o clique.
4. Bloquear o domínio e o IP de envio do E2 no gateway e no firewall.
5. Rodar uma varredura de endpoint no `WS-NURSE-04`; escalar para isolamento apenas se essa varredura ou a revisão de logs posterior mostrar um download ou execução.
6. Monitorar a conta dela por 30 dias por localizações de login desconhecidas, novas regras de caixa de entrada, ou alterações de MFA.

Até que os logs de endpoint e identidade sejam revisados, tratar isto como **possível exposição de credenciais**, e não como "nenhum comprometimento" nem "comprometimento confirmado" (ver a matriz de decisão em `7-click_investigation.md`).

## 6. Resumo de IOC

A tabela estruturada completa, a categorização por fase de ataque e as notas de qualidade estão em `11-ioc_extraction.md`; o núcleo seguro para bloqueio é:

- **Domínios:** `meddefense-portal[.]com`, `outlook-protection[.]com`, `medequip-supplies[.]net`, `meddefense-benefits[.]org`
- **IPs:** `91[.]234[.]99[.]107`, `51[.]38[.]42[.]17`, `185[.]176[.]43[.]22`, `164[.]90[.]218[.]73`
- **Endereços de remetente:** `noreply@meddefense-portal[.]com`, `security@outlook-protection[.]com`, `invoices@medequip-supplies[.]net`, `hr-notifications@meddefense-benefits[.]org`
- **URLs:** `hxxps://meddefense-portal[.]com/verify/staff`, `hxxps://outlook-protection[.]com/verify`, `hxxps://medequip-supplies[.]net/invoices/pay`, `hxxps://medequip-supplies[.]net/portal/login`, `hxxps://meddefense-benefits[.]org/enroll`
- **Indicador de arquivo:** `INV-2026-04891[.]pdf`, SHA-256 `49558e1500b82d6758379f44ce6104442ec3a5cc08912737db5584640f4b9cad` (não verificado — calculado a partir de uma reprodução em lote, tratar como pista de caça, não como hash de bloqueio)

Impressões digitais de ferramentas (PHPMailer 6.6.0, o padrão de Message-ID `PHP-<8 hex>`, `X-Priority: 1`) e as notas de hospedagem/palavra-chave do HC3 são apenas contexto e não devem ser bloqueadas isoladamente; ver `11-ioc_extraction.md` Seção 4 para o motivo.

## 7. Lacunas de Detecção e Controle

**O que os controles existentes não impediram:** o gateway de e-mail entregou os quatro e-mails de phishing apesar de cada um falhar em SPF e/ou DMARC (três com `action=none`, efetivamente sem aplicação sobre um resultado de falha), e apesar de E2 e E7 falsificarem domínios parecidos com o próprio domínio da MedDefense. Nada na evidência mostra um controle de reescrita de link ou sandbox de anexo que teria neutralizado o clique no E2 ou sinalizado o link de pagamento recém-gerado do PDF do E5.

**O que deveria melhorar:**
- Mover o tratamento de DMARC de um monitoramento equivalente a `p=none` para `quarantine` (e eventualmente `reject`) para e-mails que alegam ser de `meddefense.com` e seus parecidos próximos, para que uma mensagem falsificada ou não autenticada não chegue à caixa de entrada na entrega.
- Adicionar uma regra que sinalize qualquer domínio de entrada que esteja a uma pequena distância de edição de `meddefense.com` (palavra adicionada, TLD trocado), independentemente do resultado de sua autenticação — isso teria capturado E2 e E7 mesmo que suas falhas de DMARC já fossem visíveis.
- Colocar em sandbox ou adiar links vistos pela primeira vez de domínios externos recém-observados antes de permitir um clique, particularmente em mensagens que carregam `X-Priority: 1` combinado com um resultado de DKIM/DMARC ausente ou com falha.
- Confirmar se a plataforma de caixa de correio corporativa é de fato o Microsoft 365; se não for, bloquear diretamente iscas no estilo alerta de login referenciando a Microsoft, já que nenhuma deveria ser esperada dessa plataforma.

**Ideias de detecção que vale construir a partir desta investigação** (o entregável de engenharia de detecção referenciado como "Tarefa 12" não fazia parte do conjunto de arquivos fornecido para este relatório, então estas são propostas aqui diretamente, e não citadas a partir dele):
- Uma regra de correlação que pontue mais alto uma mensagem que combine: (a) DMARC fail ou none, (b) um domínio registrado ou visto pela primeira vez recentemente, (c) `X-Priority: 1`, e (d) `X-Mailer: PHPMailer` — nenhum desses isoladamente é uma entrada segura de lista de bloqueio (ver `11-ioc_extraction.md`), mas a combinação combinou com os quatro e-mails de phishing aqui e com nenhum de E1/E4/E8.
- Uma lista de observação para domínios contendo "portal", "benefits", "supplies", "login" mais a string da própria marca da organização, obtida a partir de logs de transparência de certificados, conforme o padrão descrito pelo HC3.
- Um alerta em qualquer e-mail de entrada cuja cadeia `Received:` mostre um nome de host no formato `mail.<domínio>` sem DNS reverso consistente com o MX, combinado com um domínio de origem que combine (de forma aproximada) com o próprio domínio da organização.
- Um controle no momento do clique (reescrita de URL com detonação em sandbox) especificamente para links que carregam um parâmetro de token ou id por destinatário, já que esse padrão (visto em E2 e E5) indica uma isca direcionada e rastreada, não spam em massa.

## 8. Recomendações

**Imediato (próximas 24 horas)**
- Redefinir a senha de Diane Marsh e revogar suas sessões/MFA conforme descrito na Seção 5; entrevistá-la.
- Bloquear os quatro domínios, quatro IPs, e oito endereços de remetente da Seção 6 no gateway de e-mail, proxy, DNS e firewall.
- Pesquisar o gateway de e-mail por outros destinatários de E2, E3, E5 e E7, e remover essas mensagens das caixas de correio.
- Rodar uma varredura de proteção de endpoint no `WS-NURSE-04`.

**Curto prazo (próximos 7 dias)**
- Completar as verificações de acompanhamento de endpoint e conta listadas em `7-click_investigation.md` (histórico do navegador, downloads, execução de processos, logs de login, atividade de MFA, regras de caixa de entrada) usando qualquer ferramental de Sysmon/Wazuh/Suricata/provedor de identidade disponível, e atualizar o resultado da matriz de decisão para a conta de Diane Marsh de acordo.
- Verificar a relação com o fornecedor MedEquip Supplies e o status de pagamento através do cadastro de fornecedores e um número de telefone conhecido; confirmar com Angela Rivera que nenhum pagamento foi feito.
- Confirmar com o RH real se alguma janela de inscrição de benefícios estava aberta neste período, e notificar a equipe amplamente de que o e-mail do E7 não era genuíno.
- Enviar o pacote de IOC em `11-ioc_extraction.md` ao HC3 referenciando o aviso `HC3-2026-PRELIM-001`.
- Fazer um breve lembrete de conscientização para a equipe clínica, financeira e ligada a RH descrevendo os quatro pretextos usados.

**Médio prazo (próximos 30 dias)**
- Implementar as melhorias de aplicação de DMARC, domínio parecido e regra de correlação descritas na Seção 7.
- Continuar monitorando a conta de Diane Marsh (e qualquer outro destinatário confirmado) por logins incomuns, alterações de MFA ou criação de regras de caixa de entrada durante toda a janela de 30 dias recomendada em `7-click_investigation.md`.
- Revisar se a ação de spam/quarentena do gateway de e-mail para e-mails com falha de DMARC deveria mudar de `action=none` para `quarantine`, com base no fato de que três dos quatro e-mails de phishing aqui foram entregues especificamente por causa dessa configuração.
- Fechar o ciclo com o HC3 sobre se outras organizações regionais relatam indicadores correspondentes, para ajudar a firmar a avaliação de atribuição em `9-campaign_thread.md` além de sua confiança MÉDIA atual.
