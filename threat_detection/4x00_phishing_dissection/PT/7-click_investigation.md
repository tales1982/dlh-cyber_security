## Investigação do Clique — Diane Marsh / WS-NURSE-04

Avaliação do clique relatado por Diane Marsh no link do Email 2, e a evidência necessária para decidir se houve comprometimento. Esta tarefa usa apenas o lote de evidências de e-mail. Nenhum log de Sysmon, Wazuh, Suricata, Windows Security, proxy, DNS ou identidade foi pesquisado. Toda verificação em "Verificações de Endpoint a Realizar" e "Verificações de Conta a Realizar" é um acompanhamento recomendado que não foi executado, e o resultado, portanto, permanece indeterminado. Domínios, endereços e IPs estão desmascarados ou em formatação de código; a URL do E2 não foi visitada.

### Fatos Confirmados

Fonte de cada fato: o lote de evidências (cabeçalhos e corpo do E2, notas do lote e rodapé do lote).

Em termos simples: **Diane Marsh** (`dmarsh@meddefense.com`), no **workstation** `WS-NURSE-04` (`10.10.2.15`), clicou no link dentro do **e-mail** E2 (`noreply@meddefense-portal.com`, "ACTION REQUIRED: Portal re-verification needed within 24 hours") na **data e hora do clique** 2026-04-14 15:02:33 CDT. A **URL/domínio** clicada foi `hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1`, no domínio parecido `meddefense-portal.com`, entregue a partir do **IP relacionado** `91[.]234[.]99[.]107`. Esses seis itens — usuária, workstation, e-mail, URL/domínio, data e hora do clique e IP relacionado — estão confirmados diretamente pelo lote de evidências; a tabela abaixo cita a fonte exata de cada um, e tudo além do clique em si é desconhecido (ver Principais Incógnitas).

| Fato | Valor | Fonte |
|---|---|---|
| Usuária | Diane Marsh, `dmarsh@meddefense.com` | Rodapé do lote, `To:` do E2 |
| Workstation | `WS-NURSE-04`, IP `10.10.2.15` | Rodapé do lote |
| E-mail | E2, "ACTION REQUIRED: Portal re-verification needed within 24 hours", de `noreply@meddefense-portal.com` | Cabeçalhos do E2 |
| URL clicada | `hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1` | Corpo do E2, rodapé do lote diz que E2 foi o e-mail clicado |
| Domínio | `meddefense-portal[.]com`, um domínio parecido com `meddefense.com` | Cabeçalhos e corpo do E2 |
| IP relacionado | `91[.]234[.]99[.]107`, o servidor de e-mail `mail.meddefense-portal.com` que entregou o E2 | Salto externo `Received:` do E2 |
| Data e hora do clique | 2026-04-14 15:02:33 CDT (20:02:33 UTC), conforme NTP do workstation | Rodapé do lote |
| Autenticação da isca | SPF `fail`, DKIM `none`, DMARC `fail` (`action=none`), então foi entregue | `Authentication-Results` do E2 |
| Conteúdo da isca | Prazo de 24 horas, ameaça de perder acesso a escalas, gateway do EHR e trocas de plantão, link por usuário com `id=dmarsh` e um token | Corpo do E2 |

Linha do tempo (todos os horários em CDT, salvo indicação):

| Horário | Evento |
|---|---|
| 2026-04-14 14:47:48 | E2 criado pelo remetente (`Date` 19:47:48 +0000) |
| 14:47:51 | `mx01.meddefense.com` aceita o E2 de `91.234.99.107` |
| 14:47:52 | E2 repassado a `inbound-relay.meddefense.com` para `dmarsh` |
| 15:02:33 | Clique registrado, 14 min 41 s após o horário do relay |
| 2026-04-15 por volta de 14:47 | O prazo de 24 horas da isca expira. Nada na evidência mostra que o acesso de Diane foi afetado. |
| 2026-04-17 09:15 | Lote de evidências coletado, 66 h 12 min após o clique |

O clique ocorreu cerca de 66 horas antes da coleta, não aproximadamente 36 horas como na nota do coletor. Como nas notas de triagem inicial, a marca de tempo do NTP do workstation é usada como referência.

A usuária relatou o clique e o lote registra a data e hora. Como esse timestamp foi obtido (histórico do navegador, log de proxy ou lembrança da usuária) não é informado.

### Principais Incógnitas

- Se a página chegou a carregar, e o que ela exibia (um formulário de login, um redirecionamento, um download, um erro). A URL nunca foi observada.
- Se Diane inseriu seu usuário e senha, e se ela aprovou algum prompt de MFA. O lote registra um clique, não um envio de credenciais.
- Se algo foi baixado ou executado no `WS-NURSE-04`.
- O endereço IP do servidor web por trás de `meddefense-portal.com`. A evidência fornece apenas o IP do servidor de e-mail, e os hosts web e de e-mail podem ser diferentes.
- Se o domínio estava acessível e ativo às 15:02 CDT, e por quanto tempo ficou no ar.
- Qual navegador e perfil foram usados, e se a mesma conta está conectada em outros dispositivos, como um celular.
- Se a senha dela é reutilizada em outros sistemas, e quais acessos `dmarsh` possui (gateway do EHR, escalas, VPN, e-mail).
- Se algum outro usuário da MedDefense recebeu ou clicou no E2, ou nos outros e-mails de domínio parecido. Apenas um destinatário por e-mail aparece no lote.
- Se houve alguma atividade de login ou de caixa de correio para `dmarsh` desde as 15:02 CDT de 2026-04-14.

### Avaliação de Risco

Um clique no link de um e-mail de coleta de credenciais é grave mesmo antes de qualquer envio de credencial ser confirmado.

- A página é avaliada, não comprovada, como um portal de coleta de credenciais. A isca pede "verificação", a URL é um link personalizado `/verify/staff` com um token, o domínio é parecido (lookalike), e o remetente falhou em toda verificação de autenticação. O próximo passo mais provável nessa página é um formulário de login estilizado como o portal da MedDefense.
- O clique sozinho já informa algo ao atacante. A URL com token confirma que uma funcionária ativa abriu o link, e a requisição expõe o IP, navegador e detalhes do dispositivo dela.
- Uma página de destino pode fazer mais do que exibir um formulário: solicitar o download de um arquivo, redirecionar por mais páginas, ou pedir permissões do navegador. O alerta do HC3 (E8) menciona possível atividade de Estágio 2 assim que as credenciais são validadas, então um clique não deve ser encerrado supondo que nada mais aconteceu.
- O risco é alto por causa de quem foi alvo. A isca nomeia o gateway do EHR e o sistema de escalas, então uma conta de enfermagem pode alcançar sistemas que armazenam dados de pacientes. O uso indevido desse acesso poderia levantar questões de privacidade e de notificação de violação.
- O MFA reduz o risco, mas não o elimina. Uma página de phishing que repassa um login em tempo real pode capturar uma sessão tão bem quanto uma senha, então a presença de MFA não é prova de segurança.
- O tempo joga a favor do atacante: 66 horas se passaram antes da coleta do lote, e a evidência não tem registro do que a conta fez nesse período.

Até que as verificações abaixo sejam feitas, este é um clique confirmado com impacto não confirmado. A prioridade P1-URGENT da triagem permanece.

### Verificações de Endpoint a Realizar

Acompanhamento recomendado. Nenhuma delas foi pesquisada nesta tarefa. Onde os logs estiverem disponíveis, revise a janela a partir de 2026-04-14 15:02:33 CDT em diante, e alguns minutos antes.

| Verificação | Onde procurar | O que seria preocupante |
|---|---|---|
| Histórico e downloads do navegador | Perfil do Chrome, Edge ou Firefox no `WS-NURSE-04` (`History`, `places.sqlite`), lista de downloads, cache | Uma visita a `meddefense-portal.com`, redirecionamentos para outros domínios, envio de formulário, arquivos baixados |
| Prompts de senha salva e autopreenchimento | Gerenciador de senhas do navegador e dados de histórico de formulários | Sinais de que credenciais foram digitadas na página |
| Atividade de DNS e proxy a partir de `10.10.2.15` | Logs de proxy, servidor DNS e firewall, Sysmon Event ID 22 se disponível | Resolução de `meddefense-portal.com`, conexões ao seu IP web, outros destinos externos novos após o clique |
| Conexões de rede após o clique | Sysmon Event ID 3, logs de firewall e IDS/IPS | Conexões repetidas a novos IPs, portas incomuns ou intervalos de beaconing |
| Arquivos baixados | Pasta Downloads da usuária, `%TEMP%`, streams Mark-of-the-Web (`Zone.Identifier`), Sysmon Event ID 15 | Executáveis, scripts, arquivos compactados, documentos do Office ou atalhos baixados do site |
| Execução de processos | Sysmon Event ID 1, Security Event ID 4688 com linhas de comando | Um navegador iniciando `cmd.exe`, `powershell.exe`, `wscript.exe`, `mshta.exe`, `rundll32.exe`, `certutil.exe` ou um instalador |
| Atividade de PowerShell e cmd | PowerShell Event IDs 4103 e 4104, `ConsoleHost_history.txt` da usuária | Comandos codificados, cradles de download, chamadas de rede |
| Criação de arquivos | Sysmon Event ID 11 no perfil da usuária, `AppData`, Temp, pasta Startup | Novos executáveis ou scripts criados após o clique |
| Persistência | Sysmon Event ID 13 (chaves Run), tarefas agendadas (Event ID 4698), novos serviços (Event ID 7045), pasta Startup | Qualquer coisa criada após 15:02 que inicie no logon |
| Proteção de endpoint | Alertas e quarentena de AV ou EDR no host | Detecções ligadas a um navegador ou download após o clique |
| Extensões e permissões do navegador | Lista de extensões, permissões de notificação | Uma extensão recém-instalada, ou notificações permitidas para o domínio |

### Verificações de Conta a Realizar

Acompanhamento recomendado. Nenhuma delas foi pesquisada nesta tarefa. Revise a partir de 2026-04-14 15:02:33 CDT até o presente.

| Verificação | Onde procurar | O que seria preocupante |
|---|---|---|
| Logins falhos | Logs de login do provedor de identidade, controlador de domínio Event IDs 4625, 4771, 4776, logs de VPN | Rajadas de falhas contra `dmarsh` a partir de fontes desconhecidas |
| Logins bem-sucedidos de fontes incomuns | Mesmos logs, Event ID 4624, localizações de login, ASN, user agent | Um IP ou país inédito, faixas de provedores de hospedagem (incluindo `91.234.99.107` ou os outros IPs de envio), viagem impossível, protocolos legados |
| Atividade de MFA | Logs de MFA e de métodos de autenticação | Prompts inesperados, aprovações que Diane não iniciou, um novo método ou dispositivo registrado |
| Alterações e redefinições de senha | Event IDs 4723 e 4724, log de auditoria do provedor de identidade | Uma alteração ou redefinição que Diane não realizou |
| Regras de caixa de entrada e encaminhamento | Configurações de regras de caixa de correio e encaminhamento, log de auditoria da caixa de correio | Novas regras que encaminham, redirecionam, excluem ou marcam mensagens como lidas, especialmente as que escondem e-mails de segurança ou de TI |
| E-mails enviados pela conta | Rastreamento de mensagens, itens enviados | Mensagens enviadas de `dmarsh` para colegas que ela não escreveu (phishing interno) |
| Consentimentos de aplicativo e delegados | Log de auditoria do provedor de identidade, permissões de caixa de correio | Uma nova concessão de aplicativo OAuth ou um delegado adicionado à caixa de correio dela |
| Alterações de associação a grupos | Event IDs 4728, 4732, 4756, log de auditoria do provedor de identidade | `dmarsh` adicionada a grupos privilegiados ou clínicos |
| Acesso a sistemas | Logs de acesso ao gateway do EHR, escalas e VPN para `dmarsh` | Acesso fora do turno ou do cargo dela, consultas incomuns a prontuários de pacientes |
| Outros destinatários | Pesquisa no gateway de e-mail por `meddefense-portal.com` e pelos outros domínios parecidos, logs de proxy pelos mesmos domínios | Outros usuários que receberam ou visitaram as páginas |

### Matriz de Decisão

| Resultado | O que as verificações mostrariam | Interpretação | Resposta |
|---|---|---|---|
| Nenhum comprometimento encontrado | A página nunca carregou ou foi bloqueada. O histórico do navegador mostra uma visita sem envio de formulário. Diane confirma que não digitou nada. Sem downloads, sem processos incomuns, sem logins incomuns, sem alterações de regras ou de MFA, e os logs cobrem toda a janela desde as 15:02 CDT. | Um clique que não levou a impacto observado. | Encerrar como clique sem comprometimento. Ainda assim, completar as precauções de baixo custo (redefinição de senha, revogação de sessão) e monitorar por 30 dias. Registrar as lacunas na cobertura de logs. |
| Possível exposição de credenciais | Diane diz que inseriu credenciais, ou a página carregou e um formulário foi enviado, ou os logs estão ausentes ou incompletos para a janela, mas nenhuma atividade do atacante foi vista ainda. | Tratar a senha como conhecida pelo atacante até que se prove o contrário. | Forçar redefinição de senha, revogar sessões e tokens, revisar métodos de MFA, checar reutilização em outros sistemas, aumentar o monitoramento da conta e continuar pesquisando. |
| Comprometimento confirmado | Um login bem-sucedido de uma fonte desconhecida após o clique, ou uma nova regra de caixa de entrada ou encaminhamento, um método de MFA alterado, uma concessão OAuth, acesso não autorizado ao EHR, ou malware ou persistência no workstation. | A conta, o endpoint, ou ambos, estão sob controle do atacante. | Declarar um incidente. Desativar a conta, isolar o workstation, preservar evidências, envolver a equipe de privacidade e conformidade se dados de pacientes puderem estar envolvidos, caçar a mesma atividade em toda a organização e bloquear os indicadores. |
| Indeterminado (estado atual) | Apenas o lote de evidências está disponível, sem revisão de logs de endpoint ou identidade. | O impacto não pode ser confirmado nem descartado. | Agir como em "Possível exposição de credenciais" até que as verificações retornem resultados. |

### Contenção Recomendada

Preserve evidências primeiro onde custar pouco, depois faça a contenção. Estas etapas são seguras e realistas para um workstation clínico.

1. Preservar evidências: manter a mensagem bruta do E2, exportar os logs relevantes de proxy, DNS, e-mail e login, e copiar o histórico do navegador do `WS-NURSE-04` antes de qualquer limpeza.
2. Redefinir a senha de Diane a partir de um dispositivo conhecidamente limpo, usando um canal fora de banda, e não usar o workstation original para a redefinição.
3. Revogar todas as sessões ativas e tokens de atualização de `dmarsh`, e reverificar os métodos de MFA registrados dela, removendo qualquer um que ela não reconheça.
4. Entrevistar Diane de forma não acusatória, e perguntar:
   - O que apareceu depois do clique?
   - Ela digitou um usuário ou senha?
   - Ela aprovou algum prompt de MFA?
   - Algum arquivo foi baixado ou aberto?
   - Ela usou outro dispositivo?
   - Ela reutiliza essa senha em outro lugar?
   - Ela encaminhou ou respondeu à mensagem?
5. Rodar uma varredura de proteção de endpoint no `WS-NURSE-04`. Se as verificações mostrarem um download ou execução, isolar o workstation da rede, mas mantê-lo ligado, e coordenar com as operações clínicas, pois ele dá suporte ao atendimento de pacientes. Sem essa evidência, um monitoramento direcionado é mais proporcional do que isolamento ou reinstalação.
6. Bloquear os indicadores no proxy, DNS, firewall e gateway de e-mail: `meddefense-portal[.]com` e o IP de envio `91[.]234[.]99[.]107`, e os outros domínios e IPs listados em `4-url_attachment_autopsy.md`.
7. Pesquisar o gateway de e-mail por outros destinatários do E2 e dos e-mails de domínio parecido E3, E5 e E7, e remover essas mensagens das caixas de correio.
8. Monitorar `dmarsh` por pelo menos 30 dias por logins de novas localizações ou faixas de hospedagem, criação de regras de caixa de entrada, alterações de método de MFA, e qualquer acesso aos quatro domínios parecidos a partir de outros hosts.
9. Relatar o clique ao líder de incidentes e, se houver possibilidade de acesso a dados de pacientes, ao responsável pela privacidade.
10. Reforçar a conscientização para os funcionários que receberam as iscas assim que a contenção estiver concluída, e enviar os indicadores ao HC3 conforme o alerta sugere.

### Conclusão

A evidência confirma que Diane Marsh clicou no link personalizado do E2 a partir do `WS-NURSE-04` (`10.10.2.15`) em 2026-04-14 15:02:33 CDT, cerca de 14 minutos após a entrega, e cerca de 66 horas antes da coleta do lote. O link aponta para `meddefense-portal[.]com`, um domínio parecido servido por um remetente que falhou em SPF, DKIM e DMARC. A evidência não mostra se credenciais foram inseridas, se o MFA foi aprovado ou se algo foi executado no workstation, então o comprometimento não está nem confirmado nem descartado.

A suposição de trabalho deve ser de possível exposição de credenciais. A contenção que não depende de evidência adicional (redefinição de senha, revogação de sessão, revisão de MFA, monitoramento, bloqueio de indicadores) deve prosseguir agora. As verificações de endpoint e de conta acima decidirão se este caso se encerra como um clique sem comprometimento ou se escala para um incidente confirmado.
