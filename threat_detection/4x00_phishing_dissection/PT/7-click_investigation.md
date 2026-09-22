## Investigação do Clique — Diane Marsh / WS-NURSE-04

Avaliação do clique relatado por Diane Marsh no link do Email 2, baseada apenas no lote de evidências de e-mail. Nenhum log de Sysmon, Wazuh, Suricata, Windows Security, proxy, DNS ou identidade foi pesquisado para produzir este relatório; todo item em Verificações de Endpoint e Verificações de Conta abaixo é um acompanhamento recomendado, não algo já feito. A URL do E2 não foi visitada.

### Fatos Confirmados

Confirmados diretamente pelo lote de evidências (cabeçalhos do E2, corpo do E2, e rodapé do lote):

- **Usuária:** Diane Marsh, `dmarsh@meddefense.com` (rodapé do lote, `To:` do E2)
- **Workstation:** `WS-NURSE-04`, IP `10.10.2.15` (rodapé do lote)
- **E-mail:** E2, "ACTION REQUIRED: Portal re-verification needed within 24 hours", de `noreply@meddefense-portal.com` (cabeçalhos do E2)
- **URL/domínio:** `hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1`, no domínio parecido `meddefense-portal.com` (corpo do E2; o rodapé do lote diz que E2 foi o e-mail clicado)
- **Data e hora do clique:** 2026-04-14 15:02:33 CDT (20:02:33 UTC), conforme NTP do workstation — 14 minutos e 41 segundos após o `mx01.meddefense.com` aceitar o E2 do remetente às 14:47:51 CDT, e cerca de 66 horas antes de o lote ser coletado em 2026-04-17 09:15 CDT (a nota do coletor dizia cerca de 36 horas; o timestamp de NTP é usado como referência, como nas notas de triagem inicial)
- **IP relacionado:** `91[.]234[.]99[.]107`, o servidor de e-mail externo (`mail.meddefense-portal.com`) que entregou o E2, conforme seu salto `Received:`

Contexto de apoio: o E2 falhou na autenticação (SPF `fail`, DKIM `none`, DMARC `fail`, entregue sob `action=none`) e carregava uma ameaça de bloqueio em 24 horas citando o sistema de escalas, o gateway do EHR e o acesso a trocas de plantão. O lote registra que Diane relatou o clique; como o timestamp exato foi capturado (histórico do navegador, log de proxy, ou a própria lembrança dela) não é informado.

### Principais Incógnitas

O que aconteceu depois do clique não está na evidência:

- Se a página carregou, e o que ela mostrava — um formulário de login, um redirecionamento, um download, ou um erro. A URL nunca foi observada.
- Se Diane inseriu seu usuário e senha, ou aprovou um prompt de MFA. O lote registra um clique, não um envio de credenciais.
- Se algo foi baixado ou executado no `WS-NURSE-04`.
- O IP do servidor web por trás de `meddefense-portal.com` — a evidência só dá o IP do servidor de e-mail, e os dois hosts podem ser diferentes.
- Se houve alguma atividade de login ou caixa de correio para `dmarsh` desde o clique, e se algum outro usuário da MedDefense clicou no E2 ou nos e-mails relacionados de domínio parecido.

Essa incerteza é o motivo pelo qual o clique é tratado como grave, e não descartado. A isca é um link personalizado e com token (`id=dmarsh`) em um domínio que falhou em toda verificação de autenticação, estilizado como uma página de "verificação" de coleta de credenciais, então o próximo passo mais provável após o clique era um formulário de login. Um clique sozinho já confirma ao atacante que uma funcionária ativa abriu o link e expõe o IP e o dispositivo dela; uma página de destino também pode solicitar um download ou uma permissão, e o alerta do HC3 (E8) menciona possível atividade de Estágio 2 assim que as credenciais são validadas, então nada além do clique deve ser presumido. Como a isca nomeia o gateway do EHR e o sistema de escalas, uma conta de enfermagem comprometida poderia alcançar sistemas com dados de pacientes, o que eleva os riscos de privacidade e de notificação de violação. O MFA reduz mas não elimina o risco, já que uma página de phishing com repasse em tempo real pode capturar uma sessão tão bem quanto uma senha. Com 66 horas já passadas e nenhum log revisado ainda, este é um clique confirmado com impacto não confirmado, e a prioridade P1-URGENT da triagem permanece.

### Verificações de Endpoint a Realizar

Apenas acompanhamento recomendado; nenhuma delas foi executada. Se os logs estiverem disponíveis, revise a partir de 2026-04-14 15:02:33 CDT em diante (e alguns minutos antes):

- **Histórico e downloads do navegador** (perfil do navegador no `WS-NURSE-04`, lista de downloads, cache) — uma visita a `meddefense-portal.com`, redirecionamentos, envio de formulário, ou arquivos baixados.
- **Arquivos baixados** (pasta Downloads, `%TEMP%`, streams Mark-of-the-Web) — executáveis, scripts, arquivos compactados ou documentos baixados do site.
- **Execução de processos** (Sysmon Event ID 1, Security 4688) — um navegador iniciando `cmd.exe`, `powershell.exe`, `mshta.exe`, `rundll32.exe` ou um instalador.
- **Atividade de PowerShell/cmd** (Event IDs 4103/4104, histórico de comandos) — comandos codificados ou cradles de download.
- **Criação de arquivos e persistência** (Sysmon 11/13, tarefas agendadas, novos serviços, pasta Startup) — qualquer coisa criada após o clique que inicie no logon.
- **Atividade de DNS/proxy a partir de `10.10.2.15`** — resolução do domínio e qualquer novo destino externo após o clique.
- **Alertas de proteção de endpoint** — detecções de AV/EDR ligadas a um navegador ou download por volta do horário do clique.

### Verificações de Conta a Realizar

Apenas acompanhamento recomendado; nenhuma delas foi executada. Revise da data e hora do clique até o presente:

- **Logins falhos** (logs de login, Event IDs 4625/4771/4776, logs de VPN) — rajadas contra `dmarsh` de fontes desconhecidas.
- **Logins bem-sucedidos de fontes incomuns** (Event ID 4624, localização/ASN/user agent do login) — um país inédito, faixa de IP de provedor de hospedagem (incluindo `91.234.99.107`), ou viagem impossível.
- **Atividade de MFA** — prompts ou aprovações que Diane não iniciou, ou um método ou dispositivo recém-registrado.
- **Alterações/redefinições de senha** (Event IDs 4723/4724) — uma alteração que Diane não fez.
- **Regras de caixa de entrada e encaminhamento** — novas regras que encaminham, redirecionam, excluem ou escondem mensagens, especialmente e-mails de segurança/TI.
- **Alterações de associação a grupos** (Event IDs 4728/4732/4756) — `dmarsh` adicionada a grupos privilegiados ou clínicos.
- **Acesso a sistemas** (logs do gateway de EHR, escalas, VPN) — acesso fora do turno ou cargo dela.
- **Outros destinatários** — pesquisa no gateway de e-mail por `meddefense-portal.com` e pelos outros domínios parecidos, para encontrar quem mais recebeu ou visitou.

### Matriz de Decisão

| Resultado | O que as verificações mostrariam | Resposta |
|---|---|---|
| Nenhum comprometimento encontrado | Página nunca carregou ou foi bloqueada; sem envio de formulário; sem downloads, processos incomuns, logins incomuns, ou alterações de regra/MFA; logs cobrem toda a janela. | Encerrar como clique sem comprometimento. Ainda assim fazer as precauções de baixo custo (redefinição de senha, revogação de sessão) e monitorar por 30 dias. |
| Possível exposição de credenciais | Diane diz que inseriu credenciais, ou um formulário foi enviado, ou os logs da janela estão ausentes/incompletos, sem atividade confirmada do atacante ainda. | Tratar a senha como conhecida pelo atacante: forçar redefinição, revogar sessões/tokens, revisar MFA, checar reutilização de senha, aumentar monitoramento. |
| Comprometimento confirmado | Um login bem-sucedido de fonte desconhecida após o clique, uma nova regra de caixa de entrada, um método de MFA alterado, acesso não autorizado ao EHR, ou malware/persistência no workstation. | Declarar um incidente: desativar a conta, isolar o workstation, preservar evidências, envolver privacidade/conformidade se dados de pacientes puderem ser afetados, caçar em toda a organização, bloquear indicadores. |
| Indeterminado (estado atual) | Apenas o lote de evidências está disponível; nenhum log de endpoint ou identidade revisado ainda. | Agir como em "Possível exposição de credenciais" até que as verificações acima retornem resultados. |

### Contenção Recomendada

1. Preservar evidências: manter a mensagem bruta do E2, exportar os logs de proxy/DNS/e-mail/login disponíveis, e copiar o histórico do navegador do `WS-NURSE-04` antes de qualquer limpeza.
2. Redefinir a senha de Diane a partir de um dispositivo conhecidamente limpo, por um canal fora de banda; não usar o workstation original.
3. Revogar sessões ativas e tokens de atualização de `dmarsh`; revisar os métodos de MFA dela e remover qualquer um que ela não reconheça.
4. Entrevistar Diane sem culpabilizar: o que apareceu depois do clique, se ela digitou credenciais ou aprovou MFA, se algo baixou, se ela usou outro dispositivo, se ela reutiliza aquela senha, se ela encaminhou a mensagem.
5. Rodar uma varredura de endpoint no `WS-NURSE-04`; isolá-lo apenas se a varredura ou as verificações mostrarem download/execução, coordenando com as operações clínicas já que ele dá suporte ao atendimento de pacientes — do contrário, monitoramento direcionado é mais proporcional.
6. Bloquear os indicadores (`meddefense-portal[.]com`, `91[.]234[.]99[.]107`, e os domínios/IPs relacionados em `4-url_attachment_autopsy.md`) no proxy, DNS, firewall e gateway de e-mail.
7. Pesquisar o gateway de e-mail por outros destinatários de E2, E3, E5 e E7, e remover essas mensagens das caixas de correio.
8. Monitorar `dmarsh` por 30 dias por logins de novas localizações, criação de regras de caixa de entrada, e alterações de MFA.
9. Relatar o clique ao líder de incidentes e, se houver possibilidade de acesso a dados de pacientes, ao responsável pela privacidade.

### Conclusão

A evidência confirma que Diane Marsh clicou no link personalizado do E2 a partir do `WS-NURSE-04` (`10.10.2.15`) em 2026-04-14 15:02:33 CDT, cerca de 14 minutos após a entrega e cerca de 66 horas antes de o lote ser coletado. O link aponta para `meddefense-portal[.]com`, um domínio parecido servido por um remetente que falhou em SPF, DKIM e DMARC. Se credenciais foram inseridas, se o MFA foi aprovado, ou se algo foi executado no workstation não é mostrado pela evidência, então o comprometimento não está nem confirmado nem descartado — a suposição de trabalho é de possível exposição de credenciais. A contenção que não depende de evidência adicional (redefinição de senha, revogação de sessão, revisão de MFA, monitoramento, bloqueio de indicadores) deve prosseguir agora, enquanto as verificações de endpoint e de conta acima decidem se este caso se encerra como um clique sem comprometimento ou escala para um incidente confirmado.
