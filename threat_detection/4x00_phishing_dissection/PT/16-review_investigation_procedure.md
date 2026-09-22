# Revisão 16 — Procedimento de Investigação

**Pergunta:** Um analista do SOC recebe um e-mail suspeito contendo um link para:

`hxxps://portal-update.meddefense-health.com/verify`

O analista precisa determinar se a URL é maliciosa.

Descreva o processo de investigação seguro que o analista deveria seguir sem visitar a URL diretamente.

## Resposta

O analista nunca deve abrir o link em um navegador, nem mesmo em uma sessão sandboxed ou anônima em uma máquina de trabalho — fazer isso ainda entrega uma conexão real ao servidor do atacante, que pode registrar o IP do analista, disparar uma cadeia de redirecionamentos, entregar um exploit, ou servir uma página de credenciais ajustada especificamente para aquele clique. O processo correto é primeiro passivo, ativo só por último:

1. **Desmascare e documente a URL imediatamente.** Reescreva `hxxps://portal-update[.]meddefense-health[.]com/verify` para que não possa ser clicada por acidente, e registre-a exatamente como recebida (subdomínio `portal-update`, domínio `meddefense-health.com`, caminho `/verify`).

2. **Compare o domínio com a marca real.** `meddefense-health.com` é um domínio separado e independente do domínio real da organização — a palavra extra com hífen ("health") e o subdomínio `portal-update` são uma construção clássica de domínio parecido (lookalike/typosquat), o que não é prova de malícia por si só, mas é um motivo forte para continuar investigando.

3. **Execute consultas passivas e somente leitura a partir de um host de análise isolado, nunca da rede corporativa:**
   - **WHOIS** — registrador e data de criação. Um domínio registrado há dias ou semanas é um forte sinal de alerta para um domínio de phishing parecido.
   - **DNS** (`dig`/`nslookup` contra um resolvedor público) — registros A, MX, NS e TXT/SPF, para ver para onde ele resolve e se possui infraestrutura de e-mail real ou DMARC/SPF configurados.
   - **Logs de Transparência de Certificados** (crt.sh) — quando um certificado TLS foi emitido pela primeira vez para o domínio/subdomínio; um certificado emitido bem perto da data de criação do WHOIS reforça a hipótese de "recém-registrado".
   - **VirusTotal / urlscan.io** — pesquise primeiro por varreduras e detecções *já existentes* (somente leitura). Se nada existir e uma renderização ao vivo for genuinamente necessária, envie apenas o domínio puro como uma nova **varredura unlisted/private no urlscan.io** — um ambiente em sandbox, não atribuível, que captura com segurança uma captura de tela, o conteúdo da página, a cadeia de redirecionamentos e as conexões de saída — em vez de visitá-la diretamente com um navegador ou `curl`.

4. **Correlacione com evidência interna sem tocar no site externo:** pesquise no gateway de e-mail pelo remetente e por qualquer outro destinatário desta mensagem, e pesquise logs de proxy/DNS/firewall para ver se alguém na organização já resolveu ou se conectou a este domínio.

5. **Decida a partir da totalidade da evidência passiva** — domínio recém-registrado, autenticação ausente ou com falha, estrutura parecida com a marca, e (se uma varredura em sandbox foi feita) uma página de coleta de credenciais — e documente o veredito com IOCs desmascarados.

6. **Aja de acordo com o veredito:** bloqueie o domínio (e qualquer IP resolvido) no gateway de e-mail, DNS, proxy e firewall, e alerte/investigue qualquer usuário que possa já ter clicado, sem nunca ter se conectado ao site a partir de um ativo identificável ou corporativo.

Isso segue a mesma metodologia primeiro-passiva-depois-sandboxed documentada em `4-url_attachment_autopsy.md` desta investigação.
