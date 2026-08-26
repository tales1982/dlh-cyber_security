# 2x04 – Perimeter Defense

## Task - 0-network_baseline.sh
O que faz: Coleta um baseline completo da rede do host — interfaces, rotas, tabela ARP, sockets em escuta, conexões estabelecidas e configuração de DNS — direto das ferramentas do sistema, sem alterar nada. Serve de referência objetiva para justificar toda regra de firewall criada depois.
Como usar: `sudo ./0-network_baseline.sh [output.json]`
Comandos:
- `date -u +%Y-%m-%dT%H:%M:%SZ` — gera timestamp UTC para marcar quando o baseline foi coletado.
- `hostname` — identifica o host que está sendo mapeado no relatório.
- `ip -j addr show` — lista interfaces de rede, MAC, estado do link e endereços IP atribuídos.
- `ip -j route show` — mostra a tabela de rotas, incluindo o gateway padrão, para saber por onde o tráfego sai.
- `ip -j neigh show` — lista a tabela ARP/vizinhos (IP, MAC, estado) para identificar hosts já conhecidos na rede local.
- `ss -tulnpH` — lista todos os sockets TCP/UDP em escuta com processo e PID donos, base do mapeamento de superfície de ataque.
- `ss -tnpH state established` — lista conexões TCP já estabelecidas com processo e PID, mostrando com quem o host já está falando.
- `grep -E '^nameserver' /etc/resolv.conf` — extrai os servidores DNS configurados no host.
- `systemctl is-active --quiet systemd-resolved` — verifica se o systemd-resolved está ativo antes de consultar seu status.
- `resolvectl status --no-pager` — mostra a configuração de resolução DNS por interface quando o systemd-resolved está em uso.

## Task - 1-attack_surface.sh
O que faz: Lê o baseline gerado pelo script 0 e classifica cada socket em escuta com função (banco de dados, web, ssh, etc.) e criticidade, sinalizando exposições perigosas — serviço de banco/RPC ligado em 0.0.0.0, ou protocolo inerentemente inseguro (telnet, ftp, snmp v1/v2c, rlogin, nfs v2/v3). Se não acha o PID direto, tenta achar o processo por outros meios antes de desistir.
Como usar: `sudo ./1-attack_surface.sh [network_baseline.json] [output.json]`
Comandos:
- `readlink -f /proc/$pid/exe` — resolve o caminho real do binário que abriu o socket, para identificar o executável exato.
- `pgrep -x "$process"` — busca o PID de um processo pelo nome exato, usado como alternativa quando o baseline não trouxe o PID.
- `pidof "$process"` — outra forma de achar o PID de um processo pelo nome, tentada se o `pgrep` não encontrar nada.
- `which "$process"` — localiza o caminho do binário de um comando no `$PATH`, último recurso antes de vasculhar diretórios fixos (`/usr/sbin`, `/usr/bin` etc.).
- `dpkg -S "$binary_path"` — descobre a qual pacote instalado pertence um binário, ligando o serviço exposto à sua origem.
- `grep -oP '[a-zA-Z0-9_.-]+\.service' /proc/$pid/cgroup` — extrai o nome da unidade systemd associada ao processo a partir do cgroup.
- `systemctl show -p Id --value nome.service` — consulta o Id de uma unidade systemd específica, pra confirmar que ela existe de verdade antes de atribuí-la ao processo.
- `systemctl list-units --type=service --no-pager` — lista todas as unidades de serviço systemd carregadas, usado como último recurso pra achar a unit certa por nome parecido.

## Task - 2-segmentation_rules.sh
O que faz: Gera o "contrato" de segmentação de rede da MedDefense — as 4 zonas (DMZ, INTERNAL, MGMT, MEDDEV) com CIDR e política padrão, a lista de fluxos liberados entre zonas (porta, protocolo, justificativa) e as regras de `deny_all` explícitas para cada par de zona sem fluxo liberado. Não mexe na rede — só produz o JSON que os exercícios 4 e 6 vão consumir como fonte da verdade.
Como usar: `./2-segmentation_rules.sh [output.json]`
Comandos: nenhum comando de sistema — o script é jq puro, só monta a estrutura de zonas/fluxos/negações direto em JSON.

## Task - 4-nftables_config.sh
O que faz: Lê o `segmentation_rules.json` e renderiza um `nftables.conf` de verdade (tabela `inet meddefense` com um set de CIDR por zona e chains `input`/`forward`/`output`), valida a sintaxe antes de aplicar, faz backup do ruleset atual pra rollback e só então aplica tudo de forma atômica — sem travar a própria sessão SSH.
Como usar: `sudo ./4-nftables_config.sh [--render-only] [segmentation_rules.json]`
Comandos:
- `ip -o -4 addr show` — lista os endereços IPv4 do host em formato de uma linha por interface, usado pra descobrir a qual zona o host pertence e detectar a interface de gerência (SSH) a exemptar do bloqueio.
- `nft -c -f arquivo.conf` — faz um parse "check-only" do arquivo de regras nftables sem aplicar nada, pra pegar erro de sintaxe antes de mexer no firewall de verdade.
- `nft list ruleset` — lista o ruleset nftables atualmente carregado no sistema, usado aqui pra gerar o backup de rollback antes de aplicar o novo.
- `nft -f arquivo.conf` — aplica um arquivo de regras nftables de forma atômica (tudo ou nada).
- `nft -a list table inet meddefense` — lista as regras carregadas de uma tabela específica junto com seus "handles" (IDs), usado pra conferir se a quantidade de regras aplicadas bate com o total esperado.

## Task - 6-windows_firewall.ps1
O que faz: Espelha o mesmo `segmentation_rules.json` no Windows Firewall — define política padrão de bloquear entrada/permitir saída nos 3 perfis (Domain/Private/Public), recria do zero as regras `MedDefense-*` (idempotente, remove as antigas antes) só pros fluxos que terminam na zona do host atual, ativa log de conexões bloqueadas e exporta o resultado em JSON pra comparar depois com o lado Linux (nftables).
Como usar: `.\6-windows_firewall.ps1` (PowerShell como Administrador)
Comandos:
- `Get-Content -Path arquivo -Raw | ConvertFrom-Json` — lê um arquivo de texto e converte o conteúdo JSON num objeto PowerShell.
- `Set-NetFirewallProfile -Profile X -DefaultInboundAction Block -DefaultOutboundAction Allow -LogBlocked True -LogFileName caminho` — define a política padrão (bloquear entrada, permitir saída) e ativa o log de conexões bloqueadas para um perfil de firewall do Windows.
- `Get-NetFirewallRule -DisplayName "padrão*"` — lista as regras de firewall existentes cujo nome bate com um padrão, usado pra achar as regras antigas antes de recriar.
- `Remove-NetFirewallRule` — remove uma ou mais regras de firewall recebidas via pipeline.
- `Get-NetIPAddress -AddressFamily IPv4` — lista os endereços IPv4 configurados no host, usado pra descobrir a qual zona da segmentação o host pertence.
- `New-NetFirewallRule -DisplayName nome -Direction Inbound -Action Allow -Protocol proto -LocalPort porta -RemoteAddress origem -Profile Any` — cria uma regra de firewall permitindo tráfego de entrada de um endereço/porta/protocolo específico.
- `ConvertTo-Json -Depth N | Set-Content -Path arquivo` — converte um objeto PowerShell em texto JSON e grava o resultado num arquivo.

## Task - 8-suricata_setup.sh
O que faz: Instala o Suricata e o jq (se ainda não estiverem), copia o conjunto de regras do laboratório pra `/var/lib/suricata/rules/`, renderiza um `suricata.yaml` mínimo em modo replay (sem interface ao vivo, sem daemon) e prova que a engine funciona rodando um teste de configuração e um replay de um PCAP de fumaça.
Como usar: `sudo ./8-suricata_setup.sh [output.json]`
Comandos:
- `apt-get install -y suricata jq` — instala os pacotes suricata e jq via apt, de forma não-interativa.
- `suricata --build-info` — mostra informações de build do Suricata, incluindo a versão instalada.
- `find diretório -maxdepth 1 -name '*.rules'` — lista os arquivos `.rules` presentes num diretório (sem descer em subpastas), usado pra montar a lista `rule-files` do `suricata.yaml`.
- `suricata -T -c ./suricata.yaml -v` — roda o Suricata em modo "test config" (`-T`), só valida o arquivo de configuração e as regras, sem processar tráfego nenhum.
- `suricata -c ./suricata.yaml -r pcap -l diretório` — roda o Suricata em modo replay offline, lendo um arquivo PCAP (`-r`) em vez de uma interface ao vivo, e salva os logs/alertas (`eve.json`) no diretório indicado (`-l`).

## Task - 9-suricata_analysis.sh
O que faz: Roda o Suricata em replay contra um PCAP com tráfego misto, filtra o `eve.json` só pelos eventos do tipo "alert", extrai os campos relevantes de cada alerta e monta um relatório agregado — total de alertas, assinaturas únicas, distribuição por severidade, por categoria (reconnaissance, exploit, lateral_movement, exfiltration, malware_c2, policy_violation, other) e top IPs de origem/destino.
Como usar: `sudo ./9-suricata_analysis.sh [pcap]`
Comandos: nenhum comando novo — reusa `suricata -c ... -r ... -l ...` (já visto no exercício 8) pra rodar o replay; o resto é jq puro sobre o `eve.json`.

## Task - 10-rule_validation.sh
O que faz: Prova que cada regra custom do `meddefense.rules` realmente dispara contra o PCAP rotulado feito especificamente pra ela — roda o Suricata com as regras injetadas pra cada PCAP, conta quantos alertas bateram com o sid esperado no `eve.json`, e falha (exit != 0) se qualquer regra não disparar.
Como usar: `sudo ./10-rule_validation.sh`
Comandos: nenhum comando novo — reusa `suricata -c ... -r ... -l ...` e `readlink -f` (já vistos antes) pra cada um dos 6 PCAPs rotulados.

## Task - 11-pcap_investigation.sh
O que faz: Investiga um PCAP "na mão" — sem regra, sem assinatura — extraindo estatísticas de conversação TCP/UDP, consultas DNS, requisições HTTP, SNI de TLS, indícios de transferência de arquivo e a distribuição de protocolos, tudo consolidado num único relatório JSON.
Como usar: `sudo ./11-pcap_investigation.sh [pcap]`
Comandos:
- `capinfos -c -u pcap` — mostra estatísticas gerais de um arquivo de captura (contagem de pacotes, duração), usado aqui pra pegar a duração e o total de pacotes.
- `tshark -q -z conv,tcp -r pcap` — estatística de conversações TCP (pares origem/destino, pacotes, bytes) de uma captura, em modo "quiet" (só o relatório resumido, sem listar pacote a pacote).
- `tshark -q -z conv,udp -r pcap` — a mesma estatística de conversação, só que pra UDP.
- `tshark -Y 'dns.flags.response==0' -T fields -e frame.time_epoch -e ip.src -e dns.qry.name -e dns.qry.type -r pcap` — extrai só as consultas DNS (não as respostas) com timestamp, origem, nome consultado e tipo de registro.
- `tshark -Y http.request -T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri -r pcap` — extrai as requisições HTTP com origem, destino, host, método e URI.
- `tshark -Y 'tls.handshake.type==1' -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tls.handshake.extensions_server_name -r pcap` — extrai o SNI (nome do servidor pedido) de cada handshake TLS ClientHello (type 1).
- `tshark -Y 'http.content_type or smb2.filename' -T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.content_type -e smb2.filename -r pcap` — extrai indícios de transferência de arquivo via HTTP (content-type) ou SMB2 (nome do arquivo).
- `tshark -q -z io,phs -r pcap` — mostra a hierarquia/distribuição de protocolos da captura (quanto por cento é tcp, udp, icmp etc.).

## Task - 13-dns_filtering.sh
O que faz: Configura o dnsmasq como filtro DNS local — encaminha tudo pro resolver upstream configurado, faz sinkhole (responde 0.0.0.0) pra todo domínio da blocklist, ativa log de todas as consultas, reinicia o serviço e valida com `dig` que um domínio permitido resolve normal, um bloqueado vira 0.0.0.0 e um domínio neutro (fora das duas listas) também resolve normal.
Como usar: `sudo ./13-dns_filtering.sh`
Comandos:
- `dnsmasq --version` — mostra a versão instalada do dnsmasq.
- `systemctl restart dnsmasq` — reinicia o serviço dnsmasq pra aplicar a configuração nova.
- `dig @127.0.0.1 dominio A` — consulta um servidor DNS específico (aqui, o dnsmasq local na loopback) pelo registro A de um domínio, usado nas 3 validações (permitido / bloqueado / neutro).
