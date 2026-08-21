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
O que faz: Lê o baseline gerado pelo script 0 e classifica cada socket em escuta com função (banco de dados, web, ssh, etc.) e criticidade, sinalizando exposições perigosas — serviço de banco/RPC ligado em 0.0.0.0, ou protocolo inerentemente inseguro (telnet, ftp, snmp v1/v2c, rlogin, nfs v2/v3).
Como usar: `sudo ./1-attack_surface.sh [network_baseline.json] [output.json]`
Comandos:
- `readlink -f /proc/$pid/exe` — resolve o caminho real do binário que abriu o socket, para identificar o executável exato.
- `dpkg -S "$exec_path"` — descobre a qual pacote instalado pertence o binário, ligando o serviço exposto à sua origem.
- `grep -oE '[a-zA-Z0-9@._-]+\.service' /proc/$pid/cgroup` — extrai o nome da unidade systemd associada ao processo a partir do cgroup.
- `systemctl show "$candidate" --no-pager -p LoadState` — confirma que a unidade systemd encontrada está realmente carregada, validando a atribuição do serviço.
