# 2x00 – Locking the Gates

## Task - 0-baseline_snapshot.sh
O que faz: Captura um snapshot completo e somente-leitura do estado de segurança do host antes de qualquer hardening — serviços, portas, binários SUID/SGID, arquivos world-writable, parâmetros sysctl e configuração SSH — para servir de linha de base comparável depois.
Como usar: `sudo ./0-baseline_snapshot.sh [output.json]`
Comandos:
- `hostname` — mostra o nome do host, usado para identificar o sistema no relatório de baseline.
- `cat /etc/os-release` — mostra a distribuição/versão do SO, necessário para saber qual benchmark de segurança se aplica.
- `uname -r` — mostra a versão do kernel em execução, usada para cruzar com CVEs de kernel conhecidas.
- `uptime -p` — mostra há quanto tempo o sistema está no ar sem reiniciar, indicador de disciplina de patch/reboot.
- `systemctl list-units --type=service --state=running` — lista todos os serviços atualmente em execução, o inventário base de superfície de ataque.
- `ss -tulnH` — lista sockets TCP/UDP em escuta, mostrando quais portas estão realmente acessíveis no host.
- `find / -xdev -type f -perm -4000` — localiza binários com bit SUID, o vetor clássico de escalonamento de privilégio local.
- `find / -xdev -type f -perm -2000` — localiza binários com bit SGID, mesmo risco de escalonamento em nível de grupo.
- `find / -xdev -type f -perm -0002` — localiza arquivos graváveis por qualquer usuário (world-writable), que um atacante pode alterar para que um processo privilegiado execute depois.
- `cat /proc/sys/<parametro>` — lê o valor atual de um parâmetro sysctl direto do kernel em execução.
- `grep -iE '^\s*<Diretiva>\s+' /etc/ssh/sshd_config` — verifica o valor atual de uma diretiva específica do sshd_config.
- `awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd` — lista as contas de usuário "normais" (não de sistema) a partir da base de senhas.
- `getent group sudo` — lista os membros do grupo sudo, ou seja, quem tem escalonamento de privilégio administrativo.

## Task - 1-cis_profile.sh
O que faz: Gera o catálogo de controles CIS priorizados por ameaça (MD-CIS-001 a 015) que a empresa decidiu implementar, mapeando cada controle ao script de remediação e ao método de verificação correspondente.
Como usar: `./1-cis_profile.sh`
Comandos:
- Nenhum comando de sistema — o script apenas gera um catálogo estático em JSON via jq, sem inspecionar o host.

## Task - 2-lynis_parse.sh
O que faz: Converte o relatório bruto do Lynis (lynis-report.dat) em um JSON estruturado com o índice de hardening e todos os achados (warning/suggestion/manual_check), para consumo pelas demais tarefas.
Como usar: `./2-lynis_parse.sh /var/log/lynis-report.dat`
Comandos:
- `grep '^hardening_index=' <relatorio.dat>` — extrai o índice de hardening (score) do relatório do Lynis.

## Task - 3-remediation_queue.sh
O que faz: Cruza o perfil CIS (Tarefa 1) e os achados do Lynis (Tarefa 2) com o estado real do sistema para classificar cada controle (compliant/non_compliant/etc.) e gera uma fila de remediação priorizada.
Como usar: `./3-remediation_queue.sh [cis_profile.json] [lynis_findings.json]`
Comandos:
- `id -u` — verifica se o script está rodando como root (necessário para visibilidade completa do sistema).
- `grep 'minlen' /etc/security/pwquality.conf` — verifica a política de tamanho mínimo de senha configurada.
- `findmnt -no OPTIONS /tmp` — mostra as opções de montagem atuais (ex.: noexec, nosuid) aplicadas a um sistema de arquivos.
- `systemctl list-unit-files --type=service --state=enabled` — lista serviços configurados para iniciar no boot (superfície de ataque persistente entre reboots).
- `grep 'deny' /etc/security/faillock.conf` — verifica o limite de tentativas configurado para bloqueio de conta.
- `aa-status --enforced` — lista os perfis AppArmor atualmente em modo enforce (bloqueio ativo).
- `grep 'identity' /etc/audit/rules.d/meddefense.rules` — verifica se uma regra de auditoria específica está presente no arquivo de regras.
- `grep 'ENABLED=' /etc/ufw/ufw.conf` — verifica se o firewall UFW está configurado para ficar habilitado.
- `find /etc/rsyslog.d -iname '*meddefense*'` — verifica se uma política customizada de roteamento de log já foi implantada.

## Task - 4-ssh_hardening.sh
O que faz: Aplica o hardening do SSH (sem senha, sem root, MaxAuthTries, timeout de sessão, banner de aviso, etc.) editando o sshd_config de forma idempotente e reiniciando o serviço.
Como usar: `sudo ./4-ssh_hardening.sh [caminho-do-sshd_config]`
Comandos:
- `cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config.bak` — faz backup de um arquivo de configuração antes de alterá-lo, preservando permissões e timestamps.
- `sed -i -E 's|...|...|' /etc/ssh/sshd_config` — edita/substitui uma diretiva de configuração no lugar, de forma idempotente.
- `sshd -t -f /etc/ssh/sshd_config` — valida a sintaxe da configuração do sshd antes de aplicar/reiniciar o serviço.
- `systemctl restart ssh.service` — reinicia um serviço para aplicar a nova configuração.
- `systemctl is-active ssh.service` — verifica se um serviço está ativo/em execução no momento.

## Task - 5-sysctl_hardening.sh
O que faz: Endurece parâmetros de rede e kernel via sysctl (desabilita IP forwarding, ICMP redirects, habilita ASLR completo, SYN cookies, etc.) para bloquear pivoteamento e reduzir a confiabilidade de exploits de memória.
Como usar: `sudo ./5-sysctl_hardening.sh [caminho-do-sysctl.conf]`
Comandos:
- `sysctl -p /etc/sysctl.conf` — aplica os parâmetros de um arquivo sysctl diretamente ao kernel em execução.

## Task - 6-filesystem_hardening.sh
O que faz: Varre o sistema em busca de binários SUID/SGID fora da whitelist e arquivos world-writable, remove os bits/permissões perigosos, aplica noexec/nosuid/nodev em /tmp, /var/tmp e /dev/shm, e restringe o acesso ao cron.
Como usar: `sudo ./6-filesystem_hardening.sh [SCAN_ROOT]`
Comandos:
- `chmod u-s <arquivo>` — remove o bit SUID de um binário, eliminando um caminho de escalonamento de privilégio.
- `chmod g-s <arquivo>` — remove o bit SGID de um binário.
- `chmod o-w <arquivo>` — remove a permissão de escrita para "outros" de um arquivo.
- `chmod <modo numérico> <arquivo>` — define permissões explícitas em modo numérico (ex.: 600 no cron.allow, restringindo quem pode agendar cron).
- `stat -c '%a' <arquivo>` — mostra os bits de permissão de um arquivo, usado para registrar o estado antes/depois.
- `mount -o remount,<opções> <ponto_de_montagem>` — reaplica opções de montagem (ex.: noexec,nosuid,nodev) a um sistema de arquivos já montado, sem precisar desmontar.

## Task - 7-service_minimization.sh
O que faz: Compara os serviços habilitados contra uma whitelist de serviços necessários e para/desabilita tudo que não está na lista, reduzindo a superfície de ataque exposta.
Como usar: `sudo ./7-service_minimization.sh` (ou `DRY_RUN=1 ./7-service_minimization.sh` só para simular)
Comandos:
- `systemctl start <unidade>` — inicia um serviço exigido que deveria estar rodando mas não está.
- `systemctl stop <unidade>` — para um serviço em execução que não está na whitelist.
- `systemctl disable <unidade>` — impede que um serviço inicie automaticamente no boot.

## Task - 8-pam_hardening.sh
O que faz: Instala e configura libpam-pwquality e pam_faillock para impor política de complexidade de senha, bloqueio de conta após tentativas falhas e histórico de senha, editando a pilha PAM com backups de segurança.
Como usar: `sudo ./8-pam_hardening.sh`
Comandos:
- `dpkg -s <pacote>` — verifica se um pacote está instalado e qual sua versão.
- `apt-get install -y <pacote>` — instala um pacote de forma não interativa.

## Task - 9-apparmor_config.sh
O que faz: Verifica e força o modo enforce dos perfis AppArmor de Apache/MySQL e implanta um perfil customizado para a aplicação de billing, confinando o processo mesmo em caso de comprometimento.
Como usar: `sudo ./9-apparmor_config.sh`
Comandos:
- `grep 'Y' /sys/module/apparmor/parameters/enabled` — verifica se o módulo de kernel do AppArmor está carregado/habilitado.
- `aa-status --complaining` — lista os perfis AppArmor rodando em modo complain (apenas registra, não bloqueia).
- `aa-enforce <binário/perfil>` — muda um perfil AppArmor de complain para enforce (bloqueio ativo).
- `apparmor_parser -r <perfil>` — recarrega/compila um perfil AppArmor no kernel.
- `diff -q <arquivo1> <arquivo2>` — compara dois arquivos para saber se o conteúdo realmente mudou (decide se precisa reescrever/recarregar).

## Task - 10-auditd_config.sh
O que faz: Instala/habilita o auditd e implanta um conjunto de regras de auditoria no nível de kernel (arquivos de identidade, config SSH/PAM, escalonamento de privilégio, ferramentas suspeitas, persistência), validando com um teste funcional controlado.
Como usar: `sudo ./10-auditd_config.sh`
Comandos:
- `systemctl enable --now <serviço>` — habilita um serviço para iniciar no boot E o inicia imediatamente, em um único comando.
- `augenrules --load` — compila e carrega todos os arquivos de regras do rules.d no subsistema de auditoria do kernel.
- `auditctl -R <arquivo_de_regras>` — carrega um arquivo de regras específico diretamente no kernel (alternativa quando augenrules não está disponível).
- `auditctl -l` — lista as regras de auditoria atualmente ativas no kernel.
- `useradd -M -N -s /usr/sbin/nologin <usuário>` — cria uma conta de teste descartável (sem home, sem grupo próprio, sem shell) para um teste controlado.
- `userdel <usuário>` — remove uma conta de usuário, limpando os artefatos do teste.
- `ausearch --input-logs -ts recent -k <chave>` — busca no log de auditoria eventos marcados com uma chave de regra específica.

## Task - 11-audit_coverage_test.sh
O que faz: Executa seis gatilhos controlados e reversíveis (sudo, criação de usuário, curl, alteração do sshd_config, escrita em init.d/cron.d) e confirma via ausearch que cada regra de auditoria da Tarefa 10 realmente captura o evento.
Como usar: `sudo ./11-audit_coverage_test.sh`
Comandos:
- `sudo -n true` — testa se há credenciais sudo em cache/sem senha disponíveis (verificação não interativa de privilégio); também usado aqui para gerar um evento controlado de escalonamento de privilégio.
- `curl --version` — comando inofensivo executado para gerar um evento controlado de "execução de ferramenta suspeita" e testar a cobertura de auditoria.
- `touch <arquivo>` — atualiza apenas a data de modificação de um arquivo (usado aqui para disparar uma regra de auditoria de mudança de atributo sem alterar o conteúdo).

## Task - 12-log_config.sh
O que faz: Configura o roteamento do rsyslog (auth/authpriv para auth.log, o resto para syslog), define políticas de retenção via logrotate e corrige permissões/dono dos arquivos de log, verificando tudo com um marcador de teste via logger.
Como usar: `sudo ./12-log_config.sh`
Comandos:
- `logger -p <facility.priority> <mensagem>` — injeta uma mensagem de teste no log do sistema numa facility/prioridade específica, usada para verificar o roteamento de log.
- `chown <usuário>:<grupo> <arquivo>` — altera o dono e o grupo de um arquivo.

## Task - 13-firewall_baseline.sh
O que faz: Configura o UFW com política default-deny de entrada, libera apenas SSH (rede de gestão), HTTP/HTTPS e MySQL (rede de aplicação), ativa logging e habilita o firewall.
Como usar: `sudo ./13-firewall_baseline.sh`
Comandos:
- `ufw default deny incoming` — define a política padrão do firewall para negar tráfego de entrada não explicitamente permitido.
- `ufw default allow outgoing` — define a política padrão do firewall para permitir tráfego de saída.
- `ufw allow from <rede> to any port <porta> proto tcp` — libera uma porta apenas para uma rede de origem específica (ACL segmentada).
- `ufw allow <porta>/tcp` — libera uma porta para qualquer origem (regra aberta).
- `ufw logging low` — define o nível de verbosidade do log do firewall.
- `ufw status verbose` — mostra o status atual do firewall, políticas padrão e o conjunto de regras.
- `ufw --force enable` — ativa o firewall sem pedir confirmação interativa.

## Task - 14-hardening_orchestrator.sh
O que faz: Orquestra a execução em ordem das tarefas 0, 2, 4-13 e 15, para o pipeline no primeiro passo que falhar, e produz o delta de score do Lynis antes/depois para provar que o hardening funcionou.
Como usar: `sudo ./14-hardening_orchestrator.sh` (ou `DRY_RUN=1 ./14-hardening_orchestrator.sh` para testar só o fluxo de controle)
Comandos:
- `lynis audit system --quick --no-colors` — executa uma varredura completa de segurança com o Lynis e grava um relatório.

## Task - 15-validation.sh
O que faz: Roda uma bateria independente de verificações pós-hardening (SSH, sysctl, SUID, mount options, PAM, serviços, auditd, AppArmor, logs, UFW) e produz um relatório PASS/FAIL por controle CIS.
Como usar: `sudo ./15-validation.sh` (funciona sem root, mas com verificações parciais em itens que exigem privilégio, como UFW)
Comandos:
- Nenhum comando novo — reaplica os padrões de verificação já listados (grep de configs, `cat /proc/sys`, `find` de SUID/SGID, `systemctl is-active`/`list-unit-files`, `ufw status verbose`, `find` da política rsyslog) para validar o estado pós-hardening.

## Task - 16-lynis_diff.sh
O que faz: Compara os achados do Lynis antes e depois do hardening (por test_id) para classificar cada um como resolvido, remanescente ou novo, e calcula o delta do índice de hardening.
Como usar: `./16-lynis_diff.sh [before_findings.json] [after_findings.json]`
Comandos:
- Nenhum comando novo — reexecuta `lynis audit system --quick --no-colors` (já listado na Tarefa 14) para gerar o scan pós-hardening de comparação, quando ainda não existe um.

## Task - 17-compliance_bundle.sh
O que faz: Consolida os seis artefatos de evidência gerados pelas tarefas anteriores em um bundle de compliance único, pronto para auditoria, com controles remediados/verificados, desvios documentados e achados residuais.
Como usar: `./17-compliance_bundle.sh`
Comandos:
- Nenhum comando de sistema novo — agrega os JSONs gerados pelas tarefas anteriores via jq; reutiliza `hostname`, `cat /etc/os-release` e `uname -r` já listados na Tarefa 0.
