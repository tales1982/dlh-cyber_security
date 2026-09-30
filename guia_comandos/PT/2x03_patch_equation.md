# 2x03 – Patch Equation

## Task - 0-vuln_inventory.sh
O que faz: Enumera pacotes instalados e identifica quais têm atualizações disponíveis vindas do pocket "security", extraindo CVEs do changelog (ou de um mapeamento USN local como fallback) e cruzando com CVSS e status no catálogo CISA KEV. Gera um inventário de vulnerabilidades priorizável por severidade.
Como usar: `./0-vuln_inventory.sh` (lê cve_feed.json e cisa_kev.json no mesmo diretório; grava vulnerability_inventory.json).
Comandos:
- `apt-cache policy <pacote>` — mostra a versão candidata e de qual repositório/pocket (security, updates, backports) ela viria, usado para priorizar apenas atualizações de segurança.
- `apt-get changelog <pacote>` — baixa o changelog do pacote (com timeout de 60s) para extrair os CVEs corrigidos em versões acima da instalada.
- `dpkg --compare-versions <v1> gt <v2>` — compara duas versões de pacote para saber se uma entrada do changelog é mais nova que a versão instalada.
- `dpkg-query -W -f='${binary:Package} ${Version} ${Status}\n'` — lista todos os pacotes instalados com nome, versão e status, em formato controlado.
- `apt list --upgradable` — lista os pacotes que têm uma versão mais nova disponível nos repositórios configurados.

## Task - 1-service_deps.sh
O que faz: Mapeia cada serviço systemd ativo ao pacote que o instalou e às bibliotecas compartilhadas que ele carrega, cruzando tudo com um arquivo de criticidade para decidir se o serviço precisa reiniciar quando o pacote for atualizado.
Como usar: `./1-service_deps.sh [service_criticality.json] [service_dependency_map.json]` (root recomendado, para ler /proc de todos os PIDs).
Comandos:
- `systemctl list-units --type=service --state=active --no-legend --plain` — lista todos os serviços systemd atualmente ativos.
- `systemctl show <serviço> --property=MainPID --value` — obtém o PID principal de um serviço, usado para localizar seu executável em /proc.
- `systemctl show <serviço> --property=ExecStart --value` — obtém o caminho do ExecStart definido na unit, usado como alternativa quando não há MainPID válido (ex: serviços oneshot).
- `dpkg -S <caminho>` — descobre qual pacote Debian é dono de um arquivo/executável específico.
- `readlink -f <caminho>` — resolve o caminho canônico (segue symlinks), necessário por causa do merged-/usr.
- `sudo -n readlink -f /proc/<pid>/exe` — tenta resolver o executável de um processo via sudo não-interativo, quando o usuário atual não tem permissão direta de leitura.
- `ldd <executável>` — lista as bibliotecas compartilhadas das quais um binário depende, para mapear pacotes adicionais afetados por uma atualização.

## Task - 2-pre_patch_snapshot.sh
O que faz: Tira a "foto" completa do sistema antes de qualquer patch: versões de todos os pacotes, estado de todos os serviços ativos, sockets escutando e hash SHA-256 de cada conffile rastreado pelo dpkg. É a linha de base contra a qual toda validação e rollback posteriores são comparados.
Como usar: `sudo ./2-pre_patch_snapshot.sh [output.json]`
Comandos:
- `dpkg-query -W -f='${Conffiles}\n' '*'` — lista todos os arquivos de configuração (conffiles) rastreados pelo dpkg em todos os pacotes instalados.
- `ss -tulnp` — lista todos os sockets TCP/UDP em modo de escuta com o processo dono, registrando a superfície de rede exposta antes do patch.
- `sha256sum -- <arquivos>` — calcula o hash SHA-256 de cada conffile, usado como impressão digital para detectar drift depois.

## Task - 3-patch_plan.sh
O que faz: Cruza o inventário de vulnerabilidades (T0) com o mapa de dependências de serviço (T1) e calcula uma pontuação de prioridade por pacote (CVSS + presença no CISA KEV + criticidade dos serviços afetados + exposição), classificando cada pacote em emergency/urgent/scheduled.
Como usar: `./3-patch_plan.sh [vulnerability_inventory.json] [service_dependency_map.json] [output.json]`
Comandos: nenhum comando de sistema — script é jq puro sobre os artefatos já gerados por T0 e T1, sem tocar no sistema real.

## Task - 4-patch_execute.sh
O que faz: Aplica cada patch do plano (T3) em ordem, com lock exclusivo contra execuções concorrentes, retry com backoff exponencial se o dpkg estiver ocupado, e reinício automático dos serviços afetados; registra estado "antes/depois" de cada pacote e serviço.
Como usar: `sudo ./4-patch_execute.sh [patch_plan.json] [output.json]` (PIPELINE_TEST=1 faz dry-run; LOCK_FILE customiza o caminho do lock).
Comandos:
- `apt-get install --only-upgrade -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold <pacote>` — atualiza um único pacote já instalado (nunca instala um novo), resolvendo automaticamente prompts de conffile modificado sem travar em stdin.
- `flock -n <fd>` — tenta obter um lock exclusivo sem bloquear, garantindo que duas execuções deste script nunca rodem ao mesmo tempo.
- `systemctl show <serviço> -p ActiveState --value` — consulta o estado ativo atual (active/inactive/failed) de um serviço, antes e depois do patch.
- `systemctl try-restart <serviço>` — reinicia um serviço somente se ele já estiver rodando, aplicado a cada serviço afetado pelo pacote recém-atualizado.
- `dpkg-query -W -f='${Version}' <pacote>` — consulta rapidamente a versão instalada de um único pacote.

## Task - 5-post_patch_validate.sh
O que faz: Compara o estado atual do sistema com o snapshot pré-patch (T2) — serviços, sockets escutando — e roda sondas de liveness (HTTP/TCP/comando) em todo serviço marcado como crítico, para provar que "o patch rodou" e "o patch é seguro" não são a mesma afirmação.
Como usar: `sudo ./5-post_patch_validate.sh [pre_patch_state.json] [output.json]`
Comandos:
- `curl -fsS --max-time 5 -o /dev/null <url>` — sonda de liveness HTTP: falha silenciosamente em erro, descarta o corpo da resposta, com timeout de 5s.
- `bash -c 'exec 3<>/dev/tcp/HOST/PORT'` — sonda de liveness TCP usando o pseudo-dispositivo /dev/tcp do bash para testar se uma porta aceita conexão (envolvido em timeout externamente).

## Task - 6-config_drift.sh
O que faz: Detecta arquivos de configuração (conffiles) que mudaram desde o snapshot pré-patch, separando drift "esperado" (causado pelo pacote que acabou de ser atualizado) de drift "inesperado", com diff unificado quando há uma cópia de referência em cache.
Como usar: `sudo ./6-config_drift.sh [pre_patch_state.json] [patch_execution_log.json] [output.json]`
Comandos:
- `diff -u <baseline> <atual>` — gera um diff unificado entre a última cópia conhecida-boa de um conffile e o arquivo atual, mostrando exatamente o que mudou.
- `cat /var/lib/dpkg/info/*.conffiles` — lê diretamente os arquivos internos do dpkg que listam quais caminhos cada pacote registra como conffile.

## Task - 7-apt_recovery.sh
O que faz: Diagnostica e repara um sistema apt/dpkg travado (lock preso, pacote meio-configurado) na ordem estritamente segura: remove locks órfãos, roda dpkg --configure -a, depois apt-get --fix-broken install, e reinicia os serviços dos pacotes que estavam quebrados.
Como usar: `sudo ./7-apt_recovery.sh [output.json]`
Comandos:
- `pgrep -fa '(dpkg|apt-get|apt)'` — lista processos vivos cujo comando corresponde ao padrão, usado para confirmar se dpkg/apt ainda está rodando antes de mexer em qualquer lock.
- `fuser <arquivo_de_lock>` — mostra qual processo, se algum, tem um arquivo de lock aberto no momento; distingue um lock "preso" (sem dono) de um lock legitimamente em uso.
- `dpkg --audit` — relata pacotes deixados em estado inconsistente (meio-instalado, meio-configurado etc).
- `dpkg -l` — lista pacotes instalados com suas flags de status; usado para achar qualquer pacote fora de ii/rc/un (quebrado).
- `df -k /` — mostra o espaço livre em disco (em KB) de um filesystem, usado aqui para diagnosticar falhas de dpkg por falta de espaço.
- `rm -f <arquivo_de_lock>` — remove um lock de dpkg/apt confirmado como órfão (sem processo vivo o segurando).
- `dpkg --configure -a` — termina de configurar todo pacote que ficou "desempacotado mas não configurado", primeiro passo obrigatório de reparo.
- `apt-get --fix-broken install -y` — resolve dependências quebradas, completando o que dpkg --configure -a não resolveu sozinho.

## Task - 8-unattended_config.sh
O que faz: Instala e configura o unattended-upgrades para aplicar somente patches de segurança automaticamente, com pacotes críticos (kernel, mysql, apache2) na blacklist e reboot automático desativado; termina com um dry-run para confirmar o que seria de fato atualizado.
Como usar: `sudo ./8-unattended_config.sh [output.json]`
Comandos:
- `dpkg -s <pacote>` — verifica se um pacote está instalado e mostra seus detalhes de status.
- `apt-get install -y unattended-upgrades -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold` — instala o pacote unattended-upgrades de forma não-interativa, se ainda não estiver presente.
- `systemctl enable --now apt-daily.timer apt-daily-upgrade.timer` — habilita e inicia imediatamente os timers systemd que disparam a checagem e o upgrade diários do apt.
- `systemctl is-active apt-daily.timer apt-daily-upgrade.timer` — confirma se os timers configurados estão de fato ativos.
- `unattended-upgrades --dry-run --debug` — simula uma execução do unattended-upgrades com log detalhado, sem instalar nada de verdade.
- `apt-mark showhold` — lista todos os pacotes atualmente marcados como "hold" (bloqueados para atualização).

## Task - 9-rollback.sh
O que faz: Reverte um pacote específico para a versão exata registrada no snapshot pré-patch (T2), confirma que essa versão ainda está disponível no cache/repositório antes de agir, aplica hold para impedir que o unattended-upgrades desfaça o rollback, e roda novamente as sondas dos serviços afetados.
Como usar: `sudo ./9-rollback.sh <pacote> [pre_patch_state.json]`
Comandos:
- `apt-cache madison <pacote>` — lista todas as versões de um pacote disponíveis no cache/repositórios configurados, usado para confirmar que a versão-alvo do rollback ainda pode ser obtida.
- `apt-get install -y --allow-downgrades <pacote>=<versão> -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold` — instala explicitamente uma versão mais antiga de um pacote, permitindo downgrade.
- `apt-mark hold <pacote>` — trava um pacote na versão atual, impedindo que o unattended-upgrades desfaça o rollback na próxima execução.

## Task - 10-version_hold.sh
O que faz: É o único script autorizado a alterar holds do apt-mark e o arquivo de pins /etc/apt/preferences.d/meddefense-pins: aplica todo hold listado em hold_registry.json (com dono e data de revisão) e libera qualquer hold que não esteja mais no registro.
Como usar: `sudo ./10-version_hold.sh [hold_registry.json] [output.json]`
Comandos:
- `apt-mark unhold <pacote>` — libera o hold de um pacote que não está mais listado no registro, permitindo que volte a ser atualizado normalmente.

## Task - 11-maintenance_window.sh
O que faz: Decide, de forma pura (sem tocar em pacotes), se o momento atual (ou um timestamp passado via AS_OF) está dentro de uma janela de manutenção configurada, incluindo suporte a uma janela de emergência sempre-ativa que exige override explícito.
Como usar: `./11-maintenance_window.sh [--check|--report|--wait <segundos>] [maintenance_windows.json]` (MEDDEFENSE_EMERGENCY=1 aceita a janela de emergência como sinal verde).
Comandos: nenhum comando de sistema — lógica pura de data/hora (date) e jq sobre maintenance_windows.json.

## Task - 12-change_log.sh
O que faz: Reconstrói o histórico de mudanças a partir de /var/log/apt/history.log (e suas rotações .gz), agrupa transações próximas no tempo em "eventos de mudança", classifica cada evento como dentro/fora da janela de manutenção e associa CVEs resolvidos por evento.
Como usar: `sudo ./12-change_log.sh [output.json]`
Comandos:
- `zcat <arquivo.log.N.gz>` — descomprime rotações antigas do log do apt (/var/log/apt/history.log.N.gz) para incluí-las na reconstrução do histórico.

## Task - 13-patch_pipeline.sh
O que faz: Orquestra a esteira completa — inventário, mapa de dependências, snapshot, plano, checagem de janela de manutenção, execução, validação, drift e change log — como uma única execução com status agregado.
Como usar: `sudo ./13-patch_pipeline.sh [output.json]` (PIPELINE_TEST=1 propaga dry-run para a execução; MEDDEFENSE_EMERGENCY=1 aceita a janela de emergência).
Comandos: nenhum comando de sistema novo — chama via bash cada um dos scripts 0, 1, 2, 3, 11, 4, 5, 6 e 12 em sequência, propagando status e artefatos.

## Task - 14-pipeline_test.sh
O que faz: Testa a esteira contra um cenário hipotético: troca temporariamente o feed de CVE real por um simulado, roda o pipeline inteiro em modo dry-run e compara o plano de patch resultante a um baseline esperado congelado.
Como usar: `sudo ./14-pipeline_test.sh [output.json]`
Comandos: nenhum comando de sistema novo — reexecuta 13-patch_pipeline.sh (PIPELINE_TEST=1) e compara patch_plan.json ao baseline via diff (já introduzido em T6).

## Task - 15-compliance_report.sh
O que faz: Consolida todos os artefatos já gerados pela esteira (inventário de vulnerabilidades, change log, holds, execução do pipeline) em um relatório único de conformidade por CVE — resolvido, aberto, adiado por hold ou por janela — com uma pontuação de conformidade sobre CVEs críticos/altos.
Como usar: `sudo ./15-compliance_report.sh [output.json]`
Comandos: nenhum comando de sistema novo — agrega, via jq, os artefatos já produzidos pelas etapas anteriores.
