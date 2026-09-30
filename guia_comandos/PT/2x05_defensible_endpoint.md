# 2x05 – Defensible Endpoint

## Task - 0-environment_intake.sh
O que faz: Coleta um retrato completo do host Linux (hawthorne-app-01) pro intake da capstone — hostname, kernel, distro, nível de patch, contagem de pacotes, sockets em escuta, serviços systemd ativos, configuração efetiva do sshd, parâmetros sysctl de segurança, contagem de binários SUID/SGID e arquivos world-writable, tamanho do ruleset nftables e status de auditd/rsyslog/Sysmon — tudo num único JSON.
Como usar: `./0-environment_intake.sh` (grava em `artifacts/<hostname>-capstone-environment_intake.json`)
Comandos:
- `hostname` — identifica o host no relatório de intake.
- `uname -r` — versão do kernel em execução.
- `grep '^PRETTY_NAME=' /etc/os-release` — extrai a distribuição/versão do SO.
- `apt list --upgradable` — conta quantas atualizações estão pendentes, usado como nível de patch.
- `dpkg-query -W` — conta o total de pacotes instalados.
- `ss -tulnpH` — lista sockets TCP/UDP em escuta com processo dono.
- `systemctl list-units --type=service --state=active --no-legend --no-pager` — lista os serviços systemd atualmente ativos.
- `sudo sshd -T` — despeja a configuração efetiva do sshd (todas as diretivas já resolvidas, não só o que está escrito no arquivo).
- `sysctl <parâmetro> [<parâmetro> ...]` — lê de uma vez vários parâmetros de segurança do kernel (ip_forward, ASLR, redirects, syncookies etc.).
- `sudo find / -perm /6000 -type f` — conta binários com bit SUID ou SGID.
- `sudo find / -path /proc -prune -o -path /sys -prune -o -perm -0002 -type f -print` — conta arquivos graváveis por qualquer usuário, excluindo /proc e /sys.
- `sudo nft list ruleset` — mede o tamanho em bytes do ruleset nftables atualmente carregado.
- `systemctl is-active auditd` / `systemctl is-active rsyslog` — status dos dois serviços de telemetria.
- `command -v sysmon` — verifica se o Sysmon for Linux está instalado e devolve o caminho do executável.

## Task - 0-environment_intake.ps1
O que faz: Contraparte Windows do intake — hostname, build do SO, nível de patch (UBR), contagem de features instaladas, serviços em execução, contas de usuário local, status do firewall por perfil, política de auditoria completa, presença/versão do Sysmon com o tamanho do canal de log, estado do Script Block Logging e política de conta — serializado num único JSON.
Como usar: `.\0-environment_intake.ps1` (PowerShell como Administrador; grava em `artifacts\<hostname>-capstone-environment_intake.json`)
Comandos:
- `hostname` — identifica o host no relatório de intake.
- `Get-ComputerInfo` — usado aqui só pelo campo OsBuildNumber, o build do SO.
- `Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'` — lê o UBR (Update Build Revision), o nível de patch fino do Windows.
- `Get-CimInstance Win32_OperatingSystem` — descobre o ProductType (workstation vs server/DC) pra decidir qual comando de feature usar a seguir.
- `Get-WindowsOptionalFeature -Online` / `Get-WindowsFeature` — contam as features instaladas; o primeiro em workstation, o segundo em server/DC.
- `Get-Service` — lista os serviços e filtra os que estão em execução.
- `Get-LocalUser` — lista as contas de usuário local.
- `Get-NetFirewallProfile` — status (ligado/desligado) de cada perfil do Windows Firewall.
- `auditpol /get /category:*` — despeja a política de auditoria completa, todas as categorias.
- `Get-Service -Name "Sysmon*"` — verifica se o serviço Sysmon está instalado.
- `Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\<serviço>"` — lê o ImagePath do serviço Sysmon pra localizar o executável e extrair a versão.
- `Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational"` — tamanho do canal de log do Sysmon, sem ler os eventos em si.
- `Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'` — estado da política de Script Block Logging.
- `net accounts` — política de conta (bloqueio, tamanho mínimo de senha, expiração).
- `ConvertTo-Json -Depth N | Set-Content -Path <arquivo> -Encoding UTF8` — serializa o objeto PowerShell resultante em JSON e grava o arquivo de intake em disco.

## Task - 1-baseline_snapshot.sh
O que faz: Roda o Lynis em modo rápido contra o host Linux, extrai do relatório bruto o Hardening Index, a contagem de warnings e de suggestions, e grava tudo — junto com o log completo do Lynis — como baseline "antes do hardening", pra comparar depois com o resultado da Tarefa 3.
Como usar: `sudo ./1-baseline_snapshot.sh` (grava em `capstone/baseline/baseline_linux.json` e `capstone/baseline/lynis_baseline.log`)
Comandos:
- `lynis audit system --quick --no-colors` — roda a auditoria completa do Lynis sem prompts interativos e sem códigos de cor, pra sair limpo no log.
- `grep -m1 '^hardening_index=' /var/log/lynis-report.dat` — extrai a primeira ocorrência do Hardening Index do relatório bruto do Lynis.
- `grep -c '^warning\[\]='` / `grep -c '^suggestion\[\]='` — contam quantos achados de cada tipo (warning/suggestion) o Lynis registrou no relatório.
- `lynis --version` — versão do Lynis instalado, registrada no baseline pra rastreabilidade.

## Task - 1-baseline_snapshot.ps1
O que faz: Roda o helper de auditoria fornecido pelo laboratório (win_audit.ps1) e o script de scoring CIS Level 1 do módulo 2x01 (15-master_validation.ps1) contra o host Windows, calcula a taxa de aprovação (pass_rate_percent) e grava o baseline "antes do hardening".
Como usar: `.\1-baseline_snapshot.ps1` (PowerShell como Administrador; grava em `capstone\baseline\baseline_windows.json` e `capstone\baseline\windows_baseline.log`)
Comandos:
- (nenhum comando novo — invoca diretamente os scripts `win_audit.ps1` e `15-master_validation.ps1` já existentes no módulo 2x01, e usa `Get-Content -Raw | ConvertFrom-Json` pra ler de volta o relatório JSON que eles produzem)

## Task - 2-target_state.sh
O que faz: Declara o "contrato" de estado-alvo da capstone — 29 controles cobrindo hardening, telemetria, patching, rede e handoff nas duas plataformas — cada um com id, plataforma, família, descrição, tipo de checagem (file_exists/json_field_equals/json_field_gte/command_exit_zero/grep_match), alvo da checagem e valor esperado. Não inspeciona o sistema — só materializa o JSON que a Tarefa 8 vai usar como fonte da verdade pra validar tudo. Recusa sobrescrever um target_state.json já existente a menos que `--force` seja passado.
Como usar: `./2-target_state.sh [--force]` (grava em `capstone/target_state.json`)
Comandos: nenhum comando de sistema — o script é jq puro, monta a lista de controles direto em JSON.

## Task - 3-linux_harden.sh
O que faz: Orquestra o hardening Linux completo em ordem determinística — SSH, sysctl, permissões (SUID/world-writable), minimização de serviços, PAM, AppArmor e auditd — reaproveitando os scripts do módulo 2x00 (com overrides locais quando um deles precisa de ajuste específico pro Hawthorne, ex.: whitelist de serviços e usuário permitido no SSH). Captura stdout e exit code de cada etapa num log, roda o Lynis de novo no final e só sai 0 se todas as etapas passaram e o novo Hardening Index bateu a meta definida em target_state.json.
Como usar: `sudo ./3-linux_harden.sh`
Comandos: nenhum comando novo — reaproveita `lynis audit system --quick --no-colors` e `grep -m1 '^hardening_index='`, já vistos na Tarefa 1; a novidade aqui é orquestrar os sete scripts de hardening do módulo 2x00 em sequência, não um comando de sistema novo.

## Task - 4-windows_harden.ps1
O que faz: Orquestra o hardening Windows completo em ordem — política de conta, política de auditoria, Windows Firewall, implantação do Sysmon, Script Block Logging, AppLocker e minimização de serviços — reaproveitando os scripts do módulo 2x01 (com overrides locais, ex.: subnet correta nas regras de firewall de gerência). Captura stdout e exit code de cada etapa, roda de novo o win_audit.ps1 e o scoring CIS Level 1 no final, e emite o mesmo schema JSON do script irmão Linux (Tarefa 3) pra que a Tarefa 8 leia as duas plataformas sem precisar de lógica diferente.
Como usar: `.\4-windows_harden.ps1` (PowerShell como Administrador)
Comandos: nenhum comando novo — reaproveita `Get-Content -Raw | ConvertFrom-Json`, já visto na Tarefa 1, pra ler o target_state.json e os relatórios de validação; a novidade aqui é orquestrar os sete scripts de hardening do módulo 2x01 em sequência, não um comando de sistema novo.

## Task - 5-telemetry_deploy.sh
O que faz: Garante que o auditd está ativo com o rules file do meddefense carregado, roda uma sequência controlada de ações de teste (criar/remover usuário, reiniciar serviço, criar/remover cron job, find como root) e confirma via ausearch que cada uma gerou o evento esperado com a chave certa. Exporta os últimos 30 minutos de eventos auditd e syslog.
Como usar: `sudo ./5-telemetry_deploy.sh` (grava em `capstone/telemetry/linux_events.json`)
Comandos:
- `ausearch -ts recent -k <chave>` — busca eventos recentes de auditoria marcados com uma chave específica, usado pra confirmar que cada ação de teste realmente gerou o registro esperado.
- `augenrules --load` — recarrega o conjunto de regras de auditoria a partir de /etc/audit/rules.d/, garantindo que a regra do meddefense.rules está efetivamente em vigor.
- `useradd -M -N -s /usr/sbin/nologin <usuário>` / `userdel <usuário>` — gatilho: cria e depois remove um usuário de teste pra disparar eventos de identidade.
- `systemctl restart cron` (ou `rsyslog` como alternativa) — gatilho: reinicia um serviço pra disparar evento de execução de processo.
- `crontab -l` / `crontab -` — gatilho: agenda e depois remove um cron job de teste pra disparar evento de persistência via cron.
- `find /tmp -maxdepth 1 -name "<padrão>"` — gatilho: execução autorizada como root, pra testar rastreamento de processo.
- `journalctl --since "30 minutes ago" --no-pager` (ou `tail -n 500 /var/log/syslog` como alternativa) — exporta a janela recente de log do sistema junto com os eventos do auditd.

## Task - 5-telemetry_deploy.ps1
O que faz: Confirma que Sysmon e Script Block Logging estão realmente ativos, roda uma sequência controlada de ações de teste (criar usuário local, tarefa agendada, reiniciar serviço, comando PowerShell autorizado) e verifica em cada canal de evento relevante (Security, System, PowerShell Operational) se o Event ID esperado apareceu dentro de 10 minutos. Exporta os últimos 30 minutos de eventos Sysmon e PowerShell.
Como usar: `.\5-telemetry_deploy.ps1` (PowerShell como Administrador; grava em `capstone\telemetry\windows_events.json` e `windows_coverage.json`)
Comandos:
- `Get-WinEvent -FilterHashtable @{ LogName=...; Id=...; StartTime=... }` — consulta um log de eventos filtrando por ID e janela de tempo, usado tanto pra confirmar cada gatilho individual quanto pra exportar a janela de 30 minutos de Sysmon/PowerShell.
- `New-LocalUser` / `Remove-LocalUser` — gatilho: cria e remove um usuário local de teste pra disparar o Security EID 4720.
- `Register-ScheduledTask` / `Start-ScheduledTask` / `Unregister-ScheduledTask` — gatilho: cria, executa e remove uma tarefa agendada de teste pra disparar o Security EID 4698.
- `Restart-Service -Name "Spooler" -Force` — gatilho: reinicia um serviço pra disparar o System EID 7036.

## Task - 6-patch_pipeline.sh
O que faz: Orquestra o pipeline de patch do módulo 2x03 (13-patch_pipeline.sh) end-to-end contra o host, redirecionando os artefatos de cada sub-etapa pra dentro do pacote da capstone via a variável CAPSTONE_ARTIFACTS_DIR, consumindo o feed de CVE e a blacklist mandatória fornecidos pelo laboratório, e configurando unattended-upgrades com essa blacklist. Só sai 0 se o pipeline terminou com exit 0 e nenhuma entrada do log de execução ficou em status "failed".
Como usar: `sudo ./6-patch_pipeline.sh` (consome `/home/analyst/MedDefense_Lab/capstone/cve_feed.json` e `blacklist.json`; grava em `capstone/patch/`)
Comandos: nenhum comando novo — a novidade é orquestração (`export CAPSTONE_ARTIFACTS_DIR=...` e `sudo -E bash <script>`, esse último necessário pra propagar as variáveis de ambiente pro sub-processo em vez de perdê-las no `sudo` puro) sobre os scripts já existentes do módulo 2x03; a checagem de falhas reusa `jq` sobre o log de execução já produzido por eles.

## Task - 7-network_deploy.sh
O que faz: Orquestra a pilha de defesa de rede contra o host — copia o segmentation_rules.json específico do Hawthorne (não regenera a topologia principal da MedDefense), valida e opcionalmente aplica o nftables do módulo 2x04, roda o teste funcional do ruleset ao vivo, sobe o Suricata e reproduz cada PCAP fornecido, roda a validação das regras customizadas contra os PCAPs rotulados e configura o filtro DNS local. Por padrão roda o nftables em `--render-only` (só valida a sintaxe, não carrega ao vivo, pra não arriscar derrubar a própria sessão de gerência); `--apply-live` é necessário pra realmente aplicar o ruleset e pra rodar o teste funcional contra ele.
Como usar: `sudo ./7-network_deploy.sh [--apply-live]` (grava em `capstone/network/`)
Comandos: nenhum comando novo diretamente — orquestra `4-nftables_config.sh`, `8-suricata_setup.sh`, `9-suricata_analysis.sh` e os overrides de `10-rule_validation.sh`/`13-dns_filtering.sh` do módulo 2x04, além do `5-firewall_test.sh` (script novo, criado neste módulo porque a Tarefa 5 original do 2x04 nunca tinha sido implementada), que reusa `nft list ruleset`, já visto no módulo 2x04, pra conferir se cada fluxo declarado em segmentation_rules.json realmente tem uma regra correspondente carregada.

## Task - 8-validate_all.sh
O que faz: Lê target_state.json, avalia cada um dos 29 controles despachando por check_type (file_exists, json_field_equals, json_field_gte, command_exit_zero, grep_match), pula os controles cuja plataforma não bate com o host atual, e agrega os resultados por família de controle (hardening/telemetry/patching/network/handoff) num relatório machine-readable. Precisa rodar como root, já que várias checagens exigem privilégio (aa-status, auditctl, nft list ruleset). Só sai 0 se não houver nenhum fail nem error entre os controles avaliados.
Como usar: `sudo ./8-validate_all.sh [target_state.json]` (grava em `capstone/validation.json`)
Comandos:
- `eval "$comando"` — checagem command_exit_zero: executa dinamicamente a string de comando definida no campo check_target de um controle e avalia só o exit code.
- `grep -Eq -- "$padrão" <arquivo>` — checagem grep_match: procura o expected_value (regex estendida) no arquivo alvo, em modo silencioso (sem imprimir nada, só o exit code).
- `jq -c "$campo" <arquivo>` — checagens json_field_equals/json_field_gte: extrai o valor de um campo do JSON alvo preservando o tipo original (string, número, bool) pra comparação, ao contrário de `jq -r`, que sempre devolve texto puro e quebraria a comparação numérica/booleana.
- `awk -v p="$total_pass" -v t="$total_avaliado" 'BEGIN { printf "%.1f", (p / t) * 100 }'` — calcula a porcentagem de aprovação com uma casa decimal.
