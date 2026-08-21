# 2x02 – Eyes on Endpoint

## Task - 0-sysmon_validation.ps1
O que faz: Valida que o Sysmon realmente captura os cinco tipos de evento dos quais o projeto depende (criação de processo, conexão de rede, criação de arquivo, modificação de registro, consulta DNS), disparando uma ação real e segura para cada um e conferindo se apareceu no log Sysmon Operational. Read-only quanto ao sistema — os únicos artefatos criados (arquivo de teste e valor de registro) são removidos ao final.
Como usar: executar localmente no Windows com Sysmon instalado (`.\0-sysmon_validation.ps1`), de preferência com privilégios administrativos para gerar todos os gatilhos.
Comandos:
- `Get-WinEvent -LogName <log>` — consulta um log de eventos do Windows por ID/horário; cmdlet central para confirmar que o Sysmon efetivamente gravou um evento.
- `cmd.exe /c whoami` — gatilho seguro que gera um evento de criação de processo (Sysmon EID 1).
- `Test-NetConnection -ComputerName <ip> -Port <porta>` — testa conectividade TCP de saída; gatilho para o evento de conexão de rede (Sysmon EID 3).
- `New-Item -Path <chave> -Force` — cria uma chave de registro; parte do gatilho de modificação de registro (Sysmon EID 13).
- `New-ItemProperty -Path <chave> -Name <nome> -Value <valor> -PropertyType String` — grava um valor de registro; completa o gatilho de modificação de registro (Sysmon EID 13).
- `nslookup <domínio>` — resolve um nome DNS; gatilho para o evento de consulta DNS (Sysmon EID 22).
- `Resolve-DnsName -Name <domínio>` — resolvedor DNS nativo do PowerShell; gatilho alternativo para a mesma telemetria de consulta DNS.
- `Out-File -FilePath <caminho>` — grava um arquivo em disco; gatilho para o evento de criação de arquivo (Sysmon EID 11).

## Task - 1-sysmon_coverage_matrix.ps1
O que faz: Lê o sysmonconfig.xml realmente implantado e mapeia 7 técnicas MITRE ATT&CK para os Event IDs do Sysmon necessários para vê-las, avaliando se o filtro include/exclude de cada RuleGroup realmente cobre (covered), cobre só uma fatia (partial) ou deixa cego (blind) cada técnica.
Como usar: executar no host Windows onde o Sysmon está configurado (`.\1-sysmon_coverage_matrix.ps1`), apontando opcionalmente um sysmonconfig.xml customizado via `-SysmonConfigPath`.
Comandos:
- `Get-Content -Path <arquivo> -Raw` — lê o conteúdo bruto do sysmonconfig.xml implantado para ser parseado como XML; usado para auditar o que o Sysmon está de fato configurado a capturar.

## Task - 2-powershell_logging_validation.ps1
O que faz: Confirma que Script Block Logging, Module Logging e Transcription (habilitados via GPO no módulo anterior) realmente funcionam contra os tipos de PowerShell que o atacante Crimson Tide usou: cmdlet simples, comando codificado em Base64, import de módulo e script block multilinha.
Como usar: executar em um host Windows com PowerShell logging habilitado (`.\2-powershell_logging_validation.ps1`).
Comandos:
- `Get-Process` — gatilho: comando simples cujo script block deve ser capturado no EID 4104 (Script Block Logging).
- `powershell.exe -EncodedCommand <base64>` — gatilho: executa um comando codificado em Base64; testa se o log decodifica o conteúdo ofuscado.
- `Import-Module <nome>` — gatilho: importa um módulo PowerShell; gera evento de Module Logging (EID 4103).
- `Invoke-Expression <script>` — gatilho: executa dinamicamente um script block multilinha; testa se o bloco completo é capturado no EID 4104.
- `Get-ChildItem -Path <dir> -Filter "*.txt"` — lista arquivos no diretório de transcript; confirma que a transcrição da sessão foi de fato gravada em disco.

## Task - 3-windows_telemetry_export.ps1
O que faz: Exporta uma janela de tempo configurável (padrão: últimas 24h) dos logs Security, Sysmon Operational e PowerShell Operational para um único JSON normalizado, extraindo os campos-chave de cada tipo de evento (4624, 4625, 4672, 4688, 4104, Sysmon 1/3/11/13/22) a partir do XML estruturado do evento, não de regex sobre o texto livre.
Como usar: executar no host Windows a exportar (`.\3-windows_telemetry_export.ps1`), ajustando `-StartTime`/`-EndTime` para outra janela.
Comandos:
- (nenhum comando novo — reaproveita `Get-WinEvent`, já descrito na Tarefa 0, agora com `-FilterHashtable` para consultar múltiplos logs numa janela de tempo)

## Task - 4-windows_telemetry_quality.ps1
O que faz: Aplica um gate de qualidade sobre o export da Tarefa 3 — distribuição de eventos, balanceamento por canal, cobertura hora a hora, detecção de gaps (>30 min sem eventos), completude de campos nos tipos de evento que analistas realmente triam, e uma pontuação única 0-100 com veredito good/acceptable/poor.
Como usar: executar após a Tarefa 3 (`.\4-windows_telemetry_quality.ps1`), lendo windows_events_export.json por padrão.
Comandos:
- (nenhum comando novo — script só lê e analisa o JSON já exportado, sem consultar o sistema ao vivo)

## Task - 5-auditd_refine.sh
O que faz: Adiciona cinco regras auditd focadas em detecção (execve, socket/connect, chaves SSH, persistência via cron, sudoers.d) ao meddefense.rules de forma idempotente, recarrega o auditd e prova que cada regra nova dispara com um gatilho real e seguro checado via ausearch.
Como usar: executar como root no host Linux (`sudo ./5-auditd_refine.sh`); RULES_FILE pode ser sobrescrito para testar em modo scratch.
Comandos:
- `auditctl -l` — lista as regras de auditoria atualmente carregadas no kernel; usado para conferir o que está realmente ativo, não só o que está escrito no arquivo.
- `augenrules --load` — funde os arquivos em /etc/audit/rules.d/ e recarrega o conjunto de regras no subsistema de auditoria do kernel.
- `auditctl -R <arquivo>` — carrega um arquivo de regras diretamente no subsistema de auditoria (caminho alternativo quando augenrules não está disponível).
- `ausearch -k <chave>` — busca no log de auditoria por registros marcados com uma chave específica; ferramenta central para confirmar que uma regra realmente disparou.
- `/usr/bin/id` — gatilho: execução simples de comando para testar o rastreamento da syscall execve.
- `curl http://localhost` — gatilho: gera uma conexão de rede de saída para testar o rastreamento das syscalls socket/connect.
- `touch <arquivo>` — gatilho: cria/atualiza um arquivo para testar uma regra de watch (-w) do auditd.

## Task - 6-log_source_map.sh
O que faz: Inventaria as fontes de log Linux existentes (auth.log, audit.log, syslog, kern.log, apache2, dpkg, ufw, fail2ban) — caminho, formato, política de rotação real (lida do logrotate), tamanho atual, taxa estimada de eventos e relevância de segurança — e sinaliza fontes esperadas que estão ausentes ou silenciosas.
Como usar: executar no host Linux a inventariar (`./6-log_source_map.sh`); somente leitura, não altera configuração.
Comandos:
- `grep -rl -F <padrão> /etc/logrotate.d/` — encontra qual stanza do logrotate governa um caminho de log específico; usado para determinar a política real de retenção em vez de presumi-la.
- `stat -c%s <arquivo>` — retorna o tamanho de um arquivo em bytes; usado para caracterizar o volume atual de uma fonte de log.
- `wc -l <arquivo>` — conta as linhas de um arquivo de log; usado para estimar sua taxa de eventos por hora.

## Task - 7-linux_export.sh
O que faz: Contraparte Linux da Tarefa 3 — normaliza auth.log (login SSH, sudo, su), audit.log (execve, acesso a arquivo, rede) e syslog (serviços, erros) para o mesmo formato JSON estruturado do export Windows, usando um único passe awk por arquivo (não um subprocesso por linha) por questão de performance.
Como usar: executar no host Linux (`./7-linux_export.sh [saida.json]`); somente leitura.
Comandos:
- `awk '<padrão>' <arquivo_de_log>` — faz o parsing campo a campo das linhas de log em um único passe (sem subprocesso por linha); é a técnica central usada para extrair logins SSH, uso de sudo/su, registros execve/arquivo/rede do auditd e eventos de serviço/erro do syslog.
- `hostname` — retorna o hostname local; usado para marcar cada evento normalizado com a origem.

## Task - 8-linux_telemetry_quality.sh
O que faz: Aplica ao linux_events_export.json exatamente o mesmo padrão de qualidade da Tarefa 4 — distribuição de eventos, cobertura hora a hora, detecção de gaps, completude de campos (command line do execve, IP/usuário de SSH, caminho de arquivo do auditd) e uma pontuação 0-100 ponderada.
Como usar: executar após a Tarefa 7 (`./8-linux_telemetry_quality.sh`), lendo linux_events_export.json por padrão.
Comandos:
- (nenhum comando novo — script usa apenas jq para analisar o JSON já exportado, sem consultar o sistema ao vivo)

## Task - 9-windows_attack_sim.ps1
O que faz: Executa em sequência realista as técnicas do playbook Crimson Tide contra o próprio endpoint do projeto — criar usuário, escalar privilégio, rodar PowerShell codificado, criar persistência, beacon de saída, dropar payload no Startup — timestampando cada ação para correlação posterior. Todas as mudanças reais (usuário, grupo, tarefa agendada, arquivo) são revertidas ao final.
Como usar: executar com privilégios administrativos no host Windows (`.\9-windows_attack_sim.ps1`); gera windows_attack_log.json como ground truth.
Comandos:
- `New-LocalUser -Name <usuário> -Password <securestring>` — gatilho: cria uma conta de usuário local (T1136.001), esperado no Security EID 4720.
- `Add-LocalGroupMember -Group "Administrators" -Member <usuário>` — gatilho: adiciona o usuário ao grupo de administradores locais (T1098), esperado no Security EID 4732.
- `schtasks /create /tn <nome> /tr <comando> /sc daily /st <hora> /f` — gatilho: cria uma tarefa agendada para persistência (T1053.005).

## Task - 10-windows_detection_proof.ps1
O que faz: Correlaciona o ground truth da Tarefa 9 com a telemetria realmente capturada (Sysmon, Security, PowerShell), produzindo uma matriz de detecção que mostra, para cada ação simulada, se foi capturada, por qual fonte, com qual Event ID e em qual nível de detalhe (full/partial/missed).
Como usar: executar após a Tarefa 9 (`.\10-windows_detection_proof.ps1`), lendo windows_attack_log.json por padrão.
Comandos:
- (nenhum comando novo — reaproveita `Get-WinEvent`, já descrito na Tarefa 0, agora buscando dentro de uma janela de ±30s ao redor de cada ação)

## Task - 11-linux_attack_sim.sh
O que faz: Contraparte Linux da Tarefa 9 — criar usuário, modificar sudoers, executar binário a partir de /tmp, tentar reverse shell (para localhost, seguro), persistência via cron, acessar /etc/shadow — com timestamp de cada ação para correlação posterior. Um trap em EXIT garante limpeza mesmo se um passo falhar.
Como usar: executar como root no host Linux (`sudo ./11-linux_attack_sim.sh`); gera linux_attack_log.json como ground truth.
Comandos:
- `useradd -M -N -s /usr/sbin/nologin <usuário>` — gatilho: cria uma conta de usuário sem home nem shell de login (T1136.001).
- `chmod 440 <arquivo_sudoers>` — gatilho: ajusta a permissão do arquivo sudoers recém-criado (T1548.003).
- `cp /usr/bin/id <destino>` — gatilho: copia um binário para /tmp para simular ferramenta suspeita antes da execução (T1059).
- `bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1 &'` — gatilho: tenta uma reverse shell usando o pseudo-dispositivo /dev/tcp do bash, contra localhost (T1071).
- `cat /etc/shadow` — gatilho: lê um arquivo de credenciais sensível (T1003.008).

## Task - 12-linux_detection_proof.sh
O que faz: Contraparte Linux da Tarefa 10 — para cada ação em linux_attack_log.json, busca em auditd (e em auth.log para a criação de usuário) dentro de uma janela de ±30s, revelando se as regras auditd realmente produzem um evento correspondente, não apenas se a chave existe no arquivo de regras.
Como usar: executar como root após a Tarefa 11 (`sudo ./12-linux_detection_proof.sh`).
Comandos:
- (nenhum comando novo — reaproveita `ausearch -k`, já descrito na Tarefa 5, agora com janela de tempo `-ts`/`-te` ao redor de cada ação)

## Task - 13-consolidated_export.sh
O que faz: Monta o pacote de handoff telemetry_handoff/ combinando os exports Windows (Tarefa 3) e Linux (Tarefa 7) com o ground truth de ataque de ambas plataformas (Tarefas 9 e 11), normalizando todo timestamp para UTC ISO 8601 e verificando que todo evento carrega os 4 campos comuns antes de empacotar.
Como usar: executar após as Tarefas 3, 7, 9 e 11 (`./13-consolidated_export.sh`), gerando o diretório telemetry_handoff/.
Comandos:
- (nenhum comando novo — script apenas combina e normaliza com jq os JSONs já exportados pelas tarefas anteriores)

## Task - 14-coverage_assessment.sh
O que faz: Gera o arquivo de metadados que acompanha o pacote de handoff — totais de eventos por plataforma/fonte/categoria, resumo das matrizes de detecção (Tarefas 10 e 12), cobertura ATT&CK vinda da Tarefa 1, uma lista de Known Gaps (toda técnica partial/blind + toda entrada [MISSED]) e um resumo de qualidade com confiança limitada a "acceptable" sempre que existir alguma técnica blind.
Como usar: executar após as Tarefas 1, 4, 8, 10, 12 e 13 (`./14-coverage_assessment.sh`).
Comandos:
- (nenhum comando novo — script apenas agrega com jq os relatórios JSON já gerados pelas tarefas anteriores)

## Task - 15-handoff_validation.sh
O que faz: Gate final de qualidade antes do handoff para o Módulo 3 — valida existência de arquivo, validade de JSON, presença de campos obrigatórios, contagem mínima de eventos, sanidade de timestamp ISO 8601 (sem datas futuras), sobreposição de intervalo de tempo entre plataformas e completude do ground truth contra as matrizes de detecção. O veredito só é PASS se todo check individual passar.
Como usar: executar como última etapa, após a Tarefa 13 (`./15-handoff_validation.sh`).
Comandos:
- (nenhum comando novo — script apenas valida com jq os arquivos JSON já gerados pelas tarefas anteriores)
