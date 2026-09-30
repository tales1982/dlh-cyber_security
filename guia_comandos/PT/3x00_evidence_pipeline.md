# 3x00 – Evidence Pipeline

## Task - 0-source_inventory.sh
O que faz: Percorre `windows/`, `linux/` e `network/` do pacote de evidência, calcula tamanho/hash/contagem de registro e o intervalo de timestamp (melhor esforço, um formato por fonte) de cada arquivo, e grava tudo em `source_inventory.json`, junto com um resumo por categoria impresso na tela.
Como usar: `./0-source_inventory.sh [pack_root]` (padrão: `$HOME/evidence_pack_primary`)
Comandos:
- `command -v python3` — confere se o Python está instalado antes de tentar usá-lo.
- `os.walk(diretorio)` — percorre uma árvore de diretórios recursivamente, usado pra descobrir os arquivos de cada categoria sem supor uma estrutura plana.
- `hashlib.sha256()` lendo em blocos de 64KB — calcula o hash do arquivo sem carregar ele inteiro na memória de uma vez.
- `json.loads` com fallback pra NDJSON — tenta interpretar o conteúdo como um único array/objeto JSON primeiro; se falhar, processa linha por linha, tolerando linhas individualmente malformadas.
- `re.match`/`re.search`, um padrão por formato de timestamp — cinco receitas diferentes (ISO já pronto, epoch puro, formato americano em CST, syslog sem ano, epoch embutido do auditd), escolhidas pelo nome do arquivo.
- `datetime.strptime`/`datetime.fromtimestamp` — fazem a conversão de cada formato bruto pra um objeto de data, que vira o texto ISO 8601 UTC final.

## Task - 2-windows_parse.sh
O que faz: Junta `security.json`, `sysmon.json` e `powershell.json` num único `windows_events.json` (NDJSON), confere que cada registro tem os 8 campos mínimos, preserva/define `source_origin`, e anexa a telemetria do aluno (`student_telemetry/windows_events.json`) mapeando os campos equivalentes quando o nome não bate.
Como usar: `./2-windows_parse.sh [pack_root]`
Comandos:
- `command -v python3` — checagem de dependência.
- `json.loads` linha a linha, com `try/except` — lê cada linha do NDJSON de origem, pulando (e avisando no stderr) qualquer linha que não seja JSON válido, em vez de abortar o script inteiro.
- `dict.setdefault(campo, None)` — garante que os 8 campos mínimos existam em todo registro, mesmo quando a fonte não tinha aquela informação.
- `rec.get(campo)` como valor de reserva — mapeia os campos da telemetria do aluno (`timestamp`→`timestamp_raw`, `source_type`→`channel`) sem sobrescrever um valor que já exista.

## Task - 3-linux_parse.sh
O que faz: Faz o parsing de `auth.log`/`syslog` (formato syslog clássico) e `audit.log` (formato chave=valor do auditd, agrupando linhas que compartilham o mesmo identificador `audit(epoch:serial)`) em registros estruturados, anexa a telemetria do aluno, e escreve tudo em `linux_events.json`.
Como usar: `./3-linux_parse.sh [pack_root]`
Comandos:
- `command -v python3` — checagem de dependência.
- `re.compile(r'(\S+) ([^ \[:]+)(?:\[(\d+)\])?: ?(.*)$')` — reconhece de uma vez hostname, programa, PID opcional e o resto da mensagem de uma linha de syslog.
- Lista de regexes tentadas em ordem (uma por grupo de programa) — extrai o usuário mencionado na mensagem, cobrindo os jeitos diferentes que `sudo`, `su`/`polkitd`/`login`/`CRON`, `systemd-logind` e `sshd` mencionam o usuário.
- `re.search(r'msg=audit\((\d+)\.(\d+):(\d+)\)')` — extrai o identificador do evento auditd (`epoch.ms:serial`), usado como chave de agrupamento.
- `re.findall(r'(\w+)=("[^"]*"|\'[^\']*\'|\S+)')` — extrai todo par chave=valor de uma linha do `audit.log`, aceitando valor entre aspas duplas, simples ou sem aspas.
- Abertura de arquivo em modo binário (`"rb"`) com decodificação manual UTF-8→latin-1 — lê cada linha tentando UTF-8 primeiro, e só cai pra latin-1 nas linhas que realmente falham, preservando o caractere original em vez de perdê-lo num caractere de substituição genérico.

## Task - 5-normalize.sh
O que faz: Lê `windows_events.json` e `linux_events.json`, aplica tabelas de categoria/severidade/ação por canal (Windows) e por programa/tipo de auditoria (Linux), converte cada timestamp intermediário pra ISO 8601 UTC, e escreve o resultado em `normalized_events.json` — mandando pra `quarantine.json` (com o motivo) todo registro que fica sem um campo obrigatório do `event_schema.json`.
Como usar: `./5-normalize.sh` (lê `event_schema.json` da pasta atual)
Comandos:
- `command -v python3` — checagem de dependência.
- `json.load(schema_file)` + compreensão de lista sobre `fields` — lê `event_schema.json` e monta a lista de campos obrigatórios dinamicamente, em vez de fixar ela no código; mudar `required` no schema muda o comportamento da quarentena sem editar esse script.
- Tabelas de mapeamento em dicionário — decidem `event_category`/`severity`/`action` a partir do `event_id`/`channel` (Windows) ou `program`/`audit_type` (Linux).
- `int(valor)` protegido por `try/except` — converte PID/porta pra número só quando o valor realmente é um dígito, sem quebrar o script em campos ausentes.

## Task - 6-network_normalize.sh
O que faz: Normaliza `firewall.csv`, `suricata_eve.json` e `pcap_summary.json` pro mesmo schema unificado (`event_category`, `severity`, `signature`, etc.), anexa o resultado em `normalized_events.json` e escreve também um `network_events.json` isolado.
Como usar: `./6-network_normalize.sh [pack_root]`
Comandos:
- `command -v python3` — checagem de dependência.
- `csv.DictReader` — lê o `firewall.csv` linha por linha já como dicionário, usando o cabeçalho da primeira linha pra nomear cada coluna.
- `datetime.fromtimestamp(epoch, tz=timezone.utc)` — converte a coluna de epoch do firewall direto pra UTC.
- `datetime.strptime(raw_ts, "%Y-%m-%dT%H:%M:%S.%f%z")` — interpreta o timestamp do Suricata (ISO 8601 com microssegundos e offset numérico).
- `datetime.strptime(raw_ts, "%m/%d/%Y %I:%M:%S %p") + timedelta(hours=6)` — interpreta o formato americano 12h do `pcap_summary.json` e soma 6 horas pra converter de CST pra UTC.
- Arquivo de saída aberto em modo *append* (`"a"`) — junta os eventos de rede no `normalized_events.json` que a Tarefa 5 já tinha escrito, sem apagar o que já estava lá.

## Task - 8-data_quality.sh
O que faz: Lê `normalized_events.json` e corrige (ou sinaliza) os defeitos conhecidos do pacote — timestamp malformado, duplicata, caixa de hostname inconsistente, erro de encoding e timestamp suspeito de timezone errada — gravando cada correção em `cleaning_log.json` e o resultado limpo em `cleaned_events.json`.
Como usar: `./8-data_quality.sh`
Comandos:
- `command -v python3` — checagem de dependência.
- Lista de formatos tentados em `datetime.strptime` — tenta o ISO 8601 estrito primeiro, cai pra formatos alternativos antes de considerar um timestamp irrecuperável.
- `dict` usado como tabela de "já vi essa combinação" (chave composta `timestamp`+`hostname`+`source_type`+`raw_message`) — é a técnica de deduplicação: a chave representa a "impressão digital" de um evento, e o dicionário garante custo baixo pra achar repetição mesmo em centenas de milhares de registros.
- `sorted()` sobre os timestamps + índice por percentil (2º/98º) — calcula a janela "esperada" de datas a partir dos próprios dados, em vez de fixar datas no código, pra sinalizar quem foge dela por mais de 12 horas.
- Checagem do caractere de substituição Unicode (`�`) dentro de `raw_message` — detecta se um registro já chegou com informação de encoding perdida antes desse estágio.

## Task - 9-enrich.sh
O que faz: Cruza cada evento de `cleaned_events.json` com `context/asset_inventory.json` (por hostname) e `context/network_zones.json` (por IP/CIDR), anexando um objeto `asset` e os campos `src_zone`/`dst_zone`, e escreve `enriched_events.json` — reportando a cobertura de contexto encontrada.
Como usar: `./9-enrich.sh [pack_root]`
Comandos:
- `command -v python3` — checagem de dependência.
- `ipaddress.ip_network(cidr)` / `endereco in rede` — o módulo padrão do Python pra representar faixas de IP e testar se um endereço cai dentro de uma delas, sem precisar implementar aritmética de CIDR na mão.
- Lista de `(rede, zona)` ordenada por tamanho de prefixo decrescente — garante que uma zona mais específica (`/24`) seja checada antes de uma genérica (`0.0.0.0/0`, que combina com qualquer IP), evitando que tudo caia na zona "catch-all".
- `dict` indexado por hostname em minúsculo — faz o cruzamento com o inventário de ativos sem se importar com a caixa exata do hostname no evento.
