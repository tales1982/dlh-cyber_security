# 3x01 – Reading the Noise

## Task - 2-query_toolkit.sh
O que faz: Executa cinco sub-comandos (`filter`, `top`, `distinct`, `count`, `window`) contra `$HANDOFF_DIR/data/enriched_events.json`, usando uma única expressão jq de `select` compartilhada, montada a partir de quais filtros `--source`/`--host`/`--category`/`--from`/`--to` foram passados, além de um acessor de campo genérico que também resolve caminhos com ponto em objetos aninhados como `asset.criticality`.
Como usar: `./2-query_toolkit.sh <verbo> [opções]` (usa `~/3x00_handoff/evidence_handoff` como padrão se `HANDOFF_DIR` não estiver definido)
Comandos:
- `jq -c --arg src ... "select($SELECT_JQ)" arquivo` — monta uma única expressão de filtro a partir das cinco flags opcionais, de forma que uma flag não usada (`$src==""`) libera o filtro em vez de restringir o resultado.
- `getpath($field | split("."))` — resolve tanto um campo simples quanto um caminho com ponto como `asset.criticality` com o mesmo código, em vez de escrever dois mecanismos de busca separados.
- `sort | uniq -c | sort -k1,1rn | head -n N` envolto em `set +o pipefail ... set -o pipefail` — o pipeline de ranking do verbo `top`; a alternância de pipefail existe porque o `head` fechando cedo depois de N linhas manda um SIGPIPE pro `sort`, que o `pipefail` trataria como falha do script.
- `awk '{c=$1; $1=""; sub(/^ /,""); printf "%s\t%s\n", $0, c}'` — inverte a saída "contagem valor" do `uniq -c` pra "valor\tcontagem", tratando corretamente valores com múltiplas palavras.

## Task - 3-event_taxonomy.sh
O que faz: Traz uma lista ordenada de ~49 regras feitas à mão (cada uma um registro `{source_type, match, label}`, definida a partir da inspeção real dos padrões de `raw_message`/`action`/`process_name` de cada fonte), compara cada evento com a primeira regra que bate, e escreve tanto a lista de regras (`event_taxonomy.json`) quanto o dataset inteiro rotulado com um novo campo `canonical_label` (`labeled_events.json`), atribuindo `"unlabeled"` a quem não bate com nada.
Como usar: `./3-event_taxonomy.sh`
Comandos:
- Um array JSON escrito via `cat > arquivo <<'EOF' ... EOF` — mantém a taxonomia editável por humano e legível por máquina ao mesmo tempo, em vez de construí-la via código.
- `to_entries | all(...)` dentro de um predicado inline do jq — confere se todo par chave/valor declarado no `match` de uma regra é verdadeiro pro evento, permitindo que uma regra teste um campo ou cinco sem mudar o código de comparação.
- Uma convenção de `*` no final de um valor de `match`, testada com `endswith("*")` e depois `startswith(value[0:-1])` — permite que algumas regras casem prefixos de mensagem (tipo `"An account was logged off.*"`) sem precisar de suporte a regex completo no schema da regra.
- `map(select(...)) | .[0].label // "unlabeled"` — pega a primeira regra que bate na ordem de declaração (primeira que casar, vence), caindo pra `"unlabeled"` quando nada bate.

## Task - 4-baseline_auth.sh
O que faz: Descobre o timestamp mais antigo do próprio dataset, soma `$BASELINE_DAYS` (padrão 7) pra derivar a janela de baseline em tempo de execução, e faz uma única passada `reduce` sobre os eventos rotulados dessa janela pra montar contagens de login por host/usuário, a lista de contas conhecidas, médias de sucesso/falha em horário comercial vs fora dele, e a maior rajada de falhas numa janela de 1 hora vinda de um único `src_ip`.
Como usar: `./4-baseline_auth.sh` (env: `BASELINE_DAYS`)
Comandos:
- `sort | head -n 1` envolto em `set +o pipefail` — acha o timestamp mais antigo; o mesmo ajuste de SIGPIPE-vs-`head` do verbo `top` da Task 2.
- `date -u -d "$WSTART + N days" +"%Y-%m-%dT%H:%M:%SZ"` — aritmética de datas do GNU `date` deriva o fim da janela a partir do início dela, em vez de fixar uma data de calendário.
- `reduce (inputs | select(...)) as $e (...; ...)` — uma única passada de streaming pelo NDJSON monta todos os agregados (contagem por host, por usuário, buckets de hora, falhas por IP+hora) de uma vez, em vez de reler o arquivo pra cada métrica.
- Contar *buckets de hora de calendário distintos* realmente presentes na janela (em vez de `dias*12`) — deixa a média por hora exata mesmo nas bordas de dia parcial da janela.

## Task - 5-baseline_process.sh
O que faz: Restringe à mesma janela de baseline e, pra cada host, monta a lista de processos que rodaram ali (com contagem, primeira/última vez vistos, e usuários distintos), o top 50 global de processos, os processos raros o suficiente pra valer a pena observar (só num host ou com menos de 5 execuções no total), e toda relação pai→filho que conseguir extrair de mensagens `"Process Create: <filho> by <pai>"`.
Como usar: `./5-baseline_process.sh` (env: `BASELINE_DAYS`)
Comandos:
- `capture("^Process Create: (?<child>.+) by (?<parent>.+)$")` protegido antes por um `test(...)` — extrai o nome do processo pai embutido em texto livre; a proteção existe porque `capture` não produz *saída nenhuma* (não é `null`) quando não bate, o que quebraria silenciosamente o `reduce` ao redor.
- `map_values(to_entries | map({...}) | sort_by(-.count, .process_name))` — transforma o acumulador interno por host no array final ordenado, contagem decrescente com o nome como critério de desempate determinístico.
- `$r.host_sets | to_entries | map(select(.host_count == 1 or .total_count < 5))` — a regra exata de "processo raro" do enunciado, calculada direto dos dois conjuntos já montados durante o reduce.
- `keys` num objeto acumulador `{"<usuario>": true}` — o idioma padrão do jq pra montar um conjunto deduplicado e já ordenado sem uma segunda passada.

## Task - 6-baseline_network.sh
O que faz: Como eventos de firewall/pcap não têm hostname (só endereço IP), monta o baseline de rede indexado por `src_ip` em vez de por host — portas de destino conhecidas por IP de origem, contagens por tipo de conexão (outbound/inbound/blocked), o top 20 de IPs de destino no geral, e a contagem total de alertas de IDS.
Como usar: `./6-baseline_network.sh` (env: `BASELINE_DAYS`)
Comandos:
- `.canonical_label | test("^network_")` — um único filtro que já pega os quatro rótulos relacionados a rede de uma vez, em vez de uma cadeia de `or`.
- `.per_src_ip[$ip].known_dst_ports[($e.dst_port|tostring)] = true` — monta um conjunto de portas por IP como chaves de objeto (teste de pertencimento rápido depois), convertendo a porta pra string porque chave de objeto em jq precisa ser string.
- `map_values(...) | keys | map(tonumber) | sort` — transforma cada conjunto de portas de volta num array ordenado de números pro JSON final, desfazendo a conversão pra string usada internamente.

## Task - 7-baseline_file.sh
O que faz: Restringe aos eventos `file_read_sensitive`/`file_write_sensitive`/`file_permission_change` na janela de baseline e produz uma contagem simples por host e global pra cada um dos três.
Como usar: `./7-baseline_file.sh` (env: `BASELINE_DAYS`)
Comandos:
- `def is_file_label: . == "a" or . == "b" or . == "c";` — um predicado nomeado pequeno, reutilizado tanto no filtro `select` quanto no agrupamento, mantido num só lugar em vez de repetido inline.
- `.totals[$lbl] = ((.totals[$lbl] // 0) + 1)` junto com a atualização equivalente por host — o mesmo padrão de contador incremental usado em todo script de baseline, aplicado uma vez pro número global e outra pro detalhamento por host no mesmo passo do reduce.

## Task - 8-baseline_temporal.sh
O que faz: Agrupa todo evento da janela de baseline por hora do dia (`"00"`–`"23"`) e por dia de calendário, e reporta a média de eventos por hora do dia (contagem bruta dividida por `$BASELINE_DAYS`) além de qual hora é a mais movimentada/mais quieta.
Como usar: `./8-baseline_temporal.sh` (env: `BASELINE_DAYS`)
Comandos:
- `$e.timestamp[11:13]` / `$e.timestamp[0:10]` — a sintaxe de fatiamento de string do jq extrai a hora do dia e a data de calendário direto do timestamp ISO 8601 sem precisar interpretá-lo.
- Um array literal `["00","01",...,"23"]` passado por `max_by`/`min_by` — garante que as 24 horas sejam consideradas pra mais movimentada/mais quieta mesmo que alguma delas tenha tido zero eventos (e portanto nenhuma chave no acumulador).

## Task - 9-baseline_summary.sh
O que faz: Carrega os cinco arquivos de baseline anteriores com `--slurpfile`, calcula a duração da janela de baseline em dias e deriva uma janela de avaliação de 24 horas logo depois dela, une toda chave `per_host` de auth/process/file num único inventário de hosts, e aninha tudo isso (mais um bloco `thresholds` documentado) num único `baseline_summary.json`.
Como usar: `./9-baseline_summary.sh`
Comandos:
- `strptime("%Y-%m-%dT%H:%M:%SZ") | mktime` — converte um timestamp ISO 8601 pra segundos desde epoch, pra dar pra calcular durações de janela por subtração.
- `mktime | (. + 86400) | strftime(...)` — soma exatamente um dia em segundos de epoch, mais simples e menos sujeito a erro que aritmética de data baseada em string pra uma janela fixa de 24h.
- `[($auth.per_host // {} | keys[]), ...] | flatten | unique | sort` — junta listas de host de três documentos com formatos diferentes num único inventário deduplicado e ordenado.
- Cada threshold guardado como `{value, comment}` em vez de um número solto — deixa o "porquê" de cada threshold legível por máquina e auditável, não só um comentário perdido no script.

## Task - 10-anomalies_auth.sh
O que faz: Lê a janela de avaliação de dentro do `baseline_summary.json`, e pra cada uma das quatro checagens exigidas (conta desconhecida, rajada de falhas, login fora de hora, surto de escalonamento de privilégio) agrupa os eventos que batem pela chave certa (usuário, `src_ip`+hora, usuário, host, respectivamente), guardando o timestamp de cada evento que bateu em `event_refs` pra cada anomalia continuar rastreável até sua evidência.
Como usar: `./10-anomalies_auth.sh` (variáveis de override: `SUMMARY_FILE`, `OUT_FILE`, usadas pela Task 15)
Comandos:
- Uma segunda passada `jq -n`, separada, sobre a janela de baseline (não a de avaliação) — calcula quais usuários só logaram em horário comercial no período *limpo*, já que essa granularidade por usuário não existe no `baseline_auth.json` e precisa ser derivada sob demanda.
- `.unknown[$user].events = ((.unknown[$user].events // []) + [$e.timestamp])` — o idioma "anexa ou inicializa" usado o tempo todo, já que o jq não tem um `+=` puro que tolere caminho ausente.
- `def sevrank: {critical:3, high:2, medium:1, low:0}[.];` e depois `sort_by([-(.severity|sevrank), .timestamp])` — ordena as piores anomalias primeiro sem escrever um comparador na mão.
- `SUMMARY_FILE`/`OUT_FILE` lidos via `${VAR:-padrao}` — permite que a Task 15 reaponte esse mesmo script pra um summary diferente e um arquivo de saída diferente sem mexer no código dele.

## Task - 11-anomalies_process.sh
O que faz: Compara todo evento de processo da janela de avaliação com a lista de processos do baseline daquele host específico e com o conjunto de pares pai→filho (ambos vindos direto do `baseline_summary.json`), sinalizando processos/pares nunca vistos naquele host, processos raros no baseline que disparam pra mais de 10 execuções, e qualquer ferramenta da watchlist (`powershell.exe`, `nc`, `python3`, etc.) aparecendo num host onde nunca rodou antes.
Como usar: `./11-anomalies_process.sh` (variáveis de override: `SUMMARY_FILE`, `OUT_FILE`)
Comandos:
- Uma rubrica de severidade declarada como quatro variáveis `SEV_*` no topo do script, passadas pro jq via `--arg` — mantém a política de severidade num lugar visível em vez de escondida dentro do filtro jq.
- `if (raw_message|test(padrao)) then capture(padrao) else null end` — garante exatamente uma saída (um objeto de captura ou `null`) por evento pra que o `reduce` ao redor nunca colapse silenciosamente quando o `raw_message` não bate.
- `def basename: (split("\\")|last) | (split("/")|last) | ascii_downcase;` — normaliza um caminho do Windows, um caminho Unix, ou um nome de binário puro pro mesmo nome-base em minúsculo antes de conferir contra a watchlist.
- `host_processes($host) | index($pname) | not` — o teste "isso é novo pra esse host", reutilizado tanto na checagem simples de processo desconhecido quanto na checagem de watchlist.

## Task - 12-anomalies_network.sh
O que faz: Como só um formato de mensagem (`"Network connection: <proc> -> <ip>:<porta>"`) carrega hostname e destino junto, varre a janela de baseline pra descobrir os IPs/portas de destino conhecidos de cada host usando esse padrão exato, e depois sinaliza qualquer conexão da janela de avaliação pra um IP novo ou uma porta nova pra aquele host.
Como usar: `./12-anomalies_network.sh` (variáveis de override: `SUMMARY_FILE`, `OUT_FILE`)
Comandos:
- `capture("^Network connection: .+ -> (?<ip>[0-9.]+):(?<port>[0-9]+)$")` — extrai o IP e a porta de destino de texto livre, já que os campos estruturados `dst_ip`/`dst_port` ficam nulos nesse formato de mensagem específico.
- Duas passadas completas por `labeled_events.json` no mesmo script (uma pra janela de baseline, outra pra janela de avaliação) — mais simples e mais fácil de verificar do que tentar juntar os dois cálculos num único reduce.
- `$known[$h].ports // {} | keys` — o mesmo idioma de "conjunto conhecido como chave de objeto" da Task 6, reaproveitado aqui por host em vez de por `src_ip`.

## Task - 13-correlate_anomalies.sh
O que faz: Marca cada entrada dos três arquivos de anomalia com sua fonte, agrupa por host, e dentro de cada grupo de host faz um clustering temporal de ligação simples (ordena por timestamp, começa um cluster novo sempre que o intervalo pro evento anterior passa de `$CORR_WINDOW_SECONDS`), mantendo só clusters com 2 ou mais itens como achados correlacionados, cada um pontuado por número de fontes mais um bônus por número de tipos, multiplicado pela criticidade do ativo do host.
Como usar: `./13-correlate_anomalies.sh` (env: `CORR_WINDOW_SECONDS`, padrão 300)
Comandos:
- `reduce events[] as $e ([]; if length==0 then [[$e]] else ... end)` — o fold de clustering por intervalo: compara cada evento só com o último evento do último cluster aberto, suficiente pra implementar clustering de ligação simples sem precisar de biblioteca de grafo.
- Uma passada única de `reduce` sobre `labeled_events.json` montando `{hostname: criticidade-da-primeira-vez-vista}` — consulta a `asset.criticality` de cada host uma vez só, a partir do mesmo dataset bruto que os scripts de anomalia já consomem, em vez de reprocessar o `asset_inventory.json` separadamente.
- `("corr-" + (epoch|tostring) + "-" + (host|@base64|.[0:8]))` — um ID curto e totalmente determinístico montado a partir de dado que já se tem em mãos, sem depender de nenhuma ferramenta externa de hash.
- `{LOW:1, MEDIUM:2, HIGH:3, CRITICAL:4}[.] // 1` — converte o rótulo de criticidade do ativo no multiplicador de score que o enunciado pede, caindo pra 1 em qualquer host sem criticidade registrada.

## Task - 15-baseline_validation.sh
O que faz: Roda as Tasks 10/11/12 duas vezes — uma vez contra uma cópia do `baseline_summary.json` cuja `evaluation_window` foi sobrescrita pra ser igual à própria `baseline_window` (`self_check_*.json`), e uma vez normalmente contra a janela de avaliação real (`live_check_*.json`) — depois calcula o total do self-check, o total do live-check, a razão entre os dois, e um veredito de aprovação/reprovação contra dois thresholds configuráveis.
Como usar: `./15-baseline_validation.sh` (env: `SELF_CHECK_THRESHOLD`, `MIN_SIGNAL_TO_NOISE`); sai com 0 se passar, 1 se falhar
Comandos:
- `jq '.evaluation_window = {start: .baseline_window.start, ...}'` — monta o summary do self-check sobrescrevendo só um campo do summary real, pra que a rodada de self-check reaproveite exatamente os mesmos thresholds e baselines por host da rodada real.
- `mktemp -d` junto com `trap 'rm -rf "$WORKDIR"' EXIT` — cria um diretório temporário pro arquivo de summary provisório e garante a limpeza dele mesmo se o script sair antes por causa de um erro.
- `SUMMARY_FILE="$SELF_SUMMARY" OUT_FILE="..." ./10-anomalies_auth.sh` — reaproveita as Tasks 10–12 sem mudar o comportamento delas, só reapontando via as variáveis de ambiente adicionadas exatamente pra esse fim.
- `([$self_total, 1] | max)` como denominador da razão — evita um erro de divisão por zero no caso (esperado, e bom) de o self-check não achar nada.

## Task - 16-rank_anomalies.sh
O que faz: Não é uma das tasks numeradas do 3x01 — é um passo pequeno de síntese, construído enquanto se trabalhava nas métricas de qualidade por regra do 3x02, que precisava de um único arquivo de ground-truth ranqueado juntando todo tipo de anomalia que este projeto já detecta. Ele carrega `anomalies_auth.json`, `anomalies_process.json`, `anomalies_network.json` e `correlated_anomalies.json` (cada um tolerado como ausente), marca cada entrada com sua `source`, converte severidade num score numérico (ou reaproveita o `score` composto já calculado de um achado correlacionado), ordena tudo decrescente, e escreve `ranked_anomalies.json` com um `rank` (base 1) em cada entrada. Não adiciona nenhuma lógica de detecção nova — só reempacota o que as Tasks 10–13 já produziram.
Como usar: `./16-rank_anomalies.sh` (rode depois que as Tasks 10, 11, 12 e 13 já geraram seus arquivos de saída)
Comandos:
- `python3 -c "..."` com uma variável bash `$SEVERITY_SCORE` injetada no heredoc — mantém o mapeamento de severidade pra número declarado uma vez só, visível, no topo do script shell, mesmo a lógica de transformação em si sendo mais fácil de expressar em Python do que em jq.
- Um helper pequeno `load(name)` envolto em `try/except FileNotFoundError: return []` — deixa o script rodar limpo mesmo que, digamos, `anomalies_network.json` nunca tenha sido gerado, em vez de exigir que toda task anterior já tenha rodado.
- `[{'host': ..., 'timestamp': ts} for ts in item.get('event_refs', [])]` — normaliza a lista de referências de formato diferente de cada fonte numa única estrutura `refs` comum de pares `{host, timestamp}`, pra quem consome depois não precisar saber qual detector produziu cada entrada.
- `entries.sort(key=lambda e: e['score'], reverse=True)` seguido de `enumerate(entries, start=1)` — uma única ordenação já define o `rank` final, então empates são resolvidos pela ordem original de inserção (auth, depois process, depois network, depois correlated) em vez de arbitrariamente.
