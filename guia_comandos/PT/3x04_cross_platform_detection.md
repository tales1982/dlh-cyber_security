# 3x04 – Cross-Platform Detection Analysis

## Task - 0-tool_check.sh
O que faz: Verifica `jq`, `yq`, `python3`, `sigma-cli`, `xmllint` e `curl` no PATH e imprime a versão de cada; confere se os 5 diretórios de handoff existem; confirma que `enriched_events.json` está presente e não vazio; conta as regras Sigma no catálogo; verifica os arquivos do Wazuh export; e confirma que o evento âncora bate contra `enriched_events.json`. Sai com status diferente de zero se qualquer checagem falhar.
Como usar: `./0-tool_check.sh` (usa os defaults de `HANDOFF_DIR`/`BASELINE_PKG`/`CATALOG_DIR`/`TRIAGE_PKG`/`ASSETS_DIR`/`WAZUH_EXPORTS`)
Comandos:
- `${VAR:-default}` combinado com `$HOME` em vez de `~` — `~` não expande dentro de aspas duplas em bash, então todo default de diretório usa `$HOME` explicitamente.
- `command -v <bin> >/dev/null 2>&1` dentro de um `if` — protege cada checagem de binário do `set -e`, permitindo que o script continue e acumule falhas em `FAILED` em vez de abortar na primeira ferramenta ausente.
- `${VERSAO#prefixo}` (remoção de prefixo por expansão de parâmetro) — usado com prefixos diferentes (`jq-`, `Python `, `version v`) porque cada ferramenta formata sua própria saída de `--version` de um jeito diferente.
- `sigma version | cut -d' ' -f1` em vez de `sigma --version` — o binário instalado pelo pacote `sigma-cli` (via pip) na verdade se chama `sigma`, e não aceita a flag `--version`; a versão só sai por um subcomando dedicado.
- `jq -c 'select(...)' arquivo | wc -l` sobre um NDJSON de ~200MB — conta eventos que casam sem carregar o arquivo inteiro na memória com `-s`.

## Task - 1-wazuh_workspace.sh
O que faz: Lê `index_metadata.json` (índice, total de documentos, intervalo de tempo), `field_mapping.json` (tabela dos 10 primeiros mapeamentos de campo) e `dashboard_credentials.json` (só o usuário); verifica a presença de todos os arquivos exigidos em `wazuh_exports/` e `query_results/`; e grava `workspace/workspace_init.json`.
Como usar: `ASSETS_DIR=<dir> ./1-wazuh_workspace.sh`
Comandos:
- `python3 -c "print(f'{$N:,}')"` — formata um inteiro com separador de milhar (`339882` → `339,882`), algo que bash puro não faz de forma portável.
- `awk -F'\t' '{printf "  %-12s -> %s\n", $1, $2}'` — espaço literal antes do `->`, porque `%-12s` sozinho não garante separação quando o campo já tem exatamente 12+ caracteres (o padding do `printf` some nesse caso).
- `jq -n --argjson total_documents "$N" ...` — injeta um número já validado como JSON (não como string), evitando aspas indevidas em torno de um campo numérico.
- Lista fixa de "arquivos exigidos" percorrida num loop, cada caminho testado com `[ -f ... ]` — a contagem final reflete exatamente o que foi checado, não um `ls | wc -l` genérico que contaria o que existir a mais na pasta.

## Task - 2-cli_anchor.sh
O que faz: Lê o manifesto do evento âncora (host, janela de tempo, IPs atacantes), filtra `enriched_events.json` por esses critérios, extrai primeiro/último evento, lê a regra Sigma `001_ssh_brute_force.yml` com `yq`, e grava `findings/anchor_cli.json` no schema travado.
Como usar: `HANDOFF_DIR=<dir> CATALOG_DIR=<dir> ASSETS_DIR=<dir> ./2-cli_anchor.sh`
Comandos:
- `test($ips)` com padrão regex montado via `map(gsub("\\."; "\\."))|join("|")` — escapa o ponto de cada IP antes de juntar em alternância, porque `.` em regex casa qualquer caractere.
- Filtro por `.raw_message | test(...)` em vez de `.src_ip == ...` — `src_ip` vem `null` em todo registro `linux_text`; o IP do atacante só existe dentro da mensagem crua do log (`Failed password for root from IP ...`).
- `date -u +%Y-%m-%dT%H:%M:%SZ` no início e no fim do script — usado tanto pros campos ISO 8601 do schema quanto, via `date +%s`, pra medir o tempo real de execução em segundos.
- Array bash (`ACTIONS+=(...)`) convertido pra JSON com `printf '%s\n' "${ACTIONS[@]}" | jq -R . | jq -s .` — vira uma lista de strings do shell numa lista JSON sem escrever a serialização na mão.

## Task - 3-export_anchor.sh
O que faz: Lê `anchor_search_results.json` (hits, query, primeiro/último evento) e `anchor_dashboard_trace.json` (click path, tempo estimado), monta uma comparação de 5 campos usando `field_mapping.json`, e grava `findings/anchor_export.json` com o click path como `actions`.
Como usar: `ASSETS_DIR=<dir> ./3-export_anchor.sh`
Comandos:
- `jq -r '[.events[]."@timestamp"] | sort | first/last'` — usa `."@timestamp"` (aspas dentro do path) porque o campo começa com `@`, que não é identificador válido sem aspas no `jq`.
- `.mappings[] | select(.normalized == $n) | .wazuh` num loop bash — busca 5 campos específicos na tabela de 23 mapeamentos, porque só esses 5 aparecem de fato no documento do anchor.
- `jq '.click_path'` usado direto como o array `actions` do finding — o enunciado pede que o click path da investigação de dashboard substitua a lista de comandos como evidência das ações tomadas.
- `if [ "$DIFF" -ge 0 ]` pra decidir "mais rápido via export" ou "mais lento" — lê o `time_to_first_answer_seconds` do finding CLI já gravado (Task 2) pra calcular o delta sem reprocessar nada.

## Task - 4-cli_scenario_a.sh
O que faz: Lê o manifesto do cenário A (host, janela, técnicas ATT&CK), escopa `enriched_events.json` por host+janela, identifica os 3 eventos da cadeia (acesso ao LSASS, criação do dump, conexão SMB) por padrão de texto, e grava `findings/scenario_a_cli.json`.
Como usar: `HANDOFF_DIR=<dir> ASSETS_DIR=<dir> ./4-cli_scenario_a.sh`
Comandos:
- Três `contains()` distintos (`"lsass.exe accessed by rundll32.exe"`, `"debug.dmp"`, `"10.1.1.10:445"`) em vez de filtrar por um campo `event_id` — o schema normalizado não tem esse campo, e o próprio exemplo de `jq` do manifesto (que assume `event_id`) não funciona contra os dados reais.
- Filtro pela substring específica da IOC (`10.1.1.10:445`), não por "qualquer conexão de rede" — o host tem outra conexão decoy (DNS) no mesmo intervalo que bateria num filtro genérico de EID3.
- `cut -dT -f2 | tr -d Z` — extrai só a hora de um timestamp ISO 8601 pra bater com o formato esperado (`14:22:00Z`), sem precisar de ferramenta de data completa pra esse recorte simples.

## Task - 5-cli_scenario_b.sh
O que faz: Lê o manifesto do cenário B, junta criticidade/classificação de dados via `asset_inventory.json`, identifica o logon do `p.morales`, a atribuição de privilégios especiais, e a execução do PowerShell com bypass, e grava `findings/scenario_b_cli.json` com hipótese de 2 frases sobre a ambiguidade TP/FP.
Como usar: `HANDOFF_DIR=<dir> ASSETS_DIR=<dir> ./5-cli_scenario_b.sh`
Comandos:
- Filtro `.user == "p.morales"` combinado com `contains("logged on")` — o host tem 3 logons decoy no mesmo minuto (outros usuários), então o filtro de conteúdo sozinho não bastaria.
- `.assets[] | select(.hostname == $h)` sobre `asset_inventory.json` — o arquivo tem estrutura aninhada (`metadata`/`sites`/`assets`), o registro do host não está na raiz do documento.
- Limite de "2 frases" no campo `hypothesis` — bug real corrigido: concatenar a frase própria com o `ambiguity_note` inteiro do manifesto (que já tem 2 frases) resultava em 3, violando o schema.

## Task - 6-cli_scenario_c.sh
O que faz: Filtra `network_events.json` pelo par src_ip/dst_ip do cenário C, resolve a zona de rede do IP de origem via CIDR contra `network_zones.json`, consulta a reputação do IP de destino em `ioc_context.json`, ordena os beacons e calcula o intervalo entre eles, e grava `findings/scenario_c_cli.json`.
Como usar: `HANDOFF_DIR=<dir> ASSETS_DIR=<dir> ./6-cli_scenario_c.sh`
Comandos:
- `ipaddress.ip_network(cidr)` / `ip in net` em Python, escolhendo o CIDR de **maior prefixo** entre todos que contêm o IP — a zona `INTERNET` (`0.0.0.0/0`) contém qualquer IP, então pegar o primeiro match sem comparar `prefixlen` classificaria tudo como `INTERNET`.
- Caminho do `ioc_context.json` com fallback (`$ASSETS_DIR/3x03_assets/...` depois `$HOME/3x03_assets/...`) — o caminho literal do enunciado não existe nesse sandbox; o arquivo real está uma pasta acima do que o texto da task descreve.
- `.indicators["$ip"]` — o objeto de indicadores é uma tabela chaveada pelo próprio IP (não um array), a busca é indexação direta, não `select()`.
- `while IFS= read -r TS; do ...; done <<< "$LISTA"` combinado com `date -u -d "$TS" +%s` — converte cada timestamp pra epoch só pra calcular a diferença em minutos entre beacons consecutivos.

## Task - 7-export_scenario_a.sh
O que faz: Lê `scenario_a_search_results.json`, filtra os eventos que realmente formam a cadeia entre os 10 retornados pela query ampla, lê o dashboard trace e o resumo Markdown, e grava `findings/scenario_a_export.json` com o delta de tempo contra a Task 4.
Como usar: `ASSETS_DIR=<dir> ./7-export_scenario_a.sh`
Comandos:
- `select(.winlog.event_id==10 or (...==11 and .process.name!=null) or (...==3 and .process.name=="cmd.exe"))` — a query KQL ampla devolve 10 eventos, mas 2 deles (EID 11 e EID 3 decoy) têm o mesmo `event_id` da cadeia real; a distinção final é por `process.name`, não por `event_id`.
- `tr -d '\r' | awk '...'` antes de extrair uma seção do `.md` — os arquivos de `dashboard_exports/` vêm com CRLF, e um `\r` sozinho numa linha "vazia" tem `NF` diferente de zero no `awk`, então o filtro de linha vazia falha silenciosamente sem essa limpeza.
- `awk '/^## SEÇÃO/{flag=1;next} /^## /{if(flag)exit} flag && NF'` — extrai o conteúdo entre um cabeçalho Markdown e o próximo, sem depender de saber quantas linhas a seção tem.

## Task - 8-export_scenario_b.sh
O que faz: Lê `scenario_b_search_results.json`, extrai host/usuário/eventos, checa se `agent.labels` carrega `data_classification` (senão cai pro fallback em `asset_inventory.json`), e grava `findings/scenario_b_export.json` anotando no `actions` se o fallback foi necessário.
Como usar: `HANDOFF_DIR=<dir> ASSETS_DIR=<dir> ./8-export_scenario_b.sh`
Comandos:
- `jq '... | has("data_classification")'` — testa a presença de uma chave (não seu valor) antes de decidir se usa o dado indexado ou cai pro fallback; nesse sandbox real, a chave realmente não existia, o fallback rodou de verdade.
- Filtro de `event_refs` restrito por `user.name`/`process.name` — a mesma pegadinha da Task 7 se repete (múltiplos logons e múltiplos EID1 no resultado bruto), então `event_refs` só inclui os 3 eventos relevantes.

## Task - 9-export_scenario_c.sh
O que faz: Lê `scenario_c_search_results.json`, confirma que `source.zone` já vem populado no documento (sem fallback, ao contrário da Task 8), ordena os 5 beacons de firewall (excluindo o alerta Suricata) e calcula o intervalo entre eles, e grava `findings/scenario_c_export.json`.
Como usar: `ASSETS_DIR=<dir> ./9-export_scenario_c.sh`
Comandos:
- `select(._source.full_log | startswith("{") | not)` — separa os 5 flows de firewall (log em CSV) do 1 alerta Suricata (log em JSON) dentro do mesmo array de eventos, usando só o primeiro caractere do `full_log` como discriminador.
- Reaproveita a mesma lógica de beacon/intervalo da Task 6, mas sem o lookup Python de CIDR — `source.zone` já vem calculado no documento indexado, uma diferença real de custo de execução entre as duas interfaces pra esse cenário específico.

## Task - 12-tradeoff_analysis.sh
O que faz: Carrega os 8 findings, pareia CLI/export por `scenario_id`, calcula o delta de tempo e de contagem de ações, atribui uma causa (de uma lista fixa de 7 categorias) pra cada vantagem, e grava `comparison/tradeoff_table.json` e `.md`.
Como usar: `./12-tradeoff_analysis.sh` (roda no diretório que contém `findings/`)
Comandos:
- `declare -A CAUSES=(...)` — dicionário associativo bash fixo, porque a atribuição de causa é julgamento analítico sobre o que realmente aconteceu em cada investigação, não algo derivável só dos números de tempo.
- Construção incremental de um array JSON via `jq --argjson row "$ROW_JSON" '. + [$row]'` num loop bash — evita montar toda a lista de uma vez com um único comando `jq` complexo.

## Task - 13-workflow_comparison.sh
O que faz: Agrega os 8 findings por interface (total/média/mediana de tempo, ações, campos, referências de evento), calcula a distribuição de confiança, computa o delta por cenário, e grava `comparison/workflow_comparison.json`.
Como usar: `./13-workflow_comparison.sh`
Comandos:
- `def median(arr): ...` — função `jq` definida na própria expressão de filtro pra calcular mediana com tratamento explícito de array par vs. ímpar.
- `group_by(.interface) | map(...) | map({(.interface): .}) | add` — transforma um array agrupado num objeto chaveado pelo nome da interface.
- **Multiplicar string por zero em `jq` retorna `null`, não string vazia** — `" " * 0` quebrou o alinhamento de "wazuh_export" (que tem exatamente o tamanho do padding calculado); a correção usa `[N, 1] | max` pra garantir pelo menos 1 espaço sempre.
- Substituição de `column -t` por `printf`/`jq` puro — o binário `column` não existe na imagem Ubuntu minimizada do sandbox.

## Task - 15-tool_evaluation_package.sh
O que faz: Monta `tool_evaluation/` com a estrutura travada (`findings/`, `comparison/`, `playbook/`, `brief/`, `workspace/`, `runtime/`), copiando cada arquivo exigido (falhando alto se algum estiver ausente ou vazio), e gera `MANIFEST.json` com caminho/tamanho/sha256 de cada entrada.
Como usar: `./15-tool_evaluation_package.sh` (roda no diretório com os subdiretórios já gerados pelas tasks anteriores)
Comandos:
- Listas bash fixas percorridas em loop, cada arquivo testado com `[ -f ... ] && [ -s ... ]` antes de copiar — garante "falha alto" na ausência de qualquer arquivo específico, não um `cp` genérico que falharia silenciosamente.
- `find "$DIR" -type f -print0 | sort -z` — lista com terminador nulo (seguro contra espaço no nome), ordenado de forma determinística antes de gerar o manifesto.
- `sha256sum arquivo | cut -d' ' -f1` — extrai só o hash da saída padrão do `sha256sum` ("hash  caminho").
- O layout original também exigia arquivos de tasks removidas da grade (`rules/wazuh/*.xml`, `comparison/questions/*.yml`) — o pacote final foi ajustado pra não depender deles.

## Task - playbook/tool_agnostic_playbook.md
Conceito: Um playbook vendor-neutro sobrevive à troca de SIEM porque documenta o workflow cognitivo (filtro → agregação → janela de tempo) separado do custo de execução de cada interface — a mesma pergunta investigativa se decompõe igual em `jq`, Sigma, KQL e Lucene, só o "quanto custa" cada etapa muda. Os "Known Pitfalls" documentados vieram de bugs reais encontrados durante a semana (campo `src_ip` nulo, ausência de `event_id`, CRLF em Markdown, `jq` reservando `end` como palavra-chave), não de suposição teórica.

## Task - vendor_brief.md
Conceito: Uma recomendação de vendor defendida por evidência contada, não por opinião, precisa admitir os limites da própria medição — nesse caso, que `time_to_first_answer_seconds` mede tempo de execução de script, não o tempo real de um analista clicando num dashboard, e que a granularidade das listas `actions` difere entre as duas interfaces por desenho da task, não por diferença real de esforço.
