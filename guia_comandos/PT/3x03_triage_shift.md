# 3x03 – Triage Shift

## Task - 0-queue_assessment.sh
O que faz: Lê `alert_queue.json` e `alert_queue_schema.json`, valida cada alerta contra o schema com um validador próprio (sem depender da lib `jsonschema`), e grava `queue_assessment.json` com contagem por banda de prioridade, por regra, por host, por tática ATT&CK (derivada das tags Sigma da regra de origem) e os 3 hosts com maior soma de `priority_score`. Também imprime um briefing de turno legível no terminal.
Como usar: `CATALOG_DIR=<dir> ./0-queue_assessment.sh` (padrão: `~/3x02_package/detection_catalog`)
Comandos:
- `re.compile` + `UUID_RE.match`/`is_datetime()` — validação de formato (`uuid`, `date-time`) reimplementada na mão em vez de importar uma lib de JSON Schema, checando cada campo contra `properties`/`required`/`enum`/`items` do schema recursivamente (incluindo o objeto aninhado `event_summary`).
- `os.path.isdir(rules_dir)` como guarda — se o diretório de regras Sigma não existir, a derivação de tática degrada graciosamente (bucket `unmapped`) em vez de travar o script.
- Parser de texto linha a linha (não YAML completo) sobre o bloco `tags:` de cada regra Sigma — reconhece `attack.<tática>` e resolve pra um ID de tática MITRE fixo (14 táticas Enterprise, tabela pequena e estável, ao contrário da centena de IDs de técnica).
- Resolução de regra "tuned" — para cada arquivo base em `rules/sigma/`, prefere o correspondente em `rules/sigma/tuned/` se existir, mesma lógica de seleção usada pelo gerador de alertas do 3x02.
- `max(generated_ats)[:10]` — usa a data do próprio `generated_at` dos alertas (não o relógio da wall-clock) para nomear o turno no briefing, garantindo saída determinística em reexecuções.

## Task - 2-context_assembly.sh
O que faz: Junta `alert_queue.json` com `asset_inventory.json`, `enriched_events.json`, `baseline_summary.json` e `ioc_context.json` numa única passada, produzindo `enriched_queue.json` onde cada alerta já carrega o registro de ativo completo, o perfil de baseline do host, o evento completo dereferenciado e os hits de IOC.
Como usar: `CATALOG_DIR=<dir> HANDOFF_DIR=<dir> BASELINE_PKG=<dir> ASSETS_DIR=<dir> ./2-context_assembly.sh`
Comandos:
- Conjunto de "chaves necessárias" (`needed_keys`) montado a partir de `event_summary` antes de abrir `enriched_events.json` — permite uma única passada de streaming pelo arquivo de ~200MB guardando na memória só os registros que algum alerta realmente referencia, não o arquivo inteiro.
- Casamento por chave composta (`timestamp`, `hostname`, `user`, `process_name`, `src_ip`, `dst_ip`, `event_category`) em vez de reabrir a linha crua pelo offset de `event_ref` — corrige um desalinhamento real encontrado entre `normalized_events.json` (onde o offset foi gravado) e `enriched_events.json` (onde a limpeza intermediária removeu ~134 linhas).
- `dict(alert)` como base do registro enriquecido — copia todos os campos originais do alerta antes de acrescentar `asset`/`baseline_host_profile`/`event_record`/`ioc_hits`/`priority_band`, sem precisar listar campo por campo.
- Detecção de formato do inventário (lista simples vs. `{"assets": [...]}`) com aviso no stderr quando `service_account_prefix`/`management_subnets` não existem — degrada de forma graciosa em vez de assumir um schema que pode não estar presente.

## Task - 3-triage_clearcut_tp.sh
O que faz: Lê `enriched_queue.json` e escalona automaticamente todo alerta `priority_band == critical` com pelo menos um IOC `malicious` e violação de baseline na categoria da regra, gravando `tickets/batch1_clearcut_tp.json`.
Como usar: `./3-triage_clearcut_tp.sh` (roda no diretório onde `enriched_queue.json` já foi gerado)
Comandos:
- `datetime.fromisoformat(...replace("Z", "+00:00"))` — converte timestamp ISO 8601 com sufixo `Z` (não suportado nativamente por `fromisoformat` em versões mais antigas) pro formato aceito.
- Dicionário de despacho por categoria (`auth`/`process`/`network`/`file`) em `baseline_violation()` — cada categoria checa um campo diferente do `baseline_host_profile` (contagem por `canonical_label`, conjunto de processos esperados, portas conhecidas), reaproveitando o mesmo threshold "nunca visto antes" descrito em `baseline_summary.json`.
- `abs((other_ts - alert_ts).total_seconds()) <= CORRELATION_WINDOW_SECONDS` — junta ao `evidence_refs` qualquer outro alerta do mesmo host dentro de uma janela de 1h, excluindo por `event_ref` (não só por identidade do objeto) pra não duplicar referência quando dois alertas apontam pro mesmo evento.
- `uuid.uuid5(TICKET_NAMESPACE, alert_id)` — gera `ticket_id` determinístico a partir de um namespace fixo, garantindo que rodar o script duas vezes produza o mesmo ID.

## Task - 4-triage_clearcut_fp.sh
O que faz: Lê `enriched_queue.json` e `asset_inventory.json`, e fecha todo alerta que bate com qualquer uma das 4 assinaturas de falso positivo da metodologia (conta de serviço, subnet de gestão, processo já visto no baseline, IOC limpo sem desvio), gravando `tickets/batch2_clearcut_fp.json`.
Como usar: `HANDOFF_DIR=<dir> ./4-triage_clearcut_fp.sh`
Comandos:
- `ipaddress.ip_network(cidr)` / `endereco in rede` — testa se o `src_ip` do alerta cai dentro de alguma subnet de gestão, sem implementar aritmética de CIDR na mão.
- `user.startswith(service_account_prefix)` — reconhece contas de serviço pelo prefixo do nome de usuário (`svc_` por padrão, ou o valor declarado no inventário), a checagem mais simples e direta possível para esse sinal.
- Cadeia de `if`/`elif` na ordem exata das 4 assinaturas do enunciado — cada ramo só é avaliado se o anterior não bateu, então o `fp_reason` registrado é sempre o da primeira assinatura satisfeita.

## Task - 6-triage_ambiguous_auth.sh
O que faz: Lê `enriched_queue.json` e processa todo alerta de autenticação ainda não classificado em batches anteriores, buscando o histórico de login do usuário em `baseline_summary.json` e os eventos brutos em `enriched_events.json` para aplicar a árvore de decisão de 4 ramos (IP desconhecido + ativo crítico/alto + nunca logou no host → escalar; IP desconhecido + ativo médio/baixo + sem IOC → fechar; IP conhecido + rajada de falha dentro do limiar → fechar; caso contrário → monitorar).
Como usar: `BASELINE_PKG=<dir> HANDOFF_DIR=<dir> ./6-triage_ambiguous_auth.sh`
Comandos:
- `glob.glob("tickets/batch*.json")` + `os.path.abspath` pra excluir o próprio arquivo de saída — monta o conjunto de alertas já classificados em qualquer batch anterior, sem precisar listar nomes de arquivo fixos (funciona mesmo com uma task intermediária ainda não implementada).
- Uma única passada por `enriched_events.json` filtrando só os usuários que aparecem nos alertas candidatos — constrói o conjunto de hosts/IPs históricos e a lista de eventos de cada usuário sem carregar o arquivo inteiro na memória.
- Operador *walrus* (`:=`) dentro de uma expressão geradora de `sum()` — calcula a rajada de falhas de 1h contando eventos cujo timestamp cai dentro da janela, tudo numa única expressão.
- `timedelta(seconds=FAILURE_BURST_WINDOW_SECONDS)` — define a janela deslizante de 1 hora usada tanto pra contar a rajada quanto pra comparar com `max_failures_1h_window` do baseline.

## Task - 7-triage_ambiguous_proc_net.sh
O que faz: Lê `enriched_queue.json` e `baseline_summary.json`, e processa todo alerta de processo ou rede ainda não classificado, aplicando a árvore de decisão de 5 ramos que decide com base na reputação do IOC já calculada pelo T2 e em se o processo/destino já é conhecido no baseline de *outro* host.
Como usar: `BASELINE_PKG=<dir> ./7-triage_ambiguous_proc_net.sh`
Comandos:
- `re.compile(r"\bby\s+(\S.*)$")` sobre `raw_message` — extrai o processo pai (`parent_process`) do texto livre do evento (ex: "Process Create: X by Y"), a mesma convenção que a regra `003_interpreter_abuse.yml` já documenta pra quando não existe campo literal de processo pai.
- `min(flagged, key=lambda h: SEVERITY_ORDER.index(...))` — escolhe o hit de IOC "pior" entre vários presentes no mesmo alerta, usando a posição numa lista ordenada (`malicious` < `suspicious` < `unknown`) como critério.
- Checagem cruzada de baseline em hosts diferentes do alerta (`process_per_host`, excluindo o próprio host) e contra `network.top_destinations` (lista global) — reconhece quando um IOC "suspeito" já é uma atividade estabelecida em outro lugar do ambiente.

## Task - 8-triage_correlation.sh
O que faz: Lê `enriched_queue.json`, agrupa alertas do mesmo host cuja diferença de timestamp fica dentro de 600 segundos numa cadeia (mesclando transitivamente), classifica cada grupo de 2+ alertas como incidente, e **atualiza os tickets já escritos** marcando `grouped: true` nos alertas agrupados.
Como usar: `./8-triage_correlation.sh`
Comandos:
- Ordenação por timestamp seguida de agrupamento por "gap" (`(ts - current_group[-1][0]).total_seconds() <= 600`) — técnica de janela deslizante que mescla corretamente cadeias transitivas (A-B ≤600s, B-C ≤600s) mesmo quando A e C sozinhos ficam mais distantes.
- `glob.glob` + dicionário `alert_id → (arquivo, índice)` — localiza em qual arquivo de ticket (e em qual posição da lista) cada alerta contribuinte já foi classificado, pra poder editar aquele ticket específico sem reescrever os outros.
- Mutação in-place do dicionário do ticket (`ticket_files[path][index]["grouped"] = True`) seguida de `json.dump` de volta pro mesmo arquivo — só os arquivos realmente tocados são regravados, preservando os demais bit a bit.
- `max(entries, key=lambda e: e[1].get("priority_score", 0))` — quando nenhum alerta do grupo já é `true_positive` em outro ticket, usa o de maior `priority_score` pra decidir a classificação do incidente "do zero".

## Task - 11-incident_assembly.sh
O que faz: Lê todos os `tickets/batch*.json` e `enriched_queue.json`, seleciona todo ticket `true_positive` com ação recomendada de escalonar ou monitorar (pulando os já marcados `grouped: true`, que viram parte de um incidente do T8), e monta `incidents.json` com timeline, ativos afetados, IOCs, técnicas ATT&CK e uma ação de contenção recomendada.
Como usar: `./11-incident_assembly.sh`
Comandos:
- `"contributing_alerts" in ticket` vs `"alert_id" in ticket` — distingue as duas formas de ticket que o glob encontra (ticket individual das batches 1-7 vs. ticket de incidente do T8) sem precisar saber o nome do arquivo de origem.
- Função de ordenação (`source_sort_key`) por timestamp mais antigo e depois pelos `alert_id`s ordenados — garante que a numeração sequencial (`INC-...-0001`, `0002`...) saia sempre na mesma ordem em reexecuções, mesmo sem depender de relógio.
- Lista de predicados `(lambda, ação)` avaliados em ordem (`CONTAINMENT_TABLE`) — implementa a "tabela fixa" de contenção pedida no enunciado como uma lista simples percorrida do topo pra baixo, parando na primeira condição satisfeita.
- Campos internos prefixados com `_` (`_hostnames`, `_ioc_values`) guardados no dicionário do incidente só pra viabilizar o segundo passo de `related_incidents` (interseção de conjuntos entre incidentes) e removidos (`.pop(..., None)`) antes de gravar o JSON final.

## Task - 1-triage_methodology.md
Conceito: Uma metodologia de triagem por escrito define, antes de qualquer alerta ser processado, os critérios objetivos que separam `true_positive` de `false_positive`, quando escalar pro Tier 2, e o que toda ticket precisa documentar — sem isso, dois analistas podem classificar o mesmo alerta de forma diferente sem nenhuma forma objetiva de resolver a discordância. O critério de escalonamento por correlação ("dois ou mais alertas no mesmo host/usuário") é o que permite que um grupo de alertas ambíguos individualmente escalone quando correlacionados.

## Task - 15-classification_under_ambiguity.md
Conceito: Um cenário de correlação onde nenhum alerta isolado cruza o limiar de escalonamento, mas o conjunto descreve um padrão crível de pós-comprometimento, expõe a diferença entre aplicar um critério "estritamente" alerta por alerta e aplicar a metodologia como um todo — o próprio critério de correlação existe pra cobrir exatamente esse caso. Rastrear o cenário pelos scripts reais (em vez de só argumentar em tese) confirma que o pipeline já escalona corretamente, e revela uma limitação honesta na checagem de baseline de processo (não olha a relação pai-filho), que a correlação compensa mesmo assim.
