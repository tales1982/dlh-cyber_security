# 4x00 - Dissecção de Phishing

Investigação de phishing do sistema MedDefense Health Systems. Oito e-mails brutos (cabeçalhos SMTP completos) foram coletados após relatos de funcionários e quarentena do gateway entre 2026-04-14 e 2026-04-16. O objetivo é fazer a triagem, decidir se os maliciosos pertencem a uma campanha coordenada e determinar se a usuária que clicou (Diane Marsh, `WS-NURSE-04`) foi comprometida.

## Regras de manuseio seguro

- Nunca navegue diretamente para uma URL suspeita. Use desmascaramento, serviços de sandbox e ferramentas de linha de comando.
- Nunca abra um anexo no workstation do analista. Use extração de metadados e sandboxes online apenas.
- Toda conclusão deve citar evidências específicas a partir de cabeçalhos, resultados de autenticação ou descobertas de OSINT.

## Tarefas

### 0 - 0-initial_triage.md

Tabela de triagem inicial para E1 a E8 (SPF, DKIM, DMARC, classe, prioridade, evidência) mais um resumo. E2 está fixado como P1-URGENT porque o lote registra o clique em 2026-04-14 às 15:02:33 CDT.

Resultado: 1 SPAM (E6), 4 SUSPEITOS (E2, E3, E5, E7), 3 LEGÍTIMOS (E1, E4, E8).

## Notas sobre o lote de evidências

- A data e hora do clique (2026-04-14 15:02:33 CDT) fica cerca de 66 horas antes da coleta do lote (2026-04-17 09:15 CDT), não aproximadamente 36 horas citadas no briefing. As tarefas posteriores devem usar a marca de tempo do NTP do workstation como referência.
- Os timestamps do DKIM `t=` nos e-mails assinados (E1, E4, E8) caem em 2025, e vários cabeçalhos `Date` contêm nomes de dias da semana que não coincidem com 2026 (2026-04-14 foi uma terça-feira). Isso afeta mensagens legítimas e maliciosas, então foi tratado como artefato do lote e não como sinal de triagem.
