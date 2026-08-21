# 2x01 – Windows Fortress

## Task - 0-domain_baseline.ps1
O que faz: Captura o baseline completo e não hardenizado do domínio AD meddefense.local antes de qualquer trabalho de hardening via GPO — contas, grupos, contas de serviço, GPOs, política de senha/lockout, tipos de criptografia Kerberos e associação a grupos privilegiados. É a referência contra a qual todas as tarefas de hardening seguintes são medidas.
Como usar: Executar como Administrador de Domínio no PowerShell, em um Domain Controller (somente leitura, não faz alterações).
Comandos:
- `Import-Module ActiveDirectory` — carrega os cmdlets do módulo Active Directory na sessão.
- `Import-Module GroupPolicy` — carrega os cmdlets do módulo Group Policy na sessão.
- `Get-ADDomain` — retorna informações do domínio (nível funcional, DN, nome NetBIOS).
- `Get-ADForest` — retorna informações da floresta AD (nível funcional da floresta).
- `Get-ADDomainController -Filter *` — lista todos os controladores de domínio.
- `Get-ADUser -Filter * -Properties Enabled,LastLogonDate,PasswordLastSet,...` — enumera contas de usuário do AD com os atributos indicados.
- `Get-ADGroup -Filter *` — enumera todos os grupos do AD.
- `Get-ADGroupMember -Identity <grupo>` — lista os membros de um grupo do AD.
- `Get-GPO -All` — lista todos os Group Policy Objects do domínio.
- `Get-ADOrganizationalUnit -Filter * -Properties LinkedGroupPolicyObjects` — lista as OUs e as GPOs vinculadas a cada uma.
- `Get-ADDefaultDomainPasswordPolicy` — lê a política padrão de senha/lockout do domínio.
- `Get-ADFineGrainedPasswordPolicy -Filter *` — lista políticas de senha granulares (por grupo) configuradas.
- `Get-ADComputer -Identity <nome> -Properties msDS-SupportedEncryptionTypes` — lê o atributo de tipos de criptografia Kerberos suportados de um objeto computador.
- `Get-SmbServerConfiguration` — lê a configuração do servidor SMB local, incluindo se o SMBv1 está habilitado.

## Task - 1-domain_findings.ps1
O que faz: Transforma o baseline bruto do script 0 em um inventário de risco acionável — cada achado (severidade, categoria, evidência, risco, remediação recomendada e tarefa responsável) é documentado individualmente. É a lista de pendências que o restante do projeto Windows Fortress executa.
Como usar: Executar como Administrador de Domínio no PowerShell, após rodar 0-domain_baseline.ps1 (somente leitura).
Comandos:
- `auditpol /get /category:* /r` — lista todas as subcategorias de auditoria configuradas no host, em formato CSV.
- `Get-ItemProperty -Path <chave> -Name <valor>` — lê um valor específico do registro do Windows (aqui, o status do Script Block Logging).
- `Get-Service -Name <nome>` — consulta o status de um serviço do Windows (aqui, o Sysmon).

## Task - 2-eventlog_assessment.ps1
O que faz: Mede a lacuna de visibilidade entre o que o domínio pode ver hoje e o que precisa ver — cruza cada Event ID crítico (4624, 4625, 4648, 4688, 4720, 4726, 4732, 4672, 1102) com a subcategoria de auditoria que o gera e com ocorrências reais nas últimas 24 horas.
Como usar: Executar como Administrador no PowerShell, em um Domain Controller (somente leitura).
Comandos:
- `Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=<data>; Id=<lista>}` — consulta o Visualizador de Eventos por log, intervalo de tempo e IDs de evento específicos.

## Task - 3-telemetry_reference.ps1
O que faz: Constrói uma referência estática, legível por máquina, ligando cada evento relevante do projeto (Security, PowerShell Operational, Sysmon) à sua dependência de auditoria/sensor, seu significado de segurança e a fase do Crimson Tide correspondente.
Como usar: Executar em qualquer estação com PowerShell para gerar o arquivo de referência JSON (não consulta o domínio ao vivo nem faz alterações).
Comandos:
- (nenhum comando novo — script de dados estáticos; documenta o uso de `Get-WinEvent`, já listado no script 2, como método de validação de cada evento).

## Task - 4-password_policy.ps1
O que faz: Implanta uma política de senha e lockout alinhada ao CIS (mínimo de 14 caracteres, complexidade, histórico de 24, lockout em 5 tentativas), criando/vinculando uma GPO real e aplicando os mesmos valores via Set-ADDefaultDomainPasswordPolicy.
Como usar: Executar como Administrador de Domínio no PowerShell, em um Domain Controller (faz alterações).
Comandos:
- `New-GPO -Name <nome> -Comment <texto>` — cria um novo Group Policy Object vazio.
- `New-Item -Path <caminho> -ItemType Directory -Force` — cria um diretório no caminho especificado.
- `Set-Content -Path <arquivo> -Value <conteúdo> -Encoding <enc>` — grava conteúdo em um arquivo; aqui, escreve manualmente os templates de segurança da GPO (GptTmpl.inf, GPT.INI).
- `Get-Content -Path <arquivo> -Raw` — lê o conteúdo completo de um arquivo como uma única string (usado para reler o GPT.INI antes de incrementar a versão).
- `Set-ADObject -Identity <DN> -Replace @{versionNumber=...; gPCMachineExtensionNames=...}` — modifica diretamente atributos de um objeto do AD, usado para atualizar a versão e os CSEs de uma GPO.
- `Set-ADDefaultDomainPasswordPolicy -Identity <domínio> -MinPasswordLength <n> -ComplexityEnabled $true ...` — define a política efetiva de senha/lockout do domínio.
- `Get-GPInheritance -Target <DN>` — lê os vínculos de GPO e a herança em um contêiner do AD.
- `New-GPLink -Guid <id> -Target <DN> -LinkEnabled Yes -Enforced Yes` — vincula uma GPO a um domínio ou OU.
- `gpupdate /target:computer /force` — força a atualização imediata da Política de Grupo no host.

## Task - 5-audit_policy.ps1
O que faz: Fecha as lacunas de visibilidade identificadas no script 2, implantando a Política de Auditoria Avançada via GPO — auditoria por subcategoria, captura de linha de comando no evento 4688, restrição de quem pode limpar o log de Segurança, e log de Segurança de 1 GB.
Como usar: Executar como Administrador de Domínio no PowerShell, em um Domain Controller (faz alterações).
Comandos:
- `Get-ADObject -Identity <DN> -Properties gPCMachineExtensionNames` — lê atributos brutos de um objeto do AD, usado para ler os CSEs atualmente registrados em uma GPO.
- `Set-GPRegistryValue -Name <gpo> -Key <chave> -ValueName <nome> -Type DWord -Value <valor>` — grava um valor de registro dentro de uma GPO.
- `wevtutil sl Security /ms:<bytes>` — define o tamanho máximo do log de eventos Security imediatamente no host local.

## Task - 6-powershell_security.ps1
O que faz: Neutraliza o PowerShell como ferramenta pós-exploração implantando Script Block Logging, Module Logging e Transcription via GPO, verifica se o AMSI está ativo e valida o pipeline ponta a ponta rodando um comando codificado.
Como usar: Executar como Administrador de Domínio no PowerShell, em um Domain Controller (faz alterações e roda um teste local).
Comandos:
- `Get-Process -Id $PID` — consulta o processo atual, usado aqui para verificar se o amsi.dll está carregado (AMSI ativo).
- `powershell.exe -NoProfile -EncodedCommand <base64>` — executa um comando PowerShell codificado em Base64, usado como teste para validar o Script Block Logging.

## Task - 7-auth_hardening.ps1
O que faz: Bloqueia Kerberoasting e roubo de credenciais em protocolos legados — limpa a flag UseDESKeyOnly de contas de serviço, restringe o domínio a tickets Kerberos AES128/AES256, recusa NTLMv1 e reporta a prontidão do Credential Guard.
Como usar: Executar como Administrador de Domínio no PowerShell, em um Domain Controller (faz alterações).
Comandos:
- `Set-ADAccountControl -Identity <DN> -UseDESKeyOnly $false` — altera flags de UserAccountControl de uma conta do AD; aqui, remove a exigência de DES.
- `Set-ADUser -Identity <nome> -Replace @{'msDS-SupportedEncryptionTypes'=<valor>}` — modifica diretamente atributos de uma conta de usuário do AD; aqui, os tipos de criptografia Kerberos suportados pelo krbtgt.
- `Set-ADComputer -Identity <DN> -Replace @{'msDS-SupportedEncryptionTypes'=<valor>}` — modifica diretamente atributos de um objeto computador do AD (mesmos tipos de criptografia, nos DCs).
- `Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard` — consulta uma classe WMI/CIM; aqui, checa o status do Credential Guard.

## Task - 8-smb_hardening.ps1
O que faz: Elimina o SMBv1 (o protocolo por trás do EternalBlue/WannaCry/NotPetya), exige assinatura SMB, habilita criptografia SMB e desativa os protocolos legados de resolução de nomes (NetBIOS e LLMNR) que ferramentas como Responder abusam para captura de credenciais.
Como usar: Executar como Administrador de Domínio no PowerShell, em um Domain Controller (faz alterações).
Comandos:
- `Get-SmbClientConfiguration` — lê a configuração do cliente SMB local.
- `Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force` — reconfigura o servidor SMB local; aqui, desabilita o SMBv1 (e depois exige assinatura e habilita criptografia).
- `Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol"` — desabilita um recurso opcional do Windows; aqui, o protocolo SMB1.
- `Set-ItemProperty -Path <chave> -Name <valor> -Type DWord -Value <valor>` — define diretamente um valor de registro do Windows.
- `Set-SmbClientConfiguration -RequireSecuritySignature $true -Force` — reconfigura o cliente SMB local para exigir assinatura.
- `Invoke-CimMethod -InputObject <adaptador> -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=2}` — invoca um método WMI em uma instância CIM; aqui, desabilita NetBIOS sobre TCP/IP.

## Task - 9-sysmon_deploy.ps1
O que faz: Baixa e instala o Sysmon com uma configuração otimizada para detecção (baseline SwiftOnSecurity), depois verifica se o serviço/driver estão ativos e se eventos estão realmente sendo gerados.
Como usar: Executar como Administrador local no PowerShell, no host onde o Sysmon será instalado (faz alterações; requer acesso à internet).
Comandos:
- `Invoke-WebRequest -Uri <url> -OutFile <arquivo> -UseBasicParsing` — baixa um arquivo de uma URL; aqui, o binário do Sysmon e a configuração SwiftOnSecurity.
- `Expand-Archive -Path <zip> -DestinationPath <pasta> -Force` — extrai um arquivo .zip.
- `Sysmon64.exe -accepteula -i <config>` — instala o serviço e o driver do Sysmon com um arquivo de configuração.
- `Remove-Item -Path <caminho> -Force` — remove um arquivo ou item; aqui, o arquivo de teste usado para validar o FileCreate.

## Task - 10-sysmon_tune.ps1
O que faz: Acrescenta 5 regras de detecção específicas do MedDefense (Rclone, PsExec, PowerShell codificado, exclusão de shadow copy, persistência via tarefa agendada) ao sysmonconfig.xml, recarrega a configuração ativa e valida cada regra com um gatilho seguro e não destrutivo.
Como usar: Executar como Administrador local no PowerShell, após 9-sysmon_deploy.ps1 (faz alterações).
Comandos:
- `Sysmon64.exe -c <config>` — recarrega a configuração do Sysmon em execução, sem reinstalar o serviço.
- `Copy-Item -Path <origem> -Destination <destino> -Force` — copia um arquivo; aqui, usado para simular artefatos de ataque (ex.: renomear whoami.exe para rclone.exe) em testes seguros.
- `Start-Process -FilePath <exe> -ArgumentList <args> -WindowStyle Hidden -Wait` — inicia um processo; usado para disparar os gatilhos de teste de cada regra.
- `New-ItemProperty -Path <chave> -Name <valor> -Value <valor> -PropertyType DWord -Force` — cria um novo valor de registro; aqui, simula a instalação de serviço do PsExec.
- `schtasks /create /tn <nome> /tr <cmd> /sc once /st <hora> /f` — cria uma tarefa agendada no Windows; usado como gatilho de teste de persistência.
- `schtasks /delete /tn <nome> /f` — remove uma tarefa agendada, limpando o artefato de teste.

## Task - 11-firewall_hardening.ps1
O que faz: Implementa segmentação de rede em nível de endpoint — bloqueio padrão de entrada nos três perfis de firewall, com regras de permissão estreitas apenas para os serviços que um Domain Controller precisa expor (RDP/WinRM da subnet de gestão, SMB da subnet de servidores, DNS/LDAP/Kerberos), e loga tudo que é descartado.
Como usar: Executar como Administrador local no PowerShell, no host a ser protegido (faz alterações).
Comandos:
- `Get-NetFirewallProfile -All` — lê o estado atual dos perfis do Firewall do Windows (Domain/Private/Public).
- `Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow` — configura os perfis do firewall; aqui, com bloqueio padrão de entrada.
- `Get-NetFirewallRule -Name <nome>` — lê uma regra específica do firewall pelo nome.
- `New-NetFirewallRule -Name <nome> -Direction Inbound -Action Allow -Protocol <proto> -LocalPort <porta> -Profile Domain` — cria uma nova regra de firewall de entrada.
- `Disable-NetFirewallRule -Name <nome>` — desabilita uma regra de firewall existente; aqui, as regras legadas que conflitam com o novo bloqueio padrão.

## Task - 12-applocker_config.ps1
O que faz: Implanta a listagem de permissões de aplicações (AppLocker) via GPO em modo apenas-auditoria, permitindo binários de Windows/Program Files e o aplicativo clínico DicomViewer.exe; tudo o mais é negado pelo comportamento padrão do AppLocker.
Como usar: Executar como Administrador de Domínio no PowerShell, em um Domain Controller (faz alterações).
Comandos:
- `Import-Module AppLocker` — carrega os cmdlets do módulo AppLocker.
- `Set-Service -Name "AppIDSvc" -StartupType Automatic` — define o tipo de inicialização de um serviço do Windows; aqui, o serviço Application Identity, exigido pelo AppLocker.
- `Start-Service -Name "AppIDSvc"` — inicia um serviço do Windows.
- `Set-AppLockerPolicy -XmlPolicy <xml> -Ldap <caminho>` — grava uma política AppLocker diretamente no armazenamento de uma GPO.
- `Test-AppLockerPolicy -PolicyObject <xml> -Path <arquivo> -User <usuário>` — avalia se um arquivo seria permitido ou bloqueado por uma política AppLocker, sem executá-lo.
- `Export-AppLockerPolicy -ALPolicy <obj> -Xml` — exporta um objeto de política AppLocker para XML.

## Task - 13-rdp_hardening.ps1
O que faz: Fecha o RDP como vetor de movimento lateral — exige NLA (autenticação antes da sessão), restringe o acesso ao grupo G_IT_Admins, limita tempo de sessão/ociosidade, força a criptografia máxima e desativa redirecionamento de área de transferência/unidades e Assistência Remota.
Como usar: Executar como Administrador de Domínio no PowerShell, em um Domain Controller (faz alterações).
Comandos:
- `Remove-ADGroupMember -Identity <grupo> -Members <membro> -Confirm:$false` — remove um membro de um grupo do AD; aqui, tira contas indevidas de "Remote Desktop Users".
- `Add-ADGroupMember -Identity <grupo> -Members <membro>` — adiciona um membro a um grupo do AD; aqui, adiciona G_IT_Admins a "Remote Desktop Users".

## Task - 14-service_accounts.ps1
O que faz: Audita cada conta de serviço do MedDefense (privilégios excessivos, senhas antigas, delegação irrestrita) e remedia os achados, marcando as contas como "sensíveis e não delegáveis", negando logon interativo via GPO e removendo associação a grupos privilegiados.
Como usar: Executar como Administrador de Domínio no PowerShell, em um Domain Controller (faz alterações).
Comandos:
- (nenhum comando novo — reutiliza `Set-ADAccountControl`, `Get-ADGroupMember`, `Remove-ADGroupMember`, `New-GPO`, `Set-ADObject`, `Get-Content`/`Set-Content`, entre outros já listados).

## Task - 15-master_validation.ps1
O que faz: Executa o checklist de conformidade semanal — lê cada configuração implantada pelos scripts 4 a 14, compara com o valor esperado e imprime um painel PASS/WARN/FAIL; sai com código 1 se algum item crítico falhar.
Como usar: Executar como Administrador de Domínio no PowerShell, em um Domain Controller, idealmente como tarefa agendada semanal (somente leitura).
Comandos:
- (nenhum comando novo — reutiliza `Get-ADDefaultDomainPasswordPolicy`, `auditpol`, `Get-ItemProperty`, `Get-Service`, `Get-SmbServerConfiguration`, `Get-NetFirewallProfile`, `Get-ADGroupMember`, entre outros já listados).

## Task - 16-hardened_state_export.ps1
O que faz: Exporta o estado final hardenizado do domínio — todos os controles das tarefas 4 a 14 (GPOs, auditoria, logging do PowerShell, Sysmon, firewall, AppLocker, RDP, protocolos de autenticação, contas de serviço) — em um único pacote de evidências estruturado em JSON.
Como usar: Executar como Administrador de Domínio no PowerShell, em um Domain Controller, após os demais scripts (somente leitura).
Comandos:
- `Get-GPOReport -Guid <id> -ReportType Xml` — gera um relatório XML com todas as configurações de uma GPO.
- `Get-AppLockerPolicy -Effective -Xml` — lê a política AppLocker efetivamente em vigor na máquina local.
