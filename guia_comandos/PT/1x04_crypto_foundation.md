# 1x04 – Crypto Foundation

## Task - 0-crypto_inventory.md
Conceito: Mapeamento de proteção de dados nos três estados em que eles existem — em repouso (at rest), em trânsito (in transit) e em uso (in use). Para cada sistema, avalia-se se a criptografia aplicada em cada estado é adequada, fraca ou ausente. É a base de qualquer avaliação de postura criptográfica: sem esse inventário não dá para saber onde faltam controles.

## Task - 1-symmetric_encrypt.sh
O que faz: Criptografa um arquivo com AES-256, permitindo escolher entre o modo CBC (via `openssl enc`) ou o modo GCM (via Python, já que o subcomando `enc` do OpenSSL não suporta cifras AEAD/autenticadas).
Como usar: `./1-symmetric_encrypt.sh <arquivo_entrada> <arquivo_saida> <cbc|gcm>` com a variável de ambiente `MEDDEFENSE_ENC_PASS` definida antes.
Comandos:
- `openssl enc -aes-256-cbc -pbkdf2 -salt -in arquivo -out arquivo.enc -pass env:MEDDEFENSE_ENC_PASS` — criptografa um arquivo com AES-256-CBC, derivando a chave da senha via PBKDF2 e usando salt aleatório.

## Task - 2-asymmetric_analysis.md
Conceito: Criptografia assimétrica (chave pública/privada) usando RSA e ECC. Mostra que RSA só consegue cifrar blocos pequenos (limitado pelo tamanho do módulo), por que ECC atinge segurança equivalente com chaves muito menores, e por que na prática (TLS) a criptografia assimétrica só é usada para negociar uma chave — o modelo híbrido, onde o dado em si é protegido por criptografia simétrica.

## Task - 3-hash_analysis.md
Conceito: Funções de hash criptográficas (MD5, SHA-256) e suas propriedades: efeito avalanche, colisões e o ataque do aniversário, tabelas rainbow e a defesa por meio de salt, e key stretching (bcrypt, PBKDF2, Argon2) para proteger senhas armazenadas contra força bruta em GPU.

## Task - 3-hash_verify.sh
O que faz: Verifica a integridade de um arquivo comparando seu hash SHA-256 atual com um hash esperado, informado como parâmetro.
Como usar: `./3-hash_verify.sh <caminho_arquivo> <hash_sha256_esperado>`.
Comandos:
- `sha256sum arquivo` — calcula o hash SHA-256 de um arquivo para checagem de integridade.

## Task - 4-key_exchange.md
Conceito: Troca de chaves Diffie-Hellman (DH) — permite que duas partes cheguem a um segredo compartilhado por um canal inseguro, sem nunca transmitir o segredo em si. Explica também a limitação central do DH puro: ele não autentica quem está do outro lado, o que abre espaço para ataque man-in-the-middle a menos que seja combinado com certificados (como no TLS via ECDHE + certificado do servidor).

## Task - 5-sign_verify.sh
O que faz: Assina digitalmente um arquivo com uma chave privada (SHA-256) e verifica essa assinatura usando a chave pública correspondente.
Como usar: `./5-sign_verify.sh sign <arquivo> <chave_privada>` para assinar, ou `./5-sign_verify.sh verify <arquivo> <arquivo.sig> <chave_publica>` para verificar.
Comandos:
- `openssl dgst -sha256 -sign chave_privada.pem -out arquivo.sig arquivo` — gera uma assinatura digital SHA-256 do arquivo usando a chave privada.
- `openssl dgst -sha256 -verify chave_publica.pem -signature arquivo.sig arquivo` — verifica se a assinatura corresponde ao arquivo usando a chave pública.

## Task - 6-algorithm_landscape.md
Conceito: Panorama de referência dos algoritmos criptográficos (simétricos, assimétricos, hash e derivação de chave), classificando cada um como atual, obsoleto ou quebrado, com a justificativa técnica de por que cada algoritmo fraco (DES, RC4, MD5, SHA-1) não deve mais ser usado.

## Task - 7-obfuscation_toolkit.md
Conceito: Comparação entre as principais técnicas de ofuscação/proteção de dados — criptografia (reversível com chave), hashing (irreversível por design), tokenização (substituição por um valor sem relação matemática com o original, mapeado em um cofre separado), mascaramento de dados (ocultação parcial para exibição) e esteganografia (ocultar dados dentro de outro arquivo).

## Task - 8-certificate_anatomy.md
Conceito: Estrutura de um certificado digital X.509 — campos como Subject, Issuer, Validade, Serial Number, algoritmo de assinatura, Subject Alternative Names (SAN), Key Usage e Authority Information Access (AIA), inspecionados em certificados reais (válido, comercial e expirado).

## Task - 9-chain_of_trust.md
Conceito: Cadeia de confiança de certificados (chain of trust) — como um certificado folha (leaf) é validado subindo até uma CA intermediária e depois uma CA raiz, por que a cadeia quebra se faltar um elo intermediário, e os mecanismos de revogação: CRL, OCSP e OCSP Stapling.

## Task - 10-csr_workshop.md
Conceito: Geração de um CSR (Certificate Signing Request) — o processo de criar um par de chaves e uma solicitação de certificado contendo os dados da organização e os nomes (SAN) que o certificado deve cobrir, antes de submeter a uma autoridade certificadora.

## Task - 10-generate_csr.sh
O que faz: Gera uma chave privada ECC P-256, cria um CSR configurado com Subject Alternative Names a partir de um Common Name informado, e exibe o conteúdo do CSR gerado.
Como usar: `./10-generate_csr.sh <common_name>` (ex.: `./10-generate_csr.sh portal.meddefense.local`).
Comandos:
- `openssl ecparam -genkey -name prime256v1 -out chave_privada.pem` — gera uma chave privada ECC na curva P-256.
- `openssl req -new -key chave_privada.pem -out arquivo.csr -config openssl.cnf` — cria um CSR usando a chave privada e um arquivo de configuração com os dados do Subject e SANs.
- `openssl req -text -noout -in arquivo.csr` — exibe o conteúdo detalhado de um CSR para inspeção.

## Task - 11-tls_audit.md
Conceito: Auditoria de configuração TLS/SSL — avaliação de versões de protocolo suportadas, força das cipher suites, forward secrecy e certificado, usando a metodologia de nota (grade) do SSL Labs para identificar configurações fracas como suporte simultâneo a TLS antigo e moderno, ou presença de RC4.

## Task - 12-disk_encryption.md
Conceito: Criptografia de disco com LUKS (Linux Unified Key Setup) — como formatar um volume com LUKS, abri-lo como um dispositivo de bloco descriptografado via device-mapper, criar um sistema de arquivos nele, e a proteção que isso oferece contra roubo/perda física do dispositivo.

## Task - 12-luks_manager.sh
O que faz: Cria, abre/monta e fecha/desmonta volumes criptografados com LUKS, automatizando o fluxo completo de disk encryption.
Como usar: `./12-luks_manager.sh create <arquivo_volume> <tamanho_MB> <nome_mapper>`, `./12-luks_manager.sh open <arquivo_volume> <nome_mapper> <ponto_montagem>` ou `./12-luks_manager.sh close <nome_mapper> <ponto_montagem>`.
Comandos:
- `dd if=/dev/zero of=arquivo.img bs=1M count=500 status=progress` — cria um arquivo de imagem de disco vazio de tamanho fixo, para servir de volume virtual.
- `sudo cryptsetup luksFormat arquivo.img` — formata o arquivo/dispositivo com criptografia LUKS (AES-256-XTS por padrão), exigindo confirmação e senha.
- `sudo cryptsetup luksOpen arquivo.img nome_mapper` — abre (descriptografa) o volume LUKS e o expõe como `/dev/mapper/nome_mapper`.
- `sudo mkfs.ext4 /dev/mapper/nome_mapper` — cria um sistema de arquivos ext4 dentro do volume já descriptografado.
- `sudo mount /dev/mapper/nome_mapper /ponto/montagem` — monta o volume descriptografado em um diretório.
- `sudo umount /ponto/montagem` — desmonta o volume antes de fechá-lo.
- `sudo cryptsetup luksClose nome_mapper` — fecha o volume LUKS, removendo o dispositivo descriptografado de `/dev/mapper`.

## Task - 13-encryption_levels.md
Conceito: Os seis níveis/escopos em que criptografia pode ser aplicada — disco inteiro, partição, volume lógico, arquivo, banco de dados e campo/registro — comparando impacto de performance, complexidade de gestão de chaves e o caso de uso ideal de cada nível.

## Task - 14-key_management.md
Conceito: Proteção de chaves criptográficas baseada em hardware e gestão de chaves — TPM (âncora de confiança de um único dispositivo), HSM (appliance dedicado para operações criptográficas em servidores), Secure Enclave (ambiente isolado dentro do processador) e KMS (serviço gerenciado de chaves na nuvem), além do ciclo de vida de uma chave: armazenamento, controle de acesso, rotação e resposta a comprometimento ou perda.

## Task - 15-crypto_posture_audit.md
Conceito: Metodologia de auditoria de postura criptográfica — transformar cada lacuna "fraca" ou "ausente" identificada em um finding formal, documentado, vinculado a algoritmo recomendado, nível de criptografia e plano de gestão de chaves, com prioridade de remediação.

## Task - 16-crypto_attack_surface.md
Conceito: Mapeamento da superfície de ataque criptográfica — ataques concretos como downgrade de TLS, colisão de hash, ataque do aniversário, Kerberoasting e man-in-the-middle em canais sem criptografia, cada um ligado a uma vulnerabilidade real e sua mitigação.

## Task - 17-certificate_lifecycle.md
Conceito: Gestão do ciclo de vida de certificados digitais — inventário de certificados, estratégia de renovação automática (ACME/Let's Encrypt), limiares de monitoramento/alerta de expiração, e política formal de certificados para evitar renovações manuais esquecidas.

## Task - 18-data_classification.md
Conceito: Matriz de classificação de dados — categorização de tipos de dado (regulado/PHI, PII, financeiro, propriedade intelectual, legal, operacional) e níveis de sensibilidade (Público, Interno, Confidencial, Restrito), cada nível definindo quem pode acessar e quais requisitos de criptografia se aplicam.

## Task - 19-hipaa_checkpoint.md
Conceito: Checkpoint de conformidade com os requisitos criptográficos da HIPAA Security Rule (45 CFR §164.312) — diferenciação entre especificações "obrigatórias" (required) e "endereçáveis" (addressable), e avaliação de quais controles de criptografia a organização efetivamente cumpre.

## Task - 22-implementation_playbook.md
Conceito: Playbook operacional de implementação — traduz os findings de auditoria em ações passo a passo, com pré-requisitos, procedimento detalhado e critérios de validação, servindo como documento de execução para a equipe de TI (não um documento de estratégia).
