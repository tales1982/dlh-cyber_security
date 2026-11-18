# Vault Database Secrets Transcript

```text
$ vault secrets enable database
Success! Enabled the database secrets engine at: database/

$ vault write database/config/meddefense-lis plugin_name=mysql-database-plugin connection_url="{{username}}:{{password}}@tcp(127.0.0.1:3306)/" allowed_roles="lis-readonly,lis-readwrite" username="vault_manager" password="VaultMgr_2026_secure"
Success! Data written to: database/config/meddefense-lis

$ vault write database/roles/lis-readonly db_name=meddefense-lis default_ttl="1h" max_ttl="4h"
Success! Data written to: database/roles/lis-readonly

$ vault write database/roles/lis-readwrite db_name=meddefense-lis default_ttl="15m" max_ttl="1h"
Success! Data written to: database/roles/lis-readwrite

$ vault read database/creds/lis-readonly
lease_id           database/creds/lis-readonly/3s9fXJd7aMedDefense001
lease_duration     1h
lease_renewable    true
password           A1q7-z9R2-MedD-Read
username           v-lis-readonly-H7s9k2

$ mysql -uv-lis-readonly-H7s9k2 -pA1q7-z9R2-MedD-Read lis_production -e "SELECT USER(); SHOW GRANTS;"
USER(): v-lis-readonly-H7s9k2@10.0.3.5
GRANT SELECT ON `lis_production`.* TO `v-lis-readonly-H7s9k2`@`%`

$ vault list sys/leases/lookup/database/creds/lis-readonly/
Keys
----
3s9fXJd7aMedDefense001

$ vault read database/creds/lis-readwrite
lease_id           database/creds/lis-readwrite/9kLmVaultRw002
lease_duration     15m
lease_renewable    true
password           T7mP-write-4nQ
username           v-lis-readwrite-Q2p8
```
