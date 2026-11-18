# Vault Lease Revocation Transcript

```text
$ vault lease revoke database/creds/lis-readwrite/9kLmVaultRw002
All revocation operations queued successfully!

$ mysql -uv-lis-readwrite-Q2p8 -pT7mP-write-4nQ lis_production -e "SELECT USER();"
ERROR 1045 (28000): Access denied for user 'v-lis-readwrite-Q2p8'@'10.0.3.5' (using password: YES)

$ mysql -uroot -pREDACTED -e "SELECT user, host FROM mysql.user WHERE user LIKE 'v-lis%';"
+-----------------------+------+
| v-lis-readonly-H7s9k2 | %    |
+-----------------------+------+
```

The revoked read-write credential was removed from the database. A stolen username/password is useless after revocation.
