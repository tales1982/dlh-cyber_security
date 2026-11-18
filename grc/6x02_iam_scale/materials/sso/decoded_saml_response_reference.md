# Decoded SAML Response Reference

| Element | Purpose | SP validation |
|---|---|---|
| Issuer | IdP entity | Must match registered IdP |
| NameID | Authenticated user | Maps to local account |
| Conditions | Validity constraints | Time and audience checked |
| NotBefore | Earliest valid time | Reject before this time |
| NotOnOrAfter | Expiration | Reject at or after this time |
| AuthnStatement | Authentication event | Session context |
| AttributeStatement | User attributes | Authorization mapping |
| MedDefenseRole | MedDefense RBAC role | Maps to clinical or IT permissions |
| Signature | Tamper protection | Reject if invalid |

Expired assertions must be rejected to prevent replay. Signed assertions prevent attackers from modifying role or subject values.
