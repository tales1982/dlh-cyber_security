# SAML Flow Notes

Actors: Keycloak IdP realm `meddefense`, service provider `meddefense-portal`, and workforce users.

Flow: user accesses SP, SP redirects to IdP, IdP authenticates, IdP issues signed SAML response, SP validates issuer/audience/recipient/time/signature, then maps `MedDefenseRole` to authorization.

Security notes: realm isolation separates users and clients; email NameID maps workforce identity; `NotBefore` and `NotOnOrAfter` limit replay; `Signature` detects tampering; centralized SSO reduces off-boarding risk because disabling the IdP account blocks connected services.
