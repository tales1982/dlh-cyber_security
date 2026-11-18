# MedDefense SAML SSO Configuration Reference

**Classification:** Internal
**Prepared by:** Tales Lima, IT Security
**Date:** 2026-11-18
**Sources:** `materials/sso/keycloak_realm_export_meddefense.json`, `saml_assertion_d_walsh.xml`, `saml_assertion_r_kim.xml`, `saml_flow_notes.md`, `decoded_saml_response_reference.md`

This reference documents how the Keycloak lab realm federates MedDefense workforce identities to a SAML 2.0 service provider. It is written so that the team evaluating an SSO deployment can check each setting against the exported configuration.

How SAML differs from password delegation: with SAML, the portal never sees or stores the user's password. The user authenticates once at the identity provider (IdP), and the IdP sends the service provider (SP) a signed statement saying who the user is and what role they hold. With password delegation, each application receives the password (or checks it against a shared directory), so every application becomes a place where the password can be stolen, and each one must be disabled separately at off-boarding.

Flow (from `saml_flow_notes.md`):

1. The user opens `meddefense-portal` (the SP).
2. The SP redirects the browser to the Keycloak realm `meddefense` (the IdP).
3. Keycloak authenticates the user.
4. Keycloak issues a signed SAML response and the browser posts it to the SP's Assertion Consumer Service (ACS) URL.
5. The SP checks issuer, audience, recipient, validity times and signature.
6. The SP maps the `MedDefenseRole` attribute to its own permissions.

## Realm Configuration Summary

| Setting | Value in export | Meaning |
| --- | --- | --- |
| Realm | `meddefense` | Isolated tenant: its own users, clients, keys and policies. A user or client in another realm cannot authenticate here. |
| Display name | `MedDefense Health Systems` | Name shown on the login page |
| Enabled | `true` | Realm accepts logins |
| Session idle timeout | `ssoSessionIdleTimeout: 1800` = **30 minutes** | An SSO session with no activity for 30 minutes ends, so an unattended workstation does not stay logged in to every connected system |
| Brute force protection | `bruteForceProtected: true` | Keycloak locks the account after repeated failures |
| Failure factor | `failureFactor: 5` = **5 failed attempts** | Lockout triggers after 5 failed logins, which limits password guessing and spraying |

Realm isolation matters for MedDefense because the workforce realm can be kept apart from any future patient-facing or vendor realm. A compromise of one realm's admin account does not give control of the others.

## Client Configuration Summary

| Setting | Value in export | Meaning |
| --- | --- | --- |
| Client ID | `meddefense-portal` | The SP entity ID; must match the `Audience` in each assertion |
| Protocol | `saml` | SAML 2.0 federation |
| Redirect URIs | `http://localhost:5000/*` | Only this origin can receive responses |
| ACS URL (POST binding) | `saml_assertion_consumer_url_post: http://localhost:5000/saml/acs` | Where the browser posts the SAML response; must match `Destination` and `Recipient` |
| NameID format | `saml_name_id_format: email` | The user is identified by email address |
| Force NameID format | `saml_force_name_id_format: true` | Keycloak always uses email, even if the SP asks for another format |
| Signed assertions | `saml.assertion.signature: true` | The `<Assertion>` itself is signed |
| Signed documents | `saml.server.signature: true` | The whole SAML response document is signed |
| Attribute mapper | `MedDefenseRole` (`saml-user-attribute-mapper`, `user.attribute: MedDefenseRole`, `attribute.name: MedDefenseRole`, name format `Basic`) | Copies the user's `MedDefenseRole` attribute into the assertion's `AttributeStatement` |

Lab note: the ACS URL uses `http://` on `localhost`. This is acceptable only for the lab. A production SP must use HTTPS so the bearer assertion cannot be captured in transit.

## Test Users and Role Attributes

| Username | Email (NameID) | Enabled | `MedDefenseRole` | Expected SP authorization |
| --- | --- | --- | --- | --- |
| `d.walsh` | `d.walsh@meddefense.internal` | true | `clinical_staff` | Clinical permissions only (Charge Nurse ICU) |
| `r.kim` | `r.kim@meddefense.internal` | true | `it_security` | IT security permissions (Security Analyst) |

Both assertions (`saml_assertion_d_walsh.xml`, `saml_assertion_r_kim.xml`) carry the same structure and timing. Only the NameID, the `MedDefenseRole` value, the IDs and the session index differ. The SP must authorize from the signed `MedDefenseRole` value, not from anything the browser sends outside the assertion.

## Annotated SAML Assertion: d.walsh

Source: `materials/sso/saml_assertion_d_walsh.xml`. Comments are added inline; the elements are unchanged.

```xml
<!-- Response: the envelope posted by the browser to the SP ACS URL.
     Destination must equal the registered ACS URL, otherwise the SP rejects it. -->
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                ID="_resp-dwalsh-20260428" Version="2.0"
                IssueInstant="2026-04-28T09:15:00Z"
                Destination="http://localhost:5000/saml/acs">

  <!-- Issuer: who produced the response. The SP accepts it only if it equals
       the registered IdP entity, here the Keycloak realm "meddefense". -->
  <saml:Issuer>http://localhost:8080/realms/meddefense</saml:Issuer>

  <!-- Signature: XML digital signature. Reference URI="#_assert-dwalsh-001"
       means it covers the assertion with that ID. The SP verifies it with the
       realm's public certificate; any change to the subject, times or role
       breaks it. SignatureValue is simulated in this lab file. -->
  <ds:Signature>
    <ds:SignedInfo><ds:Reference URI="#_assert-dwalsh-001"/></ds:SignedInfo>
    <ds:SignatureValue>SIMULATED_SIGNATURE_VALUE_FOR_LAB_ONLY</ds:SignatureValue>
  </ds:Signature>

  <!-- Assertion: the statement about the user. Its ID is what the signature
       references and what the SP stores to detect replay. -->
  <saml:Assertion ID="_assert-dwalsh-001" Version="2.0" IssueInstant="2026-04-28T09:15:00Z">

    <!-- Issuer (assertion level): must also match the IdP entity ID. -->
    <saml:Issuer>http://localhost:8080/realms/meddefense</saml:Issuer>

    <saml:Subject>
      <!-- NameID: the authenticated user, in email format as configured
           (saml_name_id_format=email). The SP maps it to its local account. -->
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">d.walsh@meddefense.internal</saml:NameID>
      <!-- SubjectConfirmation, bearer method: whoever presents the assertion
           is treated as the user, so it must be short-lived, posted only to
           the Recipient (the ACS URL) and used once. -->
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2026-04-28T09:20:00Z"
                                      Recipient="http://localhost:5000/saml/acs"/>
      </saml:SubjectConfirmation>
    </saml:Subject>

    <!-- Conditions: limits on when and where the assertion is valid.
         NotBefore = 09:14:55Z: earliest valid time (5 s before issue, to
         absorb clock skew); the SP rejects it before this time.
         NotOnOrAfter = 09:20:00Z: expiry; the SP rejects it at or after this
         time. Validity window: about 5 minutes. -->
    <saml:Conditions NotBefore="2026-04-28T09:14:55Z" NotOnOrAfter="2026-04-28T09:20:00Z">
      <!-- AudienceRestriction: the assertion is only for meddefense-portal.
           Another SP must refuse it, so it cannot be reused elsewhere. -->
      <saml:AudienceRestriction><saml:Audience>meddefense-portal</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>

    <!-- AuthnStatement: records the authentication event. AuthnInstant is
         when d.walsh logged in; SessionIndex links to the IdP session (used for
         single logout); AuthnContextClassRef says she used a password over a
         protected (TLS) channel. No MFA context is asserted here. -->
    <saml:AuthnStatement AuthnInstant="2026-04-28T09:14:58Z" SessionIndex="_session-dwalsh-001">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>

    <!-- AttributeStatement: user attributes for authorization.
         MedDefenseRole=clinical_staff comes from the MedDefenseRole mapper;
         the SP grants clinical permissions only. email repeats the identity. -->
    <saml:AttributeStatement>
      <saml:Attribute Name="MedDefenseRole"><saml:AttributeValue>clinical_staff</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="email"><saml:AttributeValue>d.walsh@meddefense.internal</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
```

SP validation checklist, in order: `Destination` and `Recipient` equal the ACS URL; `Issuer` equals the realm; `Signature` is valid with the realm certificate and covers the assertion that is used; current time is within `NotBefore` and `NotOnOrAfter`; `Audience` is `meddefense-portal`; the assertion `ID` has not been seen before; then `NameID` and `MedDefenseRole` are mapped.

## Assertion Expiration and Replay Prevention

A SAML assertion with the bearer method works like a cash voucher: anyone who holds it can present it. If an attacker copies d.walsh's response from a proxy log, browser history or a compromised workstation, they can try to post it to the ACS URL later and log in as her. The `NotBefore` and `NotOnOrAfter` values in `Conditions` and `SubjectConfirmationData` limit that window to about five minutes (09:14:55Z to 09:20:00Z). The SP must reject any assertion received before `NotBefore` or at or after `NotOnOrAfter`, allowing only a small clock skew. An expired assertion therefore cannot be replayed the next day. Expiry alone does not stop a replay inside the five-minute window, so the SP must also keep a cache of assertion IDs it has accepted (for example `_assert-dwalsh-001`) until they expire and refuse any ID it has already seen. Together with the `Audience` and `Recipient` checks, this means a captured assertion can be used once, by one SP, for a few minutes.

## Assertion Signing Risk Explanation

The signature is what makes the assertion trustworthy. The client is configured to sign both the assertion (`saml.assertion.signature: true`) and the whole response document (`saml.server.signature: true`), and the SP verifies the signature with the realm's public certificate. Without a signature, or with an SP that does not verify it, an attacker could edit the XML in transit or in the browser: change `NameID` from `d.walsh@meddefense.internal` to `r.kim@meddefense.internal`, or change `MedDefenseRole` from `clinical_staff` to `it_security`, and the SP would grant those rights. That is privilege escalation without stealing any password. The risk also applies when the SP verifies a signature but then reads data from a different, unsigned element (XML signature wrapping): the SP must use only the element the signature `Reference` points to (`#_assert-dwalsh-001`). Signing the whole document as well as the assertion closes most of these gaps. The realm's signing private key becomes a critical asset: whoever holds it can create valid assertions for any user, so it must be protected and rotated like a Domain Admin credential.

## Off-Boarding and Centralized Identity Impact

Today MedDefense staff have separate accounts in Epic, PACS, the pharmacy system and the clinical communication platform. At off-boarding each one must be disabled by hand, and during the incident two Epic accounts of departed employees were still active because that checklist was not synchronized. The current audit shows the same problem in Active Directory: `l.okafor` (left per HR on 2025-11-28) and contractor `t.morrison` are still enabled (`iam_audit_report.md`, IAM-007 and IAM-004).

With SAML SSO through the `meddefense` realm, each connected application trusts Keycloak instead of keeping its own password. Disabling the user once in the IdP (or in the directory Keycloak federates) stops new assertions for every connected application. One off-boarding action replaces four or more. Two limits must be managed:

- **Existing sessions:** an SP session that is already open is not ended by disabling the IdP account. Keep the 30-minute idle timeout, keep SP sessions short and use single logout (`SessionIndex`) where the SP supports it.
- **Local accounts:** any application that still keeps a local login (break-glass or vendor accounts) bypasses SSO and must stay on the off-boarding checklist.

The same central point also gives one place to enforce MFA, brute force lockout (5 attempts) and session policy for all clinical applications, and one log of who authenticated where.
