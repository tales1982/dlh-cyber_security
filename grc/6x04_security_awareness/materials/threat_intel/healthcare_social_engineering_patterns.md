# Healthcare Social Engineering Patterns

**Purpose:** Provide sector-specific patterns for Task 1, Task 3 and Task 6.  
**Classification:** Internal Training

## Pattern 1: EHR Account Access Threat

**Common target:** nurses, clinical assistants, physicians, unit clerks  
**Mechanism:** authority + urgency  
**Typical lure:** EHR verification, account lockout, secure patient message, chart access hold  
**Why it works:** patient care depends on fast access to records, orders and medication documentation  
**Expected employee pressure point:** fear of being unable to work at shift start  
**Safe behavior to train:** verify through known IT contact or report button, never through message link

## Pattern 2: MFA and Compliance Enrollment

**Common target:** billing, administration, contractors, remote workers  
**Mechanism:** familiarity + authority  
**Typical lure:** required MFA enrollment, compliance portal task, remote access review  
**Why it works:** employees expect periodic IT compliance messages  
**Expected employee pressure point:** desire to complete required admin tasks quickly  
**Safe behavior to train:** use known portal bookmark or ask IT through known help channel

## Pattern 3: HR and Benefits Scarcity

**Common target:** finance, administration, all workforce during open enrollment  
**Mechanism:** urgency + scarcity  
**Typical lure:** missed benefits deadline, dependent verification, payroll correction  
**Why it works:** financial consequences feel personal and immediate  
**Expected employee pressure point:** fear of losing benefits or pay  
**Safe behavior to train:** access HR systems through known intranet path, not email links

## Pattern 4: Vendor Support Impersonation

**Common target:** clinical supervisors, IT, biomedical staff  
**Mechanism:** authority + urgency + technical dependency  
**Typical lure:** emergency Epic patch, medical device support call, remote support request  
**Why it works:** clinical operations often depend on vendors and urgent support  
**Expected employee pressure point:** desire to restore or protect patient-care workflow  
**Safe behavior to train:** verify vendor callback through approved vendor contact list

## Pattern 5: Executive Authority / BEC

**Common target:** finance, executive assistants, department administrators  
**Mechanism:** authority + social proof  
**Typical lure:** urgent document review, payment action, board packet, acquisition or legal matter  
**Why it works:** executive requests are often time-sensitive and confidential  
**Expected employee pressure point:** reluctance to challenge authority  
**Safe behavior to train:** independent verbal verification for money, credentials or sensitive documents

## Pattern 6: Insider-Like Account Misuse

**Common target:** IT and SOC observers, managers  
**Mechanism:** abuse of trusted access rather than external deception  
**Typical signal:** dormant account activation, unusual access time, role-inconsistent data movement  
**Why it matters:** employees may notice context before tools do  
**Safe behavior to train:** report observable facts without accusation

## Common Design Rules

- Use MedDefense workflow language.
- Do not rely on spelling errors as the teaching cue.
- Include one clear reportable signal in each simulation.
- Teach known-channel verification.
- Avoid shaming employees after failure.
- Do not target employees during known high-stress clinical events.
