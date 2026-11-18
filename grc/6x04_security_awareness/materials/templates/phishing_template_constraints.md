# Phishing Template Constraints

Use these constraints when writing `phishing_templates.md`.

## Global Requirements

Each template must include:

- template ID
- target segment
- tier
- psychological mechanism
- expected click-rate range
- deployment timing constraints
- From line
- To line
- Subject line
- full email body
- `[SIMULATION_LINK]`
- attacker notes
- safety note for simulation operators

## Required Templates

### T-EPIC-01

- Target: SEG-B
- Tier: Baseline
- Mechanism: authority + urgency
- Required references: Epic, patient records, access interruption
- Delivery: weekdays 07:15-08:30
- Avoid ICU/OR during critical windows
- Teaching cues: external domain, unexpected verification, deadline pressure

### T-MFA-02

- Target: SEG-C
- Tier: Baseline
- Mechanism: familiarity + authority
- Required references: MFA enrollment, compliance deadline, MedDefense IT
- Teaching cues: link verification, known portal path, report button

### T-HR-03

- Target: SEG-C and SEG-E
- Tier: Intermediate
- Mechanism: urgency + scarcity
- Required references: benefits enrollment, deadline, financial consequence
- Teaching cues: HR portal through known intranet, not email link

### T-BEC-04

- Target: SEG-F and SEG-E
- Tier: Advanced
- Mechanism: authority + social proof
- Required references: CFO or executive impersonation, financial action or sensitive document
- Teaching cues: independent verification, do not rely on reply thread

## Difficulty Progression

| Tier | Characteristics |
|---|---|
| Baseline | Recognizable system/process with clear reportable cue |
| Intermediate | Familiar business process plus personal or financial pressure |
| Advanced | Low technical indicators, relies on authority and workflow realism |

## Safety Boundaries

- Do not use real patient names.
- Do not collect credentials.
- Do not ask for real financial transfers.
- Do not use actual external domains controlled by third parties.
- All links must be `[SIMULATION_LINK]`.
