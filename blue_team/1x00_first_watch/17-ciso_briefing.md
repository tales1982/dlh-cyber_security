# Board Briefing MedDefense Security Posture

MedDefense's security today stops some attacks from starting, but has almost no way to notice one that succeeds, or to recover afterward.

**Critical Finding:** Our systems generate security logs, but no one reviews them, and nothing alerts us automatically. A cryptocurrency-mining infection ran undetected on our billing server for two weeks, discovered only because it slowed the computer down. If a more serious attacker got in the same way, we would likely find out only after patient care was already disrupted.

**Priority Actions:**

1. Install basic monitoring that alerts us to suspicious activity, starting with our most critical systems about $30,000, within one month.
2. Move our only data backup off the same network as the systems it protects, and store a copy offsite about $14,400 per year, within one month.
3. Separate our medication-dosing devices onto their own protected network so a breach elsewhere can't reach them about $30,000, this quarter.

**Business Case:** A single similar hospital breach we reviewed cost $3.2 million to recover from and eleven days of ambulance diversions our entire $120,000 budget is less than four percent of that one bad month.

**Closing:** Without action, the most likely outcome is not a hypothetical future risk, but a repeat of what has already happened twice on our own network.
