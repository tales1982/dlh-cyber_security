# Executive Update: Cyberattack at Main Site (IR-2026-0420-01)

- To: MedDefense Board of Directors
- From: Dr. Patricia Morales, Chief Information Security Officer
- Prepared by: Tales Lima, Incident Response
- As of: Monday 21 April 2026, 06:30 UTC
- Status: **Attack stopped. Patient information was exposed. Patients will be notified.**

## What happened

On Thursday 17 April, a staff member at the Main site opened an email attachment that looked like an invoice. It secretly installed a program that let an outside criminal group control her computer. Over the next three days the attackers used her login to take control of five more computers at Main, including the file server that stores lab results and clinical notes and the patient scheduling server. They were also preparing to lock our files and demand a ransom. They had not done so when we stopped them.

## Impact on patients

- Early on Sunday 19 April the attackers opened **1,847 patient documents**: 1,104 lab result reports from 15 to 18 April, and 743 clinical notes from Emergency Department admissions and inpatient Floor 4. In the same half hour they sent data out of our network. We cannot tell which documents were in it, so we treat all 1,847 as taken.
- These documents contain patient names, dates of birth, medical record numbers and medical details.
- We are now working out how many individual patients this covers. It will be at most 1,847, because some patients have more than one document.
- Patient care continued throughout. Four staff computers and the scheduling system were taken offline on Sunday evening, and those teams moved to our paper procedures. No medical records were changed or deleted.

## Regulatory position

Under HIPAA this is a reportable breach of patient information. We will notify affected patients and federal regulators, and the General Counsel will confirm the final position before this meeting.

## What has been done

- Sunday evening: we declared a top-priority incident within 10 minutes of the first report, preserved the evidence, and then cut the attackers off from all six computers at the same time.
- Their prepared ransom attack was blocked on every MedDefense computer.
- Passwords were reset for every account the attackers could have stolen.
- Legal has issued a hold so that all evidence is kept.

## What remains

- Today: confirm the number of affected patients, and decide with Legal on outside forensic support and on contacting law enforcement.
- This week: rebuild the six affected computers, return the scheduling system and the four workstations to service once they are proven clean, and finish the security checks across the rest of the network.
- Within 60 days of discovery (by 19 June 2026): send notification letters to patients and report to federal regulators.
- After recovery: review why the email got through and why the attackers could move between computers so easily, and present the fixes to the board.

## Next update

Written update to the board chair every day at 17:00 UTC until recovery is complete, plus an immediate call if the situation changes (for example, signs that the stolen information is being published).
