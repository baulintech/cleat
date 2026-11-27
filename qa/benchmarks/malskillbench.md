# Cleat on MalSkillBench

[MalSkillBench](https://github.com/lxyeternal/MalSkillBench) (Guo et al.,
arXiv:2606.07131) is a public benchmark of malicious agent skills, with popular
legitimate skills as a false-alarm set. These are Cleat's results on it. The
samples are not copied into this repository; only the numbers are.

- Benchmark release: commit `1a82bb22f` (21 November 2026).
- Scanned on 27 November 2026, offline (no links fetched), nothing run.
- **Detected** means Cleat calls the skill `high-risk`. **Flagged** means
  `review` or `high-risk`.

## Results

| Group | Skills | Detected 0.1.8 | Detected 0.1.9 | Detected 0.1.10 | Flagged 0.1.9 | Flagged 0.1.10 |
|---|---|---|---|---|---|---|
| Real-world malicious skills | 193 | 69.9% | 71.0% | 72.0% | 86.5% | 83.9% |
| Generated code attacks | 1,346 | 29.8% | 30.1% | 29.9% | 54.9% | 53.4% |
| Generated prompt-only attacks | 1,300 | 21.5% | 21.6% | 21.6% | 42.1% | 39.1% |
| Popular legitimate skills (false alarms) | 3,914 | 3.7% | 3.7% | 3.7% | 34.5% | 25.1% |

By attack type, on the real-world skills with 0.1.10:

| Attack | Skills | Detected |
|---|---|---|
| Malware delivery (fake "prerequisite" installers) | 103 | 98% |
| Privilege escalation | 15 | 100% |
| Credential theft | 33 | 33% |
| Data exfiltration | 17 | 24% |

## What changed in 0.1.10, and how it was tested

Cleat 0.1.9 missed 12 of the 33 real-world credential-theft skills entirely.
To avoid tuning on the test set, those 33 were split at random (seed 20261127)
into a study half of 16 and a sealed half of 17. Rules were written from the
study half only; the sealed half was scored once, at the end.

| Credential theft | Detected 0.1.9 | Detected 0.1.10 | Flagged 0.1.9 | Flagged 0.1.10 |
|---|---|---|---|---|
| Study half (16) | 3 | 4 | 9 | 8 |
| Sealed half (17) | 6 | 7 | 12 | 11 |

The flagged counts fall by one because 0.1.9 flagged every API call that posts
data. That flagged real attacks and ordinary API clients alike: 34.5% of the
legitimate skills. 0.1.10 flags uploads of local data (files, piped input,
command output) and treats inline API posts as low, which cut false review
marks on legitimate skills from 34.5% to 25.1% (378 fewer skills).

Every new rule was also checked against a separate large sample of
public skills from GitHub: no skill there became high-risk, and the links
Cleat finds and how it classifies them are unchanged.

## Limits, stated plainly

- **Prompt-only attacks are mostly missed.** Role hijacking, goal hijacking,
  safety bypass and similar attacks are written as instructions, with no
  command or link to match. Cleat detects 0.5% to 2.3% of them. Pattern rules
  cannot read intent.
- **Many real-world credential-theft skills look like ordinary API
  documentation.** Whatever makes them malicious is not visible in their text,
  so no static rule can separate them from legitimate skills.
- **The release holds 193 of the 703 real-world skills** described in the
  paper; a 21 November update removed duplicates. Figures here are for the
  193 present.
- **3.7% of legitimate skills are called high-risk.** Most are real
  `curl ... | bash` installers, which are genuinely risky, so Cleat keeps
  flagging them.

Help with any of these is welcome: see [CONTRIBUTING.md](../../CONTRIBUTING.md).
