# Risk Methodology

CyberRisk Manager uses a 5x5 likelihood and impact scoring model commonly used in IT Security, GRC, and IT Audit programs.

## Likelihood Scale

| Value | Meaning |
|---|---|
| 1 | Rare |
| 2 | Unlikely |
| 3 | Possible |
| 4 | Likely |
| 5 | Almost Certain |

## Impact Scale

| Value | Meaning |
|---|---|
| 1 | Negligible |
| 2 | Minor |
| 3 | Moderate |
| 4 | Major |
| 5 | Severe |

## Risk Score

```text
Risk Score = Likelihood × Impact
```

## Severity Mapping

| Score | Severity |
|---|---|
| 1-4 | Low |
| 5-9 | Medium |
| 10-16 | High |
| 17-25 | Critical |

## Treatment Plans

Each risk supports a treatment plan:

- Avoid: stop the activity causing the risk
- Mitigate: reduce likelihood or impact using controls
- Transfer: shift part of the exposure through contracts or insurance
- Accept: formally accept the risk after management review

## Risk Ownership and Due Dates

Each risk can have:

- Risk owner
- Target remediation date
- Overdue indicator
- Status tracking

## Example

A VPN risk with Likelihood 5 and Impact 4 has a score of 20, which maps to Critical. A suitable treatment plan would be Mitigate by enforcing MFA and monitoring anomalous access attempts.
