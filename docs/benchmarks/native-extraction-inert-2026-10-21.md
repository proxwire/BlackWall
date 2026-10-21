# BlackWall benchmark: blackwall-inert-v1

Run `2f82fda1f0c28829` used `execute` mode across 7 verified fixtures.

| fixture | format | lane | status | tools | seconds | timeouts | evidence | IOCs | config | report |
|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| elf | elf | core | success | 7/7 | 1.948 | 0 | 100% | 100% | 100% | — |
| elf | elf | raw-rea | success | 1/1 | 6.312 | 0 | 0% | 0% | 0% | — |
| elf | elf | hybrid | success | 7/7 | 2.086 | 0 | 100% | 100% | 100% | — |
| apk | apk | core | success | 4/4 | 0.061 | 0 | 100% | 100% | 100% | — |
| apk | apk | raw-rea | success | 1/1 | 1.858 | 0 | 0% | 0% | 0% | — |
| apk | apk | hybrid | success | 5/5 | 2.096 | 0 | 100% | 100% | 100% | — |
| macho | mach-o | core | success | 5/5 | 0.098 | 0 | 100% | 100% | 100% | — |
| macho | mach-o | raw-rea | success | 1/1 | 5.343 | 0 | 0% | 0% | 0% | — |
| macho | mach-o | hybrid | success | 5/5 | 0.098 | 0 | 100% | 100% | 100% | — |
| recorded-core | elf-core | core | success | 4/4 | 0.057 | 0 | 100% | 100% | 100% | — |
| recorded-core | elf-core | raw-rea | success | 1/1 | 0.684 | 0 | 0% | 0% | 0% | — |
| recorded-core | elf-core | hybrid | success | 5/5 | 0.743 | 0 | 100% | 100% | 100% | — |
| nested-firmware | zip | core | success | 5/5 | 0.440 | 0 | 100% | 100% | 100% | — |
| nested-firmware | zip | raw-rea | success | 1/1 | 0.700 | 0 | 0% | 0% | 0% | — |
| nested-firmware | zip | hybrid | success | 6/6 | 1.136 | 0 | 100% | 100% | 100% | — |
| installer-cab | cab | core | success | 5/5 | 0.352 | 0 | 100% | 100% | 100% | — |
| installer-cab | cab | raw-rea | unsupported | 0/1 | 0.746 | 0 | 0% | 0% | 0% | — |
| installer-cab | cab | hybrid | success | 5/5 | 0.355 | 0 | 100% | 100% | 100% | — |
| family-config | blackwall-config | core | success | 5/5 | 0.204 | 0 | 100% | 100% | 100% | — |
| family-config | blackwall-config | raw-rea | unsupported | 0/1 | 0.714 | 0 | 0% | 0% | 0% | — |
| family-config | blackwall-config | hybrid | success | 5/5 | 0.202 | 0 | 100% | 100% | 100% | — |

## Aggregate

| lane | successful fixtures | tool success | seconds | timeouts | evidence | IOCs | config | report |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| core | 7/7 | 100% (35/35) | 3.160 | 0 | 100% | 100% | 100% | — |
| raw-rea | 5/7 | 71% (5/7) | 16.357 | 0 | 0% | 0% | 0% | — |
| hybrid | 7/7 | 100% (38/38) | 6.717 | 0 | 100% | 100% | 100% | — |

## Recorded gaps

- `installer-cab` / `raw-rea` / `lab.rea_static_analysis`: **unsupported**
- `family-config` / `raw-rea` / `lab.rea_static_analysis`: **unsupported**

## Interpretation limits

- Plan mode checks corpus integrity and route selection; it makes no speed or recovery claim.
- Execute mode uses static tooling only. It never launches target programs or enables network access.
- Persistent Ghidra is MCP-only and is recorded as `not_run` by this CLI harness.
- Analyst-report accuracy is `—` unless lane reports were supplied with `--reports-dir`.
- Evidence, IOC, and config percentages are recall against manifest expectations; they do not grade every structural fact an analyzer returns.
- Raw wall times are single-run observations, not statistically stable performance estimates.
