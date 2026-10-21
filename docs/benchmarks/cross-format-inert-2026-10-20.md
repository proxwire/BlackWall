# BlackWall benchmark: blackwall-inert-v1

Run `7a97c79956c295e9` used `execute` mode across 11 verified fixtures.

| fixture | format | lane | status | tools | seconds | timeouts | evidence | IOCs | config | report |
|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| native-pe | pe | core | success | 7/7 | 11.787 | 0 | 100% | 100% | 100% | — |
| native-pe | pe | raw-rea | success | 1/1 | 9.087 | 0 | 0% | 0% | 0% | — |
| native-pe | pe | hybrid | success | 6/6 | 11.642 | 0 | 100% | 100% | 100% | — |
| packed-pe | pe | core | partial | 10/11 | 35.988 | 1 | 100% | 100% | 100% | — |
| packed-pe | pe | raw-rea | success | 1/1 | 7.221 | 0 | 0% | 0% | 0% | — |
| packed-pe | pe | hybrid | success | 9/9 | 6.081 | 0 | 100% | 100% | 100% | — |
| dotnet | dotnet | core | success | 6/6 | 0.107 | 0 | 100% | 100% | 100% | — |
| dotnet | dotnet | raw-rea | success | 1/1 | 0.727 | 0 | 0% | 0% | 0% | — |
| dotnet | dotnet | hybrid | success | 9/9 | 2.168 | 0 | 100% | 100% | 100% | — |
| elf | elf | core | success | 6/6 | 1.510 | 0 | 100% | 100% | 100% | — |
| elf | elf | raw-rea | success | 1/1 | 6.235 | 0 | 0% | 0% | 0% | — |
| elf | elf | hybrid | success | 6/6 | 1.355 | 0 | 100% | 100% | 100% | — |
| apk | apk | core | success | 4/4 | 0.059 | 0 | 100% | 100% | 100% | — |
| apk | apk | raw-rea | success | 1/1 | 1.874 | 0 | 0% | 0% | 0% | — |
| apk | apk | hybrid | success | 5/5 | 1.896 | 0 | 100% | 100% | 100% | — |
| javascript | javascript | core | success | 4/4 | 0.167 | 0 | 100% | 100% | 100% | — |
| javascript | javascript | raw-rea | unsupported | 0/1 | 0.633 | 0 | 0% | 0% | 0% | — |
| javascript | javascript | hybrid | success | 4/4 | 0.169 | 0 | 100% | 100% | 100% | — |
| wasm | wasm | core | success | 4/4 | 0.165 | 0 | 100% | 100% | 100% | — |
| wasm | wasm | raw-rea | success | 1/1 | 0.657 | 0 | 100% | 100% | 100% | — |
| wasm | wasm | hybrid | success | 5/5 | 0.822 | 0 | 100% | 100% | 100% | — |
| office | ooxml-word | core | partial | 4/5 | 30.095 | 1 | 100% | 100% | 100% | — |
| office | ooxml-word | raw-rea | success | 1/1 | 0.714 | 0 | 0% | 0% | 0% | — |
| office | ooxml-word | hybrid | success | 4/4 | 0.057 | 0 | 100% | 100% | 100% | — |
| rtf | rtf | core | partial | 4/5 | 30.203 | 1 | 100% | 100% | 100% | — |
| rtf | rtf | raw-rea | unsupported | 0/1 | 0.710 | 0 | 0% | 0% | 0% | — |
| rtf | rtf | hybrid | success | 4/4 | 0.166 | 0 | 100% | 100% | 100% | — |
| pdf | pdf | core | partial | 4/5 | 30.093 | 1 | 100% | 100% | 100% | — |
| pdf | pdf | raw-rea | unsupported | 0/1 | 0.736 | 0 | 0% | 0% | 0% | — |
| pdf | pdf | hybrid | success | 4/4 | 0.058 | 0 | 100% | 100% | 100% | — |
| pcap | pcap | core | success | 4/4 | 0.166 | 0 | 100% | 100% | 100% | — |
| pcap | pcap | raw-rea | success | 1/1 | 0.840 | 0 | 0% | 0% | 0% | — |
| pcap | pcap | hybrid | success | 5/5 | 1.006 | 0 | 100% | 100% | 100% | — |

## Aggregate

| lane | successful fixtures | tool success | seconds | timeouts | evidence | IOCs | config | report |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| core | 7/11 | 93% (57/61) | 140.339 | 4 | 100% | 100% | 100% | — |
| hybrid | 11/11 | 100% (61/61) | 25.420 | 0 | 100% | 100% | 100% | — |
| raw-rea | 8/11 | 73% (8/11) | 29.434 | 0 | 9% | 9% | 9% | — |

## Recorded gaps

- `packed-pe` / `core` / `lab.binwalk_scan`: **timeout**
- `javascript` / `raw-rea` / `lab.rea_static_analysis`: **unsupported**
- `office` / `core` / `lab.binwalk_scan`: **timeout**
- `rtf` / `core` / `lab.binwalk_scan`: **timeout**
- `rtf` / `raw-rea` / `lab.rea_static_analysis`: **unsupported**
- `pdf` / `core` / `lab.binwalk_scan`: **timeout**
- `pdf` / `raw-rea` / `lab.rea_static_analysis`: **unsupported**

## Interpretation limits

- Plan mode checks corpus integrity and route selection; it makes no speed or recovery claim.
- Execute mode uses static tooling only. It never launches target programs or enables network access.
- Persistent Ghidra is MCP-only and is recorded as `not_run` by this CLI harness.
- Analyst-report accuracy is `—` unless lane reports were supplied with `--reports-dir`.
- Evidence, IOC, and config percentages are recall against manifest expectations; they do not grade every structural fact an analyzer returns.
- Raw wall times are single-run observations, not statistically stable performance estimates.
