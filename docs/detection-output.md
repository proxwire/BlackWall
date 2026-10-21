# Evidence-linked detection output

Detection files are candidates, not automatically promoted production rules.
Each sidecar records its stable detection ID, evidence IDs, validation mode,
and exact candidate type. Files live under `/work/rules` and are copied to the
host case's `detections/` directory only after their type-specific checks pass.

## YARA

`lab.generate_yara_candidate` accepts bounded literal and byte/wildcard
anchors, not arbitrary source. It compiles the generated rule, requires every
positive artifact to match, and rejects export if any explicit or bundled
inert negative fixture matches. Positive and negative hashes are retained in
the `blackwall.detection-yara.v1` sidecar. Manually authored rules can still be
tested with `lab.yara_test`, but do not inherit this validation claim.

## Sigma and Suricata

`lab.generate_sigma_candidate` supports only telemetry fields appropriate to
process creation, registry set, file event, network connection, or DNS query
records. `lab.generate_suricata_candidate` supports fixed DNS, HTTP host/URI,
TLS SNI, and IP templates. Unsupported categories or fields fail closed rather
than implying telemetry that was never observed.

## ATT&CK

`lab.attack_behavior_catalog` is the complete reviewed mapping surface.
`lab.attack_map_behavior` requires retained evidence and low/medium/high
confidence; it does not accept caller-supplied technique IDs. In particular,
DLL side-loading maps to `T1574.002` (DLL Side-Loading), with a regression test
that prevents substitution of `T1574.001`.

All candidates are also included by stable ID in
`blackwall.case-report.v1`, allowing downstream tooling to join conclusions,
rules, artifacts, and exact retained evidence.
