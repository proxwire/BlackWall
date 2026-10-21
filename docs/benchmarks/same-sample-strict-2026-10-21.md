# Same-sample comparison: initial BlackWall vs current strict default

> The original comparison below is preserved as the regression record. A
> [follow-up validation](#follow-up-validation-after-closing-the-gaps) at the
> end shows the result after closing every gap it identified.

## Method and limits

- Sample SHA-256:
  `52ebd649910eac2754dd5631d388dfdcf25e200be19918d1c94999225729a73c`.
- Baseline: the real 2026-10-13 report produced immediately after commit
  `643da6b` (`Initial BlackWall lab`). The original MCP surface was
  unrestricted/expert-equivalent: it exposed `run_python`, `shell`, and
  radare2 without a profile gate.
- Current: a fresh isolated run of the 2026-10-21 working-tree image
  `blackwall:item9`, using the shipped `strict` default. The analyst could not
  read the baseline report.
- This is an operational comparison, not a controlled model benchmark. The
  Claude version/model and threat-intelligence state may differ. Ghidra was
  already warm after a discarded permission-only launch, so elapsed times are
  not compared.
- No sample or extracted bytes are stored in this repository.

## Result

Both runs agree on the original hash, PE identity, IExpress/WEXTRACT wrapper,
`AppBundle` title, embedded CAB hash, member names, numeric executable launch,
and likely GoToMeeting DLL side-loading chain.

The baseline reached the full payload and the current strict run did not. The
baseline used 7-Zip and custom Python to unpack the LZX CAB and decrypt the
loader, identifying Amadey 5.92, its campaign, code-verified C2, crypto keys,
persistence, injection chain, install path, task protocol, and 18 command
types. The current bounded CAB worker supports uncompressed/MSZIP cabinets but
not this sample's LZX cabinet. Its fallback Binwalk pass timed out, and strict
mode correctly withheld generic shell/Python access. It therefore stopped at
the delivery wrapper and labeled Amadey/C2 details as third-party hypotheses.

## Scorecard

| Area | Initial tool/report | Current strict tool/report | Assessment |
|---|---|---|---|
| Wrapper triage | Correct IExpress/CAB chain | Same, plus hidden-window behavior, exact resource/function evidence, and correction of the stock RunOnce cleanup false positive | Current is clearer |
| Unpacking | Reached CAB, signed host EXE, loader DLL, decrypted payload, and emulator copy | Tracked original, CAB, and outer-stub memory dump; stopped at LZX | Initial is substantially deeper |
| Family/config | Code-verified Amadey 5.92, campaign `0d20ad`, C2, keys, mutex, install path, plugins, timing | No recovered payload config; Amadey/C2 explicitly third-party only | Initial wins |
| Behavior | Loader crypto/syscalls/APC and 18 bot task types | Outer WEXTRACT extraction/hidden launch only | Initial wins |
| Detections | 4 YARA rules covering wrapper, loader, payload, and campaign | 2 tested rules covering wrapper and CAB | Initial is broader; current does not overclaim payload coverage |
| Provenance | Hash/address-rich prose, but no machine-auditable claim ledger | 4 deterministic checkpoints, 35 retained evidence records, 11 claim records, 3 lineage artifacts, audit `ok=true`, 0 issues | Current wins decisively |
| Failure handling | Gaps described manually | Timeout/unsupported/partial states, fallbacks, deferred config, and stop reasons retained explicitly | Current wins |
| Safety | Generic Python, shell, and radare2 exposed by default | Strict profile excludes generic execution tools; sample container remained networkless | Current wins |
| Resumability | None | Content-addressed outputs, checkpoints, deduplication, and exact remaining/deferred work | Current wins |

## Quantitative snapshot

| Metric | Initial | Current strict |
|---|---:|---:|
| Report size | 19,380 bytes | 11,970 bytes |
| Machine-audited claims | 0 | 11 |
| Retained evidence records | not available | 35 |
| Broken audit links | not measurable | 0 |
| System-tracked artifacts | not available | 3 total / 2 derived |
| Derived layers documented in report | 5 | 2 |
| YARA rules | 4 | 2 |
| Payload configuration recovered | yes | no |
| Code-verified payload C2 | yes | no |

## Regressions and gaps exposed by this sample

1. LZX CAB support is the decisive missing strict-mode capability. Add bounded
   libmspack/cabextract-backed LZX decoding with the existing count, byte,
   ratio, path, memory, and deadline checks instead of requiring a generic
   shell.
2. The recursive graph does not discover an IExpress CAB while starting from
   the PE. The analyst had to extract the `RCDATA` resource separately before
   rerouting it.
3. The static configuration plugin interface has only its inert admission
   fixture; it has no production Amadey extractor.
4. Three deliberately skipped redundant steps on the mapped-stub dump were
   normalized as failed/timeout. The evidence schema needs a distinct
   `not_run_redundant` outcome.
5. The current report maps likely side-loading to `T1574.001`; `T1574.002 DLL
   Side-Loading` is the appropriate ATT&CK sub-technique for the claimed
   behavior.

## Bottom line

The current tool is materially safer, more deterministic, auditable, and
honest about uncertainty. For this sample, however, the default strict profile
is materially less complete because its bounded extractor lacks LZX. The
initial report remains stronger for malware-family depth; the current report
is stronger for evidence integrity and failure transparency. A fair
capability-depth comparison against the old unrestricted surface would require
an explicitly authorized current `expert` run, or preferably closing the LZX
gap so the strict path can reach the same payload without generic execution.

## Follow-up validation after closing the gaps

A targeted rerun used the completed `blackwall:roadmap-complete` image in a
fresh, capability-free container with `--network none`, a read-only root
filesystem, and the same retained password-protected sample. This exercised
the exact `analysis_plan`, `recursive_unpack`, and `config_extract` operations
available in the 64-tool strict profile. The profile check exposed no REA
runtime commands and kept generic `shell` and `run_python` expert-only.

The deterministic plan now detects the structurally valid embedded CAB in the
original PE and selects recursive unpacking automatically. One bounded pass
then completed in four nodes with no rejection:

| Layer | Result |
|---|---|
| Original PE | Detected its embedded CAB and automatically selected `lab.recursive_unpack` |
| PE `RCDATA/CABINET` | Carved 535,784 bytes at resource RVA `0x2c070`; SHA-256 `d8ec222e3f18df2fb6e70f01e3a374ca8cd26c49cbdff20c23a34f14d2ab02a8` |
| LZX member `g2m.dll` | Decoded by pinned `cabextract-1.11/libmspack`; 689,152 bytes; SHA-256 `3498a2e583114c3dccca21055f800a45649b3e79e87d7d3f291c4e86b34c6f2f` |
| LZX member `3233133.exe` | Decoded by the same bounded worker; 32,256 bytes; SHA-256 `4dc4c0bdce7d711bd4160beebbfe67d64a65a5c083429cb222926d7bd095b353` |
| Loader configuration | High-confidence Amadey v4/v5 match after reviewed ROR/XOR plus RC4 recovery; all 6 semantic anchor groups matched |

An automated comparison against the initial run's `notes/config.json` found
exact agreement for both CAB-member hashes, decrypted payload hash, loader
section and key, family, version, C2 host and path, string key, RC4/mutex key,
campaign, install-directory ID, install name, and plugin set. In particular,
the strict worker recovered Amadey `5.92`, campaign `0d20ad`, install directory
`cb385a0fb1`, `Qyhrgyrfhv.exe`, the `cred.dll`/`clip.dll` plugins, and the
decrypted payload hash
`498767f178b95b374be1334d1a7e2f9fb2d6b738887e051966bbe08419aa7474`.

The first follow-up pass exposed one useful fixture weakness: the reconstructed
install-directory ID had been left in plaintext, while this production sample
stores it in the encoded string set. The fixture and extractor were corrected,
and the final real-sample pass recovered the exact baseline value. This is why
the production sample remains a complement to, rather than a substitute for,
the inert corpus.

All five gaps from the original comparison now have admission coverage: LZX
decoding, automatic IExpress `RCDATA` discovery, production Amadey recovery,
the non-gap `not_run_redundant` state, and exact DLL side-loading mapping to
`T1574.002`. The targeted rerun does not replace the original end-to-end
analyst report: it does not claim a new Ghidra behavioral review or emulation
run, and the decrypted payload is validated in bounded memory and identified
by hash rather than exported as another sample artifact. No live network
contact or native sample execution occurred, and no sample or extracted bytes
were added to this repository.
