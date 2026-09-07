# ForenSight market position

## Positioning

**ForenSight is a local-first forensic triage and CTF workbench that turns an evidence image into recoverable, challengeable leads.**

It is not positioned as a replacement for enterprise forensic suites. It is the approachable bridge between raw artifacts, a defensible first-pass investigation, and CTF-oriented artifact hunting.

## Target users

- Students and educators learning digital forensics
- CTF players working from evidence images and artifact bundles
- Small incident-response teams needing a local, explainable first-pass triage tool

## Product promises

1. Raw evidence remains local by default.
2. Deterministic tooling extracts, classifies, filters, hashes, and recovers artifacts.
3. AI sees only selected normalized evidence when enabled.
4. Every AI citation is checked against known evidence IDs.
5. Challenge mode distinguishes direct observation, inference, alternatives, and missing evidence.

## What makes it different

| Capability | ForenSight approach |
| --- | --- |
| Evidence image triage | Read-only E01 profiling, filesystem event extraction, filtering, and safe inode recovery |
| AI reasoning | Evidence-scoped structured output with citation validation and deterministic fallback |
| Adversarial analysis | A dedicated Challenge pass looks for alternatives and missing evidence |
| CTF workflow | Configurable flag convention, extracted strings, artifact triage, and local report export |
| Trust | No claim is treated as proof merely because an LLM produced it |

## Explicit non-goals for the MVP

- Replacing Magnet, Autopsy, Cellebrite, or enterprise case-management systems
- Claiming court admissibility without a validated forensic workflow and expert review
- Autonomously declaring a suspect, malware, or flag correct

## Demo message

> We do not ask AI to tell us what happened. We ask it to reason over the evidence we selected, cite it, and then try to prove itself wrong.

## Roadmap that strengthens the wedge

1. Scan each recovered safe copy for configurable CTF flag patterns, strings, hashes, and signature mismatches.
2. Add artifact-specific extraction from E01: browser History, EVTX, Registry, MFT, and USN Journal.
3. Persist local cases, custody data, selected evidence, and analysis results in SQLite.
4. Add append-only audit records for every AI payload, finding, and report export.
