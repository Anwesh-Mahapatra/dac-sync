# CHANGES — schema hardening (branch `fix/schema-hardening`)

## TL;DR

The four reported problems were real, but the diagnosis relocated two of them.
The key discovery in Phase 0: **there are two indices, and the detection data
lives in the one the brief didn't mention.**

| Index | What it is | Attack data? |
|---|---|---|
| `winlogbeat-*` | Real desktop (`DESKTOP-LJNRISK`) telemetry, dynamically mapped, `CommandLine` truncated at 256, leaks `_time`/`filter_path` | **None** |
| `forge-windows-ecs*` | EvidenceForge lab scenario (`SRV-DC-01`, `WS-EXEC-01`, `WS-ANALYST-01`), ECS-normalized by the Cribl pipeline | **Yes** — mimikatz, PowerView, the `-enc` payload |

Detections were therefore pointed at `forge-windows-ecs*` (confirmed with the
user), and the fixes target that path.

## Phase 0 findings (read-only)

| # | Check | Result |
|---|---|---|
| 0.A | `event.code` real or pinned to "1"? | **Real & trustworthy.** 18+ codes; each lines up with its event_data (code 1→Image+CommandLine, 3→DestinationIp, 11→TargetFilename). EID predicates kept. |
| 0.B | How is `CommandLine` mapped? | On `winlogbeat-*`: `text` + `.keyword(ignore_above:256)` — **556 docs already had `CommandLine.keyword` dropped**. On `forge-*`: full length, no truncation. |
| 0.C | Rule audit | The one rule used `.keyword` wildcards on `winlog.event_data.*` and a `*-e*` clause; against `winlogbeat-*` its exact KQL returned **594 junk hits** (the `*-e*` matched nearly every command line) and **missed the real payload**. |

**Where the brief's premises moved:**

- **P1** ("Sysmon→ECS not applied") — real, but the cause is the Cribl pipeline's
  `switch` only handling Security EIDs (4688/4624/4625/4648). Every Sysmon event
  hit `default: break`, so **993 Sysmon events never reached ES at all**. Not a
  template-pattern issue.
- **P2** ("event.action mislabeled by the generator") — the mislabeling is real
  (`event.code:1` carries 9 different `event.action` texts; 1,149 say "Network
  connection detected"), but it is in the *real-desktop* `winlogbeat-*` data, not
  something the EvidenceForge generator wrote. The pipeline never sets those
  fields. Fix is the same: never key off `event.action`/`winlog.task`.
- **P3** ("long command lines silently missed") — confirmed and the most
  important. `ignore_above:256` + a `.keyword` wildcard is exactly why long `-enc`
  payloads were invisible.
- **P4** ("Cribl leaks `_time`/`filter_path`") — real, but scoped to the
  *live Winlogbeat* route (Elastic-API input on :9201 with **no pipeline**). The
  forge route runs a pipeline and is clean (0 leaked fields). The `cribl/`
  directory already existed with a tested pipeline — so this was extended, not
  created from scratch.

## Fixes (one commit each)

**F1 — Sysmon→ECS mapping** (`cribl/winxml_to_ecs.js`, `+ generate-pipeline.js`)
- Added `switch` cases for Sysmon EID **1** (process create → `process.*`,
  `process.pe.*`, `process.hash.*`, `process.parent.*`, `user.*`), **3** (network
  → `source.*`/`destination.*`/`network.transport`), **11** (file → `file.*`).
- Cases are gated on the **Sysmon provider** so a `System`-channel EID 1 is never
  mis-mapped as a process creation (regression-tested).
- Sysmon's literal `-` placeholders are dropped; `DOMAIN\user` is split into
  `user.domain`/`user.name`; the `Hashes` CSV is parsed into `process.hash.*` and
  `process.pe.imphash`.
- `event.category`/`event.type` set from ECS `allowed_values` on every branch.
- Added **`generate-pipeline.js`** — the pipeline JSON embeds the mapping code
  verbatim, and the generator its header referenced was never committed, so the
  copy could drift. `--check` fails when stale.
- 11 new tests (21 total), all green, built from the real XML on disk.

**F2 — label integrity** (in the rule + SCHEMA.md)
- Rule gates on `event.category`/`event.type`; `event.action`/`winlog.task` are
  documented as never-key-off. (The rule never referenced them; the audit
  confirmed no other rule does either.)

**F3 — ignore_above** (`cribl/forge-windows-ecs.index-template.json`, `es/*.sh`, `es/load-forge.js`)
- Rebuilt the index template on the **ECS v8.0.0 reference component templates**:
  `process.command_line`/`process.parent.command_line` → **`wildcard`** + a
  `.text: match_only_text` multi-field, **no `ignore_above`**. `event.code` etc.
  → `keyword`; IPs → `ip`.
- Added `priority: 500` so it wins over the ES dynamic default for
  `forge-windows-ecs*`. Composes cleanly (no overlap with `winlogbeat-*` or
  built-ins — verified via `_simulate_index`).
- `es/apply-templates.sh` applies + verifies the template.
- `es/load-forge.js` replays **both** EvidenceForge channels through the same
  tested `applyToEvent()` into a fresh `forge-windows-ecs-000001` (this is how the
  993 Sysmon events finally reach ES). `es/reindex-forge.sh` is the
  non-destructive reindex alternative for the legacy index.

**F4 — Cribl leakage** (`cribl/strip_cribl_internal.pipeline.json`, `cribl/README.md`)
- Added a strip pipeline (`remove: [_time, filter_path]`) to attach to the live
  Winlogbeat route, and documented where `filter_path` is injected (the Elastic
  destination's `extraParams` in `outputs.yml`) and the two-data-path model.
- `load-forge.js` already drops both fields, so the regenerated forge data is
  clean (verified: 0/2948 docs carry either).

## Phase 2 validation — all gates pass

1. `go build ./... && go test ./...` → **green**.
2. Re-ran Phase 0.A/0.B on the regenerated index: **18 distinct `event.code`**
   buckets; `process.command_line` is now **`wildcard`** with no `ignore_above`.
3. **Positive detection test:** indexed a synthetic **3,380-char** `-enc` doc into
   a fresh template-built index — nothing was `_ignored`, and the rewritten rule's
   KQL matched **exactly 1 doc**. The old `.keyword` approach would have dropped it.
4. `./dac-sync ... -dry-run` → `created=0 updated=1 failed=0` (sane UPDATE plan,
   zero failures).

## Deviations from the brief

- **ECS reference lives in `third_party/ecs`, not `vendor/ecs`.** This repo is a
  Go module; a `vendor/` directory is reserved for module vendoring and its mere
  presence breaks `go build` ("inconsistent vendoring"). The clone is still
  gitignored and dev-only. Pinned to **v8.0.0** (the `ecs.version` in the data).
- **Cribl was extended, not recreated.** The brief's F4 assumed no `cribl/`
  existed; it did, with a tested pipeline. Recreating it would have destroyed
  working mapping logic.
- **Rules target `forge-windows-ecs*`, not `winlogbeat-*`.** Per the Phase 0
  finding (confirmed with the user): the attack data only exists in forge, and
  `winlogbeat-*` has no `process.*` and truncates command lines.

## Follow-ups (not done — need confirmation / out of scope)

- The **legacy `forge-windows-ecs` index** (old mapping, no Sysmon) still exists
  and matches the rule's `forge-windows-ecs*` pattern alongside the new
  `-000001`. Recommend retiring it (`es/reindex-forge.sh` then delete the old
  one) so the pattern is uniform — **not deleting any index without explicit
  confirmation.**
- Wiring `strip_cribl_internal` onto the live Winlogbeat route and reindexing the
  existing `winlogbeat-*` docs to purge `_time`/`filter_path` is a Cribl-UI /
  ops step (documented in `cribl/README.md`).
- A **real** `dac-sync` sync (removing `-dry-run`) is held per the guardrails
  until you approve pushing the updated rule to Kibana.
