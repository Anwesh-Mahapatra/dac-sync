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

---

# Round 2 — schema drift & ECS coverage gaps (this session, branch `fix/schema-hardening`)

A second review produced six claims about drift between the template, the live
index, and the pipeline. Phase 0 verified each against the live cluster before
any edits; two turned out subtly wrong, and a new critical bug was found that
wasn't on the list at all: **the one live rule (`lab-win-encoded-powershell`)
had not actually been able to fire since its ECS rewrite** — it queries
`process.command_line.text`, and the live index (built from a stale,
intermediate version of the template, edited *after* the index was created)
only had `process.command_line.keyword`. The 9 alerts already sitting in the
alerts index all predated the rewrite commit.

## Phase 0 findings

| # | Claim | Verdict |
|---|---|---|
| 1 | Live index never got the current template's `dynamic_templates`; truncates at 256 | Confirmed the drift (index built from a stale template version — `modified_date_millis` was *after* the index's `creation_date`), but the truncation point was 32766, not 256 — a third, intermediate template version, not ES's default. Also found `process.command_line` itself (not just `winlog.event_data.*`) was on the stale shape, which is what broke the live rule. |
| 2 | No `case '5156'`/`'4689'` in the parser | Confirmed. 5156 alone was 51% of doc volume. |
| 3 | `event.kind/action/dataset/module`, `host.ip`, `host.os.*` absent from every doc | Confirmed. |
| 4 | Pipeline sets `host` as a scalar string; something outside the repo nests it into `{name:...}` | Confirmed the pipeline never reshapes it (byte-diffed deployed vs. git); could not fully attribute the live-observed nesting to any inspectable Cribl config. Made moot by owning the shape explicitly in code. |
| 5 | Sysmon not yet in the scenario; adding it risks a double-fire on the encoded-PS rule | Confirmed, not yet exercised — deferred (Sysmon ingestion is out of scope for this pass; `alert_suppression` added regardless as a defensive measure). |
| 6 | `cribl_pipe`/`cribl_breaker` leak into `_source`, destination-injected | Confirmed present, but the mechanism was split: `cribl_pipe` was destination `systemFields`-controlled (fixed there); `cribl_breaker` persisted through clearing `systemFields`, disabling the breaker ruleset's `shouldMarkCriblBreaker`, *and* a full worker restart — its actual source in the Filesystem Collector's collection-job code path couldn't be pinned down via the API. Fixed by stripping both explicitly in the pipeline's `eval` function instead of relying on either upstream setting. |

Also found: the rule query used in Phase 7a's spec (`process.name: "powershell.exe"` gating the C2 rule) doesn't match real data — both C2 connections' 5156 events show `Application=svchost.exe` (EvidenceForge doesn't correlate the WFP connection event to the earlier PowerShell process). Dropped that clause; the rule instead proves the 5156 mapping via `event.category`/`event.type`/external `destination.ip` alone.

## Phase 1 — `cribl/winxml_to_ecs.js`

- Universal fields on every event: `event.kind: 'event'`, `event.module: 'windows'`, `event.dataset` (per-channel map with a `windows.other` fallback).
- `host` changed from a scalar string to `{name, hostname, os: {}}`; `__e.asset = {}` also pre-created (see Phase 3 — this turned out to be load-bearing for the Lookup function, not just a style choice).
- New `case '5156'`/`'5157'` (Windows Filtering Platform) and `case '4689'` (process exit), field names verified against real `eforge/output/` XML — `ProcessID` (capital D) vs. 4688/4689's `ProcessId`, numeric `Protocol`, `%%14592`/`%%14593` `Direction` codes, and device-path `Application` all confirmed from actual samples, not assumed from docs.
- 15 new tests (32 total). No 5157 sample exists anywhere in this scenario's real output (confirmed via grep); that branch is exercised via the real 5156 fixture with the EventID substituted, documented inline rather than fabricating an `<Event>` block.
- **Bug found only at deploy time, not by the local test suite**: `generate-pipeline.js`'s `HELPERS` list wasn't updated for the 5 new helper functions, so the deployed Cribl Code function threw `ReferenceError` on every event and silently dropped all 2955 collected events (0 reached ES). The local `node winxml_to_ecs.js` run couldn't catch this because every top-level function in that file shares scope with every other one there — that blind spot is exactly what the file's own header comment claims doesn't exist. Fixed the immediate bug (added the helpers to `HELPERS`, made `eventDataset` self-contained instead of closing over a module-level object) and closed the blind spot itself: `generate-pipeline.js` now runs the *exact* generated string through `new Function()` against one synthetic event per switch-case branch before ever writing the file, so a missing helper fails `node generate-pipeline.js` instead of a live Cribl worker.
- Also renamed a local var from `proto` to `transportProto` — Cribl's Code function validator rejects `proto` as a prototype-pollution guard, again only surfacing at actual deploy time.

## Phase 2 — index template + `SCHEMA.md`

- Added `event.action/dataset/module`, `host.hostname/ip/type/os.*`, `asset.owner`, `network.direction/type`; bumped `total_fields.limit` to 2000.
- `winlog.event_id: long` decision documented, including that `winlogbeat-*` doesn't exist on this cluster so the cross-index conflict the template guards against is currently unverifiable (not fabricated).

## Phase 3 — asset enrichment

- `cribl/generate-assets-lookup.js` (no YAML dependency — a small targeted parser for `attack.yaml`'s specific `users`/`systems` list shape) emits `cribl/lookups/forge-assets.csv`, keyed on both the short hostname and FQDN.
- `assigned_user` → `asset.owner`, never `user.name` (the attack's premise is `attacker` acting as `jsmith`; overwriting the real actor would falsify attribution).
- **Second Cribl quirk found empirically**: the Lookup function can set a property on an object that already exists, but will not auto-create a missing intermediate object along a dotted output path — an `outFields` entry targeting a brand-new nested path (`host.os.name`, `asset.owner`) silently wrote nothing, while one targeting a new direct property of an already-existing object (`host.osname`) worked. Confirmed by testing each `outFields` entry in isolation via live replays. Fixed by pre-creating `host.os = {}` and `__e.asset = {}` in the Code function (Phase 1) so their parents exist before the Lookup function runs.

## Phase 4 — Cribl destination

- `forge_windows_ecs` destination's `systemFields` was `["cribl_pipe"]` despite the live index having both `cribl_pipe` *and* `cribl_breaker` on every doc — the config had been tightened at some point after the existing documents were ingested (same "edited after the fact" pattern as the template). Set to `[]`.
- Destination config now version-controlled at `cribl/outputs/forge_windows_ecs.json` (credentials redacted — a placeholder string, never the real value).

## Phase 5 — index rebuild

- Snapshotted `_count` (1955) and the `event.code` distribution before any destructive operation.
- PUT the updated template, deleted and recreated `forge-windows-ecs`, replayed via the Filesystem Collector Full Run job API.
- First replay attempt sent 0 documents (the `ReferenceError` bug above). After fixing `generate-pipeline.js` and redeploying, replay landed all 1955 docs with the identical `event.code` distribution as the pre-rebuild snapshot.
- `cribl_breaker` required the `eval`-function strip described above; everything else (mappings, `destination.ip` on 995 docs, `event.kind`/`host.os.type` on all 1955, `asset.owner` on 693) verified via `_field_caps`/`_count` post-replay.

## Deviations from the six-claim brief

- Claim 1's specific truncation number (256) was wrong; the real number was 32766, and the drift also hit `process.command_line`, not just `winlog.event_data.*` — which is what had silently broken the one existing rule.
- Claim 4's mechanism couldn't be fully attributed (no access to Cribl's server-side source); the fix (own the shape explicitly) doesn't depend on knowing the mechanism.
- Claim 6's `cribl_breaker` fix required a different mechanism than the brief assumed (destination System Fields) — see above.
- The Phase 7a C2 rule design in the original brief (`process.name: "powershell.exe"`) doesn't match real EvidenceForge data for this scenario; the clause was dropped.
