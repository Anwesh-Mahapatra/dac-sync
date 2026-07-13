# Cribl config for the dac-sync lab

Cribl Stream turns raw Windows Event XML into ECS-shaped documents in
Elasticsearch. There are two independent data paths, and they behave very
differently — understanding which is which is the key to the P1 and P4 fixes.

## Data paths

| Path | Cribl input | Pipeline | Destination index | Status |
|------|-------------|----------|-------------------|--------|
| **EvidenceForge replay** | Filesystem Collector reading `eforge/output/data/**` | `forge_win_ecs` | `forge-windows-ecs` | ECS-normalized, clean |
| **Live Winlogbeat** | Elastic API input on `:9201` | *(none)* | `winlogbeat-YYYY.MM.dd` | raw pass-through, leaks `_time`/`filter_path` |

The live Winlogbeat path ships events **straight from the input to the Elastic
destination with no pipeline**, which is why:

- **P1** (no `process.*`/`file.*`): only the forge path runs `forge_win_ecs`, and
  until this change that pipeline only mapped Security EIDs — every Sysmon event
  fell through untouched. Fixed in `winxml_to_ecs.js` (see below).
- **P4** (`_time` + `filter_path` in `_source`): with no pipeline on the live
  path, Cribl's internal `_time` field and the destination's `filter_path`
  **query-string param** are never stripped before indexing.

## Files

- **`winxml_to_ecs.js`** — the single source of truth for the mapping logic.
  Node module + self-contained test suite. Run the tests with:

  ```
  node cribl/winxml_to_ecs.js
  ```

- **`generate-pipeline.js`** — regenerates the embedded Code function inside
  `forge_win_ecs.pipeline.json` from `winxml_to_ecs.js` so the two cannot drift:

  ```
  node cribl/generate-pipeline.js          # rewrite the pipeline JSON
  node cribl/generate-pipeline.js --check  # CI: fail if it is stale
  ```

- **`forge_win_ecs.pipeline.json`** — the pipeline import (contains the generated
  Code function). Import via **Manage → Pipelines → Add Pipeline → Import** or
  drop it into the worker group's `pipelines/forge_win_ecs/` directory.

- **`forge-winxml.breaker.json`** — the event breaker that splits the XML stream
  into one `<Event>…</Event>` per event. Import under **Data → Event Breaker
  Rules**.

- **`forge-windows-ecs.index-template.json`** — the ES index template
  (applied with `es/apply-templates.sh`, not by Cribl).

- **`strip_cribl_internal.pipeline.json`** — the P4 fix (see below).

## Fixing the `_time` / `filter_path` leak (P4)

`filter_path` is injected as an **`extraParams`** entry on the Elastic
destination in Cribl's `outputs.yml`:

```yaml
extraParams:
  - name: filter_path
    value: errors,items.*.error,items.*._index,items.*.status
```

That is a legitimate `_bulk` **URL query parameter** — it tells ES to trim the
bulk *response*. It is **not** a document field, and Cribl should never be
copying it into events. It ends up in `_source` because the live Winlogbeat
route has no pipeline to strip Cribl internals before indexing.

To fix, do **both**:

1. **Check the Elastic destination's advanced / extra-fields config.** In the
   Cribl UI: *Data → Destinations → `elastic_local` → Advanced Settings →
   Extra Parameters*. Confirm `filter_path` is set there as an **extra
   parameter** (query string), not accidentally as an extra *field*. Leaving it
   as a query param is correct and harmless; the problem is only the event copy.

2. **Attach a strip step to the live Winlogbeat route.** Import
   `strip_cribl_internal.pipeline.json` (**Manage → Pipelines → Import**) and set
   it as the pipeline on the route feeding the Elastic API input on `:9201` —
   or just add its single Eval function (`remove: [_time, filter_path]`) as the
   final function of whatever pipeline that route uses. The forge path already
   drops these, so it needs no change.

After wiring, newly indexed live docs will have neither field. Existing docs in
`winlogbeat-*` keep them until reindexed (they are read-only in place).

## Case sensitivity (documented TODO)

`wildcard` fields are **case-sensitive** in KQL, so `process.command_line: *-enc*`
will not match `-EncodedCommand`. The rules therefore query the
`process.command_line.text` multi-field (a case-insensitive analyzed field) for
substring/keyword matching. If a future rule needs case-insensitive matching
directly on the raw `wildcard` value, add a lowercase-normalized companion field
in Cribl (an Eval that lowercases into e.g. `process.command_line_lc`). Not built
now — enumerate token variants in the rule instead.
