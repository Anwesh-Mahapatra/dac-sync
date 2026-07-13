# Detection field contract

This document is the authority for **which fields a detection rule may query**.
The rule of thumb: **the live index mapping decides what is queryable; ECS decides
what a field is named and typed.** A field name being defined in ECS does *not*
license a rule to use it — the field must actually exist in the target index
(prove it with `GET <index>/_field_caps?fields=<f>`).

## The two indices (they are not interchangeable)

| Index | Shape | Use for detections? |
|---|---|---|
| `forge-windows-ecs*` | ECS-normalized by the Cribl `forge_win_ecs` pipeline (`process.*`, `file.*`, `destination.*`, plus raw `winlog.event_data.*`). Long-string fields are `wildcard` / `keyword(1024)` — **no truncation**. | **Yes.** This is the detection target. |
| `winlogbeat-*` | Dynamically mapped raw Winlogbeat. **No `process.*`/`file.*`/`destination.*`** — only `winlog.event_data.*`, every string `text` + `.keyword(ignore_above:256)`. | No. It carries no ECS entities and truncates `CommandLine` at 256 chars (the P3 bug). It is background desktop telemetry, not the lab scenario. |

Rules target `forge-windows-ecs*` and query ECS fields. See `cribl/README.md` for
why the two indices differ (the live Winlogbeat route has no pipeline).

## Sysmon → ECS mapping table

This table documents the normalization the Cribl pipeline (`cribl/winxml_to_ecs.js`)
performs. The **ECS type** column is verified against
`vendor/ecs/generated/ecs/ecs_flat.yml` at ECS **v8.0.0** (pinned to the
`ecs.version` in the data). Every target below exists in that file with the type
shown.

| Sysmon `winlog.event_data.*` | ECS target | ECS type |
|---|---|---|
| `Image` | `process.executable` | keyword |
| `Image` (basename) | `process.name` | keyword |
| `CommandLine` | `process.command_line` | wildcard |
| `CommandLine` (tokenized) | `process.args` | keyword |
| `CurrentDirectory` | `process.working_directory` | keyword |
| `ProcessId` | `process.pid` | long |
| `ProcessGuid` | `process.entity_id` | keyword |
| `OriginalFileName` | `process.pe.original_file_name` | keyword |
| `Product` | `process.pe.product` | keyword |
| `Company` | `process.pe.company` | keyword |
| `FileVersion` | `process.pe.file_version` | keyword |
| `Description` | `process.pe.description` | keyword |
| `Hashes` MD5 | `process.hash.md5` | keyword |
| `Hashes` SHA256 | `process.hash.sha256` | keyword |
| `Hashes` IMPHASH | `process.pe.imphash` | keyword |
| `ParentImage` | `process.parent.executable` | keyword |
| `ParentImage` (basename) | `process.parent.name` | keyword |
| `ParentCommandLine` | `process.parent.command_line` | wildcard |
| `ParentProcessId` | `process.parent.pid` | long |
| `ParentProcessGuid` | `process.parent.entity_id` | keyword |
| `User` (domain part) | `user.domain` | keyword |
| `User` (name part) | `user.name` | keyword |
| `SourceIp` | `source.ip` | ip |
| `SourcePort` | `source.port` | long |
| `DestinationIp` | `destination.ip` | ip |
| `DestinationPort` | `destination.port` | long |
| `DestinationHostname` | `destination.domain` | keyword |
| `Protocol` | `network.transport` | keyword |
| `TargetFilename` | `file.path` | keyword |
| `TargetFilename` (basename) | `file.name` | keyword |
| `TargetFilename` (dir) | `file.directory` | keyword |

`event.category` / `event.type` / `event.outcome` are set only from that field's
`allowed_values` in `ecs_flat.yml` (e.g. `event.category: process`,
`event.type: start`, `event.outcome: success`).

**This table documents the intended normalization performed by the pipeline.**
The normalization already exists (the Cribl `forge_win_ecs` pipeline, F1), so
rules query the ECS targets above on `forge-windows-ecs*`. The raw
`winlog.event_data.*` fields are still preserved on every forge doc as a fallback.

## Fields a rule maps FROM (quick reference for rule authors)

| Intent | Query this (ECS, on forge) | Not this |
|---|---|---|
| process image / name | `process.name`, `process.executable` | ~~`winlog.event_data.Image`~~ (raw fallback only) |
| rename-evasion name | `process.pe.original_file_name` | — |
| command line | `process.command_line` (wildcard) or `process.command_line.text` (analyzed) | a `.keyword` wildcard (256-char truncation) |
| parent image | `process.parent.name`, `process.parent.executable` | — |
| file written | `file.path` | — |
| subject user | `user.name` (+ `user.domain`) | ~~`winlog.user.name`~~ (the log writer, not the actor) |
| host | `host.name` (also `winlog.computer_name`) | — |
| event kind | `event.code`, `event.category`, `event.type` | ~~`event.action`~~, ~~`winlog.task`~~ (mislabeled — see P2) |

## Never key off these

- **`event.action` / `winlog.task`** — unreliable in this data. A single
  `event.code:1` doc set carries nine different `event.action` text labels
  (1,149 of them literally say "Network connection detected"), and `winlog.task`
  is identical noise. Gate on `event.code` (trustworthy — it lines up with the
  event_data content) or on the ECS `event.category`/`event.type` the pipeline
  now sets.
- **A `.keyword` wildcard on a long-string field** (`CommandLine`, `ParentCommandLine`,
  `Image`, ...). On `winlogbeat-*` the `.keyword` sub-field has `ignore_above:256`,
  so a `>256`-char value is dropped entirely and invisible to any `.keyword`
  query — precisely how long `-enc <base64>` payloads escaped detection.

## `wildcard` case-sensitivity

`wildcard` fields are **case-sensitive** in KQL: `process.command_line: *-enc*`
matches `-enc` but not `-EncodedCommand`. Rules that need case-insensitive
matching query the analyzed **`.text`** multi-field
(`process.command_line.text: enc`), which lowercases and tokenizes, so `-enc`,
`-Enc`, and `-EncodedCommand` all match regardless of payload length.

**TODO (not built now):** if a rule needs case-insensitive matching directly on
the raw `wildcard` value, add a lowercase-normalized companion field in Cribl
(an Eval lowercasing into e.g. `process.command_line_lc`). Until then, use the
`.text` field or enumerate token variants in the rule.
