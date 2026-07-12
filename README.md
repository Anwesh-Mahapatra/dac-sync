# dac-sync

A minimal Detection-as-Code syncer for Elastic Kibana. It reads detection rule
definitions from local YAML/JSON files and reconciles them against the Kibana
Detection Engine API — creating rules that don't exist yet and updating ones
that do, keyed by `rule_id`.

## Why

Keep detection rules in version control instead of only in Kibana's UI: review
changes as pull requests, diff rule history, and roll out the same rule set to
multiple Kibana instances. `dac-sync` is the small tool that pushes what's on
disk to what's live.

## How it works

1. Recursively load every `.json`/`.yaml`/`.yml` file under a rules directory.
2. For each rule, check whether `rule_id` already exists in Kibana.
3. `POST` to create it if not, `PUT` to update it if it does.
4. Print a per-rule log line and a final summary (`created`/`updated`/`failed`).

The only external dependency is `gopkg.in/yaml.v3`; everything else is
`net/http` and `encoding/json` from the standard library.

## Install / build

Requires Go 1.22+.

```bash
go build -o dac-sync ./cmd/dac-sync
```

## Usage

```bash
export KIBANA_USER=elastic
export KIBANA_PASS=changeme

./dac-sync -kibana http://localhost:5601 -rules ./rules
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `-kibana` | `$KIBANA_URL` or `http://localhost:5601` | Kibana base URL; may include a space prefix, e.g. `http://host:5601/s/secops` |
| `-user` | `$KIBANA_USER` | Basic auth user |
| `-pass` | `$KIBANA_PASS` | Basic auth password |
| `-rules` | `./rules` | Directory of rule files, walked recursively |
| `-dry-run` | `false` | Print planned actions without mutating Kibana |
| `-timeout` | `30s` | Per-request HTTP timeout |
| `-insecure` | `false` | Skip TLS verification (self-signed lab certs only) |

Exits with status `1` if any rule fails to sync.

### Dry run

```bash
./dac-sync -kibana http://localhost:5601 -rules ./rules -dry-run
```

## Rule files

Each rule file must include `rule_id`, `name`, and `type` at minimum — the
fields the Detection Engine API requires to identify and create a rule. The
rest of the payload is passed through to Kibana as-is. See
[`rules/example-encoded-powershell.yml`](rules/example-encoded-powershell.yml)
for a complete example. `rule_id` must be unique across the rules directory
and should stay stable once a rule has been created, since it's the key used
to decide create vs. update.

## Testing

```bash
go test ./...
```
