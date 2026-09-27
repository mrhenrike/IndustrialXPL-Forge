# IXF lab database samples

Committed SQLite templates for the malware/C2 lab. Each user generates local runtime DBs under `.tmp/ixf_c2/`.

| File | Purpose |
|------|---------|
| `botnet.db` | Bot registry (`bots`, `deploy_log`) — Go/Python C2 sync |
| `mirai.db` | Mirai CNC schema (`users`, `history`, `whitelist`) + default `admin` user |
| `c2_state.json` | Example persisted C2 settings (optional seed) |

## Bootstrap (CLI)

```text
malware db bootstrap          # copy samples → .tmp/ixf_c2/ (skip if exists)
malware db bootstrap --force  # overwrite local DBs
malware db init               # (re)create mirai.db from SQL schema only
```

## Manual

```bash
mkdir -p .tmp/ixf_c2
cp industrialxpl/resources/sql/samples/botnet.db .tmp/ixf_c2/
cp industrialxpl/resources/sql/samples/mirai.db .tmp/ixf_c2/
```

Schemas: `../botnet_registry_schema.sqlite.sql`, `../mirai_cnc_schema.sqlite.sql`.
