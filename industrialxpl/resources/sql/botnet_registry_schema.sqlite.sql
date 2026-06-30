-- IXF lab bot registry (Go/Python C2 sync) — copy to .tmp/ixf_c2/botnet.db
CREATE TABLE IF NOT EXISTS bots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bot_ip TEXT,
    arch INTEGER,
    source TEXT,
    first_seen REAL,
    last_seen REAL,
    status TEXT DEFAULT 'online',
    deploy_method TEXT DEFAULT 'unknown'
);

CREATE TABLE IF NOT EXISTS deploy_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT,
    port INTEGER,
    cred_user TEXT,
    success INTEGER,
    detail TEXT,
    ts REAL
);
