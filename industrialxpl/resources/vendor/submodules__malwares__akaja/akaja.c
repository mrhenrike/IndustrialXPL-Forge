#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>

// ---------- Global Counters ----------
static unsigned long sent_packets = 0;
static unsigned long recv_packets = 0;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

// ---------- Checksum ----------
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;
    for (sum = 0; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// ---------- Send ICMP ----------
int send_ping(int sockfd, struct sockaddr_in *addr, int seq) {
    struct icmp icmp_pkt;
    struct timeval tv;
    memset(&icmp_pkt, 0, sizeof(icmp_pkt));
    icmp_pkt.icmp_type = ICMP_ECHO;
    icmp_pkt.icmp_code = 0;
    icmp_pkt.icmp_id = getpid() & 0xFFFF;
    icmp_pkt.icmp_seq = seq;
    gettimeofday(&tv, NULL);
    memcpy(icmp_pkt.icmp_data, &tv, sizeof(tv));
    icmp_pkt.icmp_cksum = checksum(&icmp_pkt, sizeof(icmp_pkt));
    if (sendto(sockfd, &icmp_pkt, sizeof(icmp_pkt), 0,
               (struct sockaddr *)addr, sizeof(*addr)) <= 0) {
        return -1;
    }
    pthread_mutex_lock(&lock);
    sent_packets++;
    pthread_mutex_unlock(&lock);
    return 0;
}

// ---------- Receive ICMP ----------
int recv_ping(int sockfd, struct sockaddr_in *addr, int seq) {
    char recvbuf[1024];
    struct ip *ip_hdr;
    struct icmp *icmp_hdr;
    struct timeval tv_recv, tv_sent;
    socklen_t addr_len = sizeof(*addr);

    int bytes_received = recvfrom(sockfd, recvbuf, sizeof(recvbuf), MSG_DONTWAIT,
                                  (struct sockaddr *)addr, &addr_len);
    if (bytes_received <= 0) return -1;

    ip_hdr = (struct ip *)recvbuf;
    int ip_hdr_len = ip_hdr->ip_hl * 4;
    icmp_hdr = (struct icmp *)(recvbuf + ip_hdr_len);

    if (icmp_hdr->icmp_type == ICMP_ECHOREPLY &&
        icmp_hdr->icmp_id == (getpid() & 0xFFFF)) {
        memcpy(&tv_sent, icmp_hdr->icmp_data, sizeof(tv_sent));
        gettimeofday(&tv_recv, NULL);
        double rtt = (tv_recv.tv_sec - tv_sent.tv_sec) * 1000.0;
        rtt += (tv_recv.tv_usec - tv_sent.tv_usec) / 1000.0;

        pthread_mutex_lock(&lock);
        recv_packets++;
        pthread_mutex_unlock(&lock);

        printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms\n",
               bytes_received - ip_hdr_len,
               inet_ntoa(addr->sin_addr),
               icmp_hdr->icmp_seq,
               ip_hdr->ip_ttl,
               rtt);
        return 0;
    }
    return -1;
}

// ---------- Thread Function ----------
void *ping_thread(void *arg) {
    struct sockaddr_in *addr = (struct sockaddr_in *)arg;
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket");
        pthread_exit(NULL);
    }

    int seq = 0;
    while (1) {
        if (send_ping(sockfd, addr, seq) == 0) {
            recv_ping(sockfd, addr, seq);
        }
        seq++;
        // adjust for speed; flood if commented
        //usleep(1000);
    }
    close(sockfd);
    return NULL;
}

// ---------- SIGINT Handler ----------
void sigint_handler(int signo) {
    pthread_mutex_lock(&lock);
    unsigned long sent = sent_packets;
    unsigned long recv = recv_packets;
    pthread_mutex_unlock(&lock);

    printf("\n--- ping statistics ---\n");
    printf("%lu packets transmitted, %lu received, %.1f%% packet loss\n",
           sent, recv,
           sent ? ((sent - recv) * 100.0 / sent) : 0.0);
    exit(0);
}

// ---------- Main ----------
int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <IP>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, argv[1], &addr.sin_addr) <= 0) {
        perror("inet_pton");
        exit(EXIT_FAILURE);
    }

    printf("PING %s (%s):\n", argv[1], inet_ntoa(addr.sin_addr));

    // Setup Ctrl+C handler
    signal(SIGINT, sigint_handler);

    int thread_count = 4; // run 4 threads for parallel speed
    pthread_t threads[thread_count];
    for (int i = 0; i < thread_count; i++) {
        if (pthread_create(&threads[i], NULL, ping_thread, &addr) != 0) {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }
    }

    for (int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}
