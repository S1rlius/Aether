#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sodium.h>

#define IP "127.0.0.1" //айпи сервера, на который будут подключаться клиенты
#define PORT 8080
#define MSG_LIMIT 1024
#define CONTACTS_FILE "aether_contacts.conf"

unsigned char my_pk[32], my_sk[32], other_pk[32];
int sock_fd;
char username[32];

int verify_contact(const char *name, unsigned char *received_pk) {
    FILE *f = fopen(CONTACTS_FILE, "r");
    if (!f) return 0;
    char line[256], s_name[32], s_hex[65];
    unsigned char s_pk[32];
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%s %s", s_name, s_hex) == 2) {
            if (strcmp(s_name, name) == 0) {
                sodium_hex2bin(s_pk, 32, s_hex, 64, NULL, NULL, NULL);
                fclose(f);
                return (memcmp(s_pk, received_pk, 32) == 0) ? 1 : -1;
            }
        }
    }
    fclose(f);
    return 0;
}

void save_contact(const char *name, unsigned char *pk) {
    char hex[65];
    sodium_bin2hex(hex, 65, pk, 32);
    FILE *f = fopen(CONTACTS_FILE, "a");
    if (f) { fprintf(f, "%s %s\n", name, hex); fclose(f); }
}

void *receiver(void *arg) {
    unsigned char b[MSG_LIMIT + 64], d[MSG_LIMIT], n[24];
    while (1) {
        int r = recv(sock_fd, b, sizeof(b), 0);
        if (r <= 0) { printf("\n[!] Connection lost.\n"); exit(0); }
        if (r < 24) continue;
        memcpy(n, b, 24);
        if (crypto_box_open_easy(d, b + 24, r - 24, n, other_pk, my_sk) == 0) {
            printf("\r\033[K%s\n\033[1;36m> \033[0m", d);
            fflush(stdout);
        }
    }
    return NULL;
}

int main() {
    if (sodium_init() < 0) return 1;
    
    printf("\033[1;35mAether Login: \033[0m");
    fgets(username, 32, stdin);
    username[strcspn(username, "\n")] = 0;

    crypto_box_keypair(my_pk, my_sk);
    
    struct sockaddr_in sa;
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(PORT);
    inet_pton(AF_INET, IP, &sa.sin_addr);

    printf("[...] Connecting to %s:%d\n", IP, PORT);
    if (connect(sock_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("Connect failed");
        return 1;
    }

    printf("[...] Linked. Waiting for peer...\n");
    send(sock_fd, username, 32, 0);
    send(sock_fd, my_pk, 32, 0);

    char o_name[32];
    if (recv(sock_fd, o_name, 32, 0) <= 0) return 1;
    if (recv(sock_fd, other_pk, 32, 0) <= 0) return 1;

    int check = verify_contact(o_name, other_pk);
    if (check == -1) {
        printf("\033[1;31m[!] ALERT: Key mismatch for %s!\033[0m Exit? (y/n): ", o_name);
        char c; scanf(" %c", &c); if (c == 'y') return 1;
    } else if (check == 0) {
        printf("\033[1;33m[?] New contact: %s. Trust? (y/n): \033[0m", o_name);
        char c; scanf(" %c", &c); 
        if (c == 'y') save_contact(o_name, other_pk); else return 1;
    }

    pthread_t t;
    pthread_create(&t, NULL, receiver, NULL);

    char in[MSG_LIMIT], msg[MSG_LIMIT + 64];
    unsigned char p[MSG_LIMIT + 128], n[24];

    printf("\n\033[1;32m[Secure Channel Active]\033[0m\n");
    while (1) {
        printf("\033[1;36m> \033[0m");
        if (!fgets(in, MSG_LIMIT, stdin)) break;
        in[strcspn(in, "\n")] = 0;
        if (strlen(in) == 0) continue;

        snprintf(msg, sizeof(msg), "\033[1;32m%s\033[0m: %s", username, in);
        randombytes_buf(n, 24);
        memcpy(p, n, 24);
        if (crypto_box_easy(p + 24, (const unsigned char *)msg, strlen(msg) + 1, n, other_pk, my_sk) == 0) {
            send(sock_fd, p, 24 + strlen(msg) + 1 + 16, 0);
            printf("\033[1A\033[K\033[1;90mYou:\033[0m %s\n", in);
        }
    }
    return 0;
}