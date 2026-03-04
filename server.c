#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

#define PORT 8080

typedef struct { int r; int w; } relay_t;

void *relay_engine(void *arg) {
    relay_t *d = (relay_t *)arg;
    char b[4096];
    int n;
    while ((n = recv(d->r, b, sizeof(b), 0)) > 0) send(d->w, b, n, 0);
    close(d->r); close(d->w);
    free(arg);
    return NULL;
}

int main() {
    int s, c1, c2, opt = 1;
    struct sockaddr_in a;
    int al = sizeof(a);

    s = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = INADDR_ANY;
    a.sin_port = htons(PORT);

    if (bind(s, (struct sockaddr *)&a, sizeof(a)) < 0) {
        perror("Bind failed");
        return 1;
    }
    listen(s, 10);

    printf("\033[1;32m[Aether Relay] Online on port %d\033[0m\n", PORT);

    while (1) {
        printf("[Wait] Waiting for Node A...\n");
        c1 = accept(s, (struct sockaddr *)&a, (socklen_t*)&al);
        printf("[OK] Node A connected. Waiting for Node B...\n");

        c2 = accept(s, (struct sockaddr *)&a, (socklen_t*)&al);
        printf("[OK] Node B connected. Exchanging keys...\n");

        char n1[32], n2[32];
        unsigned char k1[32], k2[32];

        recv(c1, n1, 32, 0); recv(c1, k1, 32, 0);
        printf("[Log] Got Identity from A: %s\n", n1);

        recv(c2, n2, 32, 0); recv(c2, k2, 32, 0);
        printf("[Log] Got Identity from B: %s\n", n2);

        send(c1, n2, 32, 0); send(c1, k2, 32, 0);
        send(c2, n1, 32, 0); send(c2, k1, 32, 0);

        printf("[OK] Handshake complete. Bridge starting...\n");

        relay_t *r1 = malloc(sizeof(relay_t)); r1->r = c1; r1->w = c2;
        relay_t *r2 = malloc(sizeof(relay_t)); r2->r = c2; r2->w = c1;

        pthread_t t1, t2;
        pthread_create(&t1, NULL, relay_engine, r1);
        pthread_create(&t2, NULL, relay_engine, r2);
        pthread_detach(t1); pthread_detach(t2);
    }
    return 0;
}