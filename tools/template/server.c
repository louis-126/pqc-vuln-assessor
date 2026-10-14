/*
 * server.c - Simple persistent ML-KEM messaging server
 *
 * Does a fresh ML-KEM-512 key exchange with each connecting client,
 * then echoes messages until the connection drops. Stays running
 * and accepts new connections until killed (Ctrl+C).
 *
 * Protocol:
 *   handshake: server sends public key -> client sends ciphertext
 *   messaging:  length-prefixed messages (poc_net.h transport)
 */

#include "poc_net.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void handle_client(int conn_fd) {
#if defined(WOLFSSL_HAVE_KYBER) || defined(WOLFSSL_HAVE_MLKEM)
    WC_RNG rng;
    MlKemKey key;

    wc_InitRng(&rng);
    wc_MlKemKey_Init(&key, WC_ML_KEM_512, NULL, INVALID_DEVID);
    wc_MlKemKey_MakeKey(&key, &rng);

    /* Send public key */
    word32 pubSz = 0;
    wc_MlKemKey_PublicKeySize(&key, &pubSz);
    unsigned char *pub = malloc(pubSz);
    wc_MlKemKey_EncodePublicKey(&key, pub, pubSz);
    pn_send(conn_fd, pub, pubSz);
    free(pub);
    fprintf(stdout, "[server] sent public key (%u bytes)\n", pubSz);

    /* Receive ciphertext, decapsulate */
    word32 ctSz = 0, ssSz = 0;
    wc_MlKemKey_CipherTextSize(&key, &ctSz);
    wc_MlKemKey_SharedSecretSize(&key, &ssSz);
    unsigned char *ct = malloc(ctSz);
    unsigned char *ss = malloc(ssSz);

    uint32_t n = 0;
    if (pn_recv(conn_fd, ct, ctSz, &n) < 0) {
        fprintf(stdout, "[server] handshake failed -- client disconnected\n");
        goto cleanup;
    }
    fprintf(stdout, "[server] received ciphertext (%u bytes); first 8: ", n);
    for (uint32_t i = 0; i < 8 && i < n; i++) fprintf(stdout, "%02x", ct[i]);
    fprintf(stdout, "\n[server] decapsulating with wc_MlKemKey_Decapsulate...\n");
    fflush(stdout);

    int ret = wc_MlKemKey_Decapsulate(&key, ss, ct, n);
    fprintf(stdout, "[server] decapsulate returned %d\n", ret); fflush(stdout);
    if (ret != 0) {
        fprintf(stdout, "[server] ciphertext rejected (no shared secret)\n");
        goto cleanup;
    }

    fprintf(stdout, "[server] handshake complete -- shared secret: ");
    for (word32 i = 0; i < ssSz; i++) fprintf(stdout, "%02x", ss[i]);
    fprintf(stdout, "\n"); fflush(stdout);

    /* Echo loop */
    unsigned char msg[4096];
    while (1) {
        uint32_t len = 0;
        if (pn_recv(conn_fd, msg, sizeof(msg), &len) < 0) break;
        msg[len] = 0;
        fprintf(stdout, "[server] msg: %s\n", msg); fflush(stdout);
        pn_send(conn_fd, msg, len);
    }
    fprintf(stdout, "[server] client disconnected\n");

cleanup:
    free(ct); free(ss);
    wc_MlKemKey_Free(&key);
    wc_FreeRng(&rng);
#else
    fprintf(stderr, "[server] wolfSSL ML-KEM not compiled in\n");
#endif
}

int main(int argc, char *argv[]) {
    if (argc < 2) { fprintf(stderr, "Usage: %s <port>\n", argv[0]); return 1; }
    int port = atoi(argv[1]);

    int listen_fd = pn_listen(port);
    fprintf(stdout, "[server] listening on port %d  (Ctrl+C to stop)\n", port);
    fflush(stdout);

    while (1) {
        int conn_fd = pn_accept(listen_fd);
        fprintf(stdout, "[server] client connected\n"); fflush(stdout);
        handle_client(conn_fd);
        close(conn_fd);
    }
    return 0;
}
