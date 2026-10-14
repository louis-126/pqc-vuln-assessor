/*
 * client.c - Simple ML-KEM messaging client
 *
 * Connects to the server, completes the ML-KEM-512 key exchange,
 * then reads lines from stdin and sends them. Prints echo replies.
 * Stays running until Ctrl+C or EOF.
 *
 * Usage: ./poc_client <port>
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

int main(int argc, char *argv[]) {
    if (argc < 2) { fprintf(stderr, "Usage: %s <port>\n", argv[0]); return 1; }
    int port = atoi(argv[1]);

    int conn_fd = pn_connect(port);
    fprintf(stdout, "[client] connected\n"); fflush(stdout);

#if defined(WOLFSSL_HAVE_KYBER) || defined(WOLFSSL_HAVE_MLKEM)
    WC_RNG rng;
    MlKemKey pub_key;
    wc_InitRng(&rng);
    wc_MlKemKey_Init(&pub_key, WC_ML_KEM_512, NULL, INVALID_DEVID);

    /* Receive server public key */
    word32 pubSz = 0;
    wc_MlKemKey_PublicKeySize(&pub_key, &pubSz);
    unsigned char *pub = malloc(pubSz);
    uint32_t n = 0;
    pn_recv(conn_fd, pub, pubSz, &n);
    wc_MlKemKey_DecodePublicKey(&pub_key, pub, n);
    free(pub);
    fprintf(stdout, "[client] received public key (%u bytes)\n", n);

    /* Encapsulate -> send ciphertext, keep shared secret */
    word32 ctSz = 0, ssSz = 0;
    wc_MlKemKey_CipherTextSize(&pub_key, &ctSz);
    wc_MlKemKey_SharedSecretSize(&pub_key, &ssSz);
    unsigned char *ct = malloc(ctSz);
    unsigned char *ss = malloc(ssSz);

    wc_MlKemKey_Encapsulate(&pub_key, ct, ss, &rng);
    pn_send(conn_fd, ct, ctSz);
    free(ct);

    fprintf(stdout, "[client] handshake complete -- shared secret: ");
    for (word32 i = 0; i < ssSz; i++) fprintf(stdout, "%02x", ss[i]);
    fprintf(stdout, "\n");
    fprintf(stdout, "[client] type messages and press enter  (Ctrl+C to quit)\n");
    fflush(stdout);

    /* Send/receive loop */
    char line[4096];
    unsigned char reply[4096];
    while (fgets(line, sizeof(line), stdin)) {
        uint32_t len = (uint32_t)strlen(line);
        if (len > 0 && line[len-1] == '\n') line[--len] = 0;
        if (len == 0) continue;

        pn_send(conn_fd, line, len);

        uint32_t rlen = 0;
        if (pn_recv(conn_fd, reply, sizeof(reply), &rlen) < 0) {
            fprintf(stdout, "[client] server disconnected\n");
            break;
        }
        reply[rlen] = 0;
        fprintf(stdout, "[client] echo: %s\n", reply); fflush(stdout);
    }

    free(ss);
    wc_MlKemKey_Free(&pub_key);
    wc_FreeRng(&rng);
#else
    fprintf(stderr, "[client] wolfSSL ML-KEM not compiled in\n");
    return 1;
#endif
    return 0;
}
