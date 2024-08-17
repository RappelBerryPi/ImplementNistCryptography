#include <leancrypto.h>
#include <stdio.h>


/* leancrypto is installed to the /usr/local directory and is non-standard so compile with gcc -lleancrypto [file.c] */
int main() {
    /* 
       The goal of this example is to keep everything in one file. Because of this this we'er going to fork and pipe to
       represent a client and server.
    */
    pid_t pid;
    
    /* server Write */
    int threadPipe[2];

    /* client Write */
    int threadPipe2[2];

    /* for comparison after run */
    struct lc_kyber_ss ss_server;
    struct lc_kyber_ss ss_client;

    /* setup the pipes */
    pipe(threadPipe);
    pipe(threadPipe2);
    pid = fork();

    /* child process which we're designating arbitrarily as the client*/
    // pid == 0 -> child process
    if (pid == (pid_t) 0) {
        // client should not have the private key;
        struct lc_kyber_pk pk;
        struct lc_kyber_ct ct;
        struct lc_kyber_ss ss;

        /* todo, start here, wait read PK and CT, close pipe 1, write on pipe 2*/
    } else {
        struct lc_kyber_sk sk;
        struct lc_kyber_pk pk;
        struct lc_kyber_ct ct;
        struct lc_kyber_ss ss;
        if (lc_kyber_keypair(&pk, &sk, lc_seeded_rng, LC_KYBER_1024)) {
            fprintf(stderr, "Error creating keypair\n");
        }
        if (lc_kyber_pct(&pk, &sk)) {
            fprintf(stderr, "Error in consistency check\n");
        }
        /* todo, start here, write PK and CT, close pipe 1, wait read on pipe 2*/
        fprintf(threadpipe[1])
        threadPipe[1]

    }






    /* pretend to be the person that we sent the Public key to and we're generating a shared secret */
    if (lc_kyber_enc(&ct, &ss_client, &pk)) {
        fprintf(stderr, "Error creating the shared secret from encapsulation\n");
    }

    /* pretend now that we're the person who owns the private key, and we're getting the ciphertext from a third party */
    if (lc_kyber_dec(&ss_server, &ct, &sk)) {
        fprintf(stderr, "Error creating the shared secret from decapsulation\n");
    }

    /* 
        obviously we wouldn't be able to compare that these are the same, but since we're pretending to be both parties
        we can.
    */
    if (memcmp(&ss_client, &ss_server, sizeof(&ss_client))) {
        fprintf(stderr, "The server and client shared secret are not the same!\n");
    }

    printf("We have a shared secret, now that we're quantum safe, let's print this out to the screen so everyone can see it\n");
    for (int i = 0; i < 32; i++) {
        printf("%02X ", ss_client.key.ss_1024.ss[i]);
    }
    printf("\n");
}