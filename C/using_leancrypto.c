#include <leancrypto.h>
#include <stdio.h>


/* compile with gcc -lleancrypto [file.c] */
int main() {
    /* create the structures to hold the pk, sk, and ct*/
    /* (secret) private key (decapsulation key) */
    struct lc_kyber_sk sk;

    /* public key (encapsulation key) */
    struct lc_kyber_pk pk;
    
    /* cipher text*/
    struct lc_kyber_ct ct;

    /* shared secret (symmetric key)*/
    struct lc_kyber_ss ss_client;
    struct lc_kyber_ss ss_server;


    /* generate the keypair */
    /* we're creating 1024 because we want to be extra safe */

    if (lc_kyber_keypair(&pk, &sk, lc_seeded_rng, LC_KYBER_1024)) {
        fprintf(stderr, "Error creating keypair\n");
    }

    /* perform the pairwise consistency check*/
    if (lc_kyber_pct(&pk, &sk)) {
        fprintf(stderr, "Error in consistency check\n");
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