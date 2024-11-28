#include <stdio.h>
#include <string.h>
#include "secp256k1.h"
#include "ripemd160.h"

// Target RIPEMD-160 hash
const unsigned char target_hash[20] = { /* Fill with your RIPEMD-160 hash */ };

int main() {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    unsigned char private_key[32], public_key[65], hash[20];
    int found = 0;

    for (uint64_t i = 0; i < 0xFFFFFFFF; i++) {
        // Generate a private key (use deterministic or random key generation)
        memcpy(private_key, &i, sizeof(i));

        // Compute the public key
        size_t public_key_len = 65;
        if (!secp256k1_ec_pubkey_create(ctx, public_key, &public_key_len, private_key, 1)) {
            continue;
        }

        // Perform RIPEMD-160 hash on the public key
        ripemd160(public_key, public_key_len, hash);

        // Compare with target hash
        if (memcmp(hash, target_hash, 20) == 0) {
            found = 1;
            printf("Match found!\n");
            printf("Private Key: ");
            for (int j = 0; j < 32; j++) {
                printf("%02x", private_key[j]);
            }
            printf("\n");
            printf("Public Key: ");
            for (int j = 0; j < public_key_len; j++) {
                printf("%02x", public_key[j]);
            }
            printf("\n");
            break;
        }
    }

    secp256k1_context_destroy(ctx);

    if (!found) {
        printf("No match found.\n");
    }

    return 0;
}
