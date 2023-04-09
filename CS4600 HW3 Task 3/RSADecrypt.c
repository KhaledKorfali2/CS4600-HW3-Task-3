#include <stdio.h>
#include <stdlib.h>
#include <openssl/bn.h>


/* Function to print a BIGNUM variable in hexadecimal format */
void printBN(const char* msg, BIGNUM* a)
{
    char* number_str = BN_bn2hex(a);
    printf("%s %s", msg, number_str);
    OPENSSL_free(number_str);
}



int main() {
    // Declare and initialize variables and context
    BIGNUM* n = BN_new(); // modulus n
    BIGNUM* e = BN_new(); // public exponent
    BIGNUM* d = BN_new(); // private exponent
    BIGNUM* c = BN_new(); // ciphertext message
    BIGNUM* decrypted_m = BN_new(); // decrypted plaintext message
    BN_CTX* ctx = BN_CTX_new(); // context


    // Initialize known values for n, e, c, and d
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    BN_hex2bn(&c, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");
    printBN("Ciphertext message:", c);

    // Decryption
    BN_mod_exp(decrypted_m, c, d, n, ctx);
    printf("\n");
    printBN("Decrypted plaintext message:", decrypted_m);
    printf("\n");

    // Free memory
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(c);
    BN_free(decrypted_m);
    BN_CTX_free(ctx);

    return 0;
}