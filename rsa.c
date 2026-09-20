#include <stdio.h>
#include <stdlib.h>
#include <stdint.h> 
#include <string.h>
#include <time.h>
#include <gmp.h>
#include <sys/random.h>


#define KEY_SIZE 2048

void string_to_mpz(mpz_t m, const char *str) 
{
    mpz_import(m, strlen(str), 1, sizeof(char), 0, 0, str);
}

void mpz_to_string(char *str, const mpz_t m) 
{
    size_t count;
    mpz_export(str, &count, 1, sizeof(char), 0, 0, m);
    str[count] = '\0'; // Null-terminate string
}

void generate_prime_p(mpz_t p, unsigned int bits) 
{
    mpz_t rand_num;
    int nbytes;
    ssize_t n;
    unsigned char *buf;
    nbytes=bits/8;
    
    buf = malloc(nbytes);
    n = getrandom(buf, nbytes, 0);
       if(n<nbytes){
        printf("can't generate random numbers. Exiting ...\n");
        exit(1); 
    }

    
    buf[0] = buf[0] | 0xc0;   // ensure 2 MSB is 1 for correct bit size
    
    mpz_init(rand_num); 
    mpz_import(rand_num, nbytes, 1, 1, 0, 0, buf);

    mpz_nextprime(p, rand_num);
    mpz_clear(rand_num);
}

void generate_prime_q(mpz_t q, unsigned int bits) 
{
    mpz_t rand_num;
    int nbytes;
    ssize_t n;
    unsigned char *buf;
    nbytes=bits/8;
    
    buf = malloc(nbytes);
    n = getrandom(buf, nbytes, 0);
       if(n<nbytes){
        printf("can't generate random numbers. Exiting ...\n");
        exit(1); 
    }

    
    buf[0] = buf[0] | 0x80;   // ensure MSB is 1 for correct bit size
    buf[0] = buf[0] & 0xbf;   // ensure next bit is 0 to avoid being close p
    
    mpz_init(rand_num); 
    mpz_import(rand_num, nbytes, 1, 1, 0, 0, buf);

    mpz_nextprime(q, rand_num);
    mpz_clear(rand_num);
}


void rsa_generate_keys(mpz_t n, mpz_t e, mpz_t d, unsigned int key_size) 
{
    mpz_t p, q, p_minus_1, q_minus_1, phi_n, gcd_val;
    mpz_inits(p, q, p_minus_1, q_minus_1, phi_n, gcd_val, NULL);

    generate_prime_p(p, key_size / 2);
    generate_prime_q(q, key_size / 2);

    mpz_mul(n, p, q);

    mpz_sub_ui(p_minus_1, p, 1);
    mpz_sub_ui(q_minus_1, q, 1);
    mpz_mul(phi_n, p_minus_1, q_minus_1);

    mpz_set_ui(e, 65537);
    mpz_gcd(gcd_val, e, phi_n);
    if (mpz_cmp_ui(gcd_val, 1) != 0) {
        mpz_set_ui(e, 3);
        while (1) {
            mpz_gcd(gcd_val, e, phi_n);
            if (mpz_cmp_ui(gcd_val, 1) == 0) break;
            mpz_add_ui(e, e, 2);
        }
    }

    if (mpz_invert(d, e, phi_n) == 0) {
        fprintf(stderr, "Error: Modular inverse failed.\n");
        exit(EXIT_FAILURE);
    }

    mpz_clears(p, q, p_minus_1, q_minus_1, phi_n, gcd_val, NULL);
}

void rsa_encrypt(mpz_t c, const mpz_t m, const mpz_t e, const mpz_t n) 
{
    mpz_powm(c, m, e, n);
}

void rsa_decrypt(mpz_t m, const mpz_t c, const mpz_t d, const mpz_t n) 
{
    mpz_powm(m, c, d, n);
}

void rsa_encrypt_buf(uint8_t *out, size_t *outlen, const uint8_t *c, size_t len, const mpz_t e, const mpz_t n) 
{
    mpz_t m;        
    mpz_inits(m, NULL); 

    mpz_import(m, len, 1, sizeof(uint8_t), 0, 0, c); // Convert string to MPZ
    rsa_encrypt(m, m, e, n);                       // Encrypt
    mpz_sizeinbase(m, 256);
    mpz_export(out, outlen, 1, sizeof(uint8_t), 0, 0, m); // Convert string to MPZ
    mpz_clears(m, NULL);
}

void rsa_decrypt_buf(uint8_t *out, size_t *outlen, const uint8_t *c, size_t len, const mpz_t d, const mpz_t n) 
{
    mpz_t m;        
    mpz_inits(m, NULL); 

    mpz_import(m, len, 1, sizeof(uint8_t), 0, 0, c); // Convert string to MPZ
    rsa_decrypt(m, m, d, n);                       // Decrypt
    mpz_export(out, outlen, 1, sizeof(uint8_t), 0, 0, m); // Convert string to MPZ
    mpz_clears(m, NULL);
}


int main(void) 
{
    mpz_t n, e, d;
    mpz_t message_num, ciphertext, decrypted_num;
    unsigned long seed;
    ssize_t nn;

    mpz_inits(n, e, d, message_num, ciphertext, decrypted_num, NULL);

    nn = getrandom(&seed, sizeof(seed), 0);
    if(nn<sizeof(seed)){
        printf("can't generate random numbers. Exiting ...\n");
        exit(1);
    }

    printf("=== Generating %d-bit RSA Keypair ===\n", KEY_SIZE);
    rsa_generate_keys(n, e, d, KEY_SIZE);

    const char *original_text = "Hello, world! RSA encryption via GMP library.";
    printf("Original Text: \"%s\"\n\n", original_text);

    // 1. Pack string bytes into an MPZ integer
    string_to_mpz(message_num, original_text);

    // 2. Encrypt
    rsa_encrypt(ciphertext, message_num, e, n);
    gmp_printf("Encrypted Ciphertext (Hex):\n%Zx\n\n", ciphertext);

    // 3. Decrypt
    rsa_decrypt(decrypted_num, ciphertext, d, n);

    char decrypted_text[256];
    mpz_to_string(decrypted_text, decrypted_num);
    printf("Decrypted Text: \"%s\"\n", decrypted_text);


    // Test with buffer
    size_t outlen;
    uint8_t out[256];
    size_t c_len;
    uint8_t c[256];
    
    rsa_encrypt_buf(out, &outlen, (uint8_t *)original_text, strlen(original_text), e, n);
    rsa_decrypt_buf(c, &c_len, out, outlen, d, n);
    printf("Decrypted Text (Buffer): \"%s\"\n", c);

    mpz_clears(n, e, d, message_num, ciphertext, decrypted_num, NULL);

    return 0;
}
