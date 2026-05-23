#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define AES_BLOCK_SIZE 16
#define ROUNDS 10

// --- Yardýmcý Makrolar & Endianness ---
#define GETU32(pt) (((uint32_t)(pt)[0] << 24) ^ ((uint32_t)(pt)[1] << 16) ^ ((uint32_t)(pt)[2] <<  8) ^ ((uint32_t)(pt)[3]))
#define PUTU32(ct, st) do { \
    (ct)[0] = (uint8_t)((st) >> 24); \
    (ct)[1] = (uint8_t)((st) >> 16); \
    (ct)[2] = (uint8_t)((st) >> 8);  \
    (ct)[3] = (uint8_t)(st);         \  
} while (0)

static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static uint32_t Te0[256], Te1[256], Te2[256], Te3[256];

// --- 1. Key Expansion (AES-128) ---
void key_expansion(const uint8_t *key, uint32_t *rk) {
    static const uint32_t rcon[] = { 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000 };
    for (int i = 0; i < 4; i++) rk[i] = GETU32(key + 4*i);
    for (int i = 4; i < 44; i++) {
        uint32_t temp = rk[i-1];
        if (i % 4 == 0) {
            temp = (temp << 8) ^ (temp >> 24);
            temp = ((uint32_t)sbox[temp >> 24] << 24) ^ ((uint32_t)sbox[(temp >> 16) & 0xff] << 16) ^ ((uint32_t)sbox[(temp >> 8) & 0xff] << 8) ^ (uint32_t)sbox[temp & 0xff];
            temp ^= rcon[i/4 - 1];
        }
        rk[i] = rk[i-4] ^ temp;
    }
}

// --- 2. Baseline AES Implementation ---
static uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

void aes_encrypt_baseline(const uint8_t *in, uint8_t *out, const uint32_t *rk) {
    uint8_t s[16]; memcpy(s, in, 16);
    // Initial AddRoundKey
    for (int i=0; i<4; i++) { PUTU32(s + 4*i, GETU32(s + 4*i) ^ rk[i]); }

    for (int r = 1; r <= ROUNDS; r++) {
        // SubBytes
        for (int i=0; i<16; i++) s[i] = sbox[s[i]];
        // ShiftRows
        uint8_t t;
        t=s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=t;
        t=s[2]; s[2]=s[10]; s[10]=t; t=s[6]; s[6]=s[14]; s[14]=t;
        t=s[3]; s[3]=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=t;
        // MixColumns (Skip on final round)
        if (r < ROUNDS) {
            for (int i=0; i<4; i++) {
                uint8_t a=s[4*i], b=s[4*i+1], c=s[4*i+2], d=s[4*i+3];
                s[4*i]   = xtime(a^b) ^ b ^ c ^ d;
                s[4*i+1] = xtime(b^c) ^ c ^ d ^ a;
                s[4*i+2] = xtime(c^d) ^ d ^ a ^ b;
                s[4*i+3] = xtime(d^a) ^ a ^ b ^ c;
            }
        }
        // AddRoundKey
        for (int i=0; i<4; i++) { PUTU32(s + 4*i, GETU32(s + 4*i) ^ rk[4*r + i]); }
    }
    memcpy(out, s, 16);
}

// --- 3. Optimized AES Implementation (T-Tables) ---
void generate_tables() {
    for (int i = 0; i < 256; i++) {
        uint8_t s = sbox[i];
        uint8_t s2 = xtime(s), s3 = s2 ^ s;
        Te0[i] = ((uint32_t)s2 << 24) ^ ((uint32_t)s << 16) ^ ((uint32_t)s << 8) ^ ((uint32_t)s3);
        Te1[i] = (Te0[i] >> 8) ^ (Te0[i] << 24); Te2[i] = (Te1[i] >> 8) ^ (Te1[i] << 24); Te3[i] = (Te2[i] >> 8) ^ (Te2[i] << 24);
    }
}

void aes_encrypt_optimized(const uint8_t *in, uint8_t *out, const uint32_t *rk) {
    uint32_t s0 = GETU32(in) ^ rk[0], s1 = GETU32(in+4) ^ rk[1], s2 = GETU32(in+8) ^ rk[2], s3 = GETU32(in+12) ^ rk[3];
    uint32_t t0, t1, t2, t3;
    for (int r = 1; r < ROUNDS; r++) {
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[4*r];
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[4*r+1];
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[4*r+2];
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[4*r+3];
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }
    uint32_t f0, f1, f2, f3;
    f0 = ((uint32_t)sbox[(s0 >> 24) & 0xff] << 24) ^ ((uint32_t)sbox[(s1 >> 16) & 0xff] << 16) ^ ((uint32_t)sbox[(s2 >> 8) & 0xff] << 8) ^ ((uint32_t)sbox[s3 & 0xff]) ^ rk[40];
    f1 = ((uint32_t)sbox[(s1 >> 24) & 0xff] << 24) ^ ((uint32_t)sbox[(s2 >> 16) & 0xff] << 16) ^ ((uint32_t)sbox[(s3 >> 8) & 0xff] << 8) ^ ((uint32_t)sbox[s0 & 0xff]) ^ rk[41];
    f2 = ((uint32_t)sbox[(s2 >> 24) & 0xff] << 24) ^ ((uint32_t)sbox[(s3 >> 16) & 0xff] << 16) ^ ((uint32_t)sbox[(s0 >> 8) & 0xff] << 8) ^ ((uint32_t)sbox[s1 & 0xff]) ^ rk[42];
    f3 = ((uint32_t)sbox[(s3 >> 24) & 0xff] << 24) ^ ((uint32_t)sbox[(s0 >> 16) & 0xff] << 16) ^ ((uint32_t)sbox[(s1 >> 8) & 0xff] << 8) ^ ((uint32_t)sbox[s2 & 0xff]) ^ rk[43];
    PUTU32(out, f0); PUTU32(out + 4, f1); PUTU32(out + 8, f2); PUTU32(out + 12, f3);
}

// --- 4. Benchmark Logic ---
void run_bench(int mb) {
    size_t size = (size_t)mb * 1024u * 1024u;

    uint8_t *data_base = malloc(size);
    uint8_t *data_opt = malloc(size);

    if (!data_base || !data_opt) {
        fprintf(stderr, "Memory allocation failed\n");
        free(data_base);
        free(data_opt);
        exit(EXIT_FAILURE);
    }

    memset(data_base, 0x32, size);
    memset(data_opt, 0x32, size);

    uint32_t rk[44];

    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };

    key_expansion(key, rk);

    /*
     * Baseline measurement
     * T-table kullanmayan klasik AES adýmlarý ölçülür.
     */
    clock_t start = clock();

    for (size_t i = 0; i < size; i += AES_BLOCK_SIZE) {
        aes_encrypt_baseline(data_base + i, data_base + i, rk);
    }

    double t_base = (double)(clock() - start) / CLOCKS_PER_SEC;

    /*
     * Optimized measurement
     * T-table kullanan optimize AES ölçülür.
     */
    start = clock();

    for (size_t i = 0; i < size; i += AES_BLOCK_SIZE) {
        aes_encrypt_optimized(data_opt + i, data_opt + i, rk);
    }

    double t_opt = (double)(clock() - start) / CLOCKS_PER_SEC;

    /*
     * Checksum:
     * Derleyicinin iþlemleri gereksiz görüp silmesini engellemek için.
     */
    volatile uint8_t checksum = 0;

    for (size_t i = 0; i < size; i++) {
        checksum ^= data_base[i];
        checksum ^= data_opt[i];
    }

    printf("\n--- %d MB Test ---\n", mb);
    printf("Baseline : %.4f s (%.2f MB/s)\n", t_base, (double)mb / t_base);
    printf("Optimized: %.4f s (%.2f MB/s)\n", t_opt,  (double)mb / t_opt);

    if (t_opt > 0.0) {
        printf("Speedup  : %.2fx | Checksum: %u\n", t_base / t_opt, checksum);
    } else {
        printf("Speedup  : N/A | Checksum: %u\n", checksum);
    }

    free(data_base);
    free(data_opt);
}
int main(void) {
    generate_tables();

    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };

    uint8_t pt[16] = {
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2,
        0xe0, 0x37, 0x07, 0x34
    };

    uint8_t ct_exp[16] = {
        0x39, 0x25, 0x84, 0x1d,
        0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97,
        0x19, 0x6a, 0x0b, 0x32
    };

    uint8_t ct_base[16];
    uint8_t ct_opt[16];
    uint32_t rk[44];

    key_expansion(key, rk);

    aes_encrypt_baseline(pt, ct_base, rk);
    aes_encrypt_optimized(pt, ct_opt, rk);

    printf("--- AES-128 Accuracy Check ---\n");
    printf("Baseline Accuracy : %s\n",
           memcmp(ct_base, ct_exp, AES_BLOCK_SIZE) == 0 ? "PASSED" : "FAILED");

    printf("Optimized Accuracy: %s\n",
           memcmp(ct_opt, ct_exp, AES_BLOCK_SIZE) == 0 ? "PASSED" : "FAILED");

    printf("Outputs Match     : %s\n",
           memcmp(ct_base, ct_opt, AES_BLOCK_SIZE) == 0 ? "YES" : "NO");

    printf("\n--- AES-128 Performance Benchmark ---\n");

    run_bench(1);
    run_bench(5);
    run_bench(10);

    return 0;
}
