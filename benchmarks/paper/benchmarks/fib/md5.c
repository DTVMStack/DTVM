#include <stdint.h>
#include <openssl/md5.h>

/*
 * Custom memcmp implementation for comparing two memory blocks.
 */
int my_memcmp(const void *s1, const void *s2, size_t n) {
    const unsigned char *p1 = (const unsigned char *)s1;
    const unsigned char *p2 = (const unsigned char *)s2;

    for (size_t i = 0; i < n; i++) {
        if (p1[i] != p2[i]) {
            return p1[i] - p2[i];
        }
    }
    return 0; // identical
}

/*
 * Custom strlen implementation for computing string length.
 */
size_t my_strlen(const char *s) {
    size_t len = 0;
    while (s[len] != '\0') {
        len++;
    }
    return len;
}

/*
 * Compare the MD5 hash of the string "hello world" with the expected value.
 * Returns 1 (true) if hashes match, otherwise returns 0 (false).
 */
int check_md5() {
    const char *input_string = "hello world";   // Input string
    const unsigned char expected[MD5_DIGEST_LENGTH] = {
        0x5e, 0xb6, 0x3b, 0xbb, 0xe0, 0x1e, 0xee, 0xd0, 
        0x93, 0xcb, 0x22, 0xbb, 0x8f, 0x5a, 0xcd, 0xc3  // Expected MD5 hash
    };

    unsigned char md5_output[MD5_DIGEST_LENGTH];  // Buffer to store computed MD5

    // MD5 computation
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, input_string, my_strlen(input_string));
    MD5_Final(md5_output, &ctx);

    // Compare computed MD5 with expected MD5 using custom memcmp.
    return my_memcmp(md5_output, expected, MD5_DIGEST_LENGTH) == 0;
}
