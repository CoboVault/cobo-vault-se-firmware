#include "base64.h"

#define BLOCK_BYTE       3  // Number of bytes in each base-64 24-bit block
#define BLOCK_CHAR       4  // Number of base-64 characters in a 24-bit block
#define BASE64_LINE_LEN  76 // Maximum line length of a base-64 string
#define NEWLINE_LEN      2  // Number of characters in the newline sequence
static const char *digits = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char *newline = "\r\n";
static const char padding = '=';
static size_t digit_value(char ch);
static void check_append_newline(char *dst, size_t *end);
static void convert_block(char *dst, size_t *end, const uint8_t *src, size_t bytes);
/*
    @description:
        Converts n bytes pointed to by src into base-64 representation.
*/
extern char *encode_base64(const void *src, size_t n)
{
    const uint8_t *bytes = src;
    size_t partial_block_bytes = n % BLOCK_BYTE;
    size_t full_blocks = n / BLOCK_BYTE;
    size_t k;
    // Make room for all full blocks plus one extra for a partial block
    char *dst = malloc((full_blocks + 1) * BLOCK_CHAR + 1);
    if (!dst)
        return NULL;
    // Convert all complete 24-bit blocks to base-64
    for (k = 0; full_blocks--; bytes += BLOCK_BYTE) {
        check_append_newline(dst + k, &k);
        convert_block(dst, &k, bytes, BLOCK_BYTE);
    }
    // Convert the final (possibly empty) partial block
    check_append_newline(dst + k, &k);
    convert_block(dst, &k, bytes, partial_block_bytes);
    dst[k] = '\0';
    return dst;
}
/*
    @description:
        Converts a valid base-64 string into a decoded array of bytes
        and stores the number of decoded bytes in the object pointed
        to by n.
*/
extern void *decode_base64(const char *src, size_t *n)
{
		size_t i;
    size_t len = strlen(src);
    uint8_t *dst = malloc(len + 1);
		size_t encoded[4];
		uint8_t bytes[3];
    if (len % BLOCK_CHAR)
        return NULL; // Invalid number of base-64 characters
    // There will never be more bytes than base-64 characters by definition
    for (*n = 0; *src; src += BLOCK_CHAR) {
        if (*src == '\r') {
            ++src; // Skip the CR part of CRLF
            if (*src != '\n') {
                free(dst);
                return NULL; // Unmatched CR
            }
            ++src; // Skip the LF part of CRLF
        }
				encoded[0] = digit_value(src[0]);
				encoded[1] = digit_value(src[1]);
				encoded[2] = digit_value(src[2]);
				encoded[3] = digit_value(src[3]);
        // Check for invalid base-64 characters
        for ( i = 0; i < sizeof(encoded) / sizeof(*encoded); ++i) {
            if (encoded[i] == (size_t)-1) {
                free(dst);
                return NULL;
            }
        }
        // Precompute the decoded bytes to faciliate handling of zero byte values
				bytes[0] = (encoded[0] << 2) + ((encoded[1] & 0x30) >> 4);
				bytes[1] = ((encoded[1] & 0x0f) << 4) + ((encoded[2] & 0x3c) >> 2);
				bytes[2] = ((encoded[2] & 0x03) << 6) + encoded[3];
        // Push non-zero decoded bytes into the destination
        for ( i = 0; i < BLOCK_BYTE; ++i) {
            // Zero bytes should only occur for padding, which we don't save
            if (bytes[i])
                dst[(*n)++] = bytes[i];
        }
    }
    return dst;
}
/*
    @description:
        Locates the index value of a base-64 character for decoding.
*/
static size_t digit_value(char ch)
{
    const char *p = strchr(digits, ch);
    if (ch == padding)
        return 0;
    return p ? p - digits : (size_t)-1;
}
/*
    @description:
        Appends a newline to dst if the value of end is at the correct
        position. Returns the updated value of end, which may not change
        if a newline was not appended.
*/
static void check_append_newline(char *dst, size_t *end)
{
    if ((*end + 1) % BASE64_LINE_LEN == 0) {
        memcpy(dst, newline, NEWLINE_LEN);
        *end += NEWLINE_LEN;
    }
}
/*
    @description:
        Converts a 24-bit block represented by 3 octets into four base-64
        characters and stores them in dst starting at end. Returns the 
        updated value of end for convenience.
*/
static void convert_block(char *dst, size_t *end, const uint8_t *src, size_t bytes)
{
    switch (bytes) {
        case 3:
            dst[(*end)++] = digits[src[0] >> 2];
            dst[(*end)++] = digits[((src[0] & 0x03) << 4) | (src[1] >> 4)];
            dst[(*end)++] = digits[((src[1] & 0x0f) << 2) | (src[2] >> 6)];
            dst[(*end)++] = digits[src[2] & 0x3f];
            break;
        case 2:
            dst[(*end)++] = digits[src[0] >> 2];
            dst[(*end)++] = digits[((src[0] & 0x03) << 4) | (src[1] >> 4)];
            dst[(*end)++] = digits[((src[1] & 0x0f) << 2)];
            dst[(*end)++] = padding;
            break;
        case 1:
            dst[(*end)++] = digits[src[0] >> 2];
            dst[(*end)++] = digits[((src[0] & 0x03) << 4)];
            dst[(*end)++] = padding;
            dst[(*end)++] = padding;
            break;
    }
}
#ifdef TEST_DRIVER
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void)
{
    const char *test[] = {"", "f", "fo", "foo", "foob", "fooba", "foobar"};
    size_t n;
    for (size_t i = 0; i < sizeof test / sizeof *test; ++i) {
        char *p = encode_base64(test[i], strlen(test[i]));
        char *q = decode_base64(p, &n);
        printf("BASE64(\"%s\") = \"%s\" = (%zd)\"%.*s\"\n", test[i], p, n, n, q);
        free(p);
        free(q);
    }
    return 0;
}
#endif
