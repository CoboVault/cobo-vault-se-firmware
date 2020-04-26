// hmac.h
#ifndef hmac_h
#define hmac_h

#include <stdint.h>

void hmac_sha256(const unsigned char *data, size_t len, const unsigned char *key, int len_key, unsigned char *out);
void hmac_sha512(const unsigned char *data, size_t len, const unsigned char *key, int len_key, unsigned char *out);

#endif /* hmac_h */
