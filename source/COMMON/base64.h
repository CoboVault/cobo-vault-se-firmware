#ifndef BASE_64_H
#define BASE_64_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern char *encode_base64(const void *src, size_t n);
extern void *decode_base64(const char *src, size_t *n);


#endif

