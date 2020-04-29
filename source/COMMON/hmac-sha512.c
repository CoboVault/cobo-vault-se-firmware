/*************************************************************************************************
Copyright (c) 2020 Cobo

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
in the file COPYING.  If not, see <http://www.gnu.org/licenses/>.
**************************************************************************************************/
#include <string.h>
#include "hmac.h"
#include "sha256.h"
#include "sha384.h"

void hmac_sha256(const unsigned char *data, size_t len, const unsigned char *key, int len_key, unsigned char *out)
{
    int i = 0;
    int block_size = 64;
    int hash_size = 32;
    int key_size = block_size;
    unsigned char buf[64];
    unsigned char buf2[64];

    size_t hash_buf_size = 0;
    unsigned char *hash_buf = NULL;
    unsigned char hash_out[64];

    memset(buf, 0, block_size);
    memset(buf2, 0, block_size);
    if (len_key > block_size)
    {
        key_size = hash_size;
        SHA256_hash((UINT8 *)data, len, buf);
        memcpy(buf2, buf, key_size);
    }
    else
    {
        memcpy(buf, key, len_key);
        memcpy(buf2, key, len_key);
    }
    for (i = 0; i < key_size; i++)
    {
        *(buf + i) = *(buf + i) ^ 0x5c;
        *(buf2 + i) = *(buf2 + i) ^ 0x36;
    }
    hash_buf_size = key_size + (len < hash_size ? hash_size : len);
    hash_buf = (unsigned char *)calloc(hash_buf_size, sizeof(unsigned char));

    memcpy(hash_buf, buf2, key_size);
    memcpy(hash_buf + key_size, data, len);

    SHA256_hash(hash_buf, key_size + len, hash_out);
    memcpy(hash_buf, buf, key_size);
    memcpy(hash_buf + key_size, hash_out, hash_size);
    SHA256_hash(hash_buf, key_size + hash_size, out);
    if (NULL != hash_buf)
    {
        free(hash_buf);
    }
}

void hmac_sha512(const unsigned char *data, size_t len, const unsigned char *key, int len_key, unsigned char *out)
{
    int i = 0;
    int block_size = 128;
    int hash_size = 64;
    int key_size = block_size;
    unsigned char buf[128];
    unsigned char buf2[128];

    size_t hash_buf_size = 0;
    unsigned char *hash_buf = NULL;
    unsigned char hash_out[64];

    memset(buf, 0, block_size);
    memset(buf2, 0, block_size);
    if (len_key > block_size)
    {
        key_size = hash_size;
        SHA512_hash((UINT8 *)data, len, buf);
        memcpy(buf2, buf, key_size);
    }
    else
    {
        memcpy(buf, key, len_key);
        memcpy(buf2, key, len_key);
    }
    for (i = 0; i < key_size; i++)
    {
        *(buf + i) = *(buf + i) ^ 0x5c;
        *(buf2 + i) = *(buf2 + i) ^ 0x36;
    }
    hash_buf_size = key_size + (len < hash_size ? hash_size : len);
    hash_buf = (unsigned char *)calloc(hash_buf_size, sizeof(unsigned char));
    if (hash_buf == NULL)
    {
        return;
    }

    memcpy(hash_buf, buf2, key_size);
    memcpy(hash_buf + key_size, data, len);

    // printf("hash buf size %d %d %d %d\n", hash_buf_size, key_size, len, hash_size);
    SHA512_hash(hash_buf, key_size + len, hash_out);
    memcpy(hash_buf, buf, key_size);
    memcpy(hash_buf + key_size, hash_out, hash_size);
    SHA512_hash(hash_buf, key_size + hash_size, out);

    if (NULL != hash_buf)
    {
        free(hash_buf);
    }
}
