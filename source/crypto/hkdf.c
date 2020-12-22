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
/*
HKDF implementation -- RFC 5869
 */
#include <string.h>

#include "hkdf.h"
#include "crypto_api.h"
#include "hmac.h"

int hkdf(const unsigned char *salt, size_t salt_len,
         const unsigned char *ikm, size_t ikm_len,
         const unsigned char *info, size_t info_len,
         unsigned char *okm, size_t okm_len)
{
    int ret = hkdfSuccess;
    unsigned char prk[SHA256_LEN] = {0};

    ret = hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
    if (ret == hkdfSuccess)
    {
        ret = hkdf_expand(prk, SHA256_LEN,
                          info, info_len, okm, okm_len);
    }
    memset(prk, 0, sizeof(prk));
    return ret;
}

int hkdf_extract(const unsigned char *salt, size_t salt_len,
                 const unsigned char *ikm, size_t ikm_len,
                 unsigned char *prk)
{
    unsigned char null_salt[SHA256_LEN] = {'\0'};
    if (salt == NULL)
    {
        if (salt_len != 0)
        {
            return hkdfBadParam;
        }
        salt = null_salt;
        salt_len = SHA256_LEN;
    }

    hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
    return hkdfSuccess;
}

int hkdf_expand(const unsigned char *prk, size_t prk_len,
                const unsigned char *info, size_t info_len,
                unsigned char *okm, size_t okm_len)
{
    size_t hash_len;
    size_t where = 0;
    size_t n;
    size_t t_len = 0;
    size_t i;
    int ret = hkdfSuccess;
    unsigned char t[SHA256_LEN] = {0};

    if ((okm == NULL) || (0 == okm_len))
    {
        return hkdfBadParam;
    }

    if (info == NULL)
    {
        info = (const unsigned char *)"";
        info_len = 0;
    }

    hash_len = SHA256_LEN;
    if (prk_len < hash_len)
    {
        return hkdfBadParam;
    }
    n = okm_len / hash_len;

    if (okm_len % hash_len != 0)
    {
        n++;
    }
    /*
     * Per RFC 5869 Section 2.3, okm_len must not exceed
     * 255 times the hash length
     */
    if (n > 255)
    {
        return hkdfBadParam;
    }
    /*
     * Compute T = T(1) | T(2) | T(3) | ... | T(N)
     * Where T(N) is defined in RFC 5869 Section 2.3
     */
    for (i = 1; i <= n; i++)
    {
        size_t num_to_copy;
        unsigned char c = i & 0xff;

        HMAC_SHA256_CTX hctx;
        hmac_sha256_Init(&hctx, prk, prk_len);
        hmac_sha256_Update(&hctx, t, t_len);
        hmac_sha256_Update(&hctx, info, info_len);
        hmac_sha256_Update(&hctx, &c, 1);
        hmac_sha256_Final(&hctx, t);

        num_to_copy = i != n ? hash_len : okm_len - where;
        memcpy(okm + where, t, num_to_copy);
        where += hash_len;
        t_len = hash_len;
    }

    memset(t, 0, sizeof(t));

    return (ret);
}
