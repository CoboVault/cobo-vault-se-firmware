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
#ifndef HKDF_H
#define HKDF_H

#ifdef __cplusplus
extern "C"
{
#endif
  enum
  {
    hkdfSuccess = 0,
    hkdfNull,    /* Null pointer parameter */
    hkdfBadParam /* Passed a bad parameter */
  };

  /**
 *  This is the HMAC-based Extract-and-Expand Key Derivation Function
 *  (HKDF).
 *
 *  salt      An optional salt value (a non-secret random value);
 *            if the salt is not provided, a string of all zeros of
 *            sha.size length is used as the salt.
 *  salt_len  The length in bytes of the optional salt.
 *  ikm       The input keying material.
 *  ikm_len   The length in bytes of ikm.
 *  info      An optional context and application specific information
 *            string. This can be a zero-length string.
 *  info_len  The length of info in bytes.
 *  okm       The output keying material of okm_len bytes.
 *  okm_len   The length of the output keying material in bytes. This
 *            must be less than or equal to 255 * sha.size bytes.
 */
  int hkdf(const unsigned char *salt, size_t salt_len,
           const unsigned char *ikm, size_t ikm_len,
           const unsigned char *info, size_t info_len,
           unsigned char *okm, size_t okm_len);

  /**
 *  Take the input keying material ikm and extract from it a
 *  fixed-length pseudorandom key prk.
 *
 *  salt      An optional salt value (a non-secret random value);
 *            if the salt is not provided, a string of all zeros
 *            of sha.size length is used as the salt.
 *  salt_len  The length in bytes of the optional salt.
 *  ikm       The input keying material.
 *  ikm_len   The length in bytes of ikm.
 *  prk       A pseudorandom key of at least sha.size bytes.
 */
  int hkdf_extract(const unsigned char *salt, size_t salt_len,
                   const unsigned char *ikm, size_t ikm_len,
                   unsigned char *prk);

  /**
 *  Expand the supplied prk into several additional pseudorandom
 *  keys, which is the output of the HKDF.
 *
 *  prk       A pseudorandom key of at least sha.size bytes. prk is
 *            usually the output from the HKDF extract step.
 *  prk_len   The length in bytes of prk.
 *  info      An optional context and application specific information
 *            string. This can be a zero-length string.
 *  info_len  The length of info in bytes.
 *  okm       The output keying material of okm_len bytes.
 *  okm_len   The length of the output keying material in bytes. This
 *            must be less than or equal to 255 * sha.size bytes.
 */
  int hkdf_expand(const unsigned char *prk, size_t prk_len,
                  const unsigned char *info, size_t info_len,
                  unsigned char *okm, size_t okm_len);

#ifdef __cplusplus
}
#endif

#endif /* hkdf.h */
