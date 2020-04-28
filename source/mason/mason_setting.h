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
/** Avoid duplicate definitions */
#ifndef MASON_SETTING_H
#define MASON_SETTING_H

/** Header file reference */
#include <stdint.h>
#include <stdbool.h>
#include <crypto_api.h>

/** Macro definitions*/
#define SETTING_STORE_PREFIX "COBO"
#define SETTING_STORE_PASS_SUFFIX "PASS"
#define SETTING_STORE_CONT_SUFFIX "CONT"
#define SETTING_STORE_FING_SUFFIX "FING"

#define SETTING_COUNT_ERR_MAX 5
// userpwd store have prefix and suffix
#define SETTING_USRPWD_LEN (32)
#define SETTING_COUNT_LEN (4)
#define SETTING_USRFING_LEN (64)
#define SETTING_PRESUF_LEN (8)
#define SETTING_MESSAGE_LEN (32)
#define SETTING_TOKEN_LEN (32)

/** Variable declarations */
typedef struct usrpwd_s
{
    uint32_t length;
    uint8_t pwd[SETTING_USRPWD_LEN + SETTING_PRESUF_LEN];
} usrpwd_t;

typedef struct usrcount_s
{
    uint8_t count[SETTING_COUNT_LEN + SETTING_PRESUF_LEN];
} usrcount_t;

typedef struct usrfing_s
{
    uint32_t length;
    uint8_t fing[SETTING_USRFING_LEN + SETTING_PRESUF_LEN];
} usrfing_t;

typedef struct setting_message_s
{
    uint32_t length;
    uint8_t message[SETTING_MESSAGE_LEN];
} setting_message_t;

typedef struct setting_token_s
{
    uint32_t length;
    uint8_t token[SETTING_TOKEN_LEN];
} setting_token_t;

/** Function declarations */
bool mason_usrpwd_verify(uint8_t *passwd, uint16_t passwd_len);
bool mason_usrpwd_store(uint8_t *passwd, uint16_t passwd_len);
void mason_usrcount(void);
bool mason_usrcount_reset(void);
bool mason_usrfing_verify(uint8_t *sign, uint16_t sign_len);
bool mason_usrfing_store(uint8_t *fing, uint16_t fing_len);

bool mason_message_gen(void);
setting_message_t *mason_message_get(void);
void mason_message_delete(void);
bool mason_token_gen(void);
setting_token_t *mason_token_get(void);
bool mason_token_verify(setting_token_t *token);
void mason_token_delete(void);
void mason_setting_delete(void);

#endif
