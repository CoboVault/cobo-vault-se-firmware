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
#define SETTING_STORE_PREFIX "USER"
#define SETTING_STORE_PASS_SUFFIX "PASS"
#define SETTING_STORE_CONT_SUFFIX "CONT"
#define SETTING_STORE_FING_SUFFIX "FING"
#define SETTING_STORE_SETT_SUFFIX "SETT"

#define SETTING_COUNT_ERR_MAX 5
// userpwd store have prefix and suffix
#define SETTING_USRPWD_LEN (32)
#define SETTING_COUNT_LEN (4)
#define SETTING_USRFING_LEN (64)
#define SETTING_SETTS_LEN (32)
#define SETTING_PRESUF_LEN (8)
#define SETTING_MESSAGE_LEN (32)
#define SETTING_TOKEN_LEN (32)

// user settings mask define
#define SETTING_USRSETTINGS_SIGNFP (1 << 0)
#define SETTING_USRSETTINGS_PHRASEFP (1 << 1)

typedef enum
{
    E_USRSETTINGS_SIGNFP = 0x00,
    E_USRSETTINGS_PHRASEFP = 0x01,
    E_USRSETTINGS_ERR,
} emUsrSettingsType;

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

typedef struct usrsettings_s
{
    uint32_t mask;
    uint8_t sett[SETTING_SETTS_LEN + SETTING_PRESUF_LEN];
} usrsettings_t;

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
emRetType mason_usrpwd_verify(uint8_t *passwd, uint16_t passwd_len);
bool mason_usrpwd_store(uint8_t *passwd, uint16_t passwd_len);
void mason_usrcount_check(void);
bool mason_usrcount_reset(void);
void mason_usrcount_ara(void);
bool mason_usrcount_increment(void);
emRetType mason_usrfing_verify(uint8_t *sign, uint16_t sign_len);
bool mason_usrfing_store(uint8_t *fing, uint16_t fing_len);
bool mason_usrsettings_element_load(emUsrSettingsType type, uint8_t *value);
bool mason_usrsettings_element_store(emUsrSettingsType type, uint8_t value);
bool mason_message_gen(void);
setting_message_t *mason_message_get(void);
void mason_message_delete(void);
bool mason_token_gen(void);
setting_token_t *mason_token_get(void);
emRetType mason_token_verify(setting_token_t *token);
void mason_token_delete(void);
void mason_setting_delete(void);

#endif
