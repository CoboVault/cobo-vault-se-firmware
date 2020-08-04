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
#include <crypto_api.h>
#include <string.h>
#include <stdio.h>
#include <mason_storage.h>
#include <mason_hdw.h>
#include <mason_setting.h>
#include <mason_wallet.h>
#include <mason_util.h>
#include <hrng.h>

/** Variable declarations */
setting_message_t global_message = {0};
setting_token_t global_token = {0};

/** Function implementations */
/*user password interface*/
/**
 * @functionname: mason_usrpwd_read
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_usrpwd_read(uint8_t *passwd, uint16_t *passwd_len)
{
    bool is_succeed = false;
    emRetType emRet = ERT_OK;
    usrpwd_t pwd = {0};
    emRet = mason_storage_read((uint8_t *)&pwd, sizeof(usrpwd_t), FLASH_ADDR_USRPWD);
    if ((emRet == ERT_OK) && (pwd.length > SETTING_PRESUF_LEN) && (pwd.length <= SETTING_USRPWD_LEN + SETTING_PRESUF_LEN))
    {
        uint8_t pre[5] = {0};
        uint8_t suf[5] = {0};
        memcpy(pre, &pwd.pwd[0], 4);
        memcpy(suf, &pwd.pwd[pwd.length - 4], 4);
        if (!strcmp((char *)pre, SETTING_STORE_PREFIX) && !strcmp((char *)suf, SETTING_STORE_PASS_SUFFIX))
        {
            memcpy(passwd, &pwd.pwd[4], (pwd.length - SETTING_PRESUF_LEN));
            *passwd_len = pwd.length - 8;
            is_succeed = true;
        }
    }

    memset(&pwd, 0, sizeof(usrpwd_t));
    return is_succeed;
}
/**
 * @functionname: mason_usrpwd_write
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_usrpwd_write(uint8_t *passwd, uint16_t passwd_len)
{
    bool is_succeed = false;
    usrpwd_t pwd = {0};
    if ((0 == passwd_len) || (passwd_len > SETTING_USRPWD_LEN))
    {
        return false;
    }

    pwd.length = passwd_len + SETTING_PRESUF_LEN;
    memcpy(&pwd.pwd[0], SETTING_STORE_PREFIX, 4);
    memcpy(&pwd.pwd[4], passwd, passwd_len);
    memcpy(&pwd.pwd[passwd_len + 4], SETTING_STORE_PASS_SUFFIX, 4);

    is_succeed = mason_storage_write_buffer((uint8_t *)&pwd, sizeof(usrpwd_t), FLASH_ADDR_USRPWD);

    memset(&pwd, 0, sizeof(usrpwd_t));
    return is_succeed;
}
/**
 * @functionname: mason_usrpwd_verify
 * @description: 
 * @para: 
 * @return: 
 */
emRetType mason_usrpwd_verify(uint8_t *passwd, uint16_t passwd_len)
{
    emRetType emRet = ERT_Verify_Init;
    uint8_t cur_passwd[SETTING_USRPWD_LEN] = {0};
    uint16_t cur_passwd_len = 0;
    uint8_t checksum[SHA256_LEN] = {0};
    uint16_t checksumlen = SHA256_LEN;

    do
    {
        if (SHA256_LEN != passwd_len)
        {
            emRet = ERT_VerifyLenFail;
            break;
        }

        if (!mason_usrpwd_read(cur_passwd, &cur_passwd_len))
        {
            emRet = ERT_VerifyValueFail;
            break;
        }

        if (checksumlen != cur_passwd_len)
        {
            emRet = ERT_VerifyLenFail;
            break;
        }

        mason_HDW_gen_sha256sha256(passwd, passwd_len, checksum, checksumlen);

        if (memcmp_ATA(checksum, cur_passwd, cur_passwd_len))
        {
            emRet = ERT_VerifyValueFail;
            break;
        }

        emRet = ERT_Verify_Success;
    } while (0);

    memset(cur_passwd, 0, SETTING_USRPWD_LEN);
    memset(checksum, 0, SHA256_LEN);
    return emRet;
}
/**
 * @functionname: mason_usrpwd_store
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_usrpwd_store(uint8_t *passwd, uint16_t passwd_len)
{
    bool is_succeed = false;
    uint8_t checksum[SHA256_LEN] = {0};
    uint16_t checksumlen = SHA256_LEN;

    do
    {
        if (SHA256_LEN != passwd_len)
        {
            is_succeed = false;
            break;
        }

        mason_HDW_gen_sha256sha256(passwd, passwd_len, checksum, checksumlen);

        if (!mason_usrpwd_write(checksum, checksumlen))
        {
            is_succeed = false;
            break;
        }

        is_succeed = true;
    } while (0);

    memset(checksum, 0, SHA256_LEN);
    return is_succeed;
}
/**
 * @functionname: mason_usrpwd_delete
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_usrpwd_delete(void)
{
    bool is_succeed = false;
    usrpwd_t pwd = {0};

    pwd.length = 0;
    memset(pwd.pwd, 0, (SETTING_USRPWD_LEN + SETTING_PRESUF_LEN));

    is_succeed = mason_storage_write_buffer((uint8_t *)&pwd, sizeof(usrpwd_t), FLASH_ADDR_USRPWD);
    return is_succeed;
}

/*user password err count interface*/
/**
 * @functionname: mason_usrcount_read
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_usrcount_read(uint32_t *count)
{
    bool is_succeed = false;
    emRetType emRet = ERT_OK;
    usrcount_t cnt = {0};
    emRet = mason_storage_read((uint8_t *)&cnt, sizeof(usrcount_t), FLASH_ADDR_USRPWD_COUNT);
    if (emRet == ERT_OK)
    {
        uint8_t pre[5] = {0};
        uint8_t suf[5] = {0};
        memcpy(pre, &cnt.count[0], 4);
        memcpy(suf, &cnt.count[8], 4);

        if (!strcmp((char *)pre, SETTING_STORE_PREFIX) && !strcmp((char *)suf, SETTING_STORE_CONT_SUFFIX))
        {
            memcpy((void *)count, &cnt.count[4], 4);
            is_succeed = true;
        }
    }
    return is_succeed;
}
/**
 * @functionname: mason_usrcount_write
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_usrcount_write(uint32_t *count)
{
    bool is_succeed = false;
    usrcount_t cnt = {0};
    memcpy(&cnt.count[0], SETTING_STORE_PREFIX, 4);
    memcpy(&cnt.count[4], (void *)count, 4);
    memcpy(&cnt.count[8], SETTING_STORE_CONT_SUFFIX, 4);

    is_succeed = mason_storage_write_buffer((uint8_t *)&cnt, sizeof(usrcount_t), FLASH_ADDR_USRPWD_COUNT);

    return is_succeed;
}
/**
 * @functionname: mason_usrcount_delete
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_usrcount_delete(void)
{
    bool is_succeed = false;
    usrcount_t cnt = {0};
    is_succeed = mason_storage_write_buffer((uint8_t *)&cnt, sizeof(usrcount_t), FLASH_ADDR_USRPWD_COUNT);
    return is_succeed;
}
/**
 * @functionname: mason_usrcount_reset
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_usrcount_reset(void)
{
    bool is_succeed = false;
    uint32_t usrpwd_count = 0;
    is_succeed = mason_usrcount_write(&usrpwd_count);
    return is_succeed;
}
/**
 * @functionname: mason_usrcount_ara
 * @description: anti repeated attacks
 * @para: 
 * @return: 
 */
void mason_usrcount_ara(void)
{
    uint32_t usrpwd_count = 0;
    if (!mason_usrcount_read(&usrpwd_count))
    {
        mason_usrcount_reset();
    }
}
/**
 * @functionname: mason_usrcount_check
 * @description: 
 * @para: 
 * @return: 
 */
void mason_usrcount_check(void)
{
    uint32_t usrpwd_count = 0;
    if (!mason_usrcount_read(&usrpwd_count))
    {
        mason_usrcount_reset();
    }

    if (usrpwd_count >= SETTING_COUNT_ERR_MAX)
    {
        mason_delete_wallet();
        mason_set_mode(HDW_STATUS_EMPTY);
        mason_setting_delete();
    }
}
/**
 * @functionname: mason_usrcount_increment
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_usrcount_increment(void)
{
    uint32_t usrpwd_count = 0;
    if (!mason_usrcount_read(&usrpwd_count))
    {
        mason_usrcount_reset();
    }

    if (usrpwd_count >= SETTING_COUNT_ERR_MAX)
    {
        mason_delete_wallet();
        mason_set_mode(HDW_STATUS_EMPTY);
        mason_setting_delete();
        return false;
    }

    usrpwd_count++;
    mason_usrcount_write(&usrpwd_count);
    return true;
}

/*user fingerprint interface*/
/**
 * @functionname: mason_usrfing_read
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_usrfing_read(uint8_t *fing, uint16_t *fing_len)
{
    bool is_succeed = false;
    emRetType emRet = ERT_OK;
    usrfing_t fingerprint = {0};
    emRet = mason_storage_read((uint8_t *)&fingerprint, sizeof(usrfing_t), FLASH_ADDR_USRFING);
    if ((emRet == ERT_OK) && (fingerprint.length > SETTING_PRESUF_LEN) && (fingerprint.length <= SETTING_USRFING_LEN + SETTING_PRESUF_LEN))
    {
        uint8_t pre[5] = {0};
        uint8_t suf[5] = {0};
        memcpy(pre, &fingerprint.fing[0], 4);
        memcpy(suf, &fingerprint.fing[fingerprint.length - 4], 4);
        if (!strcmp((char *)pre, SETTING_STORE_PREFIX) && !strcmp((char *)suf, SETTING_STORE_FING_SUFFIX))
        {
            memcpy(fing, &fingerprint.fing[4], (fingerprint.length - SETTING_PRESUF_LEN));
            *fing_len = fingerprint.length - 8;
            is_succeed = true;
        }
    }
    memset(&fingerprint, 0, sizeof(usrfing_t));
    return is_succeed;
}
/**
 * @functionname: mason_usrfing_write
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_usrfing_write(uint8_t *fing, uint16_t fing_len)
{
    bool is_succeed = false;
    usrfing_t fingerprint = {0};
    if ((0 == fing_len) || (fing_len > SETTING_USRFING_LEN))
    {
        return false;
    }

    fingerprint.length = fing_len + SETTING_PRESUF_LEN;
    memcpy(&fingerprint.fing[0], SETTING_STORE_PREFIX, 4);
    memcpy(&fingerprint.fing[4], fing, fing_len);
    memcpy(&fingerprint.fing[fing_len + 4], SETTING_STORE_FING_SUFFIX, 4);

    is_succeed = mason_storage_write_buffer((uint8_t *)&fingerprint, sizeof(usrfing_t), FLASH_ADDR_USRFING);
    memset(&fingerprint, 0, sizeof(usrfing_t));
    return is_succeed;
}
/**
 * @functionname: mason_usrfing_verify
 * @description: 
 * @para: 
 * @return: 
 */
emRetType mason_usrfing_verify(uint8_t *sign, uint16_t sign_len)
{
    emRetType emRet = ERT_Verify_Init;
    uint8_t cur_fing[SETTING_USRFING_LEN] = {0};
    uint16_t cur_fing_len = 0;
    setting_message_t *message = NULL;
    uint8_t hash_message[SHA256_LEN] = {0};

    do
    {
        if (!sign_len)
        {
            emRet = ERT_VerifyLenFail;
            break;
        }

        if (!mason_usrfing_read(cur_fing, &cur_fing_len))
        {
            emRet = ERT_VerifyValueFail;
            break;
        }

        message = mason_message_get();

        //r1 verify
        sha256_api(message->message, message->length, hash_message);

        if (!ecdsa_verify(CRYPTO_CURVE_SECP256R1, hash_message, cur_fing, sign))
        {
            emRet = ERT_VerifyValueFail;
            break;
        }

        emRet = ERT_Verify_Success;
    } while (0);

    memset(&cur_fing, 0, SETTING_USRFING_LEN);
    memset(&hash_message, 0, SHA256_LEN);
    return emRet;
}
/**
 * @functionname: mason_usrfing_store
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_usrfing_store(uint8_t *fing, uint16_t fing_len)
{

    if (SETTING_USRFING_LEN != fing_len)
    {
        return false;
    }

    if (!mason_usrfing_write(fing, fing_len))
    {
        return false;
    }

    return true;
}
/**
 * @functionname: mason_usrfing_delete
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_usrfing_delete(void)
{
    bool is_succeed = false;
    usrfing_t fingerprint = {0};

    fingerprint.length = 0;
    memset(fingerprint.fing, 0, (SETTING_USRFING_LEN + SETTING_PRESUF_LEN));

    is_succeed = mason_storage_write_buffer((uint8_t *)&fingerprint, sizeof(usrfing_t), FLASH_ADDR_USRFING);
    return is_succeed;
}

/*user settings interface*/
/**
 * @functionname: mason_usrsettings_read
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_usrsettings_read(uint8_t *sett, uint32_t *mask)
{
    bool is_succeed = false;
    usrsettings_t usrsettings = {0};

    if (ERT_OK == mason_storage_read((uint8_t *)&usrsettings, sizeof(usrsettings_t), FLASH_ADDR_USRSETTINGS))
    {
        uint8_t pre[5] = {0};
        uint8_t suf[5] = {0};
        memcpy(pre, &usrsettings.sett[0], 4);
        memcpy(suf, &usrsettings.sett[SETTING_SETTS_LEN + 4], 4);
        if (!strcmp((char *)pre, SETTING_STORE_PREFIX) && !strcmp((char *)suf, SETTING_STORE_SETT_SUFFIX))
        {
            memcpy(sett, &usrsettings.sett[4], SETTING_SETTS_LEN);
            *mask = usrsettings.mask;
            is_succeed = true;
        }
    }
    memset(&usrsettings, 0, sizeof(usrsettings_t));
    return is_succeed;
}
/**
 * @functionname: mason_usrsettings_write
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_usrsettings_write(uint8_t *sett, uint32_t mask)
{
    bool is_succeed = false;
    usrsettings_t usrsettings = {0};

    usrsettings.mask = mask;
    memcpy(&usrsettings.sett[0], SETTING_STORE_PREFIX, 4);
    memcpy(&usrsettings.sett[4], sett, SETTING_SETTS_LEN);
    memcpy(&usrsettings.sett[SETTING_SETTS_LEN + 4], SETTING_STORE_SETT_SUFFIX, 4);

    is_succeed = mason_storage_write_buffer((uint8_t *)&usrsettings, sizeof(usrsettings_t), FLASH_ADDR_USRSETTINGS);
    memset(&usrsettings, 0, sizeof(usrsettings_t));
    return is_succeed;
}
/**
 * @functionname: mason_usrsettings_delete
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_usrsettings_delete(void)
{
    bool is_succeed = false;
    usrsettings_t sett = {0};
    is_succeed = mason_storage_write_buffer((uint8_t *)&sett, sizeof(usrsettings_t), FLASH_ADDR_USRSETTINGS);
    return is_succeed;
}
/**
 * @functionname: mason_usrsettings_element_load
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_usrsettings_element_load(emUsrSettingsType type, uint8_t *value)
{
    bool is_succeed = false;
    uint8_t settings[SETTING_SETTS_LEN] = {0};
    uint32_t mask = 0;

    is_succeed = mason_usrsettings_read(settings, &mask);
    if (!is_succeed)
    {
        return false;
    }

    switch (type)
    {
    case E_USRSETTINGS_SIGNFP:
    {
        if (mask & SETTING_USRSETTINGS_SIGNFP)
        {
            *value = settings[type];
            return true;
        }
    }
    break;
    case E_USRSETTINGS_PHRASEFP:
    {
        if (mask & SETTING_USRSETTINGS_PHRASEFP)
        {
            *value = settings[type];
            return true;
        }
    }
    break;
    default:
        return false;
    }
    return false;
}
/**
 * @functionname: mason_usrsettings_element_store
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_usrsettings_element_store(emUsrSettingsType type, uint8_t value)
{
    bool is_succeed = false;
    uint8_t settings[SETTING_SETTS_LEN] = {0};
    uint32_t mask = 0;

    mason_usrsettings_read(settings, &mask);
    switch (type)
    {
    case E_USRSETTINGS_SIGNFP:
    {
        mask = mask | SETTING_USRSETTINGS_SIGNFP;
        settings[type] = value;
    }
    break;
    case E_USRSETTINGS_PHRASEFP:
    {
        mask = mask | SETTING_USRSETTINGS_PHRASEFP;
        settings[type] = value;
    }
    break;
    default:
        return false;
    }

    is_succeed = mason_usrsettings_write(settings, mask);
    return is_succeed;
}
/**
 * @functionname: mason_message_gen
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_message_gen(void)
{
    bool is_succeed = false;

    memset((void *)&global_message, 0, sizeof(global_message));
    global_message.length = SETTING_MESSAGE_LEN;
    is_succeed = mason_generate_entropy(global_message.message, Entropy256Bits, 0);

    return is_succeed;
}
/**
 * @functionname: mason_message_get
 * @description: 
 * @para: 
 * @return: 
 */
setting_message_t *mason_message_get(void)
{
    return (&global_message);
}
/**
 * @functionname: mason_message_delete
 * @description: 
 * @para: 
 * @return: 
 */
void mason_message_delete(void)
{
    memset((void *)&global_message, 0, sizeof(global_message));
}
/**
 * @functionname: mason_token_gen
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_token_gen(void)
{
    bool is_succeed = false;

    memset((void *)&global_token, 0, sizeof(global_token));
    global_token.length = SETTING_TOKEN_LEN;
    is_succeed = mason_generate_entropy(global_token.token, Entropy256Bits, 0);

    return is_succeed;
}
/**
 * @functionname: mason_token_get
 * @description: 
 * @para: 
 * @return: 
 */
setting_token_t *mason_token_get(void)
{
    return (&global_token);
}
/**
 * @functionname: mason_token_verify
 * @description: 
 * @para: 
 * @return: 
 */
emRetType mason_token_verify(setting_token_t *token)
{
    setting_token_t *cur_token = NULL;

    cur_token = mason_token_get();

    if ((SETTING_TOKEN_LEN == token->length) && (token->length == cur_token->length))
    {
        if (!memcmp_ATA(token->token, cur_token->token, token->length))
        {
            return ERT_Verify_Success;
        }
    }
    return ERT_VerifyValueFail;
}
/**
 * @functionname: mason_token_delete
 * @description: 
 * @para: 
 * @return: 
 */
void mason_token_delete(void)
{
    memset((void *)&global_token, 0, sizeof(global_token));
}
/**
 * @functionname: mason_setting_delete
 * @description: 
 * @para: 
 * @return: 
 */
void mason_setting_delete(void)
{
    mason_usrpwd_delete();
    mason_usrfing_delete();
    mason_message_delete();
    mason_token_delete();
    mason_usrcount_reset();
    mason_usrsettings_delete();
}
