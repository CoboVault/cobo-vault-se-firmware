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
bool mason_usrpwd_read(uint8_t *passwd , uint16_t *passwd_len)
{
    bool is_succeed = false;
    emRetType emRet = ERT_OK;
    usrpwd_t pwd ={0};
    emRet = mason_storage_read((uint8_t *)&pwd, sizeof(usrpwd_t), FLASH_ADDR_USRPWD);
    if((emRet == ERT_OK) && ( pwd.length > SETTING_PRESUF_LEN ) && (pwd.length <= SETTING_USRPWD_LEN+SETTING_PRESUF_LEN ))
    {
        uint8_t pre[5] = {0};
        uint8_t suf[5] = {0};
        memcpy(pre, &pwd.pwd[0], 4);
        memcpy(suf, &pwd.pwd[pwd.length-4], 4);
        if(!strcmp((char *)pre, SETTING_STORE_PREFIX) && !strcmp((char *)suf, SETTING_STORE_PASS_SUFFIX))
        {
            memcpy(passwd, &pwd.pwd[4], (pwd.length-SETTING_PRESUF_LEN));
            *passwd_len = pwd.length-8;
            is_succeed = true;
        }
	}

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
    if(( 0 == passwd_len ) || (passwd_len > SETTING_USRPWD_LEN ))
    {
        return false;
    }

    pwd.length = passwd_len + SETTING_PRESUF_LEN;
    memcpy(&pwd.pwd[0], SETTING_STORE_PREFIX, 4);
    memcpy(&pwd.pwd[4], passwd, passwd_len);
    memcpy(&pwd.pwd[passwd_len+4], SETTING_STORE_PASS_SUFFIX, 4);

    is_succeed = mason_storage_write_buffer((uint8_t *)&pwd, sizeof(usrpwd_t), FLASH_ADDR_USRPWD);

    return is_succeed;
}
/**
 * @functionname: mason_usrpwd_verify
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_usrpwd_verify(uint8_t *passwd , uint16_t passwd_len)
{
	uint8_t cur_passwd[SETTING_USRPWD_LEN] = {0};
	uint16_t cur_passwd_len = 0;

    uint8_t checksum[SHA256_LEN] = {0};
    uint16_t checksumlen = SHA256_LEN;
    
    if(SHA256_LEN != passwd_len)
    {
        return false;
    }

    if(!mason_usrpwd_read(cur_passwd , &cur_passwd_len))
    { 
        return false;
    }

    if(checksumlen != cur_passwd_len)
    {
        return false;
    }
	
    mason_HDW_gen_sha256sha256(passwd, passwd_len, checksum, checksumlen);

    if(memcmp(checksum, cur_passwd, cur_passwd_len))
    {
       return false;
    }

    return true;
}
/**
 * @functionname: mason_usrpwd_store
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_usrpwd_store(uint8_t *passwd, uint16_t passwd_len)
{
    uint8_t checksum[SHA256_LEN] = {0};
    uint16_t checksumlen = SHA256_LEN;

    if(SHA256_LEN != passwd_len)
    {
        return false;
    }

    mason_HDW_gen_sha256sha256(passwd, passwd_len, checksum, checksumlen);

    if(!mason_usrpwd_write(checksum , checksumlen))
    { 
        return false;
    }

    return true;

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
    memset(pwd.pwd, 0, (SETTING_USRPWD_LEN+SETTING_PRESUF_LEN));

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
    usrcount_t cnt ={0};
    emRet = mason_storage_read((uint8_t *)&cnt, sizeof(usrcount_t), FLASH_ADDR_USRPWD_COUNT);
    if(emRet == ERT_OK)
    {
        uint8_t pre[5] = {0};
        uint8_t suf[5] = {0};
        memcpy(pre, &cnt.count[0], 4);
        memcpy(suf, &cnt.count[8], 4);

        if(!strcmp((char *)pre, SETTING_STORE_PREFIX) && !strcmp((char *)suf, SETTING_STORE_CONT_SUFFIX))
        {
            memcpy((void *)count, &cnt.count[4],4);
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
 * @functionname: mason_usrcount
 * @description: 
 * @para: 
 * @return: 
 */
void mason_usrcount(void)
{
    uint32_t usrpwd_count = 0;
    if(!mason_usrcount_read(&usrpwd_count))
    {
        mason_usrcount_reset();
    }
    usrpwd_count++;
    mason_usrcount_write(&usrpwd_count);

    if(usrpwd_count >= SETTING_COUNT_ERR_MAX)
    {
		mason_set_mode(HDW_STATUS_EMPTY);        
		mason_delete_wallet();
        mason_setting_delete();
    }
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
    usrfing_t fingerprint ={0};
    emRet = mason_storage_read((uint8_t *)&fingerprint, sizeof(usrfing_t), FLASH_ADDR_USRFING);
    if((emRet == ERT_OK) && ( fingerprint.length > SETTING_PRESUF_LEN ) && (fingerprint.length <= SETTING_USRFING_LEN+SETTING_PRESUF_LEN ))
    {
        uint8_t pre[5] = {0};
        uint8_t suf[5] = {0};
        memcpy(pre, &fingerprint.fing[0], 4);
        memcpy(suf, &fingerprint.fing[fingerprint.length-4], 4);
        if(!strcmp((char *)pre, SETTING_STORE_PREFIX) && !strcmp((char *)suf, SETTING_STORE_FING_SUFFIX))
        {
            memcpy(fing, &fingerprint.fing[4], (fingerprint.length-SETTING_PRESUF_LEN));
            *fing_len = fingerprint.length-8;
            is_succeed = true;
        }
	}

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
    if(( 0 == fing_len ) || (fing_len > SETTING_USRFING_LEN ))
    {
        return false;
    }

    fingerprint.length = fing_len + SETTING_PRESUF_LEN;
    memcpy(&fingerprint.fing[0], SETTING_STORE_PREFIX, 4);
    memcpy(&fingerprint.fing[4], fing, fing_len);
    memcpy(&fingerprint.fing[fing_len+4], SETTING_STORE_FING_SUFFIX, 4);

    is_succeed = mason_storage_write_buffer((uint8_t *)&fingerprint, sizeof(usrfing_t), FLASH_ADDR_USRFING);

    return is_succeed;
}
/**
 * @functionname: mason_usrfing_verify
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_usrfing_verify(uint8_t *sign, uint16_t sign_len)
{
	uint8_t cur_fing[SETTING_USRFING_LEN] = {0};
	uint16_t cur_fing_len = 0;
	setting_message_t *message = NULL;
    uint8_t hash_message[SHA256_LEN] = {0};
	
    if(!sign_len)
    {
        return false;
    }

    if(!mason_usrfing_read(cur_fing, &cur_fing_len))
    { 
        return false;
    }

	message = mason_message_get();

    //r1 verify
	sha256_api(message->message,  message->length, hash_message);
    
	if (!ecdsa_verify(CRYPTO_CURVE_SECP256R1, hash_message, cur_fing, sign))
	{   
	    mason_message_delete();
		return false;
	}
	
	mason_message_delete();

    return true;
}
/**
 * @functionname: mason_usrfing_store
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_usrfing_store(uint8_t *fing, uint16_t fing_len)
{

    if(SETTING_USRFING_LEN != fing_len)
    {
        return false;
    }

    if(!mason_usrfing_write(fing , fing_len))
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
    memset(fingerprint.fing, 0, (SETTING_USRFING_LEN+SETTING_PRESUF_LEN));

    is_succeed = mason_storage_write_buffer((uint8_t *)&fingerprint, sizeof(usrfing_t), FLASH_ADDR_USRFING);
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
    is_succeed = mason_generate_entropy( global_message.message ,Entropy256Bits ,0);

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
    is_succeed = mason_generate_entropy( global_token.token ,Entropy256Bits ,0);
	
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
bool mason_token_verify(setting_token_t *token)
{
    bool is_succeed = false;
    setting_token_t *cur_token = NULL;

    cur_token = mason_token_get();

    if((SETTING_TOKEN_LEN == token->length) && (token->length == cur_token->length ))
    {
        if(!memcmp(token->token, cur_token->token, token->length))
        {
            return true;
        }
    }
    return is_succeed;
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
}

