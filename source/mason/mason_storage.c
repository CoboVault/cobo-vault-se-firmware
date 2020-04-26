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
#define MASON_STORAGE_GLOBAL

/** Header file reference */
#include "mason_storage.h"
#include "eflash.h"
#include "stdio.h"

/** Function implementations */
/**
 * @functionname: mason_storage_encryption
 * @description: 
 * @para: 
 * @return: 
 */
MASON_STORAGE_EXT emRetType mason_storage_encryption(uint8_t nType, uint8_t *pIn, uint16_t len, uint8_t *pOut)
{
	uint8_t bufTransKey[24] = {0};
	uint8_t bufTransIV[8] = {0};

	des_set_key_u8(DES_TRIPLE_KEY, bufTransKey, DES_SWAP_ENABLE);
	if (DES_FAIL == des_crypt_u8(pIn, pOut, len >> 3, nType, DES_MODE_CBC, bufTransIV, DES_NORMAL_MODE))
	{
		return ERT_3DESFail;
	}

	return ERT_OK;
}
/**
 * @functionname: mason_storage_read
 * @description: 
 * @para: 
 * @return: 
 */
MASON_STORAGE_EXT emRetType mason_storage_read(uint8_t *pBuf, uint32_t bufLen, uint32_t addr)
{
	emRetType emRet = ERT_OK;
	uint32_t addrTmp = addr;
	uint32_t i = 0;
	
	for (i=0; i<bufLen; i++,addrTmp++)
	{
		pBuf[i] = eflash_read_byte(addrTmp);
	}
		
	return emRet;
}
/**
 * @functionname: mason_storage_read_flag
 * @description: 
 * @para: 
 * @return: 
 */
MASON_STORAGE_EXT uint32_t
mason_storage_read_flag(uint32_t addr)
{
	return eflash_read_word(addr);
}
/**
 * @functionname: mason_storage_write_flag
 * @description: 
 * @para: 
 * @return: 
 */
MASON_STORAGE_EXT emRetType
mason_storage_write_flag(uint32_t addr, uint32_t u32Flag)
{
	eflash_rewrite_word(addr, u32Flag);

	return ERT_OK;
}
/**
 * @functionname: mason_storage_write_flag_safe
 * @description: 
 * @para: 
 * @return: 
 */
MASON_STORAGE_EXT emRetType
mason_storage_write_flag_safe(uint32_t addr, uint32_t u32Flag)
{
	eflash_rewrite_word(addr, u32Flag);

    if (u32Flag != eflash_read_word(addr))
    {
        return ERT_StorageFail;
    }

	return ERT_OK;
}
/**
 * @functionname: mason_storage_check_flag
 * @description: 
 * @para: 
 * @return: 
 */
MASON_STORAGE_EXT bool
mason_storage_check_flag(uint32_t addr, uint32_t u32Flag)
{
	return (u32Flag == eflash_read_word(addr));
}
/**
 * @functionname: mason_storage_write_buffer_in_one_page
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_storage_write_buffer_in_one_page(uint8_t *buffer, uint32_t len, uint32_t addr)
{
	uint8_t page_buffer[PAGE_SIZE];
	uint32_t page_addr = addr - addr % PAGE_SIZE;
	uint32_t addr_offset = addr % PAGE_SIZE;
	uint32_t i = 0;

	if (len == 0)
	{
		return true;
	}

	if (addr_offset + len >= PAGE_SIZE)
	{
		return false;
	}

	eflash_read_page((uint32_t *)page_buffer, page_addr);
	for (i = 0; i < len; i++)
	{
		page_buffer[addr_offset + i] = buffer[i];
	}
	eflash_erase_page(page_addr);
	eflash_write_page((uint32_t *)page_buffer, page_addr);

	return true;
}
/**
 * @functionname: mason_storage_write_buffer
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_storage_write_buffer(uint8_t *buffer, uint32_t len, uint32_t addr)
{
	return mason_storage_write_buffer_in_one_page(buffer, len, addr);
}
