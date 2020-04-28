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
#define STONE_DEBUG_GLOBAL

/** Header file reference */
#include "mason_debug.h"

/** Function implementations */
/**
 * @functionname: dump_data
 * @description: 
 * @para: 
 * @return: 
 */
void dump_data(char *pTitle, uint8_t *pBuf, uint32_t bufLen)
{
	uint32_t i = 0;

	printf("[%d]%s", bufLen, pTitle);
	for (i = 0; i < bufLen; i++)
	{
		printf("%02X", pBuf[i]);
	}
	printf("\r\n");
}
/**
 * @functionname: dump_data_printable
 * @description: 
 * @para: 
 * @return: 
 */
void dump_data_printable(char *pTitle, uint8_t *pBuf, uint32_t bufLen)
{
	uint32_t i = 0;

	printf("[%d]%s", bufLen, pTitle);
	for (i = 0; i < bufLen; i++)
	{
		printf("%c", pBuf[i]);
	}
	printf("\r\n");
}
