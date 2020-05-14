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
#define TLV_GLOBAL

/** Header file reference */
#include "TLV.h"
#include "stack.h"

/** Variable definitions */
TLV_EXT stTLVType stTLV[TLV_MAX] = {NULL};
TLV_EXT volatile uint16_t tlvLen = 0;

/** Function implementations */
/**
 * @functionname: tlv_get_tag
 * @description: 
 * @para: 
 * @return: 
 */
uint32_t tlv_get_tag(pstTLVType pstTLV, const char *stream, uint32_t index)
{
    pstTLVType pstTmpTLV = pstTLV;
    uint16_t tmpTag = 0;

    tmpTag = ((uint16_t)stream[index++] << 8) & 0xFF00;
    tmpTag |= ((uint16_t)stream[index++]) & 0x00FF;
    pstTmpTLV->T = tmpTag;

    return index;
}
/**
 * @functionname: tlv_get_len
 * @description: 
 * @para: 
 * @return: 
 */
uint32_t tlv_get_len(pstTLVType pstTLV, const char *stream, uint32_t index)
{
    pstTLVType pstTmpTLV = pstTLV;
    uint16_t tmpLen = 0;

    tmpLen = ((uint16_t)stream[index++] << 8) & 0xFF00;
    tmpLen |= ((uint16_t)stream[index++]) & 0x00FF;
    pstTmpTLV->L = tmpLen;

    return index;
}
/**
 * @functionname: tlv_get_value
 * @description: 
 * @para: 
 * @return: 
 */
uint32_t tlv_get_value(pstTLVType pstTLV, const char *stream, uint32_t index)
{
    pstTLVType pstTmpTLV = pstTLV;

    pstTmpTLV->pV = stream + index;

    return index + pstTmpTLV->L;
}
