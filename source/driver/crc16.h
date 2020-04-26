#ifndef __CRC16_H__
#define __CRC16_H__

#include  "common.h"

/************************************************************************
 * function   : crc16_ccitt
 * Description: CRC-CCITT=X16+X12+X5+1
 * input :
 *         UINT8[] crc_data: crc16 indata
 *         UINT32 len: data length
 *         UINT16 init_data: init data
 * return: UINT16 -- data
 ************************************************************************/
UINT16 crc16_ccitt(UINT8 crc_data[], UINT32 len, UINT16 init_data);

#endif


