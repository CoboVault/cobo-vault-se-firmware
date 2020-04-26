#include  "crc16.h"

/************************************************************************
 * function   : crc16_ccitt
 * Description: CRC-CCITT=X16+X12+X5+1
 * input :
 *         UINT8[] crc_data: crc16 indata
 *         UINT32 len: data length
 *         UINT16 init_data: init data
 * return: UINT16 -- data
 ************************************************************************/
UINT16 crc16_ccitt(UINT8 crc_data[], UINT32 len, UINT16 init_data) {
    UINT32 i;
    REG_CRC16_CTRL = 0x00; 
    REG_CRC16_INIT = init_data;
    for (i = 0; i < len; i++) {
        REG_CRC16_DATA = crc_data[i];
    }
    return REG_CRC16_DATA;
}


