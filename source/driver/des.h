#ifndef __DES_H__
#define __DES_H__

#include "common.h"
#include "hrng.h"

#define DES_ENCRYPTION          0
#define DES_DECRYPTION          1
#define DES_SINGLE_KEY		      0x01
#define DES_DOUBLE_KEY		      0x02
#define DES_TRIPLE_KEY		      0x03
#define DES_MODE_ECB		        0
#define DES_MODE_CBC		        1
#define DES_SWAP_ENABLE		      1
#define DES_SWAP_DISABLE        0
#define DES_MASK_ENABLE         1
#define DES_MASK_DISABLE        0
#define DES_VDES_ENABLE         1
#define DES_VDES_DISABLE        0

#define DES_NORMAL_MODE         0x12345678
#define DES_SECURITY_MODE       0 

#define DES_FAIL                0x0
#define DES_PASS                0x5a9ada68

#define ALGSRAM_DES             2

/******************************************************************************
Name:	        des_set_key
Function:     input des key, and set swap mode	            
              key_num       --    des cryption key number: DES_SINGLE_KEY, DES_DOUBLE_KEY, DES_TRIPLE_KEY
              keys          --    pointer to buffer of key            
              swap_en       --    swap input and output, DES_SWAP_ENABLE, DES_SWAP_DISABLE             
Return:       none
*******************************************************************************/
void des_set_key(UINT8 key_num, UINT32 *keys, UINT8 swap_en);


void des_set_key_u8(UINT8 key_num, UINT8 *keys, UINT8 swap_en);

/******************************************************************************
Name:		      des_crypt
Function:	    Function for des encryption and decryption
Input:
              indata		   --  pointer to buffer of input
              outdata	     --  pointer to buffer of result
              block_len	   --	 block(64bit) length for des cryption
              operation	   --	 DES_ENCRYPTION,DES_DECRYPTION
			        mode         --   DES_MODE_ECB, DES_MODE_CBC,
			        iv           --   initial vector for CBC mode
              security_mode  --   DES_NORMAL_MODE, DES_SECURITY_MDOE, DES_SECURITY_MODE
Return:		  DES_FAIL(0x00) or DES_PASS(0x5a9ada68)
*******************************************************************************/
UINT32 des_crypt(
    UINT32 *indata,
    UINT32 *outdata,
    UINT32 block_len,
    UINT8  operation,
    UINT8  mode,
    UINT32 *iv,
    UINT32 security_mode
);


UINT32 des_crypt_u8(
    UINT8 *indata,
    UINT8 *outdata,
    UINT32 block_len,
    UINT8  operation,
    UINT8  mode,
    UINT8 *iv,
    UINT32 security_mode
);

#endif
