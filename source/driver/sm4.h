
#ifndef __SM4_H__
#define __SM4_H__

#include "common.h"

#define SM4_ENCRYPTION  	 1
#define SM4_DECRYPTION  	 0
#define SM4_ECB_MODE			 0
#define SM4_CBC_MODE			 1 
#define SM4_SWAP_ENABLE    1
#define SM4_SWAP_DISABLE   0

#define SM4_NORMAL_MODE    0x12345678
#define SM4_SECURITY_MODE  0

#define SM4_FAIL   0x0
#define SM4_PASS   0xa59ada68

/****************************************************************************** 
Name:		   sm4_set_key
Function:	 set sm4 key for encryption and decryption
Input:
           keyin	   --    pointer to buffer of key           	
           swap_en   --    SM4_SWAP_ENABLE, SM4_SWAP_DISABLE               
Return:		 None
*******************************************************************************/
void sm4_set_key(UINT32 *keyin, UINT8 swap_en);

/******************************************************************************
Name:		   sm4_crypt
Function:	 Function for des encryption and decryption
Input:
           indata		       --   pointer to buffer of input
           outdata	       --	  pointer to buffer of result
           block_len	     --	  block(128bit) length for des cryption
           operation	     --	  SM4_ENCRYPTION,SM4_DECRYPTION
				   mode            --   SM4_ECB_MODE, SM4_CBC_MODE,
				   iv              --   initial vector for CBC mode
           security_mode   --   SM4_NORMAL_MODE, SM4_SECURITY_MDOE
Return:		 SM4_FAIL(0x00) or SM4_PASS(0xa59ada68)
*******************************************************************************/
UINT32 sm4_crypt(
    UINT32 *indata,
    UINT32 *outdata,
    UINT32 block_len,
    UINT8  operation,
    UINT8  mode,
    UINT32 *iv,
    UINT32 security_mode
);

#endif
/******************************************************************************
 * end of file
*******************************************************************************/
