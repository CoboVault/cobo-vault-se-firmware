#ifndef __SM1_H__
#define __SM1_H__

#include "common.h"

#define SM1_ENCRYPTION       1
#define SM1_DECRYPTION       0
#define SM1_INTERPRAR	       0
#define SM1_EXTERPRAR	       1 
#define SM1_ECB_MODE	       0
#define SM1_CBC_MODE	       1 
#define SM1_SWAP_ENABLE      1
#define SM1_SWAP_DISABLE     0

#define SM1_NORMAL_MODE      0x12345678
#define SM1_SECURITY_MODE    0

#define SM1_FAIL   0x0
#define SM1_PASS   0x5aaada6e

/******************************************************************************
Name:		  sm1_set_key
Function:	input sm1 key for encryption and decryption
Input:
          keyin    --    pointer to buffer of key                
          sk       --    SCBII_INTERPRAR, SCBII_EXTERPRAR
          swap_en  --    SCBII_SWAP_ENABLE, SM1_SWAP_DISABLE
					 
Return:		None
*******************************************************************************/
void sm1_set_key(UINT32 *keyin, UINT8 sk,  UINT8 swap_en);

/******************************************************************************
Name:		  sm1_crypt
Function: Function for des encryption and decryption
Input:
          indata	      --   pointer to buffer of input
          outdata	      --	 pointer to buffer of result
          block_len	    --	 block(128bit) length for des cryption
          operation	    --	 SM1_ENCRYPTION,SCBII_DECRYPTION
				  mode          --   SCBII_ECB_MODE, SCBII_CBC_MODE,
				  iv            --   initial vector for CBC mode
          security_mode --   SM1_NORMAL_MODE, SM1_SECURITY_MODE
Return:		SM1_FAIL(0x00) or SM1_PASS(0x5aaada6e)
*******************************************************************************/
UINT32 sm1_crypt(
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
