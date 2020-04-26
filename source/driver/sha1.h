#ifndef __SHA1_H__
#define __SHA1_H__

#include "common.h"

/**********************************************************
*	definitions
**********************************************************/
#define SHA1CircularShift(bits,word) (((word) << (bits)) | ((word) >> (32-(bits))))

/**********************************************************
*	structure
**********************************************************/
//SHA1 context
typedef struct {
  UINT32 state[5];                                   //state (ABCD)
  UINT32 count[2];        // number of bits, modulo 2^64 (msb first) 
  UINT8  buffer[64];                         // input buffer
} SHA1_CTX;

/**********************************************************
*	extern variable
***********************************************************/
extern const unsigned char PADDING[128];

/**************************************************************************
* Function Name  : SHA1_init
* Description    : SHA1 initialization. Begins an SHA1 operation, writing a new context.
* Input          : None
* Output         : - *context : the point of sha1 context
* Return         : None
**************************************************************************/
void SHA1_init (SHA1_CTX *context);
	
/**************************************************************************
* Function Name  : SHA1_transform
* Description    : transform a block(512bit) of message to digest in SHA1 algorithm
* Input          : - *block   : input a block data to be tranformed;
*				         : - *state   : interim state data before transform
* Output		     : - *state   : interim state data after transform
* Return         : None
**************************************************************************/
void SHA1_transform (UINT32 *state, UINT8 *block);

/**************************************************************************
* Function Name  : SHA1_update
* Description    : SHA1 block update operation. Continues an SHA1 message-digest
*				         : operation, processing another message block, and updating the
*				         : context.
* Input          : - *context : context before transform
*				         : - *input   : input message
*                : - inputlen : the byte length of input message
* Output		     : - *context : context after transform
* Return         : None
**************************************************************************/
void SHA1_update (SHA1_CTX *context,UINT8 *input,UINT32 inputLen);

/**************************************************************************
* Function Name  : SHA1_final
* Description    : SHA1 finalization. Ends an MD5 message-digest operation, writing the
*                : the message digest and zeroizing the context.
* Input          : - *context : context before transform
* Output		     : - *digest  : message digest
* Return         : None
**************************************************************************/
void SHA1_final (UINT8 *digest, SHA1_CTX *context);
	
/**************************************************************************
* Function Name  : SHA1_hash
* Description    : transform message to digest in SHA1 algorithm
* Input          : - *pDataIn : input message to be tranformed;
				         : - DataLen  : the byte length of message;
* Output		     : - *pDigest : output the digest;
* Return         : None
**************************************************************************/
void SHA1_hash(UINT8 *pDataIn,UINT32 DataLen,UINT8 *pDigest);
	
void SHA_encode (UINT8 *output, UINT32 *input, UINT32 len);


#endif
