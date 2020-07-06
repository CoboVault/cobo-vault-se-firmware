
#ifndef __SHA384_H__
#define __SHA384_H__

#include "common.h"
/**********************************************************
*	structure
**********************************************************/
//SHA1 context
typedef struct
{
  UINT32 state[16];  //state (ABCDEFGH)
  UINT32 count[4];   // number of bits, modulo 2^64 (msb first)
  UINT8 buffer[128]; // input buffer
} SHA384_CTX;

/**********************************************************
*	extern functions
***********************************************************/

/**************************************************************************
* Function Name  : SHA384_init
* Description    : SHA384 initialization. Begins an SHA1 operation, writing a new context.
* Input          : None
* Output         : - *context : the point of sha384 context
* Return         : None
**************************************************************************/
void SHA384_init(SHA384_CTX *context);
/**************************************************************************
* Function Name  : SHA384_transform
* Description    : transform a block(512bit) of message to digest in SHA1 algorithm
* Input          : - *block   : input a block data to be tranformed;
*				 : - *state   : interim state data before transform
* Output		 : - *state   : interim state data after transform
* Return         : None
**************************************************************************/
void SHA384_transform(UINT32 *state, UINT8 *block);
#define SHA384_transform_rom ((void (*)())(ROM_BASE_ADDR + 0x00002ea3))
/**************************************************************************
* Function Name  : SHA384_update
* Description    : SHA384 block update operation. Continues an SHA1 message-digest
*				 : operation, processing another message block, and updating the
*				 : context.
* Input          : - *context : context before transform
*				 : - *input   : input message
*                : - inputlen : the byte length of input message
* Output		 : - *context : context after transform
* Return         : None
**************************************************************************/
void SHA384_update(SHA384_CTX *context, UINT8 *input, UINT32 inputLen);
/**************************************************************************
* Function Name  : SHA384_final
* Description    : SHA384 finalization. Ends an SHA384 message-digest operation, writing the
*                : the message digest and zeroizing the context.
* Input          : - *context : context before transform
* Output		 : - *digest  : message digest
* Return         : None
**************************************************************************/
void SHA384_final(UINT8 *digest, SHA384_CTX *context);
/**************************************************************************
* Function Name  : SHA384_hash
* Description    : transform message to digest in SHA1 algorithm
* Input          : - *pDataIn : input message to be tranformed;
				 : - DataLen  : the byte length of message;
* Output		 : - *pDigest : output the digest;
* Return         : None
**************************************************************************/
void SHA384_hash(UINT8 *pDataIn, UINT32 DataLen, UINT8 *pDigest);
/**************************************************************************
* Function Name  : SHA512_init
* Description    : SHA512 initialization. Begins an SHA1 operation, writing a new context.
* Input          : None
* Output         : - *context : the point of sha1 context
* Return         : None
**************************************************************************/
void SHA512_init(SHA384_CTX *context);
#define SHA512_init_rom ((void (*)())(ROM_BASE_ADDR + 0x00002b7d))
/**************************************************************************
* Function Name  : SHA512_final
* Description    : SHA512 finalization. Ends an SHA512 message-digest operation, writing the
*                : the message digest and zeroizing the context.
* Input          : - *context : context before transform
* Output		 : - *digest  : message digest
* Return         : None
**************************************************************************/
void SHA512_final(UINT8 *digest, SHA384_CTX *context);
/**************************************************************************
* Function Name  : SHA512_hash
* Description    : transform message to digest in SHA1 algorithm
* Input          : - *pDataIn : input message to be tranformed;
				 : - DataLen  : the byte length of message;
* Output		 : - *pDigest : output the digest;
* Return         : None
**************************************************************************/
void SHA512_hash(UINT8 *pDataIn, UINT32 DataLen, UINT8 *pDigest);

#endif
