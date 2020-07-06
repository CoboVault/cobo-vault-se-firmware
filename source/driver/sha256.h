#ifndef __SHA256_H__
#define __SHA256_H__

#include "common.h"

/**********************************************************
*	definitions
**********************************************************/
#define SHA256_ROTR(bits, word) (((word) >> (bits)) | ((word) << (32 - (bits))))
#define SHA256_SHR(bits, word) ((word) >> (bits))
#define SHA256_CH(x, y, z) ((x & y) ^ (~x & z))
#define SHA256_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SHA256_E0(x) (SHA256_ROTR(2, x) ^ SHA256_ROTR(13, x) ^ SHA256_ROTR(22, x))
#define SHA256_E1(x) (SHA256_ROTR(6, x) ^ SHA256_ROTR(11, x) ^ SHA256_ROTR(25, x))
#define SHA256_A0(x) (SHA256_ROTR(7, x) ^ SHA256_ROTR(18, x) ^ SHA256_SHR(3, x))
#define SHA256_A1(x) (SHA256_ROTR(17, x) ^ SHA256_ROTR(19, x) ^ SHA256_SHR(10, x))

/**********************************************************
*	structure
**********************************************************/
//SHA256 context
typedef struct
{
  UINT32 state[8];  //state (ABCD)
  UINT32 count[2];  // number of bits, modulo 2^64 (msb first)
  UINT8 buffer[64]; // input buffer
} SHA256_CTX;

/**********************************************************
*	extern functions
***********************************************************/

/**************************************************************************
* Function Name  : SHA256_init
* Description    : SHA256 initialization. Begins an SHA1 operation, writing a new context.
* Input          : None
* Output         : - *context : the point of sha1 context
* Return         : None
**************************************************************************/
void SHA256_init(SHA256_CTX *context);
#define SHA256_init_rom ((void (*)())(ROM_BASE_ADDR + 0x00002945))

/**************************************************************************
* Function Name  : SHA256_transform
* Description    : transform a block(512bit) of message to digest in SHA1 algorithm
* Input          : - *block   : input a block data to be tranformed;
*				         : - *state   : interim state data before transform
* Output		     : - *state   : interim state data after transform
* Return         : None
**************************************************************************/
void SHA256_transform(UINT32 *state, UINT8 *block);
#define SHA256_transform_rom ((void (*)())(ROM_BASE_ADDR + 0x0000296d))

/**************************************************************************
* Function Name  : SHA256_update
* Description    : SHA256 block update operation. Continues an SHA1 message-digest
*				         : operation, processing another message block, and updating the
*				         : context.
* Input          : - *context : context before transform
*				         : - *input   : input message
*                : - inputlen : the byte length of input message
* Output		     : - *context : context after transform
* Return         : None
**************************************************************************/
void SHA256_update(SHA256_CTX *context, UINT8 *input, UINT32 inputLen);
#define SHA256_update_rom ((void (*)())(ROM_BASE_ADDR + 0x00002a51))

/**************************************************************************
* Function Name  : SHA256_final
* Description    : SHA256 finalization. Ends an SHA256 message-digest operation, writing the
*                : the message digest and zeroizing the context.
* Input          : - *context : context before transform
* Output		     : - *digest  : message digest
* Return         : None
**************************************************************************/
void SHA256_final(UINT8 *digest, SHA256_CTX *context);
#define SHA256_final_rom ((void (*)())(ROM_BASE_ADDR + 0x00002abb))

/**************************************************************************
* Function Name  : SHA256_hash
* Description    : transform message to digest in SHA1 algorithm
* Input          : - *pDataIn : input message to be tranformed;
				         : - DataLen  : the byte length of message;
* Output		     : - *pDigest : output the digest;
* Return         : None
**************************************************************************/
void SHA256_hash(UINT8 *pDataIn, UINT32 DataLen, UINT8 *pDigest);
#define SHA256_hash_rom ((void (*)())(ROM_BASE_ADDR + 0x00002b17))

#endif
