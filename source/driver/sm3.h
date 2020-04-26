#ifndef __SM3_H__
#define __SM3_H__

#include "common.h"

/**********************************************************
*	definitions
**********************************************************/
#define SM3_T1  0x79CC4519										// Rounds  0-15 
#define SM3_T2  0x7A879D8A										// Rounds  16-63 

#define SM3_FF1(x,y,z)      x^y^z								// Rounds  0-15  x,y,z is word length;
#define SM3_FF2(x,y,z)      (x&y)|(x&z)|(y&z)						// Rounds  16-63  x,y,z is word length;

//#define SM3_GG1(x,y,z)    x^y^z									// Rounds  0-15 x,y,z is word length;
#define SM3_GG2(x,y,z)      (x&y)|(~x&z)							// Rounds  16-63 x,y,z is word length;


#define ROTATE_LEFT(n,x)    ( ( ( x ) << n ) | ( ( x ) >> ( 32 - n ) ) )

#define SM3_P0(x)           x^ ROTATE_LEFT(9,x) ^  ROTATE_LEFT(17,x)                        
#define SM3_P1(x)           x^ ROTATE_LEFT(15,x) ^  ROTATE_LEFT(23,x)                        

#define SM3_EXPAND(data,i)  SM3_P1(data[i-16] ^data[i-9] ^ ROTATE_LEFT(15,data[i-3])) ^ ROTATE_LEFT(7,data[i-13]) ^ data[i-6]

#define SM3_SWAP32(a)       ((a<<24)|((a&0x0000ff00)<<8)|((a&0x00ff0000)>>8)|(a>>24))

/**********************************************************
*	structure
**********************************************************/
//SM3 context
typedef struct {
  UINT32 state[8];           //state (ABCDEFGH)
  UINT32 count[2];           // number of bits, modulo 2^64 (msb first) 
  UINT8  buffer[64];         // input buffer
} SM3_CTX;


/**********************************************************
*	extern functions
***********************************************************/
///**************************************************************************
//* Function Name  : sm3_memcpy
//* Description    : copy a array data to other array
//* Input          : - *pSrc : input array data;
//				 : - cnt   : the word length of input data;
//* Output         : - *pDst : input array data;
//* Return         : None
//**************************************************************************/
//void sm3_memcpy(UINT32 *pDst,const UINT32 *pSrc, UINT32 cnt);

/**************************************************************************
* Function Name  : SM3_transform
* Description    : transform a block of message to digest in sm3 algorithm
* Input          : - *pBlock  : input a block data to be tranformed;
* Output		     : - *pDigest : output the tranformed data;
* Return         : None
**************************************************************************/
//void SM3_transform (UINT32 *pBlock,UINT32 *pDigest);

/* Encodes input (UINT32) into output (unsigned char). Assumes len is
  a multiple of 4.
 */
void SM3_encode (UINT8 *output, UINT32 *input, UINT32 len);

/* Decodes input (unsigned char) into output (UINT32). Assumes len is
  a multiple of 4.
 */
void SM3_Decode (UINT32 *output, UINT8 *input, UINT32 len);

/**************************************************************************
* Function Name  : SM3_initial
* Description    : SM3 initialization. Begins an SM3 operation, writing a new context.
* Input          : None
* Output         : - *context : the point of SM3 context
* Return         : None
**************************************************************************/
void SM3_initial (SM3_CTX *context);

/**************************************************************************
* Function Name  : SM3_update
* Description    : SM3 block update operation. Continues an SM3 message-digest
*				         : operation, processing another message block, and updating the
*				         : context.
* Input          : - *context : context before transform
*				         : - *input   : input message
*                : - inputlen : the byte length of input message
* Output		     : - *context : context after transform
* Return         : None
**************************************************************************/
void SM3_update (SM3_CTX *context, UINT8 *input,UINT32 inputLen);

/**************************************************************************
* Function Name  : SHA256_final
* Description    : SHA256 finalization. Ends an SHA256 message-digest operation, writing the
*                : the message digest and zeroizing the context.
* Input          : - *context : context before transform
* Output		     : - *digest  : message digest
* Return         : None
**************************************************************************/
void SM3_final (UINT8 *digest, SM3_CTX *context);

/**************************************************************************
* Function Name  : sm3_hash
* Description    : transform message to digest in SM3 algorithm
* Input          : - *pDataIn : input message to be tranformed;
				         : - DataLen  : the byte length of message;
* Output		     : - *pDigest : output the digest;
* Return         : None
**************************************************************************/
void sm3_hash(UINT8 *pDataIn,UINT32 DataLen,UINT8 *pDigest);


#endif
