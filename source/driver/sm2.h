#ifndef __SM2_H__
#define __SM2_H__

#include "common.h"
#include "ecc.h"
#include "sm3.h"
#include "ecdsa.h"

/**********************************************************
*	definitions
**********************************************************/
#define SM2_WL  9

#define SM2_NORMAL    0xF27E4B40 
#define SM2_SECURITY  0x5CF2F7A2 

/**********************************************************
*	structure
**********************************************************/
enum
{
    SM2_SUCCESS = 0, 
    NotInCurve,
    SM2_ZeroALL,
    SM2_DecryFailed,
	SM2_FAIL
};
//SM3 context
typedef struct {
  UINT32 byte_len;       // byte length 
  UINT32  x2[8];         // x2
  UINT32  y2[8];         // y2
  UINT32  ct;            // count
  UINT8   digest[32];    // sm3 digest 
} SM2_CRYPT_CTX;

/**********************************************************
*	extern functions
***********************************************************/
/* Returns nonzero if a is zero. */
int NN8_Zero (UINT8 *a,UINT32 digits);
/**************************************************************************************************
* Function Name  : sm2_swap_array
* Description    : swap array 
				         : ptr[0] <-> ptr[len-1] 
				         : ptr[1] <-> ptr[len-2]
				         : ...
				         : ptr[len-1] <-> ptr[0] 
* Input          : - *ptr       : input array to be swapped;
				         : - len        : the word length of array
* Output		     : - *ptr       : output the swapped array
* Return         : none
**************************************************************************************************/
void sm2_swap_array(UINT32 *ptr, UINT32 len);

/**************************************************************************************************
* Function Name  : sm2_LShift
* Description    : Computes a = b * 2^c (i.e., shifts left c bits), returning carry
* Input          : - *b         : input data to be shifted(big endian);
				         : - *c         : the shifts bit length(shoule less than 32)
				         : - digits     : the word length of b
* Output		     : - *a         : output the shifted data (big endian) 
* Return         : carry
**************************************************************************************************/
UINT32 sm2_LShift (UINT32 *a, UINT32 *b, UINT32 c, UINT32 digits);

/**************************************************************************************************
* Function Name  : sm2_sign
* Description    : generate the sm2 signature in sm2 encrypt algorithm
			           : Note: the length of input and output parameters should be no less than p_ecc_para->ECC_CurveLength
* Input          : - *p_ecc_para: the struct of ecc curve parameter point
				         : - *p_math_str: the struct of global variable of math.c
				         : - *hashdata  : input digest(big endian) to be signatured;
				         : - *PrivateKey: the private key(big endian)
				         : - mode       : SM2_NORMAL:normal mode; SM2_SECURITY: security mode
* Output		     : - *Signature0: output the signatured data r = (e+x0) mod n (big endian) 
				         : - *Signature1: output the signatured data s = (1+dA)^(-1) * (k - r.dA) mod n (big endian)
* Return         : 0:sign success; 1:fail
**************************************************************************************************/
UINT8 sm2_sign(ECC_G_STR *p_ecc_para,MATH_G_STR *p_math_str,UINT8 *hashdata,UINT8 *PrivateKey,UINT8 *Signature0,UINT8 *Signature1,UINT32 mode);

/**************************************************************************************************
* Function Name  : sm2_verify
* Description    : verify the sm2 signature in sm2 verify algorithm
			           : Note: the length of input and output parameters should be no less than p_ecc_para->ECC_CurveLength
* Input          : - *p_ecc_para: the struct of ecc curve parameter point
				         : - *p_math_str: the struct of global variable of math.c
				         : - *hashdata  : input digest(big endian) to be signatured;
				         : - *PublicKey : the public key(big endian)
				         : - *Signature0: the signatured data r = (e+x0) mod n (big endian)
				         : - *Signature1: the signatured data s = (1+dA)^(-1) * (k - r.dA) mod n(big endian)
* Output         : None
* Return         : 0:verify success; 1:fail
**************************************************************************************************/
int sm2_verify(ECC_G_STR *p_ecc_para,MATH_G_STR *p_math_str,UINT8 *hashdata,UINT8 *PublicKey,UINT8 *Signature0,UINT8 *Signature1);

/**************************************************************************************************
* Function Name  : sm2_encrypt_init
* Description    : generate C1 and (x2,y2) in sm2 encrypt algorithm and initail sm3
* Input          : - *p_ecc_para   : ecc struct point
* input 		     : - *sm2_context  : sm2 encrypt struct point output x2,y2(big endian) and set byte_len = 0
* input 		     : - *sm3_context  : sm3 struct point,initail count and state value
* Input          : - *pubkey       : the public key(big endian)
* Output		     : - *C1           : output the encrypted data C1 = kG;(big endian)
* Return         : refer to enum list in sm2.h
**************************************************************************************************/
UINT8 sm2_encrypt_init(ECC_G_STR *p_ecc_para, SM2_CRYPT_CTX* sm2_context, SM3_CTX * sm3_context, UINT8 pubkey[64], UINT8 C1[64]);

/**************************************************************************************************
* Function Name  : sm2_encrypt_process
* Description    : generate C2 in sm2 encrypt algorithm
* Input  		     : - *sm2_context  : sm2 encrypt struct point
* Input  		     : - *sm3_context  : sm3 struct point
* Input          : - *plain        : input plain text(big endian) to be encrypted
* Input          : - byte_len      : the byte length of message
* Output		     : - *C2           : output the encrypted data C2(big endian)
* Return         : refer to enum list in sm2.h
**************************************************************************************************/
UINT8 sm2_encrypt_process(SM2_CRYPT_CTX* sm2_context, SM3_CTX * sm3_context, UINT8 *plain, UINT32 byte_len, UINT8 *C2);

/**************************************************************************************************
* Function Name  : sm2_encrypt_final
* Description    : generate C3 in sm2 encrypt algorithm
* Input  		     : - *sm2_context  : sm2 encrypt struct point
* Input          : - *sm3_context  : sm3 struct point
* Output		     : - *C3           : output the third part of cipher text C3(big endian)
* Return         : refer to enum list in sm2.h
**************************************************************************************************/
UINT8 sm2_encrypt_final(SM2_CRYPT_CTX* sm2_context, SM3_CTX * sm3_context, UINT8 C3[32]);

/**************************************************************************************************
* Function Name  : sm2_encrypt
* Description    : encrypt input plain text (big endian) in sm2 encrypt algorithm
* Input          : - *p_ecc_para   : ecc struct point
* input 		     : - *sm2_context  : sm2 encrypt struct point output x2,y2(big endian) and set byte_len = 0
* input 		     : - *sm3_context  : sm3 struct point,initail count and state value
* Input          : - *plain        : input plain text(big endian) to be encrypted
* Input          : - byte_len      : the byte length of message
* Input          : - *pubkey       : the public key(big endian)
* Output		     : - *C1           : output the encrypted data C1 = kG;(big endian)
* Output		     : - *C2           : output the encrypted data C2(big endian)
* Output		     : - *C3           : output the third part of cipher text C3(big endian)
* Return         : refer to enum list in sm2.h
**************************************************************************************************/
UINT8 sm2_encrypt(ECC_G_STR *p_ecc_para, SM2_CRYPT_CTX* sm2_context, SM3_CTX * sm3_context, UINT8 *plain, UINT32 byte_len, UINT8 pubkey[64], UINT8 C1[64], UINT8 *C2, UINT8 C3[32]);

/**************************************************************************************************
* Function Name  : sm2_decrypt_init
* Description    : check C1 and generate(x2,y2) in sm2 encrypt algorithm and initail sm3
* Input          : - *p_ecc_para   : ecc struct point
* input 		     : - *sm2_context  : sm2 encrypt struct point output x2,y2(big endian) and set byte_len = 0
* input 		     : - *sm3_context  : sm3 struct point,initail count and state value
* Input          : - *prikey       : the private key(big endian)
* Input  		     : - *C1           : input the encrypted data C1 = kG;(big endian)
* Input          : - mode          : SM2_NORMAL:normal mode; SM2_SECURITY: security mode
* Return         : refer to enum list in sm2.h
**************************************************************************************************/
UINT8 sm2_decrypt_init(ECC_G_STR *p_ecc_para, SM2_CRYPT_CTX* sm2_context, SM3_CTX * sm3_context, UINT8 prikey[32], UINT8 C1[64],UINT32 mode);

/**************************************************************************************************
* Function Name  : sm2_decrypt_process
* Description    : decrypt cipher to plain text in sm2 encrypt algorithm
* Input  		     : - *sm2_context  : sm2 encrypt struct point
* Input  		     : - *sm3_context  : sm3 struct point
* Input          : - *C2           : input the encrypted data C2(big endian)
* Input          : - byte_len      : the byte length of message
* Output		     : - *plain        : output plain text message(big endian)
* Return         : refer to enum list in sm2.h
**************************************************************************************************/
UINT8 sm2_decrypt_process(SM2_CRYPT_CTX* sm2_context, SM3_CTX * sm3_context, UINT8 *C2, UINT32 byte_len, UINT8 *plain);

/**************************************************************************************************
* Function Name  : sm2_decrypt_final
* Description    : generate and compare C3 in sm2 encrypt algorithm
* Input  		     : - *sm2_context  : sm2 encrypt struct point
* Input          : - *sm3_context  : sm3 struct point
* input 		     : - *C3           : input the third part of cipher text C3
* Return         : refer to enum list in sm2.h
**************************************************************************************************/
UINT8 sm2_decrypt_final(SM2_CRYPT_CTX* sm2_context, SM3_CTX * sm3_context, UINT8 C3[32]);

/**************************************************************************************************
* Function Name  : sm2_decrypt
* Description    : decrypt input cipher (big endian) in sm2 encrypt algorithm
* Input          : - *p_ecc_para   : ecc struct point
* input 		     : - *sm2_context  : sm2 encrypt struct point output x2,y2(big endian) and set byte_len = 0
* input 		     : - *sm3_context  : sm3 struct point,initail count and state value
* Input          : - *prikey       : the private key(big endian)
* Output		     : - *C1           : input the encrypted data C1 = kG;(big endian)
* Output		     : - *C2           : input the encrypted data C2(big endian)
* Output		     : - *C3           : input the third part of cipher text C3(big endian)	 
* Input          : - byte_len      : the byte length of message
* Input          : - mode          : SM2_NORMAL:normal mode; SM2_SECURITY: security mode	
* Output         : - *plain        : output decrypted plain text(big endian)
* Return         : refer to enum list in sm2.h
**************************************************************************************************/
UINT8 sm2_decrypt(ECC_G_STR *p_ecc_para, SM2_CRYPT_CTX* sm2_context, SM3_CTX * sm3_context, UINT8 prikey[32], UINT8 C1[64], UINT8 *C2, UINT8 C3[32], UINT32 byte_len, UINT8 *plain,UINT32 mode);

/**************************************************************************************************
* Function Name  : sm2_Exchange_Key
* Description    : exchange key through sm2 exchange key mode
* Input          : - *p_ecc_para  : the struct of ecc curve parameter point
				         : - role         : the role of exchange key; 1: Initiator; 0: responder
				         : - *Prikey      : the private key of yourself(big endian) ;
				         : - *PubkeyB     : the public key of others(big endian) ;
				         : - *Prikey_temp : the temp private key of yourself(big endian); 
				         : - *Pubkey_temp : the temp public key of yourself(big endian);
				         : - *Pubkey_tempB: the temp public key of others(big endian);
				         : - *ZA          : the Z value of yourself(big endian);
				         : - *ZB          : the Z value of other(big endian);
				         : - kLen         : the bit length of Ex_K;
* Output		     : - *Ex_K        : output the exchange key(big endian);
				         : - *S1          : if role==1 then output S1,else output SB(big endian);
				         : - *SA          : if role==1 then output SA,else output S2(big endian);
* Return         : 0:exchange key successs; 1:fail
**************************************************************************************************/
int sm2_Exchange_Key(ECC_G_STR *p_ecc_para,UINT8 role,UINT8 *Prikey,UINT8 *PubkeyB,UINT8 *Prikey_temp,UINT8 *Pubkey_temp,UINT8 *Pubkey_tempB,UINT8 *ZA,UINT8 *ZB,UINT32 klen,UINT8 *Ex_K,UINT8 *S1,UINT8 *SA);


#endif
