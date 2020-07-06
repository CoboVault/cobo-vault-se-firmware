#include "ecc.h"
#include "rsa_keygen.h"
#include "common.h"

#ifndef _ECDSA_H
#define _ECDSA_H

//Signature and Verification
/******************************************************************************
* Function Name  : ECDSA_keypair
* Description    : generate ECC private and public key
	               Step 1. Generate PrivateKey - k
	               Step 2. Caculate PublicKey  - kG
Note: the length of PrivateKey , PublicKeyX , PrivateKeyY should be no less than CurveLength
* Input          : - *p_ecc_para        : the struct of ecc curve parameter point

* Output         : - PrivateKey[]       : used to store the generated private key(little endian)
								 : - PublicKeyX[]       : used to store the x coordination of generated public key(little endian)
								 : - PublicKeyY[]       : used to store the y coordination of generated public key(little endian)
* Return         : 0:success; 1:fail
******************************************************************************/
UINT8 ECDSA_keypair(ECC_G_STR *p_ecc_para, UINT32 PrivateKey[], UINT32 PublicKeyX[], UINT32 PublicKeyY[]);

/******************************************************************************
* Function Name  : ECDSA_sign
* Description    : generate the ECC signature
	               hashdata is hash value of given message
	               Step 1. Generate random k (k<P)
	               Step 2. Signature0 = kG.x mod P
	               Step 3. Signature1 = k^-1 * (hashdata + PrivateKey * Signature0) mod P
Note: the length of input and output parameters should be no less than CurveLength
* Input          : - *p_ecc_para        : the struct of ecc curve parameter point
								 : - *p_math_str        : the struct of global variable of math.c
								 : - *hashdata          : start address of hashdata(little endian)
								 : - *PrivateKey        : start address of PrivateKey(little endian)

* Output         : - *Signature0        : start address of signature r(little endian)
								 : - *Signature1        : store address of signature s(little endian)
* Return         : 0:successful 1:failure
******************************************************************************/
UINT8 ECDSA_sign(ECC_G_STR *p_ecc_para, MATH_G_STR *p_math_str, UINT32 *hashdata, UINT32 *PrivateKey, UINT32 *Signature0, UINT32 *Signature1);

/******************************************************************************
* Function Name  : ECDSA_verify
* Description    : verify the ECC signature
	               hashdata is hash value of message to be verified
			   	   Step 1. Check signature's range
			       Step 2. u1 = Signature1^-1 * hashdata mod P
			       Step 3. u2 = Signature1^-1 * Signature0 mod P
			       Step 4. P1 = u1*G, P2 = u2 * (PublicKeyX,PublicKeyY)
			       Step 5. P = P1 + P2 , if P is infinite point , return 0
			       Step 6. if P.x mod P = Signature0 ,return 1
Note: the length of input and output parameters should be no less than CurveLength
* Input          : - *p_ecc_para        : the struct of ecc curve parameter point
								 : - *p_math_str        : the struct of global variable of math.c
								 : - *hashdata          : start address of hashdata(little endian)
								 : - *PublicKeyX        : start address of PublicKeyX(little endian)
								 : - *PublicKeyY        : start address of PublicKeyY(little endian)
								 : - *Signature0        : start address of signature r(little endian)
								 : - *Signature1        : store address of signature s(little endian)

* Output         : NONE
* Return         : 0:successful 1:failure
******************************************************************************/
int ECDSA_verify(ECC_G_STR *p_ecc_para, MATH_G_STR *p_math_str, UINT32 *hashdata, UINT32 *PublicKeyX, UINT32 *PublicKeyY, UINT32 *Signature0, UINT32 *Signature1);
/******************************************************************************
* Function Name  : ECC_Encrypt
* Description    : Encrypt the plain text
Note: the length of input and output parameters should be no less than CurveLength
* Input          : - *p_ecc_para        : the struct of ecc curve parameter point
								 : - *PlaintextX        : the x coordination of plain text(little endian)
				         : - *PlaintextY        : the y coordination of plain text(little endian)
				         : - *PublicKeyX        : the x coordination of public key(little endian)
				         : - *PublicKeyY        : the y coordination of public key(little endian)
* Output         : - *Ciphertext0X      : the x coordination of cipher text0(little endian)
				         : - *Ciphertext0Y      : the y coordination of cipher text0(little endian)
				         : - *Ciphertext1X      : the x coordination of cipher text1(little endian)
				         : - *Ciphertext1Y      : the y coordination of cipher text1(little endian)
* Return         : 0:successful 1:failure
******************************************************************************/
UINT8 ECC_Encrypt(ECC_G_STR *p_ecc_para, UINT32 *PlaintextX, UINT32 *PlaintextY, UINT32 *PublicKeyX, UINT32 *PublicKeyY, UINT32 *Ciphertext0X, UINT32 *Ciphertext0Y, UINT32 *Ciphertext1X, UINT32 *Ciphertext1Y);

/******************************************************************************
* Function Name  : ECC_Decrypt
* Description    :Decrypt the cipher text
Note: the length of input and output parameters should be no less than CurveLength
* Input          : - *p_ecc_para        : the struct of ecc curve parameter point
								 : - *Ciphertext0X      : the x coordination of cipher text0(little endian)
				         : - *Ciphertext0Y      : the y coordination of cipher text0(little endian)
				         : - *Ciphertext1X      : the x coordination of cipher text1(little endian)
				         : - *Ciphertext1Y      : the y coordination of cipher text1(little endian)
								 : - *PrivateKey        : the private key(little endian)
* Output         : - *DeciphertextX     : the x coordination of decipher text(little endian)
				         : - *DeciphertextY     : the y coordination of decipher text(little endian)
* Return         : 0:successful 1:failure
******************************************************************************/
UINT8 ECC_Decrypt(ECC_G_STR *p_ecc_para, UINT32 *Ciphertext0X, UINT32 *Ciphertext0Y, UINT32 *Ciphertext1X, UINT32 *Ciphertext1Y, UINT32 *PrivateKey, UINT32 *DeciphertextX, UINT32 *DeciphertextY);

/******************************************************************************
* Function Name  : Square_of_Y
* Description    : calculate y2=y^2=x^3+ax+b mod p
Note: the length of input and output parameters should be no less than CurveLength
* Input          : - *p_ecc_para        : the struct of ecc curve parameter point
								 : - *x                 : the x coordination(little endian)
* Output         : - *y2                : y2=y^2=x^3+ax+b mod p(little endian)
* Return         : none
******************************************************************************/
void Square_of_Y(ECC_G_STR *p_ecc_para, UINT32 *x, UINT32 *y2);

/******************************************************************************
* Function Name  : TextToECP
* Description    : transform the text M to ECP 
Note: the length of input and output parameters should be no less than CurveLength,,256*M < ECC_P
* Input          : - *p_ecc_para        : the struct of ecc curve parameter point
								 : - *M                 : message to be transformed (big endian)
* Output         : - *PlaintextX        : the x coordination of text(little endian)
				         : - *PlaintextY        : the y coordination of text(little endian)
* Return         : 0:successful 1:failure
******************************************************************************/
UINT8 TextToECP(ECC_G_STR *p_ecc_para, UINT32 *M, UINT32 *PlaintextX, UINT32 *PlaintextY);

/******************************************************************************
* Function Name  : ECPToText
* Description    : transform the ECP to text M  
Note: the length of input and output parameters should be no less than CurveLength
* Input          : - *p_ecc_para        : the struct of ecc curve parameter point
								 : - *PlaintextX        : the x coordination of plain text(little endian)
* Output         : - *M                 : the message(big endian)
* Return         : none
******************************************************************************/
void ECPToText(ECC_G_STR *p_ecc_para, UINT32 *PlaintextX, UINT32 *M);

/******************************************************************************
* Function Name  : ECDSA_sign_v
* Description    : generate the ECC signature
	               hashdata is hash value of given message
	               Step 1. Generate random k (k<P)
	               Step 2. Signature0 = kG.x mod P
	               Step 3. Signature1 = k^-1 * (hashdata + PrivateKey * Signature0) mod P
Note: the length of input and output parameters should be no less than CurveLength
* Input          : - *p_ecc_para        : the struct of ecc curve parameter point
				         : - *p_math_str        : the struct of global variable of math.c
				         : - *hashdata          : start address of hashdata(little endian)
				         : - *PrivateKey        : start address of PrivateKey(little endian)
* Output         : - *Signature0        : start address of signature r(little endian)
				         : - *Signature1        : store address of signature s(little endian)
								 : - *v                 : bit0: 1: RY is odd; 0: RY is even; bit1: 1: r>n; 0: r<n;
* Return         : 0:successful 1:failure
******************************************************************************/
UINT8 ECDSA_sign_v(ECC_G_STR *p_ecc_para, MATH_G_STR *p_math_str, UINT32 *hashdata, UINT32 *PrivateKey, UINT32 *Signature0, UINT32 *Signature1, UINT8 *v);
/******************************************************************************
* Function Name  : ECDSA_PubKeyRecvOpr
* Description    : Public Key Recovery Operation	              
			   	   Step 1. Convert the r to an elliptic curve point R
			       Step 2. Compute a candidate public key,Q = r^(-1) *(sR - eG)	
			       Step 3. use ecdsa verify function to verify that Q is the authentic public key.
Note: the length of input and output parameters should be no less than CurveLength
* Input          : - *p_ecc_para        : the struct of ecc curve parameter point
				         : - *p_math_str        : the struct of global variable of math.c
				         : - *hashdata          : start address of hashdata(little endian)
								 : - *Signature0        : start address of signature r(little endian)
				         : - *Signature1        : store address of signature s(little endian)
								 : - v                  : bit0: 1: RY is odd; 0: RY is even; v <=1		 
* Output         : - *PublicKeyX        : start address of PublicKeyX(little endian)
				         : - *PublicKeyY        : start address of PublicKeyY(little endian)
* Return         : 0:successful 1:failure
******************************************************************************/
UINT32 ECDSA_PubKeyRecvOpr(ECC_G_STR *p_ecc_para, MATH_G_STR *p_math_str, UINT32 *hashdata, UINT32 *Signature0, UINT32 *Signature1, UINT8 v, UINT32 *PublicKeyX, UINT32 *PublicKeyY);
/******************************************************************************
* Function Name  : ECDSA_PubKeyRecvOpr
* Description    : Public Key Recovery Operation	              
			   	   Step 1. Convert the r to an elliptic curve point R
			       Step 2. Compute a candidate public key,Q = r^(-1) *(sR - eG)	
			       Step 3. use ecdsa verify function to verify that Q is the authentic public key.
Note: the length of input and output parameters should be no less than CurveLength
* Input          : - *p_ecc_para        : the struct of ecc curve parameter point
				         : - *p_math_str        : the struct of global variable of math.c
				         : - *hashdata          : start address of hashdata
								 : - *Signature0        : start address of signature r
				         : - *Signature1        : store address of signature s
								 : - v                  : bit0: 1: RY is odd; 0: RY is even; bit1: 1: r>n; 0: r<n;	v<=3		 
* Output         : - *PublicKeyX        : start address of PublicKeyX
				         : - *PublicKeyY        : start address of PublicKeyY
* Return         : 0:successful 1:failure
******************************************************************************/
UINT32 ECDSA_PubKeyRecvOpr_3(ECC_G_STR *p_ecc_para, MATH_G_STR *p_math_str, UINT32 *hashdata, UINT32 *Signature0, UINT32 *Signature1, UINT8 v, UINT32 *PublicKeyX, UINT32 *PublicKeyY);

UINT32 CalLength_B(UINT32 *B, UINT32 curve_len);
void Updatek(ECC_G_STR *p_ecc_para, UINT32 *k);

#endif
