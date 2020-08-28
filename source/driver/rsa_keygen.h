#ifndef _RSA_KEGGEN_H
#define _RSA_KEGGEN_H 

/**********************************************************
*	include files
**********************************************************/
#include "common.h"
#include "ecc.h"
#include "hrng.h"
/**********************************************************
*	definitions
**********************************************************/	
//rsa related
/* RSA key lengths. */
#define MIN_RSA_MODULUS_BITS 508
#define MAX_RSA_MODULUS_BITS 4096  //1024 or 2048 or 4096

#define NDIGITS ((MAX_RSA_MODULUS_BITS + NN_DIGIT_BITS - 1)/(NN_DIGIT_BITS))
#define HALF_NDIGITS ((NDIGITS+1)/2)
#define MAX_RSA_MODULUS_LEN ((MAX_RSA_MODULUS_BITS + 7) / 8)
#define MAX_RSA_PRIME_BITS ((MAX_RSA_MODULUS_BITS + 1) / 2)
#define MAX_RSA_PRIME_LEN ((MAX_RSA_PRIME_BITS + 7) / 8)

/* Length of digit in bits */
#define NN_DIGIT_BITS 32
#define NN_HALF_DIGIT_BITS 16
/* Length of digit in bytes */
#define NN_DIGIT_LEN (NN_DIGIT_BITS / 8)
/* Maximum length in digits */
#define MAX_NN_DIGITS ((MAX_RSA_MODULUS_LEN + NN_DIGIT_LEN - 1) / NN_DIGIT_LEN + 1)
/* Maximum digits */
#define MAX_NN_DIGIT 0xffffffff
#define MAX_NN_HALF_DIGIT 0xffff

#define NN_LT   -1
#define NN_EQ   0
#define NN_GT 1

//define Macros
#define LOW_HALF(x) ((x) & MAX_NN_HALF_DIGIT)
#define HIGH_HALF(x) (((x) >> NN_HALF_DIGIT_BITS) & MAX_NN_HALF_DIGIT)
#define TO_HIGH_HALF(x) (((UINT32)(x)) << NN_HALF_DIGIT_BITS)
#define DIGIT_MSB(x) (unsigned int)(((x) >> (NN_DIGIT_BITS - 1)) & 1)
#define DIGIT_2MSB(x) (unsigned int)(((x) >> (NN_DIGIT_BITS - 2)) & 3)
#define NN_ASSIGN_DIGIT(a, b, digits) {NN_AssignZero (a, digits); a[0] = b;}
#define NN_EQUAL(a, b, digits) (! NN_Cmp (a, b, digits))

//#define CNST_RSA_EXP 0x30
//#define CNST_RSA_MUL 0x01	

#define CONT_RSA_PRIORITY_LEVEL	18
#define CONT_RSA_PRIORITY_LEVEL_INTS 0x40000   

//#define NUM_SMALL_PRIMES 300      //1024bits key: 100    2048bits key: 300

#define ECC_SRAM_BUF  (volatile UINT32 *)0x40011000


#define RSA_NORMAL    0x57D525A0 
#define RSA_SECURITY  0x6A5BFF58 

//array assign 

/**********************************************************
*	structure
**********************************************************/
typedef struct {
//for rsa_keygen.c                                   
  UINT32 *rsa_keygen_N1;                                   
  UINT32 *rsa_keygen_N1_ODD;                                   
  UINT32 *rsa_keygen_check;                                   
  UINT32 *rsa_keygen_N3;                                   
  UINT32 *rsa_keygen_R;                               
  UINT32 *rsa_keygen_RESULT;                               
  UINT32 *rsa_keygen_pMinus1;                          
  UINT32 *rsa_keygen_qMinus1;
  UINT32 *rsa_keygen_u;                              
  UINT32 *rsa_keygen_phiN;
  UINT16 *rsa_keygen_rest;
  UINT32 *RSA_n;
  UINT32 *RSA_d;
  UINT32 *RSA_e;
  UINT32 *RSA_p;
  UINT32 *RSA_q;
  UINT32 *RSA_dp;
  UINT32 *RSA_dq;
  UINT32 *RSA_qInv; 
	UINT32 *math_databuf;
//end  
} RSA_KEYGEN_G_STR;   

typedef struct { 
//for rsa.c
  UINT32 *rsa_temp1;
  UINT32 *rsa_m2;
  UINT32 *rsa_h;
  UINT32 *rsa_m1;
  UINT32 *rsa_temp;
  UINT32 *rsa_data_buf;
//end  
} RSA_G_STR;

typedef struct {
//for math.c
  UINT32 *t1;
  UINT32 *t3;
  UINT32 *u1;
  UINT32 *u3;
  UINT32 *v3;
  UINT32 *w;
  UINT32 *Mod_t;
  UINT32 *Gcd_t;
  UINT32 *Div_dd;
  UINT32 *Div_cc;
  UINT32 *Mult_t;
  //UINT32 *math_databuf1;
//end  
} MATH_G_STR;

/**********************************************************
*	extern variables
**********************************************************/

/*
e,d,n  ---main()
p,q    ---RSA_keygen()
N1,N1_ODD,check  ---RabinMiller_test() in GeneratePrime()
N3     ---gen_check() in RabinMiller_test() in GeneratePrime()
R,RESULT  ---witness() in RabinMiller_test() in GeneratePrime()
rest   ---GeneratePrime()
pMinus1,u ---RSAFilter()
Gcd_t  ---NN_Gcd() in RSAFilter()
pMinus1,qMinus1,phiN  ---Generate_d()
t1,v1,t3,u1,u3,v3,w  ---NN_ModInv() in Generate_d()
Mod_t  ---NN_Mod() in NN_Gcd and in NN_ModInv and other func
Mult_t ---NN_Mult()
Div_dd ---NN_Div() in NN_Mod() and in NN_ModInv
Div_cc ---NN_Div() in NN_Mod() and in NN_ModInv

*/

//valiable assign
// valiable in RSA_keygen_CRT() of rsa_keygen.c 
/*
UINT32 *N1 = RSA_dp;
UINT32 *N1_ODD = RSA_dq;
UINT32 *check = RSA_qInv;
UINT32 *N3 = RSA_n;
UINT32 *R = RSA_n;
UINT32 *RESULT = RSA_n+HALF_NDIGITS;
//can be change
UINT32 *pMinus1 = RSA_n;
UINT32 *qMinus1 = RSA_n+HALF_NDIGITS;
UINT32 *u = RSA_dp;
UINT32 *phiN = RSA_dq;

UINT16 *rest= (UINT16 *)(MATH_DATABUF1+MAX_NN_DIGITS);
*/
// valiable in math.c 
/*
UINT32 *t1 = MATH_DATABUF1;
UINT32 *t3 = MATH_DATABUF1+1*MAX_NN_DIGITS;
UINT32 *u1 = MATH_DATABUF1+2*MAX_NN_DIGITS;
UINT32 *u3 = MATH_DATABUF1+3*MAX_NN_DIGITS;
UINT32 *v3 = MATH_DATABUF1+4*MAX_NN_DIGITS;
UINT32 *w = MATH_DATABUF1+5*MAX_NN_DIGITS;

UINT32 *Mod_t = MATH_DATABUF1;
UINT32 *Gcd_t = MATH_DATABUF1+2*MAX_NN_DIGITS;

UINT32 *Div_dd = MATH_DATABUF2+2*MAX_NN_DIGITS+1;
UINT32 *Div_cc = MATH_DATABUF2;
UINT32 *Mult_t = MATH_DATABUF2;
*/
// valiable in rsa_decrypt_CRT() of rsa.c
/*
UINT32 *temp1 = MATH_DATABUF1 + 1*MAX_NN_DIGITS;
UINT32 *m2    = MATH_DATABUF1 + 2*MAX_NN_DIGITS;
UINT32 *h     = MATH_DATABUF1 + 3*MAX_NN_DIGITS;
UINT32 *m1    = MATH_DATABUF1 + 3*MAX_NN_DIGITS + HALF_NDIGITS;
UINT32 *temp  = MATH_DATABUF1 + 4*MAX_NN_DIGITS + 1;
*/

/**********************************************************
*	extern functions
**********************************************************/
//define rsa functions
/******************************************************************************
* Function Name  : rsa_variable_initial
* Description    : initial global variable in rsa.c
///////////////////////////////////////////////////////////////////////////
//		temp1 = (MATH_DATABUF1);                                         //
//		m2    = (MATH_DATABUF1 + 1*(max_nn_digits));                     //
//		h     = (MATH_DATABUF1 + 2*(max_nn_digits));                     //
//		m1    = (MATH_DATABUF1 + 2*(max_nn_digits));                     //
//		temp  = (MATH_DATABUF1 + 2*(max_nn_digits) + (half_ndigits) + 1);//
///////////////////////////////////////////////////////////////////////////
* Input          : - *p_rsa_str         : the struct point of RSA_G_STR
				         : - max_nn_digits      : Maximum word length of modulus n
				         : - half_ndigits       : half word length of modulus n
* Output         : NONE
* Return         : NONE
******************************************************************************/
void rsa_variable_initial(RSA_G_STR *p_rsa_str,UINT32 max_nn_digits, UINT32 half_ndigits);

/******************************************************************************
* Function Name  : AsubB
* Description    : c=a-b;(condition : a>b)
* Input          : - length        : word length of data
				 : - *a              : start address of a
				 : - *b              : start address of b

* Output         : - *c              : start address of c
* Return         : NONE
******************************************************************************/
void AsubB(UINT32 length,UINT32 data_A[], UINT32 data_B[],UINT32 result[]);

/******************************************************************************
* Function Name  : rsa_precal
* Description    : precalculate
* Input          : - N[]        : start address of modnumber n
				 : - length     : word length of n

* Output         : NONE
* Return         : NONE
******************************************************************************/
void rsa_precal(UINT32 N[],UINT32 length);

/******************************************************************************
* Function Name  : rsa_read2r
* Description    : read rsa precalculate result
* Input          : None
* Output         : - R[]     : start address of R,the word length of R must be %2=0; 
* Return         : NONE
******************************************************************************/
void rsa_read2r(UINT32 R[]);

/******************************************************************************
* Function Name  : rsa_enhance_mm_me
* Description    : calculate a^b mod n or a*b mod n
* Input          : - a[]        : start address of a
				 : - b[]        : start address of b
				 : - r[]        : start address of r(it is the result of rsa_read2r())
				 : - length     : max word length of data in A and B
				 : - mode       : select calculate mode:2 :modular multiple ; 3: modular exponent

* Output         : NONE
* Return         : NONE
******************************************************************************/
void rsa_enhance_mm_me(UINT32 a[],UINT32 b[],UINT32 r[],UINT32 length,UINT8 mode);

/******************************************************************************
* Function Name  : check_result
* Description    : if Res> N, then Res = Res - N
* Input          : - *Res       : start address of result data
				 : - N[]        : start address of N
				 : - length     : word length of data Res

* Output         : NONE
* Return         : NONE
******************************************************************************/
void check_result(UINT32 *Res,UINT32 RSA_N[],UINT32 length);

/******************************************************************************
* Function Name  : rsa_read_result
* Description    : read rsa modmul or modexp calculate result
* Input          : NONE
* Output         : - R[]       : start address of result data,the word length of R must be %2=0; 
* Return         : NONE
******************************************************************************/
void rsa_read_result(UINT32 []);

/******************************************************************************
* Function Name  : rsa_mul_me
* Description    : rsa modexp calculate:out_data=(a_data*b_data) mod n_data or (a_data^b_data) mod n_data
* Input          : - *a_data       : start address of a_data
				 : - a_length      : word length of a_data
				 : - *b_data       : start address of b_data
				 : - b_length      : word length of b_data
				 : - *n_data       : start address of a_data
				 : - n_length      : word length of a_data
				 : - mode          : select calculate mode:0x01 :modular multiple ; 0x30: modular exponent
* Output         : - *out_data     : start address of out_data,the word length of out_data must be %2=0; 
				 : - *out_length   : word length of out_data,the length is even
* Return         : 0:success;1:fail
******************************************************************************/
UINT8 rsa_mul_me(       //calculate out_data=(a_data*b_data) mod n_data or out_data=(a_data^b_data) mod n_data
	UINT32 *a_data, 	// input a_data
	UINT8 a_length,		// length of a, in words
	UINT32 *b_data,		// input b_data
	UINT8 b_length,		// length of b, in words 
	UINT32 *n_data,		// input n_data
	UINT8 n_length,		// length of n, in words  
	UINT32 *out_data,	// result for RSA modular mul or exp operation
	UINT8 *out_length,	// length of output, in words 
	UINT8 mode          // 1: modular multiply ;0x30: modular me
	);

/******************************************************************************
* Function Name  : rsa_decrypt_CRT
* Description    : rsa decrypt using CRT out_data = decrypt(in_data) using CRT
				   Assumes p_length and q_length is half of n(mod number) length
				   Assumes n_length is 8/16/32/64
* Input          : - *in_data       : start address of in_data
				 : - in_length      : word length of in_data
				 : - *p_data        : start address of p_data
				 : - p_length       : word length of p_data
				 : - *q_data        : start address of q_data
				 : - q_length       : word length of q_data
				 : - *dp_data       : start address of dp_data
				 : - dp_length      : word length of dp_data
				 : - *dq_data       : start address of dq_data
				 : - dq_length      : word length of dq_data
				 : - *qInv_data     : start address of qInv_data
				 : - qInv_length    : word length of qInv_data
				 : - *p_rsa_str     : the struct point of RSA_G_STR

* Output         : - *out_data      : start address of out_data
				 : - *out_length    : word length of out_data
* Return         : 0:success;1:fail
******************************************************************************/
UINT8 rsa_decrypt_CRT_nor( //calculate out_data = decrypt(in_data) using CRT
	UINT32 *in_data,      // input number   
	UINT8 in_length,     // length of input, in words
	UINT32 *p_data,      //prime factor p
	UINT8  p_length,     //length of p, in words
	UINT32 *q_data,      //prime factor q
	UINT8 q_length,      //length of q, in words
	UINT32 *dp_data,      //prime exponent dp
	UINT8 dp_length,     //length of dp, in words
	UINT32 *dq_data,      //prime exponent dq
	UINT8 dq_length,     //length of dq, in words
	UINT32 *qInv_data,    //coefficient qInv
	UINT8 qInv_length,   //length of qInv, in words
	UINT32 *out_data,   //result
	UINT8*out_length,    //length of output, in words
	RSA_G_STR *p_rsa_str,
	MATH_G_STR *p_math_str
	);

/******************************************************************************
* Function Name  : rsa_decrypt_CRT
* Description    : rsa decrypt using CRT out_data = decrypt(in_data) using CRT (normal or security mode)
				   Assumes p_length and q_length is half of n(mod number) length
				   Assumes n_length is 8/16/32/64
* Input          : - *in_data       : start address of in_data
				 : - in_length      : word length of in_data
				 : - *p_data        : start address of p_data
				 : - p_length       : word length of p_data
				 : - *q_data        : start address of q_data
				 : - q_length       : word length of q_data
				 : - *dp_data       : start address of dp_data
				 : - dp_length      : word length of dp_data
				 : - *dq_data       : start address of dq_data
				 : - dq_length      : word length of dq_data
				 : - *qInv_data     : start address of qInv_data
				 : - qInv_length    : word length of qInv_data
				 : - *p_rsa_str     : the struct point of RSA_G_STR
				 : - *p_math_str    : the struct point of MATH_G_STR
				 : - *e_data        : start address of e_data
				 : - e_length       : word length of e_data
				 : - mode           : RSA_SECURITY: security mode, RSA_NORMAL:normal mode

* Output         : - *out_data     : start address of out_data
				 : - *out_length   : word length of out_data
* Return         : 0:success;1:fail
******************************************************************************/
UINT8 rsa_decrypt_CRT( //calculate out_data = decrypt(in_data) using CRT	
	UINT32 *in_data,      // input number   
	UINT8 in_length,     // length of input, in words
	UINT32 *p_data,      //prime factor p
	UINT8  p_length,     //length of p, in words
	UINT32 *q_data,      //prime factor q
	UINT8 q_length,      //length of q, in words
	UINT32 *dp_data,      //prime exponent dp
	UINT8 dp_length,     //length of dp, in words
	UINT32 *dq_data,      //prime exponent dq
	UINT8 dq_length,     //length of dq, in words
	UINT32* qInv_data,    //coefficient qInv
	UINT8 qInv_length,   //length of qInv, in words
	UINT32 *out_data,   //result
	UINT8 *out_length,    //length of output, in words
	RSA_G_STR *p_rsa_str,
	MATH_G_STR *p_math_str,
	UINT32 *e_data, 	// input e_data
	UINT8 e_length,	// length of e, in words   if e_length == 0, then don't use and e_data
	UINT32 mode // RSA_SECURITY: security mode, RSA_NORMAL:normal mode	
	);

/******************************************************************************
* Function Name  : gen_check
* Description    : generate random check between 2 and n-2,return 1 when succeeding
* Input          : - *p_rsa_keygen_str : the struct point of RSA_KEYGEN_G_STR
                 : - *p_math_str       : the struct point of MATH_G_STR
                 : - *check         : start address of random number to be generated
				 : - *n             : candidate of primality tests
				 : - nDigits        : word length of n

* Output         : NONE
* Return         : 1:if probably prime; 0: if the candidate n is composite;
******************************************************************************/
void gen_random_check(UINT32 *random, UINT8 digits);

//rsa key generation
/******************************************************************************
* Function Name  : rsa_keygen_variable_initial
* Description    : initial global variable in rsa_keygen.c
//////////////////////////////////////////////////////////////
//		N1 = RSA_dp;                                        //
//		N1_ODD = RSA_dq;                                    //
//		check = RSA_qInv;                                   //
//		N3 = RSA_n;                                         //
//		R = RSA_n;                                          //
//		RESULT = (RSA_n+half_ndigits);                      //
//		pMinus1 = RSA_n;                                    //
//		qMinus1 = (RSA_n+half_ndigits);                     //
//		u = RSA_dp;                                         //
//  	phiN = RSA_dq;	                                    //
//		rest= (UINT16 *)(MATH_DATABUF1);                    //
//////////////////////////////////////////////////////////////
* Input          : - *p_rsa_keygen_str : the struct point of RSA_KEYGEN_G_STR
                 : - *p_math_str       : the struct point of MATH_G_STR
								 : - max_nn_digits     : Maximum word length of modulus n
								 : - half_ndigits      : half word length of modulus n

* Output         : NONE
* Return         : NONE
******************************************************************************/
void rsa_keygen_variable_initial(RSA_KEYGEN_G_STR *p_rsa_keygen_str,MATH_G_STR *p_math_str,UINT32 max_nn_digits,UINT32 half_ndigits);

/******************************************************************************
* Function Name  : RSAFilter
* Description    : validate GCD(p-1,e) = 1,if yes return 1,else 0;
* Input          : - *p_rsa_keygen_str : the struct point of RSA_KEYGEN_G_STR
                 : - *p_math_str       : the struct point of MATH_G_STR
				 : - *p                : start address of prime number to be validated
				 : - pDigits           : word length of prime number
				 : - *e                : start address of e

* Output         : NONE
* Return         : 1:if GCD (p-1,e) = 1; else return 0
******************************************************************************/
UINT8 RSAFilter(RSA_KEYGEN_G_STR *p_rsa_keygen_str,MATH_G_STR *p_math_str,UINT32 *p, UINT8 pDigits, UINT32 *e);

/******************************************************************************
* Function Name  : small_prime_test
* Description    : test a using small prime test method
* Input          : - *p_math_str       : the struct point of MATH_G_STR
				         : - *a                : start address of prime number to be tested
				         : - aDigits           : word length of odd number
				         : - *rest             : start address of rest,record the result of trial division,  to speed up the small_prime_test
								 : - first_time        : flag, 1 effective. when it is the first time of small prime test, initiate rest[NUM_SMALL_PRIMES]
								 : - num_small_primes  : the number of small prime number used in small prime test
* Output         : NONE
* Return         : 1:if probably prime; 0: if the candidate n is composite;
******************************************************************************/
UINT8 small_prime_test(MATH_G_STR *p_math_str,UINT32 *a, UINT8 aDigits,UINT16 *rest,UINT8 first_time, UINT32 num_small_primes);

/******************************************************************************
* Function Name  : RabinMiller_test
* Description    : test n using Miller Rabin method, execute checks times
				 : (the probability of error is less than 2^(-80))
* Input          : - *p_rsa_keygen_str : the struct point of RSA_KEYGEN_G_STR
                 : - *p_math_str       : the struct point of MATH_G_STR
								 : - *n             : start address of prime number to be tested
				         : - nDigits        : word length of odd number
				         : - checks         : the times of MillerRabin test needed to do according to the bitlength of the candidate prime number
* Output         : NONE
* Return         : 1:if probably prime; 0: if the candidate n is composite;
******************************************************************************/
UINT8 RabinMiller_test(RSA_KEYGEN_G_STR *p_rsa_keygen_str,MATH_G_STR *p_math_str,UINT32 *n,UINT8 nDigits,UINT8 checks);

/******************************************************************************
* Function Name  : gen_check
* Description    : generate random check between 2 and n-2,return 1 when succeeding
* Input          : - *p_rsa_keygen_str : the struct point of RSA_KEYGEN_G_STR
                 : - *p_math_str       : the struct point of MATH_G_STR
                 : - *check         : start address of random number to be generated
				 : - *n             : candidate of primality tests
				 : - nDigits        : word length of n

* Output         : NONE
* Return         : 1:if probably prime; 0: if the candidate n is composite;
******************************************************************************/
UINT8 gen_check(RSA_KEYGEN_G_STR *p_rsa_keygen_str,MATH_G_STR *p_math_str,UINT32 *check, UINT32 *n, UINT8 nDigits);

/******************************************************************************
* Function Name  : witness
* Description    : validate n if prime or composite, Return 0 if n is probably prime, 1 if composite
* Input          : - *p_math_str       : the struct point of MATH_G_STR
                 : - *check            : start address of witness, used by Miller Rabin test
				 : - *n                : candidate
				 : - nDigits           : word length of n
				 : - *N1               : N1 = n-1
				 : - *N1_ODD           : N1=N1_ODD*2^j
				 : - j                 : N1=N1_ODD*2^j

* Output         : - *r        : start address of r which is generate in function(r^2 mod n)
 				 : - *result   : start address of result used to restore interim data
* Return         : 1:if n is composite; 0: if n is probably prime;
******************************************************************************/
UINT8 witness(MATH_G_STR *p_math_str,UINT32 *r,UINT32 *result,UINT32 *check,UINT32 *n,UINT8 nDigits,UINT32 *N1,UINT32 *N1_ODD,UINT32 j);

/******************************************************************************
* Function Name  : GeneratePrime
* Description    : Return 1 if prime generation succeed.
				   First do trial division using small primes,
				   then do Miller Rabin test.If failed, add 2 to the candidate until
		           passing the tests above.
* Input          : - *p_rsa_keygen_str : the struct point of RSA_KEYGEN_G_STR
                 : - *p_math_str       : the struct point of MATH_G_STR
				 : - aDigits           : word length of a
                 : - checks            : the times of MillerRabin test needed to do according to the bitlength of the candidate prime number
				 : - num_small_primes  : the number of small prime number used in small prime test

* Output         : - *a        : start address of a to be generated prime number
* Return         :  Return 1 if prime generation succeed, else return 0
******************************************************************************/
UINT8 GeneratePrime(RSA_KEYGEN_G_STR *p_rsa_keygen_str,MATH_G_STR *p_math_str,UINT32 *a,UINT8 aDigits,UINT8 checks, UINT32 num_small_primes);

/******************************************************************************
* Function Name  : RSA_keygen_CRT
* Description    : the top function of generate CRT struct key to be used in RSA CRT encrypt or decrypt
				   Return 1 if key generation is successful.
				   1. e=3,5,17,257,or 65537. 65537 is recommended, 4<=nDigits<=64 and (nDigits%2==0)
			       2. generate prime p, gcd((p-1),e)=1
			       3. generate prime q, gcd((p-1),e)=1
				   4. n=pq
				   5. qInv = q^{-1} mod p
				   6. phiN=(p-1)(q-1)
				   7. d=e^(-1)mod phiN
				   8. dp = d mod p-1, dq = d mod q-1
* Input          : - *p_rsa_keygen_str : the struct point of RSA_KEYGEN_G_STR, need	input e value
                 : - *p_math_str       : the struct point of MATH_G_STR
                 : - nDigits           : word length of modulus n

* Output         : n,d,p,q,dp,dq,qInv in the struct RSA_KEYGEN_G_STR
* Return         :  Return 0 if key generation is successful, else return 1
******************************************************************************/
UINT8 RSA_keygen_CRT(RSA_KEYGEN_G_STR *p_rsa_keygen_str,MATH_G_STR *p_math_str,UINT8 nDigits);

/******************************************************************************
* Function Name  : RSA_keygen
* Description    : the top function of generate key to be used in rsa encrypt or decrypt
		  		   Return 1 if key generation is successful.
		 		   1. e=3,5,17,257,or 65537. 65537 is recommended, 4<=nDigits<=64 and (nDigits%2==0)
		 		   2. generate prime p, gcd((p-1),e)=1
		  		   3. generate prime q, gcd((p-1),e)=1
		  		   4. n=pq
		  		   5. phiN=(p-1)(q-1)
		  		   6. d=e^(-1)mod phiN
* Input          : - *p_rsa_keygen_str : the struct point of RSA_KEYGEN_G_STR, need	input e value
                 : - *p_math_str       : the struct point of MATH_G_STR
                 : - nDigits           : word length of modulus n

* Output         : n,d in the struct RSA_KEYGEN_G_STR
* Return         :  Return 0 if key generation is successful, else return 1
******************************************************************************/
UINT8 RSA_keygen(RSA_KEYGEN_G_STR *p_rsa_keygen_str,MATH_G_STR *p_math_str,UINT8 nDigits);

/******************************************************************************
* Function Name  : Generate_d
* Description    : generate private key d
		           Return 1 if successful.
		           d = e^{-1} mod (p-1)(q-1)
* Input          : - *p_rsa_keygen_str : the struct point of RSA_KEYGEN_G_STR, need	input e value
                 : - *p_math_str       : the struct point of MATH_G_STR
				 : - *p                : start address of p
                 : - *q                : start address of q
				 : - *e                : start address of e
                 : - pDigits           : word length of p,q
				 : - nDigits           : word length of modulus n

* Output         : - *d           : start address of private key d
* Return         :  Return 1 if successful, else return 0
******************************************************************************/
UINT8 Generate_d(RSA_KEYGEN_G_STR *p_rsa_keygen_str,MATH_G_STR *p_math_str,UINT32 *p,UINT32 *q,UINT32 *e,UINT32 *d,UINT32 pDigits,UINT32 nDigits);

void gen_random_odd(UINT32 *random, UINT8 digits);

// math function
/******************************************************************************
* Function Name  : NN_ModInv_variable_initial
* Description    : initial global variable of NN_ModInv function in math.c
* Input          : - *p_math_str        : the struct point of MATH_G_STR
				         : - max_nn_digits      : Maximum word length of modulus n
* Output         : NONE
* Return         : NONE
******************************************************************************/
void NN_ModInv_variable_initial(MATH_G_STR *p_math_str,UINT32 *databuf,UINT32 max_nn_digits);
#define NN_ModInv_variable_initial_v2               ( (void(*)())(ROM_BASE_ADDR+0x00003291))
//#define NN_ModInv_variable_initial_v1               ( (void(*)())(ROM_BASE_ADDR+0x000030d9))
/******************************************************************************
* Function Name  : NNModMult_variable_initial
* Description    : initial global variable of NN_Mod and NN_Mult function in math.c
* Input          : - *p_math_str        : the struct point of MATH_G_STR
				 : - max_nn_digits      : Maximum word length of modulus n

* Output         : NONE
* Return         : NONE
******************************************************************************/
void NNModMult_variable_initial(MATH_G_STR *p_math_str,UINT32 max_nn_digits);
#define NNModMult_variable_initial_v2               ( (void(*)())(ROM_BASE_ADDR+0x000032d1))
//#define NNModMult_variable_initial_v1               ( (void(*)())(ROM_BASE_ADDR+0x00003119))
/******************************************************************************
* Function Name  : NN_Gcd_variable_initial
* Description    : initial global variable of NN_Gcd function in math.c
* Input          : - *p_math_str        : the struct point of MATH_G_STR
				 : - digits             : word length of modulus n

* Output         : NONE
* Return         : NONE
******************************************************************************/
void NN_Gcd_variable_initial(MATH_G_STR *p_math_str,UINT32 digits);
#define NN_Gcd_variable_initial_v2               ( (void(*)())(ROM_BASE_ADDR+0x000032eb))
//#define NN_Gcd_variable_initial_v1               ( (void(*)())(ROM_BASE_ADDR+0x00003133))

/******************************************************************************
* Function Name  : NN_Mod_variable_initial
* Description    : initial global variable of NN_Mod function in math.c
* Input          : - *p_math_str        : the struct point of MATH_G_STR
				 : - digits             : word length of modulus n

* Output         : NONE
* Return         : NONE
******************************************************************************/
void NN_Mod_variable_initial(MATH_G_STR *p_math_str,UINT32 digits);
#define NN_Mod_variable_initial_v2               ( (void(*)())(ROM_BASE_ADDR+0x0000330b))
//#define NN_Mod_variable_initial_v1               ( (void(*)())(ROM_BASE_ADDR+0x00003153))	
/******************************************************************************
* Function Name  : NN_Gcd
* Description    : Computes a = gcd(b, c)
		           Assumes b > c, digits < MAX_NN_DIGITS
* Input          : - *p_math_str       : the struct point of MATH_G_STR
                 : - *b           : start address of b
				 : - *c           : start address of c
				 : - nDigits      : word length of data

* Output         : - *a           : start address of a
* Return         : NONE
******************************************************************************/
void NN_Gcd(MATH_G_STR *p_math_str,UINT32 *a ,UINT32 *b ,UINT32 *c, UINT32 digits);
#define NN_Gcd_v2                        ( (void(*)())(ROM_BASE_ADDR+0x0000373b))
//#define NN_Gcd_v1                        ( (void(*)())(ROM_BASE_ADDR+0x00003561))
/******************************************************************************
* Function Name  : NN_Div
* Description    : Computes a = c div d and b = c mod d
				   Lengths: a[cDigits], b[dDigits], c[cDigits], d[dDigits]
		           Assumes d > 0, cDigits < 2 * MAX_NN_DIGITS
				   dDigits < MAX_NN_DIGITS
* Input          : - *p_math_str       : the struct point of MATH_G_STR
                 : - *c           : start address of c
				 : - cDigits      : word length of c
				 : - *d           : start address of d
				 : - dDigits      : word length of d

* Output         : - *a           : start address of a
 				 : - *b           : start address of b
* Return         : NONE
******************************************************************************/
void NN_Div (MATH_G_STR *p_math_str,UINT32 *a, UINT32 *b, UINT32 *c, UINT32 cDigits, UINT32 *d, UINT32 dDigits);
#define NN_Div_v2                        ( (void(*)())(ROM_BASE_ADDR+0x0000347b))
//#define NN_Div_v1                        ( (void(*)())(ROM_BASE_ADDR+0x0000329d))
/******************************************************************************
* Function Name  : NN_Div
* Description    : Computes a = b mod c
				   Lengths: a[cDigits], b[bDigits], c[cDigits]
		           Assumes c > 0, bDigits < 2 * MAX_NN_DIGITS, cDigits < MAX_NN_DIGITS
* Input          : - *p_math_str       : the struct point of MATH_G_STR
                 : - *b           : start address of b
				 : - bDigits      : word length of b
				 : - *c           : start address of c
				 : - cDigits      : word length of c

* Output         : - *a           : start address of a
* Return         : NONE
******************************************************************************/
void NN_Mod (MATH_G_STR *p_math_str,UINT32 *a,UINT32 *b,UINT32 bDigits,UINT32 *c,UINT32 cDigits);
#define NN_Mod_v2                        ( (void(*)())(ROM_BASE_ADDR+0x000036d3))
//#define NN_Mod_v1                        ( (void(*)())(ROM_BASE_ADDR+0x000034f1))
/******************************************************************************
* Function Name  : NN_Digits
* Description    : calculate the significant length of a in words
* Input          : - *a           : start address of a
				 : - digits       : word length of a

* Output         : NONE
* Return         : the significant length of a in words
******************************************************************************/
unsigned int NN_Digits (UINT32 *a,UINT32 digits);
#define NN_Digits_v2                     ( (unsigned int(*)())(ROM_BASE_ADDR+0x0000345f))
//#define NN_Digits_v1                     ( (unsigned int(*)())(ROM_BASE_ADDR+0x00003285))
/******************************************************************************
* Function Name  : NN_AssignZero
* Description    : Assigns a = 0
* Input          : - digits       : word length of a

* Output         : - *a           : start address of a
* Return         : NONE
******************************************************************************/
void NN_AssignZero (UINT32 *a,UINT32 digits);
#define NN_AssignZero_v2                  ( (void(*)())(ROM_BASE_ADDR+0x0000336f))
//#define NN_AssignZero_v1                  ( (void(*)())(ROM_BASE_ADDR+0x000031ad))

/******************************************************************************
* Function Name  : NN_LShift
* Description    : Computes a = b * 2^c (i.e., shifts left c bits), returning carry
* Input          : - *b           : start address of b
				 : - c            : c<32
				 : - digits       : word length of b

* Output         : - *a           : start address of a
* Return         : carry
******************************************************************************/
UINT32 NN_LShift (UINT32 *a, UINT32 *b, UINT32 c, UINT32 digits);
#define NN_LShift_v2                      ( (UINT32(*)())(ROM_BASE_ADDR+0x0000342f))
//#define NN_LShift_v1                      ( (UINT32(*)())(ROM_BASE_ADDR+0x00003257))
/******************************************************************************
* Function Name  : NN_RShift
* Description    : Computes a = b div 2^c (i.e., shifts right c bits), returning carry
* Input          : - *b           : start address of b
				 : - c            : c<32
				 : - digits       : word length of b

* Output         : - *a           : start address of a
* Return         : carry
******************************************************************************/
UINT32 NN_RShift (UINT32 *a, UINT32 *b, UINT32 c, UINT32 digits);
#define NN_RShift_v2                      ( (UINT32(*)())(ROM_BASE_ADDR+0x00003331))
//#define NN_RShift_v1                      ( (UINT32(*)())(ROM_BASE_ADDR+0x00003179))
/******************************************************************************
* Function Name  : NN_Sub
* Description    : Computes a = b - c. Returns borrow
* Input          : - *b           : start address of b
				 : - *c           : start address of c
				 : - digits       : word length of b,c

* Output         : - *a           : start address of a
* Return         : Returns borrow
******************************************************************************/
UINT32 NN_Sub (UINT32 *a, UINT32 *b, UINT32 *c, UINT32 digits);
#define NN_Sub_v2                         ( (UINT32(*)())(ROM_BASE_ADDR+0x0000337d))
//#define NN_Sub_v1                         ( (UINT32(*)())(ROM_BASE_ADDR+0x000031bb))
	
/******************************************************************************
* Function Name  : NN_Cmp
* Description    : Returns sign of a - b
* Input          : - *a           : start address of a
				 : - *b           : start address of b
				 : - digits       : word length of a,b

* Output         : NONE
* Return         : 1: a>b; 0: a=b; -1: a<b
******************************************************************************/
int NN_Cmp (UINT32 *a, UINT32 *b, UINT32 digits);
#define NN_Cmp_v2                         ( (int(*)())(ROM_BASE_ADDR+0x000033b7))
//#define NN_Cmp_v1                         ( (int(*)())(ROM_BASE_ADDR+0x000031f3))
/******************************************************************************
* Function Name  : NN_Assign
* Description    : Assigns a = b
* Input          : - *b           : start address of b
				 : - digits       : word length of b

* Output         : - *a           : start address of a
* Return         : 1: a>b; 0: a=b; -1: a<b
******************************************************************************/
void NN_Assign (UINT32 *a,UINT32 *b, UINT32 digits);
#define NN_Assign_v2                      ( (void(*)())(ROM_BASE_ADDR+0x00003323))
//#define NN_Assign_v1                      ( (void(*)())(ROM_BASE_ADDR+0x0000316b))
/******************************************************************************
* Function Name  : NN_Zero
* Description    : Returns nonzero iff a is zero
* Input          : - *a           : start address of a
				 : - digits       : word length of b

* Output         : NONE
* Return         : 1: a=0; 0: a!=0;
******************************************************************************/
int NN_Zero (UINT32 *a,UINT32 digits);
#define NN_Zero_v2                        ( (int(*)())(ROM_BASE_ADDR+0x00003725))
//#define NN_Zero_v1                        ( (int(*)())(ROM_BASE_ADDR+0x0000354b))

/******************************************************************************
* Function Name  : NN_Add
* Description    : Computes a = b + c. Returns carry
* Input          : - *b           : start address of b
				 : - *c           : start address of c
				 : - digits       : word length of b,c

* Output         : - *a           : start address of a
* Return         : Returns carry
******************************************************************************/
UINT32 NN_Add (UINT32 *a, UINT32 *b, UINT32 *c, UINT32 digits);
#define NN_Add_v2                         ( (UINT32(*)())(ROM_BASE_ADDR+0x000037d9))
//#define NN_Add_v1                         ( (UINT32(*)())(ROM_BASE_ADDR+0x000035f9))
/******************************************************************************
* Function Name  : NN_Mult
* Description    : Computes a = b * c
				   Lengths: a[2*digits], b[digits], c[digits]
		           Assumes digits < MAX_NN_DIGITS
* Input          : - *p_math_str       : the struct point of MATH_G_STR
                 : - *b           : start address of b
								 : - *c           : start address of c
								 : - digits       : word length of b,c
* Output         : - *a           : start address of a
* Return         : NONE
******************************************************************************/
void NN_Mult (MATH_G_STR *p_math_str,UINT32 *a, UINT32 *b, UINT32 *c, UINT32 digits);
#define NN_Mult_v2                        ( (void(*)())(ROM_BASE_ADDR+0x00003807))
//#define NN_Mult_v1                        ( (void(*)())(ROM_BASE_ADDR+0x00003627))
/******************************************************************************
* Function Name  : NN_ModInv
* Description    : Compute a = 1/b mod c, assuming inverse exists
				   Lengths: a[digits], b[digits], c[digits]
		           Assumes gcd (b, c) = 1, digits < MAX_NN_DIGITS
* Input          : - *p_math_str       : the struct point of MATH_G_STR
                 : - *b           : start address of b
								 : - *c           : start address of c
								 : - digits       : word length of b,c
* Output         : - *a           : start address of a
* Return         : NONE
******************************************************************************/
void NN_ModInv (MATH_G_STR *p_math_str,UINT32 *a, UINT32 *b, UINT32 *c, UINT32 digits);
#define NN_ModInv_v2                      ( (void(*)())(ROM_BASE_ADDR+0x000038c7))
//#define NN_ModInv_v1                      ( (void(*)())(ROM_BASE_ADDR+0x000036e9))
	
#endif   //_RSA2048_H
