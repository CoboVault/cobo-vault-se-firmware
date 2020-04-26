#ifndef __ECC_H__
#define __ECC_H__

#include "common.h"

/**********************************************************
*	definitions
**********************************************************/
//#define _ECC_521
//#define _ECC_384
#define _ECC_256
//#define _ECC_224
//#define _ECC_192
//#define _ECC_160

#define WL 18
#define W 32
#define CNST_RSA_EXP 0x30
#define CNST_RSAALL_EXP 0x34
#define CNST_RSA_MUL 0x01
#define CNST_MOD_ADD 0x02
#define CNST_MOD_SUB 0x04
#define CNST_POINT_ADD 0x24
#define CNST_POINT_SUB 0x28

/**********************************************************
*	structure
**********************************************************/
typedef struct
{
	UINT32 *ECC_p;
	UINT32 *ECC_a;
	UINT32 *ECC_b;
	UINT32 *ECC_n;
	UINT32 *ECC_BaseX;
	UINT32 *ECC_BaseY;
	UINT32 ECC_CurveLength;
} ECC_G_STR;

/**********************************************************
*	extern functions
***********************************************************/
/*********************************************************************************
* Function Name  : ECC_write_SRAM
* Description    : write data to NSRAM of ECC,the max length(words) is 64
* Input          : - *rst_addr   : the sram rst reg addr
				         : - *reg_addr   : the sram reg addr
				         : - *n_data     : the write data	
				         : - n_len       : length of the write data, in words
* Output         : NONE
* Return         : NONE
*********************************************************************************/
void ECC_write_SRAM(UINT32 *rst_addr, UINT32 *reg_addr, UINT32 *n_data, UINT8 n_len);

/*********************************************************************************
* Function Name  : ECC_write0_SRAM
* Description    : write 0 to SRAM of ECC,the max length(words) is 128
* Input          : - t_len       : length of the write data, in words
* Output         : NONE
* Return         : NONE
*********************************************************************************/
void ECC_write0_SRAM(UINT32 *rst_addr, UINT32 *reg_addr, UINT8 n_len);

/*********************************************************************************
* Function Name  : ECC_read_SRAM
* Description    : read data from SRAM of ECC,the max length(words) is 64
* Input          : NONE
* Output         : - *a_data     : the read data
				         : - a_len       : length of the read data, in words
* Return         : NONE
*********************************************************************************/
void ECC_read_SRAM(UINT32 *rst_addr, UINT32 *reg_addr, UINT32 *rdlen_addr, UINT32 *rdata, UINT8 *wlen);

/*********************************************************************************
* Function Name  : ECC_precal
* Description    : ecc pre calculate R^2 mod N
* Input          : - *n_data     : n,modular for ecc or rsa operation
				         : - n_length    : length of n_data, in words
* Output         : NONE
* Return         : 0: success; 1: error, n is even
*********************************************************************************/
UINT8 ECC_precal(UINT32 *n_data, UINT8 n_length);

/*********************************************************************************
* Function Name  : ECC_rsa_enhance_mm_me
* Description    : rsa modexp modmul calculate:out_data=(a_data^b_data) mod n_data
*                : 							   out_data=(a_data*b_data) mod n_data
* Input          : - *a_data     : input number for a
				         : - a_length    : length of a_data, in words
				         : - *b_data     : input number for b
				         : - b_length    : length of b_data, in words
				         : - *r_data     : input number for r
				         : - r_length    : length of r_data, in words
				         : - mode        : 0x30: modexp; 0x01: modmul
* Output         : NONE 
* Return         : NONE
*********************************************************************************/
void ECC_rsa_enhance_mm_me(
	UINT32 *a_data,
	UINT8 a_length,
	UINT32 *b_data,
	UINT8 b_length,
	UINT32 *r_data,
	UINT8 r_length,
	UINT8 mode);

/*********************************************************************************
* Function Name  : ECC_mul_me
* Description    : rsa modexp modmul calculate:out_data=(in_data^e_data) mod n_data
*                :                             out_data=(in_data*e_data) mod n_data
* Input          : - *in_data    : input number for RSA modular exp operation
				         : - in_length   : length of in_data, in words
				         : - *e_data     : exponent for RSA modular exp operation
				         : - e_length    : length of e_data, in words
				         : - *n_data     : n,modular for RSA modular exp operation
				         : - n_length    : length of n_data, in words
				         : - mode        : 0x30: modexp; 0x01: modmul
* Output         : - *out_data   : result for RSA modular exp operation
				         : - *out_length : length of output, in words 
* Return         : 0: success; 1: error, n is even
*********************************************************************************/
UINT8 ECC_mul_me(
	UINT32 *in_data,
	UINT8 in_length,
	UINT32 *e_data,
	UINT8 e_length,
	UINT32 *n_data,
	UINT8 n_length,
	UINT32 *out_data,
	UINT8 *out_length,
	UINT8 mode);

/*********************************************************************************
* Function Name  : ECC_mod_sqr
* Description    : mod square calculate:out_data=(in_data*in_data) mod n_data
* Input          : - *in_data    : input number for modular sqr operation
				         : - in_length   : length of in_data, in words
				         : - *n_data     : n,modular for modular sqr operation
				         : - n_length    : length of n_data, in words
* Output         : - *out_data   : result for modular sqr operation
				         : - *out_length : length of output, in words 
* Return         : 0: success; 1: error, n is even
*********************************************************************************/
UINT8 ECC_mod_sqr(
	UINT32 *in_data,
	UINT8 in_length,
	UINT32 *n_data,
	UINT8 n_length,
	UINT32 *out_data,
	UINT8 *out_length);

/*********************************************************************************
* Function Name  : ECC_mod_inv
* Description    : mod inv calculate:out_data=(in_data^(-1)) mod n_data
* Input          : - *in_data    : input number for modular inv operation
				         : - in_length   : length of in_data, in words
				         : - *n_data     : n,modular for modular inv operation
				         : - n_length    : length of n_data, in words
* Output         : - *out_data   : result for modular inv operation
				         : - *out_length : length of output, in words 
* Return         : 0: success; 1: error, n is even
*********************************************************************************/
UINT8 ECC_mod_inv(
	UINT32 *in_data,
	UINT8 in_length,
	UINT32 *n_data,
	UINT8 n_length,
	UINT32 *out_data,
	UINT8 *out_length);

/*********************************************************************************
* Function Name  : ECC_mod_add
* Description    : ecc modadd calculate:out_data=(a_data+b_data) mod n_data	or out_data=(a_data-b_data) mod n_data
* Input          : - *a_data    : input number for ecc modular add operation
				         : - a_length   : length of in_data, in words
				         : - *b_data     : exponent for ecc modular add operation
				         : - b_length    : length of e_data, in words
				         : - *n_data     : n,modular for ecc modular add operation
				         : - n_length    : length of n_data, in words
				         : - mode        : 0x02: modadd; 0x04: modsub
* Output         : - *out_data   : result for ecc modular add operation
				         : - *out_length : length of output, in words 
* Return         : NONE
*********************************************************************************/
void ECC_mod_add_sub(
	UINT32 *a_data,
	UINT8 a_length,
	UINT32 *b_data,
	UINT8 b_length,
	UINT32 *n_data,
	UINT8 n_length,
	UINT32 *out_data,
	UINT8 *out_length,
	UINT8 mode);

/*********************************************************************************
* Function Name  : ECC_para_initial
* Description    : initial parameter for ecc point operation
* Input          : - p_ecc_para    : the struct of ecc curve parameter point
				         : - CurveLength   : the word length of the ecc curve
				         : - *p _data      : the order of prime field p
				         : - *a _data      : parameter a
				         : - *b _data      : parameter b
				         : - *n _data      : the order of base point G
				         : - *BaseX_data   : x coordinate of base point
				         : - *BaseY_data   : y coordinate of base point					  				
* Output         : NONE
* Return         : NONE
*********************************************************************************/
void ECC_para_initial(ECC_G_STR *p_ecc_para, UINT32 CurveLength, UINT32 *p_data, UINT32 *a_data, UINT32 *b_data, UINT32 *n_data, UINT32 *BaseX_data, UINT32 *BaseY_data);

/*********************************************************************************
* Function Name  : ECC_PM
* Description    : ecc point multiple
* Input          : - p_ecc_para    : the struct of ecc curve parameter point
				         : - *k_data       : the big number k
				         : - *X0_data      : the operation point x coordinate
				         : - *Y0_data      : the operation point y coordinate				
* Output         : - *pmx_data     : the result point x coordinate
				         : - *pmy_data     : the result point y coordinate
* Return         : 0: PM success; 1: result is infinite point or point add error
*********************************************************************************/
UINT8 ECC_PM(ECC_G_STR *p_ecc_para, UINT32 *k_data, UINT32 *X0_data, UINT32 *Y0_data, UINT32 *pmx_data, UINT32 *pmy_data);

/*********************************************************************************
* Function Name  : ECC_PA_PS
* Description    : ecc point addition(p0+p1) or subtration(p1-p0)  
* Input          : - p_ecc_para    : the struct of ecc curve parameter point
				         : - cmd           : 0x24: point add; 0x28: point sub
				         : - *X0_data      : x coordinate of p0 
				         : - *Y0_data      : y coordinate of p0
				         : - *X1_data      : x coordinate of p1 
				         : - *Y1_data      : y coordinate of p1
* Output         : - *x_data       : the result point x coordinate
				         : - *y_data       : the result point y coordinate
* Return         : 0: PA or PS success; 1: result is infinite point or point add error
*********************************************************************************/
UINT8 ECC_PA_PS(ECC_G_STR *p_ecc_para, UINT32 cmd, UINT32 *X0_data, UINT32 *Y0_data, UINT32 *X1_data, UINT32 *Y1_data, UINT32 *x_data, UINT32 *y_data);

/*********************************************************************************
* Function Name  : ECC_PD
* Description    : ecc double point (2*p0) 
* Input          : - p_ecc_para    : the struct of ecc curve parameter point
				         : - *X0_data      : x coordinate of p0	
				         : - *Y0_data      : y coordinate of p0				
* Output         : - *x_data       : the result point x coordinate
				         : - *y_data       : the result point y coordinate
* Return         : 0: PD success; 1: result is infinite point or point add error
*********************************************************************************/
UINT8 ECC_PD(ECC_G_STR *p_ecc_para, UINT32 *X0_data, UINT32 *Y0_data, UINT32 *x_data, UINT32 *y_data);

/*********************************************************************************
* Function Name  : ECC_PJ
* Description    : ecc point p0 on curve judgement				  				 
* Input          : - p_ecc_para    : the struct of ecc curve parameter point
				         : - *X0_data      : x coordinate of p0	
				         : - *Y0_data      : y coordinate of p0 				
* Output         : NONE
* Return         : 0:point on curve; 1:point not on curve
*********************************************************************************/
UINT8 ECC_PJ(ECC_G_STR *p_ecc_para, UINT32 *X0_data, UINT32 *Y0_data);

/*********************************************************************************
* Function Name  : ECC_red_dvm
* Description    : division algorithm, out_data = d_data mod n_data
* Input          : - *d_data     : input divisor number 
				         : - d_length    : length of d_data, in words
				         : - *n_data     : input dividend number
				         : - n_length    : length of n_data, in words
* Output         : - *r_data     : remainder
				         : - *r_length   : length of remainder, in words 
				         : - *q_data     : quotient
				         : - *q_length   : length of quotient, in words
* Return         : NONE
*********************************************************************************/
void ECC_red_dvm(
	UINT32 *d_data,
	UINT8 d_length,
	UINT32 *n_data,
	UINT8 n_length,
	UINT32 *r_data,
	UINT8 *r_length,
	UINT32 *q_data,
	UINT8 *q_length);

/*********************************************************************************
* Function Name  : ecc_swap_array
* Description    : swap array a[0]...a[31] -> a[31]...a[0]
* Input          : - *ptr      : input swap array 
				         : - len       : length of swap array, in words
* Output         : - *ptr      : output swap array
				         : - *len      : length of swap array, in words 
* Return         : NONE
*********************************************************************************/
void ecc_swap_array(UINT32 *ptr, UINT32 len);

/******************************************************************************
* Function Name  : ECC_NN_Digits
* Description    : calculate the significant length of a in words
* Input          : - *a           : start address of a
				         : - digits       : word length of a
* Output         : NONE
* Return         : the significant length of a in words
******************************************************************************/
unsigned int ECC_NN_Digits(UINT32 *a, UINT32 digits);

/******************************************************************************
* Function Name  : NN_AssignZero
* Description    : Assigns a = 0
* Input          : - digits       : word length of a
* Output         : - *a           : start address of a
* Return         : NONE
******************************************************************************/
void ECC_NN_AssignZero(UINT32 *a, UINT32 digits);

/*********************************************************************************
* Function Name  : alg2nor_sram
* Description    : config algrithom sram to noraml sram
* Input          : None
* Output         : None
* Return         : None
*********************************************************************************/
void alg2nor_sram(void);

/*********************************************************************************
* Function Name  : clear_sram
* Description    : write 0 to algrithom sram
* Input          : None
* Output         : None
* Return         : None
*********************************************************************************/
void clear_sram(void);

#endif //_ECC_H
