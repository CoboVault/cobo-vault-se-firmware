#ifndef __COMMON_H__
#define __COMMON_H__

#include  "stdio.h"	   //printf .....
#include  "string.h"   //strlen ,memset,strcmp,memcmp,strcpy .....
#include  "types.h"
#include  "config.h"
#include  "acl16.h"
#include  "uart.h"

#define SWAP(x)             ((((x) & 0xFF) << 8) | (((x) >> 8) & 0xFF))
#define max(a, b)		    (((a) > (b)) ? (a) : (b))
#define min(a, b)		    (((a) < (b)) ? (a) : (b))

#ifndef _delay_ms
#define _delay_ms  delay_ms
#endif

#ifndef _delay_us
#define _delay_us  delay_us
#endif


/************************************************************************
 * function   : printf_buff_byte
 * Description: printf data block by byte
 * input :
 *         UINT8* buff: buff
 *         UINT32 length: byte length
 * return: none
 ************************************************************************/
void printf_buff_byte(UINT8* buff, UINT32 length);

/************************************************************************
 * function   : printf_buff_word
 * Description: printf data block by word
 * input :
 *         UINT8* buff: buff
 *         UINT32 length: word length
 * return: none
 ************************************************************************/
void printf_buff_word(UINT32* buff, UINT32 length);

void delay(UINT32 count);
void delay_us(UINT32 count);
void delay_ms(UINT32 count);
void reverse_DWORD(UINT32 *var);
void reverse_memory(UINT8 *buff, UINT32 length);


#endif

