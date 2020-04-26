#ifndef __EFLASH_H__
#define __EFLASH_H__

#include "common.h"

#define ROM_DRIVER_FLASH

#define EFLASH_VERIFY_EN

#define EFLASH_BASE_ADDR            0x00000000  
                                   
#define EFlashMainBaseAddr	        (EFLASH_BASE_ADDR + 0x00000000)
#define EFlashNVR2BaseAddr		    (EFLASH_BASE_ADDR + 0x00080200)

#define SM_FLASH_FF_VALUE_ADDR 	    (EFlashNVR2BaseAddr + 0x64)		

#define EFC_RD_TIME 		        50    

#define EFC_WRITE_MODE		        (1<<0)
#define EFC_PAGE_ERASE_MODE	        (1<<1)
#define EFC_CHIP_ERASE_MODE	        (1<<2)
#define EFC_DOUBLE_READ_EN	        (1<<3)
#define EFC_PROGRAM_VRI_EN	        (1<<4)
#define EFC_ERASE_VRI_EN	        (1<<5)
#define EFC_ARCT_EN			        (1<<6)
#define EFC_TIME_OUT_EN		        (1<<7)
//#define EFC_RD_WAIT 		        (2<<8)
#define EFC_SLEEP_EN		        (1<<13)
#define EFC_ERA_WRI_EN		        (1<<14)

	                               
#define PagePerChip	 	            640
#define PAGE_SIZE		            512



#define eflash_read_word(addr)  	(*(volatile UINT32 *)(addr))	  //read by word
#define eflash_read_halfword(addr)  (*(volatile UINT16 *)(addr))	  //read by half word
#define eflash_read_byte(addr)  	(*(volatile UINT8 *)(addr))	      //read by byte

UINT8 eflash_write_word(UINT32 addr, UINT32 value);
UINT8 eflash_erase_page(UINT32 page_addr);
void eflash_read_page(UINT32 *buff, UINT32 pageBaseAddr);
void eflash_write_page(UINT32 *buff, UINT32 pageBaseAddr);
void eflash_erase_pages(UINT32 startPageAddr, UINT32 pageCnt);
void eflash_rewrite_word(UINT32 addr, UINT32 value);



#endif



