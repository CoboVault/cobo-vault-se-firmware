#include  "eflash.h"

UINT8 eflash_write_word(UINT32 addr, UINT32 value)
{
    UINT8 vf;
    REG_EFC_CTRL |= EFC_WRITE_MODE;
#ifdef EFLASH_VERIFY_EN
    REG_EFC_CTRL |= EFC_PROGRAM_VRI_EN;
#endif
    REG_EFC_SEC = 0x55AAAA55;
    *((volatile UINT32 *)(addr)) = value;
    while(!(REG_EFC_STATUS & 0x01));
    REG_EFC_CTRL &= ~EFC_WRITE_MODE;
    vf = 0;

#ifdef EFLASH_VERIFY_EN	
	while(!(REG_EFC_INTSTATUS & (0x01 << 4)));
	REG_EFC_INTSTATUS = (0x01 << 4);
    if(REG_EFC_INTSTATUS & (0x01 << 6)) //vf error
    {
        REG_EFC_INTSTATUS = (0x01 << 6);
        vf = 1;
    }
	REG_EFC_CTRL &= ~EFC_PROGRAM_VRI_EN;
#endif

    return vf;
}

/************************************************************************
 * function   : eflash_erase_page
 * Description: eflash erase page
 * input : 
 *         UINT32 page_addr: page address
 * return: 0--success   1--fail
 ************************************************************************/
UINT8 eflash_erase_page(UINT32 page_addr)
{
    UINT8 vf;

    REG_EFC_CTRL |= EFC_PAGE_ERASE_MODE;
    REG_EFC_SEC = 0x55AAAA55;
    *((volatile UINT32 *)(page_addr)) = 0;
    while(!(REG_EFC_STATUS & 0x01));
    REG_EFC_CTRL &= ~EFC_PAGE_ERASE_MODE;
    vf = 0;

#ifdef EFLASH_VERIFY_EN
    REG_EFC_ADCT = (page_addr) >> 2;
    REG_EFC_CTRL |= EFC_ERASE_VRI_EN;
    while(!(REG_EFC_INTSTATUS & (0x01 << 4)));
	REG_EFC_INTSTATUS = (0x01 << 4);
    if(REG_EFC_INTSTATUS & (0x01 << 3)) //vf error
    {
        REG_EFC_INTSTATUS = (0x01 << 3);
        vf = 1;
    }
#endif

    return vf;
}


void eflash_read_page(UINT32 *buff, UINT32 pageBaseAddr)
{
    UINT32 i;

    for(i = 0; i < (PAGE_SIZE >> 2); i++)
    {
        buff[i] = eflash_read_word(pageBaseAddr + (i << 2));
    }   
}

void eflash_write_page(UINT32 *buff, UINT32 pageBaseAddr)
{
    UINT32 i;

    for(i = 0; i < (PAGE_SIZE >> 2); i++)
    {
        eflash_write_word(pageBaseAddr + (i << 2), buff[i]);
    }   
}

void eflash_erase_pages(UINT32 startPageAddr, UINT32 pageCnt)
{
	UINT32 i;

	for(i = 0; i < pageCnt; i++)
	{
		eflash_erase_page(startPageAddr + i * PAGE_SIZE);
	}
}

void eflash_rewrite_word(UINT32 addr, UINT32 value)
{
	UINT32 buff[PAGE_SIZE >> 2];
	UINT32 page_addr;  //page base address

	if(eflash_read_word(addr) == value)
	{
		return;
	}
    
	//if(eflash_read_word(addr) == 0xFFFFFFFF)
    if(eflash_read_word(addr) == *((UINT32 *)SM_FLASH_FF_VALUE_ADDR))
	{
		eflash_write_word(addr,value);	
		return;
	}

	page_addr = addr & (~(PAGE_SIZE - 1));	

	eflash_read_page(buff, page_addr);
	buff[(addr - page_addr) >> 2] = value;
	eflash_erase_page(page_addr);
	
	eflash_write_page(buff, page_addr);
}





