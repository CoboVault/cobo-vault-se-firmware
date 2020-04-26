#include  "wdt.h"

volatile UINT8 flag_wdt_int = 0;
/************************************************************************
 * function   : WDT_IRQHandler
 * Description:
 * input :
 * return:
 ************************************************************************/
void WDT_IRQHandler(void)
{
    printf("APP wdt int!\n");
    REG_WDT_FEED = 0xAA55A55A; //feed wdt and clear int
    flag_wdt_int = 1;
}
/************************************************************************
 * function   : wdt_init
 * Description: wdt initial
 * input : none
 * return: none
 ************************************************************************/
void wdt_init(void)
{
	enable_module(BIT_WDT);
    reset_module(RESET_WDT);

    NVIC_ClearPendingIRQ(WDT_IRQn);
    NVIC_EnableIRQ(WDT_IRQn);

    REG_WDT_LOAD = WDT_1S*20;
    REG_WDT_INT_CLR_TIME = 0x8000;

    REG_WDT_CTRL =  WDT_DIVIDER_16 | WDT_ACTION_INT | WDT_INT_EN;
//  REG_WDT_CTRL |= WDT_ENABLE;    //start wdt
}
/************************************************************************
 * function   : wdt_start
 * Description: watch dog start
 * input : none
 * return: none
 ************************************************************************/
void wdt_start(void)
{
    REG_WDT_CTRL |= WDT_ENABLE;    //start wdt
}
/************************************************************************
 * function   : wdt_stop
 * Description: watch dog stop
 * input : none
 * return: none
 ************************************************************************/
void wdt_stop(void)
{
    REG_WDT_CTRL &= ~WDT_ENABLE;    //stop wdt
}
/************************************************************************
 * function   : wdt_feed
 * Description: watch dog feed
 * input : none
 * return: none
 ************************************************************************/
void wdt_feed(void)
{
    REG_WDT_FEED = 0xAA55A55A;
}

