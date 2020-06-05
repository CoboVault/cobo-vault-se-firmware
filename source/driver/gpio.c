#include "gpio.h"
#include "wdt.h"

volatile bool flag_active_defense_trigger = false;
volatile bool flag_passtive_defense_trigger = false;

extern bool bIsOnSleeping;

/************************************************************************
 * function   : GPIO_IRQHandler
 * Description: 
 * input : none
 * return: none
 ************************************************************************/
void GPIO_IRQHandler(void)
{
    UINT32 status = 0UL;

    status = REG_GPIO_MIS;	//read interrupt status register

    //status = REG_GPIO_RIS;

    bIsOnSleeping = false;

    if (status & BIT_DET0)
    {
        flag_active_defense_trigger = true;
        REG_GPIO_IEN &= ~BIT_DET0; 
    }

    if (status & (BIT_DET1 | BIT_DET2 | BIT_DET3))
    {
        flag_passtive_defense_trigger = true;
        REG_GPIO_IEN &= ~(BIT_DET1 | BIT_DET2 | BIT_DET3); 
    }

    REG_GPIO_IC = status;	//clear interrupt bit
}

/************************************************************************
 * function   : gpio_init
 * Description: gpio initial
 * input : none
 * return: none
 ************************************************************************/
void gpio_init(void)
{
    reset_module(RESET_GPIO);

    NVIC_ClearPendingIRQ(GPIO_IRQn);
    NVIC_EnableIRQ(GPIO_IRQn);
}

bool gpio_high(uint32_t bit, uint32_t durationMS)
{
    uint32_t countMs = 30;

    delay_ms(50);
    while (bit == (REG_GPIO_IDATA & bit))
    {
        wdt_feed();
        delay_ms(50);
        countMs += 50;
        if (countMs > durationMS)
        {
            return true;
        }
    }

    return false;
}

bool gpio_low(uint32_t bit, uint32_t durationMS)
{
    uint32_t countMs = 30;

    while (~bit == (REG_GPIO_IDATA | ~bit))
    {
        wdt_feed();
        delay_ms(50);
        countMs += 50;
        if (countMs > durationMS)
        {
            return true;
        }
    }

    return false;
}
