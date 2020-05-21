#ifndef __SYSTEM_SE_H__
#define __SYSTEM_SE_H__

#include  "common.h"

#ifdef __cplusplus
extern "C"
{
#endif

//#define LOW_POWER

/*----------------lower power bit--------------------*/
#define BIT_EFC         (1<<0)
//#define BIT_RSV       (1<<1)
#define BIT_ROM         (1<<2)
#define BIT_WDT         (1<<3)
#define BIT_TIMER       (1<<4)
#define BIT_GPIO        (1<<5)
#define BIT_7816MS      (1<<6)
#define BIT_USB         (1<<7)
#define BIT_SPIA        (1<<8)
#define BIT_SPIB        (1<<9)
#define BIT_UARTA       (1<<10)
#define BIT_UARTB       (1<<11)
#define BIT_CRC         (1<<12)
#define BIT_I2C         (1<<13)
#define BIT_SENSOR      (1<<14)
#define BIT_HRNG        (1<<15)
#define BIT_DES         (1<<16)
#define BIT_SM4         (1<<17)
#define BIT_SM1         (1<<18)
#define BIT_PKI         (1<<19)
#define BIT_SM3         (1<<20)
#define BIT_AES         (1<<21)
#define enable_module(x)   do{ REG_SCU_BCR |= (x); } while(0)
#define disable_module(x)  do{ REG_SCU_BCR &= ~(x); } while(0)
#define init_module(value) do{ REG_SCU_BCR = (value); } while(0)

/*----------------module reset bit--------------------*/
#define RESET_EFC       (1<<16)
#define RESET_SENSOR    (1<<17)
#define RESET_I2C       (1<<18)
#define RESET_WDT       (1<<19)
#define RESET_CRC       (1<<20)
#define RESET_GPIO      (1<<21)
#define RESET_7816MS    (1<<22)
#define RESET_TIMER     (1<<23)
#define RESET_UARTB     (1<<24)
#define RESET_UARTA     (1<<25)
#define RESET_SPIB      (1<<26)
#define RESET_SPIA      (1<<27)
#define RESET_USB       (1<<28)
#define RESET_UAC       (1<<29)
#define reset_module(x) do{ REG_SCU_RCR &= ~(x); delay(5); REG_SCU_RCR |= (x); } while(0)

#define CLK_SRC_RC48M   (0x00)  //clk src from RC48M
#define CLK_SRC_RC32    (0x01)  //clk src from RC32K
#define CLK_SRC_PLL48   (0x02)  //clk src from PLL48M

#define CLK_DIV_CORE    (0<<0)  //no div freq
#define CLK_DIV_ALG     (0<<8)  //no div freq
#define CLK_DIV_SPI     (1<<12) // 2 div
#define CLK_DIV_HRNGS   (47<<17) //HRNGS = 1Mhz

extern uint32_t SystemCoreClock;     //core/HCLK (uint:Hz)
extern uint32_t SRCClock;            //source clk_src (uint:Hz)
extern uint32_t PClock;              //APB PCLK  (uint:Hz)

/************************************************************************
 * function   : SystemInit
 * Description: SystemInit
 * input : none
 * return: none
 ************************************************************************/
void SystemInit(void);

/************************************************************************
 * function   : clock_init
 * Description: clock init, initil several clock variables
 * input :
 *         uint32_t system_clk_mhz: expected system core clock
 * return: none
 ************************************************************************/
void clock_init(uint32_t system_clk_mhz);


void SystemCoreClockUpdate(void);


#ifdef __cplusplus
}
#endif

#endif
