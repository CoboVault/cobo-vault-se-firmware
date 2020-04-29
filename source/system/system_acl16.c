#include  "system_acl16.h"
#include  "acl16.h"

uint32_t SystemCoreClock = 0;   //core CLK (uint:Hz)
uint32_t SRCClock = 0;          //source CLK (uint:Hz)
uint32_t PClock = 0;            //APB ClK (uint:Hz)

/************************************************************************
 * function   : clock_init
 * Description: clock init, initil several clock variables
 * input : 
 *		   uint32_t system_clk_mhz: expected system core clock
 * return: none
 ************************************************************************/
void clock_init(uint32_t system_clk_mhz)
{
    uint32_t div, rc48m;
    uint8_t wait_value;

    switch (system_clk_mhz)
    {
        case 48:
            div = 1; break;
        case 24:
            div = 2; break;
        case 12:
            div = 4; break;
        case 6 :
            div = 8; break;
        default:
            SystemCoreClock = 0; SRCClock = 0; PClock = 0; return;
    }

    REG_EFC_CTRL = (REG_EFC_CTRL & (~(0x1f << 8))) | (5 << 8);  //config init EFC RD wait >40ns
    REG_SCU_CCR = (REG_SCU_CCR & ~0x03) | CLK_SRC_RC48M; //RC48M

    //REG_SCU_DIVR = ((div -1 ) << 0) | CLK_DIV_ALG | CLK_DIV_SPI | CLK_DIV_HRNGS;
    REG_SCU_DIVR = ((div - 1) << 0) | CLK_DIV_ALG | CLK_DIV_SPI | ((system_clk_mhz - 1) << 17);
    while ((REG_SCU_DIVR & (1 << 16)) == 0x00);

    rc48m = (*(volatile UINT32 *)(0x0008022C)) * 16000;
    if ((rc48m <= 52000000) && (rc48m >= 44000000)) SRCClock = rc48m;
    else SRCClock = 48000000;

    SystemCoreClock = SRCClock / div;
    PClock = SystemCoreClock;
    //set EFC RD_WAIT (at least 50ns)
    if (SystemCoreClock >= 30000000) wait_value = 1;
    else                             wait_value = 0;

    REG_EFC_CTRL = (REG_EFC_CTRL & (~(0x1f << 8))) | (wait_value << 8);
}

/************************************************************************
 * function   : SystemInit
 * Description: SystemInit
 * input : none
 * return: none
 ************************************************************************/
void SystemInit(void)
{
    clock_init(FCLK);

    while (!(REG_SCU_PHYCR & (1 << 19)));//wait USB PHY wait long to 20ms
    if (!(REG_SCU_PHYCR & (1 << 16))) //select inter rc
    {
        REG_SCU_RCCR &= ~(1 << 7); //disable X12M
    }
}

void SystemCoreClockUpdate(void)
{
    //SystemCoreClock=FCLK;
}
