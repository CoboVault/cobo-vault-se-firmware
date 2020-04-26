#ifndef __GPIO_H__
#define __GPIO_H__

#include  "common.h"

#define BIT0	                    (1<<0)
#define BIT1	                    (1<<1)
#define BIT2	                    (1<<2)
#define BIT3	                    (1<<3)
#define BIT4	                    (1<<4)
#define BIT5	                    (1<<5)
#define BIT6	                    (1<<6)
#define BIT7	                    (1<<7)
#define BIT8	                    (1<<8)
#define BIT9	                    (1<<9)
#define BIT10	                    (1<<10)
#define BIT11	                    (1<<11)
#define BIT12	                    (1<<12)
#define BIT13	                    (1<<13)
#define BIT14	                    (1<<14)
#define BIT15	                    (1<<15)
#define BIT16	                    (1<<16)
#define BIT17	                    (1<<17)
#define BIT18	                    (1<<18)
#define BIT19	                    (1<<19)
#define BIT20	                    (1<<20)
#define BIT21	                    (1<<21)
#define BIT22	                    (1<<22)
#define BIT23	                    (1<<23)
#define BIT24	                    (1<<24)
#define BIT25	                    (1<<25)
#define BIT26	                    (1<<26)
#define BIT27	                    (1<<27)
#define BIT28	                    (1<<28)
#define BIT29	                    (1<<29)
#define BIT30	                    (1<<30)
#define BIT31	                    (1UL<<31)
#define BIT(num)                    (1UL<<(num))

#define GPIO_DIR_IN  	            0
#define GPIO_DIR_OUT  	            1
#define GPIO_IS_EDGE                0
#define GPIO_IS_LEVEL               1
#define GPIO_IBE_SINGLE             0
#define GPIO_IBE_DOUBLE             1
#define GPIO_IEV_DOWN_LOW	        0
#define GPIO_IEV_UP_HIGH            1


//mason defines
#define GPIO_DET0                   GPIO25
#define GPIO_DET1                   GPIO2
#define GPIO_DET2                   GPIO3
#define GPIO_DET3                   GPIO4
#define GPIO_WAKE_UP                GPIO30

#define PIN_DET0                    (25)
#define PIN_DET1                    (2)
#define PIN_DET2                    (3)
#define PIN_DET3                    (4)
#define PIN_WAKE_UP                 (30)

#define BIT_DET0                    (BIT(25))
#define BIT_DET1                    (BIT(2))
#define BIT_DET2                    (BIT(3))
#define BIT_DET3                    (BIT(4))
#define BIT_WAKE_UP                 (BIT(30))


extern volatile bool flag_active_defense_trigger;
extern volatile bool flag_passtive_defense_trigger;


/************************************************************************
 * function   : gpio_init
 * Description: gpio initial
 * input : none
 * return: none
 ************************************************************************/
void gpio_init(void);
bool gpio_high(uint32_t bit, uint32_t durationMS);
bool gpio_low(uint32_t bit, uint32_t durationMS);

#endif

