#ifndef __ACL16_H__
#define __ACL16_H__

#ifdef __cplusplus
extern "C"
{
#endif

/* -------------------------  Interrupt Number Definition  ------------------------ */

typedef enum IRQn
{
/* -------------------  Cortex-M0 Processor Exceptions Numbers  ------------------- */
    NonMaskableInt_IRQn           = -14,      /*  2 Non Maskable Interrupt */
    HardFault_IRQn                = -13,      /*  3 HardFault Interrupt */

    SVCall_IRQn                   = -5,      /* 11 SV Call Interrupt */

    PendSV_IRQn                   = -2,      /* 14 Pend SV Interrupt */
    SysTick_IRQn                  = -1,      /* 15 System Tick Interrupt */

/* ----------------------  ARMCM0 Specific Interrupt Numbers  --------------------- */
    WDT_IRQn		              = 0,        // 0:  WDT_IRQHandler
    TIMER0_IRQn	                  = 1,        // 1:  TIMER0_IRQHandler
    TIMER1_IRQn	                  = 2,        // 2:  TIMER1_IRQHandler
    GPIO_IRQn		              = 3,        // 3:  GPIO_IRQHandler
    MS7816_IRQn                   = 4,        // 4:  MS7816_IRQHandler
    USB_IRQn                      = 5,        // 5:  USB_IRQHandler
    EFC_IRQn                      = 6,        // 6:  EFC_IRQHandler
    SPIA_IRQn	                  = 7,        // 7:  SPIA_IRQHandler
    SPIB_IRQn	                  = 8,        // 8:  SPIB_IRQHandler
    MPU_IRQn	                  = 9,        // 9:  MPU_IRQHandler
    SENSOR_IRQn                   = 10,       // 10: SENSOR_IRQHandler
    SM1_IRQn		              = 11,       // 11: SM1_IRQHandler
    DES_IRQn		              = 12,       // 12: DES_IRQHandler
    SM4_IRQn		              = 13,       // 13: SM4_IRQHandler
    PKI_IRQn		              = 14,       // 14: PKI_IRQHandler
    UARTA_IRQn	                  = 15,       // 15: UARTA_IRQHandler
    UARTB_IRQn	                  = 16,       // 16: UARTB_IRQHandler
    I2C_IRQn                      = 17,       // 17: I2C_IRQHandler
    SCDRST_IRQn                   = 18,       // 18: SCDRST_IRQHandler
    MIC_IRQn                      = 19,       // 19: MIC_IRQHandler
    AES_IRQn                      = 20,       // 20: AES_IRQHandler
    WAKEUP_IRQn                   = 21,       // 21: WAKEUP_IRQHandler
	TIMER2_IRQn                   = 22,       // 22: WAKEUP_IRQHandler

} IRQn_Type;

/* ================================================================================ */
/* ================      Processor and Core Peripheral Section     ================ */
/* ================================================================================ */

/* -------  Start of section using anonymous unions and disabling warnings  ------- */
#if   defined (__CC_ARM)
#pragma push
#pragma anon_unions
#elif defined (__ICCARM__)
#pragma language=extended
#elif defined(__ARMCC_VERSION) && (__ARMCC_VERSION >= 6010050)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc11-extensions"
#pragma clang diagnostic ignored "-Wreserved-id-macro"
#elif defined (__GNUC__)
/* anonymous unions are enabled by default */
#elif defined (__TMS470__)
/* anonymous unions are enabled by default */
#elif defined (__TASKING__)
#pragma warning 586
#elif defined (__CSMC__)
/* anonymous unions are enabled by default */
#else
#warning Not supported compiler type
#endif


/* --------  Configuration of the Cortex-M0 Processor and Core Peripherals  ------- */
#define __CM0_REV                 0x0000U   /* Core revision r0p0 */
#define __MPU_PRESENT             0         /* MPU present or not */
#define __VTOR_PRESENT            0         /* no VTOR present*/
#define __NVIC_PRIO_BITS          2         /* Number of Bits used for Priority Levels */
#define __Vendor_SysTickConfig    0         /* Set to 1 if different SysTick Config is used */


#include "core_cm0.h"                       /* Processor and core peripherals */
#include "system_acl16.h"                 /* System Header */

/* --------  End of section using anonymous unions and disabling warnings  -------- */
#if   defined (__CC_ARM)
#pragma pop
#elif defined (__ICCARM__)
/* leave anonymous unions enabled */
#elif (__ARMCC_VERSION >= 6010050)
#pragma clang diagnostic pop
#elif defined (__GNUC__)
/* anonymous unions are enabled by default */
#elif defined (__TMS470__)
/* anonymous unions are enabled by default */
#elif defined (__TASKING__)
#pragma warning restore
#elif defined (__CSMC__)
/* anonymous unions are enabled by default */
#else
#warning Not supported compiler type
#endif

/* ================================================================================ */
/* ================       Device Specific Peripheral Section       ================ */
/* ================================================================================ */
#define ROM_BASE_ADDR                    0x60000000

///*----------------------EFC------------------------*/
#define EFLASH_BASE_ADDR                 0x00000000
#define EFC_REG_BASE_ADDR				 0x00100000

#define REG_EFC_CTRL    	             (*(volatile UINT32 *)(EFC_REG_BASE_ADDR + 0x00))
#define REG_EFC_SEC    		             (*(volatile UINT32 *)(EFC_REG_BASE_ADDR + 0x04))
#define REG_EFC_ADCT    	             (*(volatile UINT32 *)(EFC_REG_BASE_ADDR + 0x08))
#define REG_EFC_ERTO   		             (*(volatile UINT32 *)(EFC_REG_BASE_ADDR + 0x0C))
#define REG_EFC_WRTO    	             (*(volatile UINT32 *)(EFC_REG_BASE_ADDR + 0x10))
#define REG_EFC_STATUS    	             (*(volatile UINT32 *)(EFC_REG_BASE_ADDR + 0x14))
#define REG_EFC_INTSTATUS                (*(volatile UINT32 *)(EFC_REG_BASE_ADDR + 0x18))
#define REG_EFC_INEN    	             (*(volatile UINT32 *)(EFC_REG_BASE_ADDR + 0x1c))


///*------------------------MPU----------------------*/
#define MPU_BASE_ADDR	                 0x40060000
#define REG_MPUCR   			         (*(volatile UINT32 *)(MPU_BASE_ADDR + 0x00))
#define REG_MPUDUMMYDATA  		         (*(volatile UINT32 *)(MPU_BASE_ADDR + 0x04))
#define REG_MPUVectorOffset  	         (*(volatile UINT32 *)(MPU_BASE_ADDR + 0x08))
#define REG_MPUSG0Conf   		         (*(volatile UINT32 *)(MPU_BASE_ADDR + 0x0C))
#define REG_MPUSG1Conf   		         (*(volatile UINT32 *)(MPU_BASE_ADDR + 0x10))
#define REG_MPUSG2Conf  		         (*(volatile UINT32 *)(MPU_BASE_ADDR + 0x14))
#define REG_MPUSG3Conf  		         (*(volatile UINT32 *)(MPU_BASE_ADDR + 0x18))
#define REG_MPUSG4Conf   		         (*(volatile UINT32 *)(MPU_BASE_ADDR + 0x1C))
#define REG_MPUSG5Conf 			         (*(volatile UINT32 *)(MPU_BASE_ADDR + 0x20))
#define REG_MPUSG6Conf 			         (*(volatile UINT32 *)(MPU_BASE_ADDR + 0x24))
#define REG_MPUSG7Conf 			         (*(volatile UINT32 *)(MPU_BASE_ADDR + 0x28))
#define REG_MPUSGxConf(x) 		         (*(volatile UINT32 *)(MPU_BASE_ADDR + 0x0C + (x) * 4))
#define REG_MPUREGConf 			         (*(volatile UINT32 *)(MPU_BASE_ADDR + 0x2C))
#define REG_MPUAccCtrl0   		         (*(volatile UINT32 *)(MPU_BASE_ADDR + 0x30))
#define REG_MPUAccCtrl1 		         (*(volatile UINT32 *)(MPU_BASE_ADDR + 0x34))
#define REG_MPUSR   			         (*(volatile UINT32 *)(MPU_BASE_ADDR + 0x400))
#define REG_MPUADDR  			         (*(volatile UINT32 *)(MPU_BASE_ADDR + 0x404))
#define REG_MPUINTEN  			         (*(volatile UINT32 *)(MPU_BASE_ADDR + 0x408))

///*----------------------USB------------------------*/
#define USB_BASE_ADDR                    0x40070000

#define REG_USBC_WORKMODE			     (*(volatile UINT32 *)(USB_BASE_ADDR + 0x00))
#define REG_USBC_EPXCSR(x) 			     (*(volatile UINT32 *)(USB_BASE_ADDR + 0x04 + (x) * 4))
#define REG_USBC_EP0CSR 			     (*(volatile UINT32 *)(USB_BASE_ADDR + 0x04))
#define REG_USBC_EP1CSR 			     (*(volatile UINT32 *)(USB_BASE_ADDR + 0x08))
#define REG_USBC_EP2CSR 			     (*(volatile UINT32 *)(USB_BASE_ADDR + 0x0C))
#define REG_USBC_EP3CSR 			     (*(volatile UINT32 *)(USB_BASE_ADDR + 0x10))
#define REG_USBC_EP4CSR 			     (*(volatile UINT32 *)(USB_BASE_ADDR + 0x14))
#define REG_USBC_ADDR 				     (*(volatile UINT32 *)(USB_BASE_ADDR + 0x18))
#define REG_USBC_SETUP03 			     (*(volatile UINT32 *)(USB_BASE_ADDR + 0x1C))
#define REG_USBC_SETUP47 			     (*(volatile UINT32 *)(USB_BASE_ADDR + 0x20))
#define REG_USBC_EPADDR 			     (*(volatile UINT32 *)(USB_BASE_ADDR + 0x24))
#define REG_USBC_PID 				     (*(volatile UINT32 *)(USB_BASE_ADDR + 0x28))
#define REG_USBC_FRAMENUM 			     (*(volatile UINT32 *)(USB_BASE_ADDR + 0x2C))
#define REG_USBC_CRCERRCNT			     (*(volatile UINT32 *)(USB_BASE_ADDR + 0x30))
#define REG_USBC_STSDETECTCNT		     (*(volatile UINT32 *)(USB_BASE_ADDR + 0x34))
#define REG_USBC_EPXSENDCOUNT(x)	     (*(volatile UINT32 *)(USB_BASE_ADDR + 0x40 + (x) * 4))
#define REG_USBC_EP0SENDCOUNT		     (*(volatile UINT32 *)(USB_BASE_ADDR + 0x40))
#define REG_USBC_EP1SENDCOUNT		     (*(volatile UINT32 *)(USB_BASE_ADDR + 0x44))
#define REG_USBC_EP2SENDCOUNT		     (*(volatile UINT32 *)(USB_BASE_ADDR + 0x48))
#define REG_USBC_EP3SENDCOUNT		     (*(volatile UINT32 *)(USB_BASE_ADDR + 0x4C))
#define REG_USBC_EP4SENDCOUNT		     (*(volatile UINT32 *)(USB_BASE_ADDR + 0x50))

#define REG_USBC_EPXFIFO(x)			     (*(volatile UINT32 *)(USB_BASE_ADDR + 0x100 + (x) * 4))
#define REG_USBC_EP0FIFO			     (*(volatile UINT32 *)(USB_BASE_ADDR + 0x100))
#define REG_USBC_EP1FIFO			     (*(volatile UINT32 *)(USB_BASE_ADDR + 0x104))
#define REG_USBC_EP2FIFO			     (*(volatile UINT32 *)(USB_BASE_ADDR + 0x108))
#define REG_USBC_EP3FIFO			     (*(volatile UINT32 *)(USB_BASE_ADDR + 0x10C))
#define REG_USBC_EP4FIFO			     (*(volatile UINT32 *)(USB_BASE_ADDR + 0x110))
#define USB_EPX_MEM8(x,y)	             (*(volatile UINT8  *)(USB_BASE_ADDR + 0x200 + (y) * 64 + (x)))  //x:byte_index,y:ep_index
#define USB_EPX_MEM32(x,y)	             (*(volatile UINT32 *)(USB_BASE_ADDR + 0x200 + (y) * 64 + (x)))
#define USB_EP0_MEM8(x)                  (*(volatile UINT8  *)(USB_BASE_ADDR + 0x200 + (x)))
#define USB_EP1_MEM8(x)                  (*(volatile UINT8  *)(USB_BASE_ADDR + 0x240 + (x)))
#define USB_EP2_MEM8(x)                  (*(volatile UINT8  *)(USB_BASE_ADDR + 0x280 + (x)))
#define USB_EP3_MEM8(x)                  (*(volatile UINT8  *)(USB_BASE_ADDR + 0x2C0 + (x)))
#define USB_EP4_MEM8(x)                  (*(volatile UINT8  *)(USB_BASE_ADDR + 0x300 + (x)))
#define REG_USBC_INTSTATRAW			     (*(volatile UINT32 *)(USB_BASE_ADDR + 0xffe4))
#define REG_USBC_INTEN				     (*(volatile UINT32 *)(USB_BASE_ADDR + 0xffe8))
#define REG_USBC_INTCLR				     (*(volatile UINT32 *)(USB_BASE_ADDR + 0xfff0))


///*----------------------SPI------------------------*/
#define SPIA                             0
#define SPIB                             1
#define SPI_BASE_ADDR(x)                 (0x40080000 + 0x10000 * (x))
#define REG_SPI_TX_DAT(x)                (*(volatile UINT8  *)(SPI_BASE_ADDR(x) + 0x00))
#define REG_SPI_RX_DAT(x)                (*(volatile UINT8  *)(SPI_BASE_ADDR(x) + 0x00))
#define REG_SPI_BAUD(x)                  (*(volatile UINT32 *)(SPI_BASE_ADDR(x) + 0x04))
#define REG_SPI_CTL(x)                   (*(volatile UINT32 *)(SPI_BASE_ADDR(x) + 0x08))
#define REG_SPI_TX_CTL(x)                (*(volatile UINT32 *)(SPI_BASE_ADDR(x) + 0x0c))
#define REG_SPI_RX_CTL(x)                (*(volatile UINT32 *)(SPI_BASE_ADDR(x) + 0x10))
#define REG_SPI_IE(x)                    (*(volatile UINT32 *)(SPI_BASE_ADDR(x) + 0x14))
#define REG_SPI_STATUS(x)                (*(volatile UINT32 *)(SPI_BASE_ADDR(x) + 0x18))
#define REG_SPI_TX_DLY(x)                (*(volatile UINT32 *)(SPI_BASE_ADDR(x) + 0x1c))
#define REG_SPI_BATCH(x)                 (*(volatile UINT32 *)(SPI_BASE_ADDR(x) + 0x20))
#define REG_SPI_CS(x)                    (*(volatile UINT32 *)(SPI_BASE_ADDR(x) + 0x24))
#define REG_SPI_OUT_EN(x)                (*(volatile UINT32 *)(SPI_BASE_ADDR(x) + 0x28))

///*----------------------SCU------------------------*/
#define SCU_BASE_ADDR                    0x88000000
#define REG_SCU_RCR		                 (*(volatile UINT32 *)(SCU_BASE_ADDR + 0x00))
#define REG_SCU_RSR		                 (*(volatile UINT32 *)(SCU_BASE_ADDR + 0x04))
#define REG_SCU_DIVR	                 (*(volatile UINT32 *)(SCU_BASE_ADDR + 0x08))
#define REG_SCU_CCR		                 (*(volatile UINT32 *)(SCU_BASE_ADDR + 0x0C))
#define REG_SCU_BCR		                 (*(volatile UINT32 *)(SCU_BASE_ADDR + 0x10))
#define REG_SCU_WMR		                 (*(volatile UINT32 *)(SCU_BASE_ADDR + 0x14))
#define REG_SCU_WUCR	                 (*(volatile UINT32 *)(SCU_BASE_ADDR + 0x18))
#define REG_SCU_WUSR	                 (*(volatile UINT32 *)(SCU_BASE_ADDR + 0x1C))
#define REG_SCU_PSCR1	                 (*(volatile UINT32 *)(SCU_BASE_ADDR + 0x20))
#define REG_SCU_PSCR2	                 (*(volatile UINT32 *)(SCU_BASE_ADDR + 0x24))
#define REG_SCU_PSCR3	                 (*(volatile UINT32 *)(SCU_BASE_ADDR + 0x28))
#define REG_SCU_PUCR	                 (*(volatile UINT32 *)(SCU_BASE_ADDR + 0x2c))
#define REG_SCU_REV	                     (*(volatile UINT32 *)(SCU_BASE_ADDR + 0x30))
#define REG_SCU_PHYCR	                 (*(volatile UINT32 *)(SCU_BASE_ADDR + 0x34))
#define REG_SCU_ANACR	                 (*(volatile UINT32 *)(SCU_BASE_ADDR + 0x38))
#define REG_SCU_RCCR	                 (*(volatile UINT32 *)(SCU_BASE_ADDR + 0x3c))
#define REG_SCU_BUZERCR	                 (*(volatile UINT32 *)(SCU_BASE_ADDR + 0x40))
#define REG_SCU_VDBATCR	                 (*(volatile UINT32 *)(SCU_BASE_ADDR + 0x44))
#define REG_SCU_MICCR	                 (*(volatile UINT32 *)(SCU_BASE_ADDR + 0x48))
#define REG_SCU_RC200CR                  (*(volatile UINT32 *)(SCU_BASE_ADDR + 0x4C))
#define REG_SCU_VERSION                  (*(volatile UINT32 *)(SCU_BASE_ADDR + 0x50))

///*----------------------UART------------------------*/
#define UARTA		                     0
#define UARTB		                     1
#define UART_BASE_ADDR(x)	             (0x88010000 + 0x10000 * (x))
#define REG_UART_DR(x)   	             (*(volatile UINT32 *)(UART_BASE_ADDR(x) + 0x00))
#define REG_UART_RSR(x)  	             (*(volatile UINT32 *)(UART_BASE_ADDR(x) + 0x04))
#define REG_UART_ECR(x)  	             (*(volatile UINT32 *)(UART_BASE_ADDR(x) + 0x04))
#define REG_UART_FR(x)   	             (*(volatile UINT32 *)(UART_BASE_ADDR(x) + 0x18))
#define REG_UART_ILPR(x) 	             (*(volatile UINT32 *)(UART_BASE_ADDR(x) + 0x20))
#define REG_UART_IBRD(x) 	             (*(volatile UINT32 *)(UART_BASE_ADDR(x) + 0x24))
#define REG_UART_FBRD(x) 	             (*(volatile UINT32 *)(UART_BASE_ADDR(x) + 0x28))
#define REG_UART_LCRH(x) 	             (*(volatile UINT32 *)(UART_BASE_ADDR(x) + 0x2C))
#define REG_UART_CR(x)   	             (*(volatile UINT32 *)(UART_BASE_ADDR(x) + 0x30))
#define REG_UART_IFLS(x) 	             (*(volatile UINT32 *)(UART_BASE_ADDR(x) + 0x34))
#define REG_UART_IMSC(x) 	             (*(volatile UINT32 *)(UART_BASE_ADDR(x) + 0x38))
#define REG_UART_RIS(x)  	             (*(volatile UINT32 *)(UART_BASE_ADDR(x) + 0x3C))
#define REG_UART_MIS(x)  	             (*(volatile UINT32 *)(UART_BASE_ADDR(x) + 0x40))
#define REG_UART_ICR(x)  	             (*(volatile UINT32 *)(UART_BASE_ADDR(x) + 0x44))

///*----------------------TIMER------------------------*/
#define TIMER0                           0
#define TIMER1                           1
#define TIMER2                           2

#define TIMER_BASE_ADDR		             0x88030000
#define REG_TIMER_ARR(x)                 (*(volatile UINT32 *)(TIMER_BASE_ADDR + 0x14 * (x)))
#define REG_TIMER_CNT(x)                 (*(volatile UINT32 *)(TIMER_BASE_ADDR + 0x14 * (x) + 4))
#define REG_TIMER_CR(x)                  (*(volatile UINT32 *)(TIMER_BASE_ADDR + 0x14 * (x) + 8))
#define REG_TIMER_IF(x)                  (*(volatile UINT32 *)(TIMER_BASE_ADDR + 0x14 * (x) + 12))
#define REG_TIMER_CIF(x)                 (*(volatile UINT32 *)(TIMER_BASE_ADDR + 0x14 * (x) + 16))
#define REG_TIMER_PSC                    (*(volatile UINT32 *)(TIMER_BASE_ADDR + 0x50))
#define REG_TIMER_ICMODE                 (*(volatile UINT32 *)(TIMER_BASE_ADDR + 0x54))
#define REG_TIMER_CCR                    (*(volatile UINT32 *)(TIMER_BASE_ADDR + 0x58))
#define REG_TIMER_CCIF                   (*(volatile UINT32 *)(TIMER_BASE_ADDR + 0x5C))
#define REG_TIMER_CX_CR(x)               (*(volatile UINT32 *)(TIMER_BASE_ADDR + 0x60 + 4 * (x)))
#define REG_TIMER_PCR                    (*(volatile UINT32 *)(TIMER_BASE_ADDR + 0x68))
#define REG_TIMER_CPIF                   (*(volatile UINT32 *)(TIMER_BASE_ADDR + 0x6C))
#define REG_TIMER_CX_PR(x)               (*(volatile UINT32 *)(TIMER_BASE_ADDR + 0x70 + 4 * (x)))

///*----------------------7816MS------------------------*/
#define ISO7816S_BASE_ADDR               0x88040000
#define REG_7816_ISR   	                 (*(volatile UINT32 *)(ISO7816S_BASE_ADDR + 0x00))
#define REG_7816_IER   	                 (*(volatile UINT32 *)(ISO7816S_BASE_ADDR + 0x04))
#define REG_7816_CTRL  	                 (*(volatile UINT32 *)(ISO7816S_BASE_ADDR + 0x08))
#define REG_7816_MCTRL                   (*(volatile UINT32 *)(ISO7816S_BASE_ADDR + 0x0c))
#define REG_7816_DR    	                 (*(volatile UINT32 *)(ISO7816S_BASE_ADDR + 0x10))
#define REG_7816_RSTT  	                 (*(volatile UINT32 *)(ISO7816S_BASE_ADDR + 0x14))
#define REG_7816_BPR   	                 (*(volatile UINT32 *)(ISO7816S_BASE_ADDR + 0x18))
#define REG_7816_ETU   	                 (*(volatile UINT32 *)(ISO7816S_BASE_ADDR + 0x1c))
#define REG_7816_EDC   	                 (*(volatile UINT32 *)(ISO7816S_BASE_ADDR + 0x20))
#define REG_7816_CCKCNT                  (*(volatile UINT32 *)(ISO7816S_BASE_ADDR + 0x24))

///*----------------------GPIO------------------------*/
#define GPIO_BASE_ADDR                   0x88050000
#define REG_GPIO_DIR                     (*(volatile UINT32 *)(GPIO_BASE_ADDR + 0x00))
#define REG_GPIO_SET                     (*(volatile UINT32 *)(GPIO_BASE_ADDR + 0x08))
#define REG_GPIO_CLR                     (*(volatile UINT32 *)(GPIO_BASE_ADDR + 0x0C))
#define REG_GPIO_ODATA                   (*(volatile UINT32 *)(GPIO_BASE_ADDR + 0x10))
#define REG_GPIO_IDATA                   (*(volatile UINT32 *)(GPIO_BASE_ADDR + 0x14))
#define REG_GPIO_IEN	                 (*(volatile UINT32 *)(GPIO_BASE_ADDR + 0x18))
#define REG_GPIO_IS                      (*(volatile UINT32 *)(GPIO_BASE_ADDR + 0x1c))
#define REG_GPIO_IBE                     (*(volatile UINT32 *)(GPIO_BASE_ADDR + 0x20))
#define REG_GPIO_IEV                     (*(volatile UINT32 *)(GPIO_BASE_ADDR + 0x24))
#define REG_GPIO_IC                      (*(volatile UINT32 *)(GPIO_BASE_ADDR + 0x28))
#define REG_GPIO_RIS                     (*(volatile UINT32 *)(GPIO_BASE_ADDR + 0x2c))
#define REG_GPIO_MIS                     (*(volatile UINT32 *)(GPIO_BASE_ADDR + 0x30))

///*----------------------CRC16------------------------*/
#define CRC16_BASE_ADDR                  0x88060000
#define REG_CRC16_DATA                   (*(volatile UINT32 *)(CRC16_BASE_ADDR + 0x00))
#define REG_CRC16_INIT                   (*(volatile UINT32 *)(CRC16_BASE_ADDR + 0x04))
#define REG_CRC16_CTRL                   (*(volatile UINT32 *)(CRC16_BASE_ADDR + 0x08))

///*---------------------WDT------------------------*/
#define WDT_BASE_ADDR                    0x88070000
#define REG_WDT_LOAD                     (*(volatile UINT32 *)(WDT_BASE_ADDR + 0x00))
#define REG_WDT_CNT                      (*(volatile UINT32 *)(WDT_BASE_ADDR + 0x04))
#define REG_WDT_CTRL                     (*(volatile UINT32 *)(WDT_BASE_ADDR + 0x08))
#define REG_WDT_FEED                     (*(volatile UINT32 *)(WDT_BASE_ADDR + 0x0C))
#define REG_WDT_INT_CLR_TIME             (*(volatile UINT32 *)(WDT_BASE_ADDR + 0x10))
#define REG_WDT_RIS                      (*(volatile UINT32 *)(WDT_BASE_ADDR + 0x14))

///*----------------------IIC------------------------*/
#define I2C_BASE_ADDR                    0x88080000
#define REG_I2C_CLK_DIV    	             (*(volatile UINT32 *)(I2C_BASE_ADDR + 0x04))
#define REG_I2C_CR    	                 (*(volatile UINT32 *)(I2C_BASE_ADDR + 0x08))
#define REG_I2C_SR    	                 (*(volatile UINT32 *)(I2C_BASE_ADDR + 0x0C))
#define REG_I2C_DR    	                 (*(volatile UINT32 *)(I2C_BASE_ADDR + 0x10))
#define REG_I2C_2SR    	                 (*(volatile UINT32 *)(I2C_BASE_ADDR + 0x04))
#define REG_I2C_SLAVE_ADDR1              (*(volatile UINT32 *)(I2C_BASE_ADDR + 0x00))
#define REG_I2C_SLAVE_ADDR2              (*(volatile UINT32 *)(I2C_BASE_ADDR + 0x14))
#define REG_I2C_DET                      (*(volatile UINT32 *)(I2C_BASE_ADDR + 0x18))
#define REG_I2C_FITER                    (*(volatile UINT32 *)(I2C_BASE_ADDR + 0x1C))
#define REG_I2C_FITER1                   (*(volatile UINT32 *)(I2C_BASE_ADDR + 0x20))

///*-----------------------Sensor----------------------*/
#define SENSOR_BASE_ADDR                 0x88090000
#define REG_SENSOR_SECR1                 (*(volatile UINT32 *)(SENSOR_BASE_ADDR + 0x00))
#define REG_SENSOR_SECR2                 (*(volatile UINT32 *)(SENSOR_BASE_ADDR + 0x04))
#define REG_SENSOR_EFDTH                 (*(volatile UINT32 *)(SENSOR_BASE_ADDR + 0x08))
#define REG_SENSOR_IFDTH                 (*(volatile UINT32 *)(SENSOR_BASE_ADDR + 0x0C))
#define REG_SENSOR_SEINTEN               (*(volatile UINT32 *)(SENSOR_BASE_ADDR + 0x10))
#define REG_SENSOR_SESR                  (*(volatile UINT32 *)(SENSOR_BASE_ADDR + 0x14))
#define REG_SENSOR_FDCNTR                (*(volatile UINT32 *)(SENSOR_BASE_ADDR + 0x18))

#ifdef __cplusplus
}
#endif

#endif  /* ARMCM0_H */
