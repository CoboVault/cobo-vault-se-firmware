/*************************************************************************************************
Copyright (c) 2020 Cobo

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
in the file COPYING.  If not, see <http://www.gnu.org/licenses/>.
**************************************************************************************************/
/** Avoid duplicate definitions */
#define MAIN_GLOBAL

/** Header file reference */
#include "acl16.h"
#include "wdt.h"
#include "uart.h"
#include "timer.h"
#include "gpio.h"
#include "mason_errno.h"
#include "base58.h"
#include "mason_debug.h"
#include "queue.h"
#include "mason_comm.h"
#include "mason_iap.h"
#include "mason_hdw.h"
#include "secp256.h"
#include "crypto_api.h"
#include "mason_wallet.h"
#include "mason_setting.h"
#include "version_def.h"
/** Macro definitions*/
#define standby_auto ((void (*)(void))(ROM_BASE_ADDR + 0x00001053))

/* Force a compilation error if condition is false */
#ifndef _STATIC_ASSERT
#define _STATIC_ASSERT(expr) ((void)sizeof(char[1 - 2 * !!!(expr)]))
#endif

#define STATIC_ASSERT(COND, MSG) typedef char static_assertion_##MSG[(!!(COND)) * 2 - 1]
// token pasting madness:
#define COMPILE_TIME_ASSERT3(X, L) STATIC_ASSERT(X, at_line_##L)
#define COMPILE_TIME_ASSERT2(X, L) COMPILE_TIME_ASSERT3(X, L)
#define COMPILE_TIME_ASSERT(X) COMPILE_TIME_ASSERT2(X, __LINE__)

/** Variable definitions */
extern bool bIsOnSleeping;
extern bool defense_trig_flag;
static UINT32 tamper_check_counter = 0;

/** Function implementations */
/**
 * @functionname: low_power_init
 * @description: 
 * @para: 
 * @return: 
 */
void low_power_init(void)
{
	REG_SCU_PHYCR = 0x02 << 3;	//manual select internal RC
	REG_SCU_PHYCR &= ~(1 << 0); //USB_PHY soft reset, use for force to manual select internal RC
	delay(1);
	REG_SCU_PHYCR |= (1 << 0);

	//all PINs config as GPIO , reduce 1.5mA, config base on actual confiditons
#if 1
	REG_SCU_PSCR1 = 0;
	REG_SCU_PSCR2 = 0;
	REG_SCU_PSCR3 = 0;
#endif

	REG_SCU_PSCR2 = (REG_SCU_PSCR2 & ~(0x03 << 14)) | 0x00 << 14; // close clockout
	REG_SCU_PSCR2 &= ~(0x03 << 18);								  //DET0 as GPIO
	REG_SCU_PSCR2 |= (0x01 << 16);								  //enable RSTN

	REG_SCU_RCCR &= ~(1 << 7);				 //disable X12M 8mA
	REG_SCU_RCCR &= ~(1 << 0);				 //disable RC32K
	REG_SCU_PHYCR |= 1 << 2;				 //disable PLL 2.8mA
	REG_SCU_VDBATCR &= ~(1 << 0);			 //disable VBAT
	REG_SCU_MICCR &= ~((1 << 3) | (1 << 0)); //disable AUDIO/MIC

	init_module(BIT_EFC | BIT_ROM | BIT_SENSOR); //enable EFC/ROM/SENSOR;

//  SENSOR function power could be config (default BUS/TD/LD/AS/VD/PGD enable)
#if 1
	REG_SENSOR_SECR1 |= ((1 << 17) | (1 << 16) | (1 << 8) | (1 << 4) | (1 << 0)); //enable verify ROM/BUS/TD/IFD/EFD
	REG_SENSOR_SECR2 |= ((1 << 14) | (1 << 11) | (1 << 4) | (1 << 0));			  //enable verify LD/AS/VD/PGD
#else
	REG_SENSOR_SECR1 &= ~((1 << 17) | (1 << 16) | (1 << 8) | (1 << 4) | (1 << 0)); //forbid verify ROM/BUS/TD/IFD/EFD
	REG_SENSOR_SECR2 &= ~((1 << 14) | (1 << 11) | (1 << 4) | (1 << 0));			   //forbid verify LD/AS/VD/PGD
#endif
}
/**
 * @functionname: tamper_init
 * @description: 
 * @para: 
 * @return: 
 */
void tamper_init(void)
{
	stHDWStatusType status;

	mason_get_mode(&status);

	enable_module(BIT_GPIO);
	gpio_init();

	REG_SCU_PSCR2 &= ~(0x03 << 18); //DET0 as GPIO
	REG_SCU_PSCR1 &= ~(0x03 << 4);	//DET1 as GPIO
	REG_SCU_PSCR1 &= ~(0x03 << 6);	//DET2 as GPIO
	REG_SCU_PSCR1 &= ~(0x03 << 8);	//DET3 as GPIO

	//DET0, Active defense trigger, wakeup from sleep
	REG_GPIO_DIR &= ~BIT_DET0; //set input function
	REG_GPIO_IC |= BIT_DET0;   //clean irq
	REG_GPIO_IS |= BIT_DET0;   //level detect
	REG_GPIO_IEV &= ~BIT_DET0; //low level trigger

	//DET1, Passtive defense trigger,
	REG_GPIO_DIR &= ~BIT_DET1; //set input function
	REG_GPIO_IC |= BIT_DET1;   //clean irq
	REG_GPIO_IS &= ~BIT_DET1;  //edge detect
	REG_GPIO_IBE &= ~BIT_DET1; //single edge trigger
	REG_GPIO_IEV |= BIT_DET1;  //rising edge trigger

	//DET2, Passtive defense trigger,
	REG_GPIO_DIR &= ~BIT_DET2; //set input function
	REG_GPIO_IC |= BIT_DET2;   //clean irq
	REG_GPIO_IS &= ~BIT_DET2;  //edge detect
	REG_GPIO_IBE &= ~BIT_DET2; //single edge trigger
	REG_GPIO_IEV |= BIT_DET2;  //rising edge trigger

	//DET3, Passtive defense trigger,
	REG_GPIO_DIR &= ~BIT_DET3; //set input function
	REG_GPIO_IC |= BIT_DET3;   //clean irq
	REG_GPIO_IS &= ~BIT_DET3;  //edge detect
	REG_GPIO_IBE &= ~BIT_DET3; //single edge trigger
	REG_GPIO_IEV |= BIT_DET3;  //rising edge trigger

	if (!(status.emHDWStatus == E_HDWS_CHIP || status.emHDWStatus == E_HDWS_FACTORY))
	{
		REG_GPIO_IEN |= BIT_DET0; //Enable Irq
		REG_GPIO_IEN |= BIT_DET1; //Enable Irq
		REG_GPIO_IEN |= BIT_DET2; //Enable Irq
		REG_GPIO_IEN |= BIT_DET3; //Enable Irq
	}
}
/**
 * @functionname: enter_sleep
 * @description: 
 * @para: 
 * @return: 
 */
void enter_sleep(void)
{
	UINT32 backup_PSCR1, backup_PSCR2, backup_PSCR3;
	UINT32 backup_SECR1, backup_SECR2;
	UINT32 backup_RCR;
	stHDWStatusType status;

	mason_get_mode(&status);
	delay(0x80000);
	//printf("REG_SCU_PSCR2 = %08X\r\n", REG_SCU_PSCR2);
	printf("Sleep now!\r\n");
	backup_PSCR1 = REG_SCU_PSCR1;
	backup_PSCR2 = REG_SCU_PSCR2;
	backup_PSCR3 = REG_SCU_PSCR3;
	//all function pin as gpio
	REG_SCU_PSCR1 = 0;
	REG_SCU_PSCR2 = 0;
	REG_SCU_PSCR3 = 0;
	REG_SCU_PSCR2 |= (0x01 << 16);									  //enable RSTN
	REG_SCU_PSCR1 = (REG_SCU_PSCR1 & (~(0x0f << 22))) | (0x05 << 22); //keep UARTA

	backup_RCR = REG_SCU_RCR;
	REG_SCU_RCR &= ~((1 << 11) | (1 << 8) | (1 << 7) | (1 << 6) | (1 << 5) | (1 << 4) | (1 << 3) | (1 << 2) | (1 << 1) | (1 << 0)); //disable CGD/BUS/PGD/AS/FD/TDL/TDH/LD/VDH/VDL reset

	backup_SECR1 = REG_SENSOR_SECR1;
	backup_SECR2 = REG_SENSOR_SECR2;
	REG_SENSOR_SECR1 &= ~((1 << 17) | (1 << 16) | (1 << 8) | (1 << 4) | (1 << 0)); //forbid verify ROM/BUS/TD/IFD/EFD
	REG_SENSOR_SECR2 &= ~((1 << 14) | (1 << 11) | (1 << 4) | (1 << 0));			   //forbid verify LD/AS/VD/PGD

	REG_SCU_CCR |= (1 << 4);	//RC48M power down when standby
	REG_SCU_CCR |= (0x03 << 5); //LDO12 power down when standby

	if (status.emHDWStatus == E_HDWS_CHIP || status.emHDWStatus == E_HDWS_FACTORY)
	{
		REG_SCU_WUCR = (1 << 2) | (1 << 8); //enable uarta-rx & GPIO30
	}
	else
	{
		REG_SCU_WUCR = (1 << 2) | (1 << 8) | (1 << 9); //enable uarta-rx & GPIO30 & GPIO25 wakeup
	}

	init_module(BIT_SENSOR | BIT_ROM | BIT_EFC | BIT_UARTA | BIT_GPIO); // init modules

	standby_auto();
	//	REG_SCU_CCR |= 0x80000000;	  					//enter standby mode

	REG_SENSOR_SECR1 = backup_SECR1;
	REG_SENSOR_SECR2 = backup_SECR2;
	REG_SCU_RCR = backup_RCR;
	REG_SCU_PSCR1 = backup_PSCR1;
	REG_SCU_PSCR2 = backup_PSCR2;
	REG_SCU_PSCR3 = backup_PSCR3;

	delay(10000);
	enable_module(BIT_TIMER | BIT_WDT); //enable timer and WDT module
	printf("Wake up!!!\r\n");
	//printf("REG_SCU_PSCR2 = %08X\r\n", REG_SCU_PSCR2);

	bIsOnSleeping = false;
}
/**
 * @functionname: tamper_check
 * @description: 
 * @para: 
 * @return: 
 */
void tamper_check(void)
{
	stHDWStatusType status;

	if (tamper_check_counter && (tamper_check_counter < 1000000))
	{
		tamper_check_counter++;
		return;
	}
	else
	{
		tamper_check_counter = 1;
	}

	mason_get_mode(&status);

	if (status.emHDWStatus == E_HDWS_CHIP || status.emHDWStatus == E_HDWS_FACTORY)
	{
		return;
	}

	if (defense_trig_flag)
	{
		return;
	}

	if (flag_active_defense_trigger)
	{
		printf("Defense trigger active!\r\n");
		REG_GPIO_IEN |= BIT_DET0; //enable irq
		flag_active_defense_trigger = false;
	}

	if (flag_passtive_defense_trigger)
	{
		printf("Defense trigger passtive!\r\n");
		REG_GPIO_IEN |= (BIT_DET1 | BIT_DET2 | BIT_DET3); //enable irq
		flag_passtive_defense_trigger = false;
	}

	if (gpio_low(BIT_DET0, 500))
	{
		printf("Active defense !\r\n");
		defense_trig_flag = true;
	}

	if (gpio_high(BIT_DET1, 500)||gpio_high(BIT_DET2, 500)||gpio_high(BIT_DET3, 500))
	{
		printf("Passive defense !\r\n");
		defense_trig_flag = true;
	}

	if (E_HDWS_ATTACK == status.emHDWStatus)
	{
		printf("Status in ATTCK!\r\n");
		defense_trig_flag = true;
	}

	if (defense_trig_flag)
	{
		if (E_HDWS_ATTACK == status.emHDWStatus)
		{
			printf("Already in ATTCK!\r\n");
		}
		else
		{
			printf("Status goto ATTCK!\r\n");
			mason_set_mode(HDW_STATUS_ATTACK);
			mason_delete_wallet();
			mason_setting_delete();
		}
	}
}
/**
 * @functionname: timer_handler
 * @description: 
 * @para: 
 * @return: 
 */
void timer_handler(void)
{
	printf("Timer time out!\r\n");
}
/**
 * @functionname: mason_init
 * @description: 
 * @para: 
 * @return: 
 */
void mason_init(void)
{
	(void)mason_set_appvercode();
}
/**
 * @functionname: main
 * @description: 
 * @para: 
 * @return: 
 */
int main(void)
{
	SystemInit();
	low_power_init();
	enable_module(BIT_PKI);

	uart_init(UARTA, UART_BAUD_RATE);
	queue_init(&stQueue);

	timer_init();

	wdt_init();
	wdt_start();

	tamper_init();

	crypto_init();

#if VER_REL
	printf("Mason startup.\r\n");
#else
	printf("Mason Develop Mode, startup.\r\n");
#endif

	mason_init();

	while (1)
	{
		wdt_feed();
		mason_comm_handler();
		tamper_check();
	}
}
