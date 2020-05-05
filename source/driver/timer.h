
#ifndef __TIMER_H__
#define __TIMER_H__

#include  "common.h"

/*----------------------TIMER BIT------------------------*/
#define VAL_TIMER_ENABLE               1
#define VAL_TIMER_DISABLE              0

#define VAL_TIMER_CONTROL_MOD_FREE     0
#define VAL_TIMER_CONTROL_MOD_CYC      2
#define VAL_TIMER_CONTROL_MOD_SINGLE   3

#define VAL_TIMER_INT_MASK             1
#define VAL_TIMER_INT_NOMASK           0

#define VAL_TIMER_COUNT_UP             0
#define VAL_TIMER_COUNT_DOWN           1
#define VAL_TIMER_COUNT_CENTER         2

#define VAL_TIMER_PRES_DIVISOR_1       0
#define VAL_TIMER_PRES_DIVISOR_2       1
#define VAL_TIMER_PRES_DIVISOR_4       2
#define VAL_TIMER_PRES_DIVISOR_8       3
#define VAL_TIMER_PRES_DIVISOR_16      4
#define VAL_TIMER_PRES_DIVISOR_32      5
#define VAL_TIMER_PRES_DIVISOR_64      6
#define VAL_TIMER_PRES_DIVISOR_128     7

#define CAPTURE_TRIGGER_RISING         0
#define CAPTURE_TRIGGER_FALLING        1

extern volatile UINT8 flag_timer0_int;
extern volatile UINT8 flag_timer0_pwm_int;
extern volatile UINT8 flag_timer0_cc_int;

extern volatile UINT8 flag_timer1_int;
extern volatile UINT8 flag_timer1_cc_int;
extern volatile UINT8 flag_timer1_pwm_int;

extern volatile UINT8 flag_timer2_int;

/************************************************************************
 * function   : timer_init
 * Description: timer initial
 * input : none
 * return: none
 ************************************************************************/
void timer_init(void);

/************************************************************************
 * function   : timer_set_us
 * Description: timer set_us
 * input :
 *         UINT8 num: TIMER0,1,2
 *         UINT32 timer_us: delay timer_us
 *         void(*pFunc)() pFunc: processing function
 * return: none
 ************************************************************************/
void timer_set_us(UINT8 num, UINT32 timer_us, void (*pFunc)());

/************************************************************************
 * function   : timer_set_ms
 * Description: timer set_ms
 * input :
 *         UINT8 num: TIMER0,1,2
 *         UINT32 timer_us: delay timer_ms
 *         void(*pFunc)() pFunc: processing function
 * return: none
 ************************************************************************/
void timer_set_ms(UINT8 num, UINT32 timer_ms, void (*pFunc)());

/************************************************************************
 * function   : timer_start
 * Description: timer start
 * input :
 *         UINT8 num: TIMER0,1,2
 * return:
 ************************************************************************/
void timer_start(UINT8 num);

/************************************************************************
 * function   : timer_stop
 * Description: timer stop
 * input :
 *         UINT8 num: TIMER0,1,2
 * return:
 ************************************************************************/
void timer_stop(UINT8 num);

/************************************************************************
 * function   : capture_set
 * Description: capture set
 * input :
 *         UINT8 num: only TIMER0,1
 *         UINT8 source: 0-GPIO,1-USB_RECV,2-AUDIO_RECV_OUT
 *         UINT8 divider: divider 2^n
 *         UINT8 trigger: 0 -- CAPTURE_TRIGGER_RISING
 *                        1 -- CAPTURE_TRIGGER_FALLING
 *         void(*pFunc)() pFunc: processing function
 * return: none
 ************************************************************************/
void capture_set(UINT8 num,UINT8 source,UINT8 divider, UINT8 trigger, void (*pFunc)());

/************************************************************************
 * function   : capture_start
 * Description: capture start
 * input :
 *         UINT8 num: only TIMER0,1
 * return: none
 ************************************************************************/
void capture_start(UINT8  num);

/************************************************************************
 * function   : capture_stop
 * Description: capture stop
 * input :
 *         UINT8 num: only TIMER0,1
 * return: none
 ************************************************************************/
void capture_stop(UINT8  num);

/************************************************************************
 * function   : pwm_set
 * Description: pwm set frequence
 * input :
 *         UINT8 num: only TIMER0,1
 *         UINT32 timer_freq: timer frequence
 *         UINT32 pwm_freq: pwm frequence
 * return: none
 ************************************************************************/
void pwm_set(UINT8 num, UINT32 timer_arr, UINT32 pwm_pr);

/************************************************************************
 * function   : pwm_start
 * Description: pwm start
 * input :
 *         UINT8 num: only TIMER0,1
 * return: none
 ************************************************************************/
void pwm_start(UINT8 num);

/************************************************************************
 * function   : pwm_stop
 * Description: pwm stop
 * input :
 *         UINT8 num: only TIMER0,1
 * return: none
 ************************************************************************/
void pwm_stop(UINT8 num);

/************************************************************************
 * function   : pwm_output_wave
 * Description: pwm output wave --hz
 * input :
 *         UINT8 num: only TIMER0,1
 *         UINT32 freq_hz: output freq
 *         UINT32 duty: 0 - 100 percent
 * return: none
 ************************************************************************/
void pwm_output_wave(UINT8 num, UINT32 freq_hz, UINT8 duty);

void timer_output_stop(UINT8 num);



#endif


