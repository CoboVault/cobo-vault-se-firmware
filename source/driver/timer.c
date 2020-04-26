#include  "timer.h"

volatile UINT8 flag_timer0_int = 0;
volatile UINT8 flag_timer0_cc_int = 0;
volatile UINT8 flag_timer0_pwm_int = 0;

volatile UINT8 flag_timer1_int = 0;
volatile UINT8 flag_timer1_cc_int = 0;
volatile UINT8 flag_timer1_pwm_int = 0;

volatile UINT8 flag_timer2_int = 0;

void (*TimerFunc[3])(void) = { 0 };

//timer2 have no capture / pwm
void (*CaptureFunc[3])(void) = { 0 };
void (*PwmFunc[3])(void) = { 0 };

/************************************************************************
 * function   :TIMER0_IRQHandler
 * Description: 
 * input :
 * return: none
 ************************************************************************/
/*TIMER0 int handler*/
void TIMER0_IRQHandler(void)
{
    if(REG_TIMER_IF(TIMER0))
    {
        flag_timer0_int = 1;
        REG_TIMER_CIF(TIMER0) = 0xff; // clean irq
        if(TimerFunc[0] != NULL)
        {
            ((void(*)())(TimerFunc[0]))(); //timer0 irq func
        }
    }
    if(REG_TIMER_CCIF & 0x01)
    {
        flag_timer0_cc_int = 1;
        REG_TIMER_CCIF |= 0x01; //clean CC0 irq
        if(CaptureFunc[0] != NULL)
        {
            ((void (*)())(CaptureFunc[0]))(); //timer irq func
        }
    }
    if(REG_TIMER_CPIF & 0x01)
    {
        flag_timer0_pwm_int = 1;
        REG_TIMER_CPIF |= 0x01; //clean PWM0 irq
        /*if(PwmFunc[0] != NULL)
        {
            ((void (*)())(PwmFunc[0]))(); //timer irq func
        }*/
    }
}

/************************************************************************
 * function   :TIMER1_IRQHandler
 * Description: 
 * input :
 * return: none
 ************************************************************************/
/*TIMER1 int handler*/
void TIMER1_IRQHandler(void)
{
    if(REG_TIMER_IF(TIMER1))
    {
        flag_timer1_int = 1;
        REG_TIMER_CIF(TIMER1) = 0xff; 
        if(TimerFunc[1] != NULL)
        {
            ((void(*)())(TimerFunc[1]))(); 
        }
    }
    if(REG_TIMER_CCIF & 0x02)
    {
        flag_timer1_cc_int = 1;
        REG_TIMER_CCIF |= 0x02; 
        if(CaptureFunc[1] != NULL)
        {
            ((void (*)())(CaptureFunc[1]))(); 
        }
    }
    if(REG_TIMER_CPIF & 0x02)
    {
        flag_timer1_pwm_int = 1;
        REG_TIMER_CPIF |= 0x02; 
        /*if(PwmFunc[1] != NULL)
        {
            ((void (*)())(PwmFunc[1]))(); 
        }*/
    }
}

/************************************************************************
 * function   :TIMER2_IRQHandler
 * Description: 
 * input :
 * return: none
 ************************************************************************/
/*TIMER2 int handler*/
void TIMER2_IRQHandler(void)
{
    if(REG_TIMER_IF(TIMER2))
    {
        flag_timer2_int = 1;
        REG_TIMER_CIF(TIMER2) = 0xff;
        if(TimerFunc[2] != NULL)
        {
            ((void (*)())(TimerFunc[2]))();
        }
    }
}
/************************************************************************
 * function   : timer_init
 * Description: timer initial
 * input : none
 * return: none
 ************************************************************************/
void timer_init(void)
{
	enable_module(BIT_TIMER);

    NVIC_ClearPendingIRQ(TIMER0_IRQn);
    NVIC_EnableIRQ(TIMER0_IRQn);

    NVIC_ClearPendingIRQ(TIMER1_IRQn);
    NVIC_EnableIRQ(TIMER1_IRQn);

    NVIC_ClearPendingIRQ(TIMER2_IRQn);
    NVIC_EnableIRQ(TIMER2_IRQn);
}
/************************************************************************
 * function   : timer_set_us
 * Description: timer set_us
 * input :
 *         UINT8 num: TIMER0,1,2
 *         UINT32 timer_us: delay timer_us
 *         void(*pFunc)() pFunc: processing function
 * return: none
 ************************************************************************/
void timer_set_us(UINT8 num, UINT32 timer_us, void (*pFunc)())
{
    UINT32 timer_clk_hz;

    UINT32 tmp;


    timer_clk_hz = PClock;

    TimerFunc[num] = pFunc;

    REG_TIMER_CR(num) =  0x01 << 4 | VAL_TIMER_CONTROL_MOD_CYC << 1; //down counter,interrupt not masked,Cyclic mode,close

    //divided by 8,timer clk = (timer_clk_hz/8)

    REG_TIMER_PSC = (REG_TIMER_PSC & ~(0x07 << (3 * num))) | (VAL_TIMER_PRES_DIVISOR_8 << (3 * num)); //8 div freq

    tmp = timer_clk_hz / ((1 << VAL_TIMER_PRES_DIVISOR_8) * 1000000); //real clk of timer
    tmp *= timer_us;

    REG_TIMER_ARR(num) = tmp; //delay tmp us


}

/************************************************************************
 * function   : timer_set_ms
 * Description: timer set_ms
 * input :
 *         UINT8 num: TIMER0,1,2
 *         UINT32 timer_us: delay timer_ms
 *         void(*pFunc)() pFunc: processing function
 * return: none
 ************************************************************************/
void timer_set_ms(UINT8 num, UINT32 timer_ms, void (*pFunc)())
{
    UINT32 timer_clk_hz;

    UINT32 tmp;

    timer_clk_hz = PClock;

    TimerFunc[num] = pFunc;

    REG_TIMER_CR(num) = (VAL_TIMER_COUNT_DOWN << 4) | (VAL_TIMER_CONTROL_MOD_CYC << 1); //down counter,interrupt not masked,Cyclic mode,close

    //divided by 8,timer clk = (timer_clk_hz/8)

    REG_TIMER_PSC = (REG_TIMER_PSC & ~(0x07 << (3 * num))) | (VAL_TIMER_PRES_DIVISOR_8 << (3 * num)); 

    tmp = timer_clk_hz / ((1 << VAL_TIMER_PRES_DIVISOR_8) * 1000); 
    tmp *= timer_ms;

    REG_TIMER_ARR(num) = tmp; 

}

/************************************************************************
 * function   : timer_start
 * Description: timer start
 * input :
 *         UINT8 num: TIMER0,1,2
 * return:
 ************************************************************************/
void timer_start(UINT8 num)
{
    REG_TIMER_CR(num) |= 0x01;      //enable timer
}

/************************************************************************
 * function   : timer_stop
 * Description: timer stop
 * input :
 *         UINT8 num: TIMER0,1,2
 * return:
 ************************************************************************/
void timer_stop(UINT8 num)
{
    REG_TIMER_CR(num) &= ~0x01;    //close timer
    REG_TIMER_CIF(num) = 0xff; //clear irq
}

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
void capture_set(UINT8 num, UINT8 source, UINT8 divider, UINT8 trigger, void (*pFunc)())
{

    divider &= 0x07;

    if(num == TIMER0)
    {
        REG_SCU_PSCR3 = (REG_SCU_PSCR3 & ~(0x03 << 7)) | source << 7; //cc source   = gpio20
        if(source == 0)
        {
            REG_SCU_PSCR2 = (REG_SCU_PSCR2 & ~(0x03 << 6)) | 0x02 << 6; //pwm mode
        }
    }
    else if(num == TIMER1)
    {
        REG_SCU_PSCR3 = (REG_SCU_PSCR3 & ~(0x03 << 9)) | source << 9; //cc source   = gpio20
        if(source == 0)
        {
            REG_SCU_PSCR2 = (REG_SCU_PSCR2 & ~(0x03 << 8)) | 0x02 << 8; //pwm mode
        }
    }
    else
    {
        return;
    }

    CaptureFunc[num] = pFunc;

    REG_TIMER_PSC = (REG_TIMER_PSC & ~(0x07 << (3 * num))) | (divider << (3 * num)); //8 div freq
    REG_TIMER_CR(num) = 0x01 << 3 | 0x00 << 1; //up counter,interrupt masked,free mode,close
    REG_TIMER_ICMODE &= ~(1 << num);

    REG_TIMER_CCR = (REG_TIMER_CCR & ~(0x07 << (3 * num))) | (trigger << (2 + (3 * num))); //enable irq ,close CC module
}

/************************************************************************
 * function   : capture_start
 * Description: capture start
 * input :
 *         UINT8 num: only TIMER0,1
 * return: none
 ************************************************************************/
void capture_start(UINT8 num)
{
    REG_TIMER_CCR |= 0x01 << (3 * num); //Start Capture
}

/************************************************************************
 * function   : capture_stop
 * Description: capture stop
 * input :
 *         UINT8 num: only TIMER0,1
 * return: none
 ************************************************************************/
void capture_stop(UINT8 num)
{
    REG_TIMER_CCR &= ~(0x01 << (3 * num)); //close Capture
}

/************************************************************************
 * function   : pwm_set
 * Description: pwm set frequence
 * input :
 *         UINT8 num: only TIMER0,1
 *         UINT32 timer_arr: timer load value
 *         UINT32 pwm_pr: pwm compare vale
 * return: none
 ************************************************************************/
void pwm_set(UINT8 num, UINT32 timer_arr, UINT32 pwm_pr)
{
    if(num == TIMER0)
    {
        REG_SCU_PSCR2 = (REG_SCU_PSCR2 & ~(0x03 << 6)) | 0x02 << 6; //pwm0
    }
    else if(num == TIMER1)
    {
        REG_SCU_PSCR2 = (REG_SCU_PSCR2 & ~(0x03 << 8)) | 0x02 << 8; //pwm1
    }
    else
    {
        return;
    }

    REG_TIMER_PSC = (REG_TIMER_PSC & ~(0x07 << (3 * num))) | (VAL_TIMER_PRES_DIVISOR_1 << (3 * num)); // 1 div freq
    REG_TIMER_CR(num) = (VAL_TIMER_COUNT_DOWN << 4) | (VAL_TIMER_INT_MASK << 3) | (VAL_TIMER_CONTROL_MOD_CYC << 1); //down counter,interrupt masked,Cyclic mode,close
    REG_TIMER_ICMODE |= 1 << num;

    REG_TIMER_ARR(num) = timer_arr;
    REG_TIMER_CX_PR(num) = pwm_pr;

    REG_TIMER_PCR &= ~(1 << (2 * num + 1));  //enable pwm interrupt
}

/************************************************************************
 * function   : pwm_start
 * Description: pwm start
 * input :
 *         UINT8 num: only TIMER0,1
 * return: none
 ************************************************************************/
void pwm_start(UINT8 num)
{
    REG_TIMER_PCR |= 1 << (2 * num);  //enable
}

/************************************************************************
 * function   : pwm_stop
 * Description: pwm stop
 * input :
 *         UINT8 num: only TIMER0,1
 * return: none
 ************************************************************************/
void pwm_stop(UINT8 num)
{
    REG_TIMER_PCR &= ~(1 << (2 * num));
}

/************************************************************************
 * function   : pwm_output_wave
 * Description: pwm output wave --hz
 * input :
 *         UINT8 num: only TIMER0,1
 *         UINT32 freq_hz: output freq
 *         UINT32 duty: 0- 100 percent
 * return: none
 ************************************************************************/
void pwm_output_wave(UINT8 num, UINT32 freq_hz, UINT8 duty)
{
    UINT32 frep;

    if(num == TIMER0)
    {
        REG_SCU_PSCR2 = (REG_SCU_PSCR2 & ~(0x03 << 6)) | 0x02 << 6; //pwm0
    }
    else if(num == TIMER1)
    {
        REG_SCU_PSCR2 = (REG_SCU_PSCR2 & ~(0x03 << 8)) | 0x02 << 8; //pwm1
    }
    else
    {
        return;
    }

    REG_TIMER_PSC = (REG_TIMER_PSC & ~(0x07 << (3 * num))) | (VAL_TIMER_PRES_DIVISOR_1 << (3 * num)); // 1 div freq
    REG_TIMER_CR(num) = (VAL_TIMER_COUNT_DOWN << 4) | (VAL_TIMER_INT_MASK << 3) | (VAL_TIMER_CONTROL_MOD_CYC << 1); //down counter,interrupt masked,Cyclic mode,close
    REG_TIMER_ICMODE |= 1 << num;

    frep = PClock / freq_hz  - 1;

    REG_TIMER_ARR(num) = frep;
    REG_TIMER_CX_PR(num) = (frep * duty) / 100;

    REG_TIMER_PCR |= 1 << (2 * num + 1);  //disable pwm interrupt



    timer_start(num); //enable timer0
    pwm_start(num);
}
/************************************************************************
 * function   :
 * Description: 
 * input :
 * return: none
 ************************************************************************/
void timer_output_stop(UINT8 num)
{
    timer_stop(num); //enable timer0
    pwm_stop(num);
}

