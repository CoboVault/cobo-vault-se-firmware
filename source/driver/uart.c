#include "uart.h"
#include "timer.h"

UINT8 uart_rx_buf[UART_RX_BUF_MAX];
cbuf_handle_t cbuf_handle = NULL;

extern bool bIsOnSleeping;
/************************************************************************
 * function   :UARTA_IRQHandler
 * Description: 
 * input :
 * return: none
 ************************************************************************/
void UARTA_IRQHandler(void)
{
	UINT32 temp;

	temp = REG_UART_RIS(UARTA);

	if (temp & 0x10) // Rx int
	{
		REG_UART_ICR(UARTA) |= (1 << 4);

		while ((REG_UART_FR(UARTA) & 0x10) != 0x10) //read the DR ential Rx fifo  empty
		{
			if (!circular_buf_full(cbuf_handle))
			{
				circular_buf_put(cbuf_handle, REG_UART_DR(UARTA));
			}
			else
			{
				REG_UART_DR(UARTA);
			}
			bIsOnSleeping = false;
		}
	}
	else if (temp & 0x20) // Tx int
	{
		REG_UART_ICR(UARTA) |= (1 << 5);
	}
	else if (temp & 0x40) //Rx timeout int
	{
		REG_UART_ICR(UARTA) |= (1 << 6);
		while ((REG_UART_FR(UARTA) & 0x10) != 0x10)
		{
			if (!circular_buf_full(cbuf_handle))
			{
				circular_buf_put(cbuf_handle, REG_UART_DR(UARTA));
			}
			else
			{
				REG_UART_DR(UARTA);
			}
		}
	}
	else
	{
		REG_UART_ICR(UARTA) = 0xfff; //clear int
	}

	NVIC_ClearPendingIRQ(UARTA_IRQn); 
}
/************************************************************************
 * function   :UARTB_IRQHandler
 * Description: 
 * input :
 * return: none
 ************************************************************************/
void UARTB_IRQHandler(void)
{
	UINT32 temp;

	temp = REG_UART_RIS(UARTB);

	if (temp & 0x10) // Rx int
	{
		REG_UART_ICR(UARTB) |= (1 << 4);

		while ((REG_UART_FR(UARTB) & 0x10) != 0x10) //read the DR ential Rx fifo  empty
		{
			REG_UART_DR(UARTB);
		}
	}
	else if (temp & 0x20) // Tx int
	{
		REG_UART_ICR(UARTB) |= (1 << 5);

	}
	else if (temp & 0x40) //Rx timeout int
	{
		REG_UART_ICR(UARTB) |= (1 << 6);

		while ((REG_UART_FR(UARTB) & 0x10) != 0x10)
		{
			REG_UART_DR(UARTB);
		}
	}
	else
	{
		REG_UART_ICR(UARTB) = 0xfff; //clear int
	}
	NVIC_ClearPendingIRQ(UARTB_IRQn); 
}

/************************************************************************
 * function   : uart_set_baud_rate
 * Description: uart set baud rate
 * input : 
 *         UINT32 uart_index: Serial port number
 *         UINT32 clk_hz: cpu frequency
 *         UINT32 baud_rate: Series rate
 * return: none
 ************************************************************************/
void uart_set_baud_rate(UINT32 uart_index, UINT32 clk_hz, UINT32 baud_rate)
{
	UINT32 temp, divider, remainder, fraction;

	//	cpu_mhz = cpu_mhz * 1000000;
	temp = 16 * baud_rate;
	divider = clk_hz / temp;
	remainder = clk_hz % temp;
	temp = 1 + (128 * remainder) / temp;
	fraction = temp / 2;

	REG_UART_IBRD(uart_index) = divider + (fraction >> 6);
	REG_UART_FBRD(uart_index) = fraction & 0x3f;
}

/************************************************************************
 * function   : uart_init
 * Description: uart initial for uart_index, cpu_mhz, baud_rate
 * input : 
 *         UINT32 uart_index: Serial port number
 *         UINT32 baud_rate: Series rate
 * return: none
 ************************************************************************/
void uart_init(UINT32 uart_index, UINT32 baud_rate)
{
	UINT32 uart_clk_hz;

	enable_module(BIT_UARTA);
	uart_clk_hz = PClock;
	if(uart_index == UARTA) // uspport CTS RTS
	{
		reset_module(RESET_UARTA);
		REG_SCU_PSCR1 = (REG_SCU_PSCR1 &( ~(0x0f << 22))) | (0x05 << 22); //select UARTA func PIN

#ifdef UARTA_USE_RTSMODE
		REG_SCU_PSCR1 = (REG_SCU_PSCR1 & (~(0x03 << 26))) | (0x01 << 26); //confing RTS IO reuse
		REG_UART_CR(UARTA) |= (1 << 14);
#endif
#ifdef UARTA_USE_CTSMODE
		REG_SCU_PSCR1 = (REG_SCU_PSCR1 & (~(0x03 << 28))) | (0x01 << 28); //config CTS IO reuse 
		REG_UART_CR(UARTA) |= (1 << 15);
#endif
		NVIC_ClearPendingIRQ(UARTA_IRQn);
		NVIC_EnableIRQ(UARTA_IRQn);
	}
	else
	{
		reset_module(RESET_UARTB);
		{
			REG_SCU_PSCR3 &= ~0x01; //GPIO20 input											
			REG_SCU_PSCR2 = (REG_SCU_PSCR2 & (~(0x0f << 6))) | (0x05 << 6); //select UARTB func PIN GPIO19,GPIO20
		}

		NVIC_ClearPendingIRQ(UARTB_IRQn);
		NVIC_EnableIRQ(UARTB_IRQn);
	}

	REG_UART_CR(uart_index) &= ~0x01; //disable uart
	uart_set_baud_rate(uart_index, uart_clk_hz, baud_rate);

#ifdef UART_ENABLE_FIFO_MODE
	REG_UART_LCRH(uart_index) = 0x70; //8 databit 1 stopbit none verifybit open FIFO func 
	REG_UART_IFLS(uart_index) = 0x12; //FIFO send and rev irq trigger num 8 
	REG_UART_IMSC(uart_index) = 0x50; //open Rx_INT , Rx_TIMEOUT_INT
#else
	REG_UART_LCRH(uart_index) = 0x60;  //8 databit 1 stopbit none verifybit close FIFO func 
	REG_UART_IMSC(uart_index) = 0x10; // open Rx_INT 
#endif

	cbuf_handle = circular_buf_init(uart_rx_buf, sizeof(uart_rx_buf));

	REG_UART_CR(uart_index) = 0x0301; //enable uart
	REG_UART_ICR(uart_index) = 0xfff; //clear int
}

/************************************************************************
 * function   : outbyte
 * Description: uart out byte
 * input : 
 *         UINT32 uart_index: Serial port number
 *         char c: out byte
 * return: none
 ************************************************************************/
void outbyte(UINT32 uart_index, char c)
{
	REG_UART_DR(uart_index) = c;

	while (REG_UART_FR(uart_index) & 0x08); //wait for idle
}

/************************************************************************
 * function   : uart_send_bytes
 * Description: uart send bytes
 * input : 
 *         UINT32 uart_index: Serial port number
 *         UINT8* buff: out buffer
 *         UINT32 length: buffer length
 * return: none
 ************************************************************************/
void uart_send_bytes(UINT32 uart_index, UINT8 *buff, UINT32 length)
{
	UINT32 i;

	for (i = 0; i < length; i++)
	{
		outbyte(uart_index, *buff++);
	}
}
/************************************************************************
 * function   :UART_ReceByte
 * Description: 
 * input :
 * return: none
 ************************************************************************/
UINT8 UART_ReceByte(UINT8 UARTx, UINT8 *pData)
{
	if (circular_buf_get(cbuf_handle, pData))
	{
		return FALSE;
	}

	return TRUE;
}

struct __FILE //please select UART NO( UARTA or UARTB)
{
	int handle;
	/* Add whatever you need here */
};
FILE __stdout;
FILE __stdin;
/************************************************************************
 * function   :fputc
 * Description: 
 * input :
 * return: none
 ************************************************************************/
int fputc(int ch, FILE *f)
{
	/* Place your implementation of fputc here */
	/* e.g. write a character to the USART */
	outbyte(UARTA, ch); //debug uart: UARTA or UARTB
	return ch;
}
/************************************************************************
 * function   :UART_reset
 * Description: 
 * input :
 * return: none
 ************************************************************************/
void UART_reset(UINT8 UARTx)
{
	circular_buf_reset(cbuf_handle);
}

