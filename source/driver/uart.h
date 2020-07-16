#ifndef __UART_H__
#define __UART_H__

#include "common.h"
#include "circular_buffer.h"

extern UINT8 uart_rx_buf[];
extern cbuf_handle_t cbuf_handle;
/************************************************************************
 * function   : uart_set_baud_rate
 * Description: uart set baud rate
 * input : 
 *         UINT32 uart_index: Serial port number
 *         UINT32 clk_hz: cpu frequency
 *         UINT32 baud_rate: Series rate
 * return: none
 ************************************************************************/
void uart_set_baud_rate(UINT32 uart_index, UINT32 clk_hz, UINT32 baud_rate);

/************************************************************************
 * function   : uart_init
 * Description: uart initial for uart_index, cpu_mhz, baud_rate
 * input : 
 *         UINT32 uart_index: Serial port number
 *         UINT32 baud_rate: Series rate
 * return: none
 ************************************************************************/
void uart_init(UINT32 uart_index, UINT32 baud_rate);

/************************************************************************
 * function   : outbyte
 * Description: uart out byte
 * input : 
 *         UINT32 uart_index: Serial port number
 *         char c: out byte
 * return: none
 ************************************************************************/
void outbyte(UINT32 uart_index, char c);

/************************************************************************
 * function   : uart_send_bytes
 * Description: uart send bytes
 * input : 
 *         UINT32 uart_index: Serial port number
 *         UINT8* buff: out buffer
 *         UINT32 length: buffer length
 * return: none
 ************************************************************************/
void uart_send_bytes(UINT32 uart_index, UINT8 *buff, UINT32 length);

/************************************************************************
 * function   :UART_ReceByte
 * Description: 
 * input :
 * return: none
 ************************************************************************/
UINT8 UART_ReceByte(UINT8 UARTx, UINT8 *pData);

/************************************************************************
 * function   :UART_reset
 * Description: 
 * input :
 * return: none
 ************************************************************************/
void UART_reset(UINT8 UARTx);

#endif
