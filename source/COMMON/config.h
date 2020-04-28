
#ifndef __CONFIG_H__
#define __CONFIG_H__

#define DEBUG

#ifdef DEBUG
#define printfS printf
#define printfB8 printf_buff_byte
#define printfB32 printf_buff_word
#else
#define printfS(format, ...) ((void)0)
#define printfB8(buff, byte_len) ((void)0)
#define printfB32(buff, word_len) ((void)0)
#endif

/*--------------- clock----------------------- */
#define FCLK 48

/*--------------- uart----------------------- */
#define UART_BAUD_RATE 115200
//#define UART_Tx_INT_MODE
//#define UART_ENABLE_FIFO_MODE

//#define UARTA_USE_RTSMODE
//#define UARTA_USE_CTSMODE

#define UART_RX_BUF_MAX 2048

#endif
