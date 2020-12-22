;/*****************************************************************************
; * @file:    startup_CM0.s
; * @purpose: CMSIS Cortex-M0 Core Device Startup File 
; *           for the ARM 'Microcontroller Prototyping System' 
; * @version: V1.0
; * @date:    
; *
; *****************************************************************************/
Stack_Size      EQU     0x00002800
Heap_Size       EQU     0x00000800
;__initial_sp    EQU    0x20003000	   ;config sp value

                AREA    STACK, NOINIT, READWRITE, ALIGN=3
Stack_Mem       SPACE   Stack_Size
__initial_sp

                AREA    HEAP, NOINIT, READWRITE, ALIGN=3
__heap_base
Heap_Mem        SPACE   Heap_Size
__heap_limit

                PRESERVE8
                THUMB

; Vector Table Mapped to Address 0 at Reset

                AREA    RESET, DATA, READONLY
                EXPORT __Vectors

__Vectors       
				DCD     __initial_sp                ; Top of Stack
                DCD     Reset_Handler               ; Reset Handler
                DCD     NMI_Handler                 ; NMI Handler
                DCD     HardFault_Handler           ; Hard Fault Handler
                DCD     0                           ; Reserved
                DCD     0                           ; Reserved
                DCD     0                           ; Reserved
                DCD     0                           ; Reserved
                DCD     0                           ; Reserved
                DCD     0                           ; Reserved
                DCD     0                           ; Reserved
                DCD     SVC_Handler                 ; SVCall Handler, like SWI
                DCD     0                           ; Reserved
                DCD     0                           ; Reserved
                DCD     PendSV_Handler              ; PendSV Handler
                DCD     SysTick_Handler             ; SysTick Handler, sys timer

                ; External Interrupts
                DCD     WDT_IRQHandler				; 0:  WDT_IRQHandler    
                DCD     TIMER0_IRQHandler			; 1:  TIMER0_IRQHandler 
                DCD     TIMER1_IRQHandler			; 2:  TIMER1_IRQHandler 
                DCD     GPIO_IRQHandler				; 3:  GPIO_IRQHandler 
                DCD     MS7816_IRQHandler           ; 4:  MS7816_IRQHandler
                DCD     USB_IRQHandler              ; 5:  USB_IRQHandler 
                DCD     EFC_IRQHandler              ; 6:  EFC_IRQHandler
                DCD     SPIA_IRQHandler	          	; 7:  SPIA_IRQHandler
                DCD     SPIB_IRQHandler	          	; 8:  SPIB_IRQHandler
                DCD     MPU_IRQHandler	          	; 9:  MPU_IRQHandler
                DCD     SENSOR_IRQHandler           ; 10: SENSOR_IRQHandler
                DCD     SM1_IRQHandler				; 11: SM1_IRQHandler/SCB2_IRQHandler 
                DCD    	DES_IRQHandler				; 12: DES_IRQHandler
                DCD     SM4_IRQHandler				; 13: SM4_IRQHandler
                DCD     PKI_IRQHandler				; 14: PKI_IRQHandler
                DCD     UARTA_IRQHandler			; 15: UARTA_IRQHandler
                DCD     UARTB_IRQHandler			; 16: UARTB_IRQHandler
                DCD     I2C_IRQHandler              ; 17: I2C_IRQHandler
                DCD     SCDRST_IRQHandler           ; 18: SCDRST_IRQHandler
                DCD     MIC_IRQHandler				; 19: MIC_IRQHandler
                DCD     AES_IRQHandler              ; 20: AES_IRQHandler
                DCD     WAKEUP_IRQHandler           ; 21: WAKEUP_IRQHandler
                DCD     TIMER2_IRQHandler           ; 22: TIMER2_IRQHandler
                DCD     0                           ; 23: Reserved
                DCD     0                           ; 24: Reserved
                DCD     0                           ; 25: Reserved
                DCD     0                           ; 26: Reserved
                DCD     0                           ; 27: Reserved
                DCD     0                           ; 28: Reserved 
                DCD     0                           ; 29: Reserved
                DCD     0                           ; 30: Reserved
                DCD     0                           ; 31: Reserved

                AREA    |.text|, CODE, READONLY

Reset_Handler   PROC
                EXPORT  Reset_Handler             [WEAK]
                IMPORT  __main

                ;IMPORT  __set_CONTROL
				;MOVS     R0, #0x01		;user level,Thread and handler mode share same stack MSP
				;BL 	    __set_CONTROL	  ;jump to user level thread mode


                LDR     R0, =__main
                BX      R0	              ;BX:jump to address from register.B:jump to related address
                ENDP


NMI_Handler     PROC
                EXPORT  NMI_Handler               [WEAK]
                B       .
                ENDP
HardFault_Handler\
                PROC
                EXPORT  HardFault_Handler         [WEAK]
                B       .
                ENDP
SVC_Handler     PROC
                EXPORT  SVC_Handler               [WEAK]
                B       .
                ENDP
PendSV_Handler  PROC
                EXPORT  PendSV_Handler            [WEAK]
                B       .
                ENDP
SysTick_Handler PROC
                EXPORT  SysTick_Handler           [WEAK]
                B       .
                ENDP

Default_Handler PROC
				EXPORT   WDT_IRQHandler			  [WEAK]
              	EXPORT   TIMER0_IRQHandler		  [WEAK]
               	EXPORT   TIMER1_IRQHandler		  [WEAK]
               	EXPORT   GPIO_IRQHandler		  [WEAK]	
               	EXPORT   MS7816_IRQHandler    	  [WEAK]
                EXPORT   USB_IRQHandler       	  [WEAK]
                EXPORT   EFC_IRQHandler       	  [WEAK] 
                EXPORT   SPIA_IRQHandler	      [WEAK]
                EXPORT   SPIB_IRQHandler	      [WEAK]
                EXPORT   MPU_IRQHandler	      	  [WEAK]
                EXPORT   SENSOR_IRQHandler    	  [WEAK]
                EXPORT   SM1_IRQHandler			  [WEAK]
                EXPORT   DES_IRQHandler			  [WEAK]
                EXPORT   SM4_IRQHandler			  [WEAK]
                EXPORT   PKI_IRQHandler			  [WEAK]
                EXPORT   UARTA_IRQHandler		  [WEAK]
                EXPORT   UARTB_IRQHandler		  [WEAK]
				EXPORT   I2C_IRQHandler       	  [WEAK]
				EXPORT   SCDRST_IRQHandler    	  [WEAK]
				EXPORT   MIC_IRQHandler			  [WEAK]	
				EXPORT   AES_IRQHandler    	      [WEAK]
				EXPORT   WAKEUP_IRQHandler		  [WEAK]
                EXPORT   TIMER2_IRQHandler		  [WEAK]						
WDT_IRQHandler			
TIMER0_IRQHandler		
TIMER1_IRQHandler		
GPIO_IRQHandler			
MS7816_IRQHandler   
USB_IRQHandler      
EFC_IRQHandler      
SPIA_IRQHandler	    
SPIB_IRQHandler	    
MPU_IRQHandler	    
SENSOR_IRQHandler   
SM1_IRQHandler			
DES_IRQHandler			
SM4_IRQHandler			
PKI_IRQHandler			
UARTA_IRQHandler		
UARTB_IRQHandler		
I2C_IRQHandler      
SCDRST_IRQHandler   
MIC_IRQHandler	
AES_IRQHandler
WAKEUP_IRQHandler
TIMER2_IRQHandler
                B       .
                ENDP								 								 
                 
                ALIGN
                                 
; User Initial Stack & Heap
                 
                IF      :DEF:__MICROLIB
                 
                EXPORT  __initial_sp
                EXPORT  __heap_base
                EXPORT  __heap_limit
                 
                ELSE
                 
                IMPORT  __use_two_region_memory
                EXPORT  __user_initial_stackheap
__user_initial_stackheap
                 
                LDR     R0, =  Heap_Mem
                LDR     R1, =(Stack_Mem + Stack_Size)
                LDR     R2, = (Heap_Mem +  Heap_Size)
                LDR     R3, = Stack_Mem
                BX      LR

                ALIGN

                ENDIF

                END
