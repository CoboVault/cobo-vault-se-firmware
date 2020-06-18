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
#ifndef MASON_COMMANDS_H
#define MASON_COMMANDS_H

/** Avoid duplicate definitions */
#ifdef MASON_COMMANDS_GLOBAL
#define MASON_COMMANDS_EXT
#else
#define MASON_COMMANDS_EXT extern
#endif

/** Header file reference */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h> //memcpy...
#include "mason_errno.h"

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

/** Macro definitions*/
#define PROT_STX                0x02
#define PROT_ETX                0x03

#define CMD_H_MAX               10
#define CMD_L_MAX               8

#define USER_CHIP               0x01
#define USER_FACTORY            0x02
#define USER_ATTACK             0x04
#define USER_EMPTY              0x08
#define USER_WALLET             0x80
#define USER_ALL                0xFF

	/** Variable declarations */
	typedef enum
	{
		E_CMD_FSM_WAIT_CMD,
		E_CMD_FSM_MANAGE_CMD,
		E_CMD_FSM_MANAGE_ERR,
		E_CMD_FSM_IDLE,
	} emCmdFSMType;
	MASON_COMMANDS_EXT volatile emCmdFSMType gemCmdFSM;

	typedef enum
	{
		E_PROT_FSM_STX,
		E_PROT_FSM_FLAGS,
		E_PROT_FSM_MSG_LEN_H,
		E_PROT_FSM_MSG_LEN_L,
		E_PROT_FSM_MSG,
		E_PROT_FSM_ETX,
		E_PROT_FSM_LRC,
	} emProtType;
	MASON_COMMANDS_EXT volatile emProtType gemProtFSM;

	typedef enum
	{
		PLAIN = 0,
		ENCRYPT,
	} emEncryptType;

	typedef struct
	{
		emEncryptType enc : 1;
		uint8_t ver : 3;
		uint8_t RFU : 4;
	} stFlagType, *pstFlagType;

	typedef union
	{
		stFlagType stFlag;
		uint8_t flag;
	} unFlagType, *punFlagType;

	typedef struct
	{
		uint32_t len;
		uint8_t *pV;
		unFlagType unFlag;
	} stCMDType, *pstCMDType;
	MASON_COMMANDS_EXT volatile pstCMDType gpstCMD;

	typedef union
	{
		uint16_t u16;
		uint8_t buf[2];
	} un2ByteOrderType, unCMDNoType;

	typedef struct
	{
		uint32_t u32_1 : 8;
		uint32_t u32_2 : 8;
		uint32_t u32_3 : 8;
		uint32_t u32_4 : 8;
	} st4ByteOrderType;
	typedef union
	{
		uint32_t u32;
		uint8_t buf[4];
	} un4ByteOrderType;

	/** Function declarations */
	typedef void (*pfunc_mason_cmd_handler)(void *);
	typedef struct
	{
		uint8_t users;
		pfunc_mason_cmd_handler pFunc;
	} stCmdHandlerType;
	MASON_COMMANDS_EXT volatile stCmdHandlerType gstCmdHandlers[CMD_H_MAX][CMD_L_MAX];

	emCmdFSMType mason_command_handler(void);
	emCmdFSMType mason_command_manager(void);
	emCmdFSMType mason_command_manage_error(void);

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
} /* Extern C */
#endif

#endif
