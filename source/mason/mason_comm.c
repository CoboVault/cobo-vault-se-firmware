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
#define MASON_COMM_GLOBAL

/** Header file reference */
#include "mason_comm.h"
#include "mason_tags.h"
#include "mason_debug.h"
#include "mason_util.h"
#include "mason_commands.h"
#include "uart.h"
#include "timer.h"
#include "wdt.h"

/** Function declarations */
extern void enter_sleep(void);

/** Variable definitions */
bool bIsOnSleeping = false;
bool defense_trig_flag = false;

/** Function implementations */
/**
 * @functionname: mason_comm_handler
 * @description: 
 * @para: 
 * @return: 
 */
void mason_comm_handler(void)
{
	switch (gemCmdFSM)
	{
	case E_CMD_FSM_WAIT_CMD:
	{
		gemCmdFSM = mason_command_handler();
		break;
	}
	case E_CMD_FSM_MANAGE_CMD:
	{
		gemCmdFSM = mason_command_manager();
		break;
	}
	case E_CMD_FSM_MANAGE_ERR:
	{
		gemCmdFSM = mason_command_manage_error();
		break;
	}
	case E_CMD_FSM_IDLE:
	{
		if (!bIsOnSleeping)
		{
			bIsOnSleeping = true;
			timer_stop(TIMER1);
			timer_set_ms(TIMER1, 100000, enter_sleep);
			timer_start(TIMER1);
		}
		gemCmdFSM = E_CMD_FSM_WAIT_CMD;
		break;
	}
	default:
	{
		break;
	}
	}
}
