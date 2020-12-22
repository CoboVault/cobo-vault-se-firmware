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
#define MASON_COMMANDS_GLOBAL

/** Header file reference */
#include "mason_commands.h"
#include "uart.h"
#include "mason_comm.h"
#include "queue.h"

#include "TLV.h"
#include "stack.h"
#include "mason_storage.h"
#include "util.h"
#include "mason_tags.h"
#include "eflash.h"
#include "mason_iap.h"
#include "version_def.h"
#include "mason_hdw.h"
#include "gpio.h"
#include "wdt.h"
#include "stdio.h"
#include "mason_wallet.h"
#include "bip44.h"
#include "mason_key.h"
#include "base58.h"
#include "crypto_api.h"
#include <mason_setting.h>

#if (1 != VER_REL)
#define MASON_TEST
#endif

/** Macro definitions*/
#define MASON_CMD_DECLARE_VARIABLE(ret)         \
	emRetType emRet = ret;                      \
	uint8_t bufRet[2] = {0x00, 0x00};           \
	pstStackType pstS = (pstStackType)pContext; \
	stStackType stStack = {{NULL}, -1};         \
	stackElementType pstTLV = NULL;

#define MASON_CMD_RESP_OUTPUT()                                                           \
	u16_to_buf(bufRet, (uint16_t)emRet);                                                  \
	mason_cmd_append_to_outputTLVArray(&stStack, TLV_T_RESPONSE, sizeof(bufRet), bufRet); \
	mason_cmd_end_outputTLVArray(&stStack, gpstCMD->unFlag.stFlag.enc ? ENCRYPT : PLAIN); \
	stack_destroy(&stStack);

/** Variable definitions */
MASON_COMMANDS_EXT volatile emCmdFSMType gemCmdFSM = E_CMD_FSM_IDLE;

/** Function declarations */
uint32_t stream_to_tlv(pstStackType pstStack, const char *stream, uint32_t streamLen);
void mason_execute_cmd(pstStackType pstStack);
emRetType mason_cmd_preprocess(pstCMDType pstCMD);
void mason_cmd_invalid(void *pContext);
emRetType mason_cmd_verify_passwd(pstStackType pstStack, stackElementType *pelement);
emRetType mason_cmd_verify_mnemonic(pstStackType pstStack, stackElementType *pelement);
emRetType mason_cmd_verify_token(pstStackType pstStack, stackElementType *pelement);
emRetType mason_cmd_verify_fing(pstStackType pstStack, stackElementType *pelement);
static void mason_cmd0102_get_information(void *pContext);
static void mason_cmd0107_factory_activate(void *pContext);
static void mason_cmd0108_reboot(void *pContext);
static void mason_cmd0201_iap_request(void *pContext);
static void mason_cmd0203_iap_verify(void *pContext);
static void mason_cmd0301_get_entropy(void *pContext);
static void mason_cmd0302_create_wallet(void *pContext);
static void mason_cmd0303_change_wallet_passphrase(void *pContext);
static void mason_cmd0305_get_extpubkey(void *pContext);
static void mason_cmd0306_delete_wallet(void *pContext);
static void mason_cmd0307_sign(void *pContext);
static void mason_cmd0308_get_masterkey_fingerprint(void *pContext);
#ifdef MASON_TEST
static void mason_cmd0401_generate_public_key_from_private_key(void *pContext);
#endif
static void mason_cmd0402_derive_deposit_key(void *pContext);
static void mason_cmd0502_mnemonic_verify(void *pContext);
static void mason_cmd0701_web_authentication(void *pContext);
static void mason_cmd0802_tamper_test(void *pContext);
static void mason_cmd0901_usrpwd_modify(void *pContext);
static void mason_cmd0902_usrpwd_reset(void *pContext);
static void mason_cmd0903_usrpwd_verify(void *pContext);
static void mason_cmd0904_usrsettings(void *pContext);
static void mason_cmd0905_message_gen(void *pContext);
static void mason_cmd0906_usrfing_create(void *pContext);
static void mason_cmd0907_usrfing_verify(void *pContext);
static void mason_cmd0908_token_delete(void *pContext);
#ifdef MASON_TEST
static void mason_cmd0A01_crypto_sign_test(void *pContext);
static void mason_cmd0A02_crypto_verify_test(void *pContext);
static void mason_cmd0A06_hash_test(void *pContext);
#endif

MASON_COMMANDS_EXT volatile stCmdHandlerType gstCmdHandlers[CMD_H_MAX][CMD_L_MAX] =
	{
		{//01 XX
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd0102_get_information,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_CHIP | USER_FACTORY,
			 mason_cmd0107_factory_activate,
		 },
		 {
			 USER_ALL,
			 mason_cmd0108_reboot,
		 }},
		{//02 XX
		 {
			 USER_CHIP | USER_FACTORY | USER_EMPTY | USER_WALLET,
			 mason_cmd0201_iap_request,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_CHIP | USER_FACTORY | USER_EMPTY | USER_WALLET,
			 mason_cmd0203_iap_verify,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 }},
		{//03 XX
		 {
			 USER_CHIP | USER_FACTORY | USER_EMPTY | USER_WALLET,
			 mason_cmd0301_get_entropy,
		 },
		 {
			 USER_CHIP | USER_FACTORY | USER_EMPTY | USER_WALLET,
			 mason_cmd0302_create_wallet,
		 },
		 {
			 USER_WALLET,
			 mason_cmd0303_change_wallet_passphrase,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_WALLET,
			 mason_cmd0305_get_extpubkey,
		 },
		 {
			 USER_ALL,
			 mason_cmd0306_delete_wallet,
		 },
		 {
			 USER_WALLET,
			 mason_cmd0307_sign,
		 },
		 {
			 USER_WALLET,
			 mason_cmd0308_get_masterkey_fingerprint,
		 }},
		{//04 XX
		 {
			 USER_ALL,
#ifdef MASON_TEST
			 mason_cmd0401_generate_public_key_from_private_key,
#else
			 mason_cmd_invalid,
#endif
		 },
		 {
			 USER_WALLET,
			 mason_cmd0402_derive_deposit_key,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 }},
		{//05 XX
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_WALLET,
			 mason_cmd0502_mnemonic_verify,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 }},
		{//06 XX
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 }},
		{//07 XX
		 {
			 USER_ALL,
			 mason_cmd0701_web_authentication,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 }},
		{//08 XX
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd0802_tamper_test,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 }},
		{//09 XX
		 {
			 USER_CHIP | USER_FACTORY | USER_EMPTY | USER_WALLET,
			 mason_cmd0901_usrpwd_modify,
		 },
		 {
			 USER_CHIP | USER_FACTORY | USER_EMPTY | USER_WALLET,
			 mason_cmd0902_usrpwd_reset,
		 },
		 {
			 USER_CHIP | USER_FACTORY | USER_EMPTY | USER_WALLET,
			 mason_cmd0903_usrpwd_verify,
		 },
		 {
			 USER_CHIP | USER_FACTORY | USER_EMPTY | USER_WALLET,
			 mason_cmd0904_usrsettings,
		 },
		 {
			 USER_CHIP | USER_FACTORY | USER_EMPTY | USER_WALLET,
			 mason_cmd0905_message_gen,
		 },
		 {
			 USER_CHIP | USER_FACTORY | USER_EMPTY | USER_WALLET,
			 mason_cmd0906_usrfing_create,
		 },
		 {
			 USER_CHIP | USER_FACTORY | USER_EMPTY | USER_WALLET,
			 mason_cmd0907_usrfing_verify,
		 },
		 {
			 USER_CHIP | USER_FACTORY | USER_EMPTY | USER_WALLET,
			 mason_cmd0908_token_delete,
		 }},
		{//0A XX
		 {
			 USER_ALL,
#ifdef MASON_TEST
			 mason_cmd0A01_crypto_sign_test,
#else
			 mason_cmd_invalid,
#endif
		 },
		 {
			 USER_ALL,
#ifdef MASON_TEST
			 mason_cmd0A02_crypto_verify_test,
#else
			 mason_cmd_invalid,
#endif
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
#ifdef MASON_TEST
			 mason_cmd0A06_hash_test,
#else
			 mason_cmd_invalid,
#endif
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 },
		 {
			 USER_ALL,
			 mason_cmd_invalid,
		 }}};

/** Function implementations */
/**
 * @functionname: stream_to_tlv
 * @description: 
 * @para: 
 * @return: 
 */
uint32_t stream_to_tlv(pstStackType pstStack, const char *stream, uint32_t streamLen)
{
	pstStackType pstS = pstStack;
	uint32_t index = 0;
	pstTLVType pstTLV = NULL;

	while (index < streamLen)
	{
		pstTLV = (pstTLVType)calloc(1, sizeof(stTLVType));
		if (NULL == pstTLV)
		{
			return index;
		}
		index = tlv_get_tag(pstTLV, stream, index);
		index = tlv_get_len(pstTLV, stream, index);
		index = tlv_get_value(pstTLV, stream, index);
		stack_push(pstS, pstTLV);
	}

	return index;
}
/**
 * @functionname: stack_search_by_tag
 * @description: 
 * @para: 
 * @return: 
 */
bool stack_search_by_tag(pstStackType pstStack, stackElementType *pelement, uint16_t T)
{
	pstStackType pstS = pstStack;
	int index = 0;
	stackElementType *pstTLV = pelement;

	for (index = 0; index <= pstS->top; index++)
	{
		stack_get(pstS, pstTLV, index);
		if (T == (*pstTLV)->T)
		{
			return true;
		}
	}

	return false;
}
/**
 * @functionname: stack_search_CMDNo
 * @description: 
 * @para: 
 * @return: 
 */
bool stack_search_CMDNo(pstStackType pstStack, stackElementType *pelement, unCMDNoType *punCMDNo)
{
	stackElementType *pstTLV = pelement;

	if ((stack_search_by_tag(pstStack, pstTLV, 0x0001)) && (sizeof(unCMDNoType) == (*pstTLV)->L))
	{
		memcpy(punCMDNo->buf, (*pstTLV)->pV, (*pstTLV)->L);
		return true;
	}
	return false;
}
/**
 * @functionname: mason_command_handler
 * @description: 
 * @para: 
 * @return: 
 */
emCmdFSMType mason_command_handler(void)
{
	static uint8_t dat = 0x00;
	static uint8_t lrc = 0x00;
	static uint32_t index = 0;

	while (UART_ReceByte(UARTA, &dat)) /* recieve command data*/
	{
		// TMR_ClrCnt(T0);
		lrc ^= dat;
		switch (gemProtFSM) /* cmd parse FSM*/
		{
		case E_PROT_FSM_STX:
		{
			if (PROT_STX == dat)
			{
				// TMR_Start(T0);
				gemProtFSM = E_PROT_FSM_FLAGS;
				lrc = PROT_STX;
			}
			break;
		}
		case E_PROT_FSM_FLAGS:
		{
			gpstCMD = (pstCMDType)calloc(1, sizeof(stCMDType));
			if (NULL == gpstCMD)
			{
				gemProtFSM = E_PROT_FSM_STX;
				return E_CMD_FSM_MANAGE_ERR;
			}
			gpstCMD->unFlag.flag = dat;
			gemProtFSM = E_PROT_FSM_MSG_LEN_H;
			break;
		}
		case E_PROT_FSM_MSG_LEN_H:
		{
			gpstCMD->len = (uint16_t)dat << 8;
			gemProtFSM = E_PROT_FSM_MSG_LEN_L;
			break;
		}
		case E_PROT_FSM_MSG_LEN_L:
		{
			gpstCMD->len |= (uint16_t)dat;
			if ((gpstCMD->len > 0) && (gpstCMD->len <= UART_RX_BUF_MAX))
			{
				gemProtFSM = E_PROT_FSM_MSG;
				index = 0;
				gpstCMD->pV = (uint8_t *)calloc(gpstCMD->len, sizeof(uint8_t));
				if (NULL == gpstCMD->pV)
				{
					gemProtFSM = E_PROT_FSM_STX;
					return E_CMD_FSM_MANAGE_ERR;
				}
			}
			else /* illegal len*/
			{
				gemProtFSM = E_PROT_FSM_STX;
				/* add error msg here*/
				return E_CMD_FSM_MANAGE_ERR;
			}
			break;
		}
		case E_PROT_FSM_MSG:
		{
			gpstCMD->pV[index++] = dat;
			if (index >= gpstCMD->len)
			{
				gemProtFSM = E_PROT_FSM_ETX;
			}
			break;
		}
		case E_PROT_FSM_ETX:
		{
			if (PROT_ETX == dat)
			{
				gemProtFSM = E_PROT_FSM_LRC;
			}
			else
			{
				gemProtFSM = E_PROT_FSM_STX;
				/* add error msg here*/
				return E_CMD_FSM_MANAGE_ERR;
			}
			break;
		}
		case E_PROT_FSM_LRC:
		{
			gemProtFSM = E_PROT_FSM_STX;
			if (0x00 == lrc) /* recieve cmd success*/
			{
				enqueue_safe(&stQueue, gpstCMD);
				return E_CMD_FSM_MANAGE_CMD;
			}
			else
			{
				/* add error msg here*/
				return E_CMD_FSM_MANAGE_ERR;
			}
		}
		default:
		{
			gemProtFSM = E_PROT_FSM_STX;
			return E_CMD_FSM_MANAGE_ERR;
		}
		}
	}

	return E_CMD_FSM_IDLE;
}
/**
 * @functionname: mason_command_manager
 * @description: 
 * @para: 
 * @return: 
 */
emCmdFSMType mason_command_manager(void)
{
	stStackType stStack = {{NULL}, -1};
	pstCMDType pstCMD = NULL;

	while (!queue_is_empty(&stQueue))
	{
		pstCMD = dequeue(&stQueue);

		mason_cmd_preprocess(pstCMD);

		stack_init(&stStack);

		stream_to_tlv(&stStack, (const char *)(pstCMD->pV), pstCMD->len);

		mason_execute_cmd(&stStack);

		stack_destroy(&stStack);

		UART_reset(UARTA);
		if (pstCMD)
		{
			if (pstCMD->pV)
			{
				free(pstCMD->pV);
				pstCMD->pV = NULL;
			}
			free(pstCMD);
			pstCMD = NULL;
		}
	}
	return E_CMD_FSM_WAIT_CMD;
}
/**
 * @functionname: mason_command_usr
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_command_usr(emHDWStatusType status, uint8_t usr)
{
	switch (status)
	{
	case E_HDWS_CHIP:
	{
		return ((usr & USER_CHIP) ? true : false);
	}
	case E_HDWS_FACTORY:
	{
		return ((usr & USER_FACTORY) ? true : false);
	}
	case E_HDWS_ATTACK:
	{
		return ((usr & USER_ATTACK) ? true : false);
	}
	case E_HDWS_EMPTY:
	{
		return ((usr & USER_EMPTY) ? true : false);
	}
	case E_HDWS_WALLET:
	{
		return ((usr & USER_WALLET) ? true : false);
	}
	default:
		break;
	}
	return false;
}
/**
 * @functionname: mason_execute_cmd
 * @description: 
 * @para: 
 * @return: 
 */
void mason_execute_cmd(pstStackType pstStack)
{
	bool is_succeed = false;
	stackElementType pstTLV = NULL;
	unCMDNoType unCMDNo = {0};
	stCmdHandlerType cmdHandle = {0};
	stHDWStatusType status;

	is_succeed = stack_search_CMDNo(pstStack, &pstTLV, &unCMDNo);

	if ((false == is_succeed) || unCMDNo.buf[0] > CMD_H_MAX || unCMDNo.buf[1] > CMD_H_MAX || 0 == unCMDNo.buf[0] || 0 == unCMDNo.buf[1])
	{
		mason_cmd_invalid((void *)pstStack);
		return;
	}

	cmdHandle = gstCmdHandlers[unCMDNo.buf[0] - 1][unCMDNo.buf[1] - 1];
	mason_get_mode(&status);

	if (mason_command_usr(status.emHDWStatus, cmdHandle.users))
	{
		cmdHandle.pFunc((void *)pstStack);
	}
	else
	{
		mason_cmd_invalid((void *)pstStack);
	}
}
/**
 * @functionname: mason_cmd_preprocess
 * @description: 
 * @para: 
 * @return: 
 */
emRetType mason_cmd_preprocess(pstCMDType pstCMD)
{
	emRetType emRet = ERT_OK;
	pstCMDType pstC = pstCMD;

	if (pstC->unFlag.stFlag.enc)
	{
		emRet = mason_storage_encryption(0, pstC->pV, pstC->len, pstC->pV);
		pstC->len -= pstC->pV[pstC->len - 1];
	}

	return emRet;
}
/**
 * @functionname: mason_cmd_tlv_to_buf
 * @description: 
 * @para: 
 * @return: 
 */
uint16_t mason_cmd_tlv_to_buf(pstStackType pstStack, uint8_t *pBuf)
{
	uint16_t i, j;
	int index = 0;
	pstStackType pstS = pstStack;
	uint8_t *pB = pBuf;

	for (i = 0; i <= pstS->top; i++)
	{
		pB[index++] = (uint8_t)(pstS->stack[i]->T >> 8);
		pB[index++] = (uint8_t)(pstS->stack[i]->T);
		pB[index++] = (uint8_t)(pstS->stack[i]->L >> 8);
		pB[index++] = (uint8_t)(pstS->stack[i]->L);
		for (j = 0; j < pstS->stack[i]->L; j++)
		{
			pB[index++] = pstS->stack[i]->pV[j];
		}
	}

	return index;
}
/**
 * @functionname: mason_cmd_init_outputTLVArray
 * @description: 
 * @para: 
 * @return: 
 */
void mason_cmd_init_outputTLVArray(pstStackType pstStack)
{
	stack_init(pstStack);
}
/**
 * @functionname: mason_cmd_append_to_outputTLVArray
 * @description: 
 * @para: 
 * @return: 
 */
emRetType mason_cmd_append_to_outputTLVArray(pstStackType pstStack, uint16_t tag, uint16_t len, uint8_t *pValue)
{
	emRetType emRet = ERT_OK;
	pstStackType pstS = pstStack;
	pstTLVType pstTLV = NULL;

	pstTLV = (pstTLVType)calloc(1, sizeof(stTLVType));

	if (pstTLV == NULL)
	{
		//printf("Calloc failed %02X %u\n", tag, (uint32_t)sizeof(stTLVType));
		return ERT_MallocFail;
	}

	pstTLV->T = tag;
	pstTLV->L = len;
	pstTLV->pV = (const char *)pValue;

	stack_push(pstS, pstTLV);

	return emRet;
}
/**
 * @functionname: mason_cmd_append_ele_to_outputTLVArray
 * @description: 
 * @para: 
 * @return: 
 */
emRetType mason_cmd_append_ele_to_outputTLVArray(pstStackType pstStack, stackElementType element)
{
	emRetType emRet = ERT_OK;
	pstStackType pstS = pstStack;
	pstTLVType pstTLV = NULL;

	pstTLV = (pstTLVType)calloc(1, sizeof(stTLVType));

	if (pstTLV == NULL)
	{
		//printf("Calloc failed\n");
		return ERT_MallocFail;
	}

	pstTLV->T = element->T;
	pstTLV->L = element->L;
	pstTLV->pV = element->pV;

	stack_push(pstS, pstTLV);

	return emRet;
}
/**
 * @functionname: mason_cmd_end_outputTLVArray
 * @description: 
 * @para: 
 * @return: 
 */
void mason_cmd_end_outputTLVArray(pstStackType pstStack, emEncryptType eEnc)
{
	pstStackType pstS = pstStack;
	int index = 0;
	uint8_t *strSend = NULL;
	uint16_t tlvLen = 0;
	uint16_t bodyLen = 0;
	uint16_t strSendLen = 0;

	for (index = 0; index <= pstS->top; index++)
	{
		tlvLen += (4 + pstS->stack[index]->L);
	}
	bodyLen = tlvLen;
	if (ENCRYPT == eEnc)
	{
		bodyLen += 8 - (tlvLen & 7); /* add padding length*/
	}
	strSendLen = bodyLen + 6; /* add protocol head*/
	strSend = (uint8_t *)calloc(strSendLen, sizeof(uint8_t));
	if (NULL == strSend)
	{
		return;
	}

	strSend[0] = PROT_STX;
	strSend[1] = 0x00;
	strSend[2] = (uint8_t)(bodyLen >> 8);
	strSend[3] = (uint8_t)(bodyLen);

	mason_cmd_tlv_to_buf(pstS, strSend + 4);

	if (ENCRYPT == eEnc)
	{
		strSend[1] |= 0x01;
		data_padding(strSend + 4, &tlvLen, PKCS5);
		mason_storage_encryption(0, strSend + 4, bodyLen, strSend + 4);
	}

	strSend[bodyLen + 4] = PROT_ETX;
	strSend[bodyLen + 5] = get_lrc(strSend, bodyLen + 5);

	uart_send_bytes(UARTA, strSend, strSendLen);

	if (NULL != strSend)
	{
		free(strSend);
	}
}
/**
 * @functionname: mason_command_manage_error
 * @description: 
 * @para: 
 * @return: 
 */
emCmdFSMType mason_command_manage_error(void)
{
	emRetType emRet = ERT_CommInvalidCMD;
	uint8_t bufRet[2] = {0x00, 0x00};
	stStackType stStack = {{NULL}, -1};

	mason_cmd_init_outputTLVArray(&stStack);
	mason_cmd_append_to_outputTLVArray(&stStack, TLV_T_ERR_MSG, 4, (uint8_t *)"err!");
	u16_to_buf(bufRet, (uint16_t)emRet);
	mason_cmd_append_to_outputTLVArray(&stStack, TLV_T_RESPONSE, sizeof(bufRet), bufRet);
	mason_cmd_end_outputTLVArray(&stStack, PLAIN);
	stack_destroy(&stStack);
	UART_reset(UARTA);
	if (gpstCMD)
	{
		if (gpstCMD->pV)
		{
			free(gpstCMD->pV);
			gpstCMD->pV = NULL;
		}
		free(gpstCMD);
		gpstCMD = NULL;
	}
	return E_CMD_FSM_WAIT_CMD;
}
/**
 * @functionname: mason_cmd_invalid
 * @description: 
 * @para: 
 * @return: 
 */
void mason_cmd_invalid(void *pContext)
{
	emRetType emRet = ERT_CommInvalidCMD;
	uint8_t bufRet[2] = {0x00, 0x00};
	stStackType stStack = {{NULL}, -1};

	mason_cmd_init_outputTLVArray(&stStack);
	u16_to_buf(bufRet, (uint16_t)emRet);
	mason_cmd_append_to_outputTLVArray(&stStack, TLV_T_RESPONSE, sizeof(bufRet), bufRet);
	mason_cmd_end_outputTLVArray(&stStack, PLAIN);
	stack_destroy(&stStack);
}
/**
 * @functionname: mason_cmd_verify_passwd
 * @description: 
 * @para: 
 * @return: 
 */
emRetType mason_cmd_verify_passwd(pstStackType pstStack, stackElementType *pelement)
{
	emRetType emRet = ERT_Verify_Init;
	uint8_t *cur_pwd = NULL;
	uint16_t cur_pwd_len = 0;
	uint8_t time = 0;

	do
	{
		if (!stack_search_by_tag(pstStack, pelement, TLV_T_USRPWD_CUR))
		{
			emRet = ERT_needUsrPass;
			break;
		}

		if (!mason_usrcount_increment())
		{
			emRet = ERT_UsrPassFAIL;
			break;
		}

		cur_pwd = (uint8_t *)(*pelement)->pV;
		cur_pwd_len = (*pelement)->L;
		if (ERT_Verify_Success != mason_usrpwd_verify(cur_pwd, cur_pwd_len))
		{
			mason_usrcount_check();
			emRet = ERT_UsrPassVerifyFail;
			break;
		}
		mason_usrcount_ara();
		//sleep
		gen_random(&time, 8);
		_delay_us(time * 2);

		cur_pwd = NULL;
		cur_pwd_len = 0;
		if (!stack_search_by_tag(pstStack, pelement, TLV_T_USRPWD_CUR))
		{
			emRet = ERT_needUsrPass;
			break;
		}
		cur_pwd = (uint8_t *)(*pelement)->pV;
		cur_pwd_len = (*pelement)->L;
		if (ERT_Verify_Success != mason_usrpwd_verify(cur_pwd, cur_pwd_len))
		{
			mason_usrcount_check();
			emRet = ERT_UsrPassVerifyFail;
			break;
		}
		mason_usrcount_ara();
		mason_usrcount_reset();
		emRet = ERT_Verify_Success;
	} while (0);

	if (cur_pwd)
	{
		memset(cur_pwd, 0, cur_pwd_len);
		cur_pwd = NULL;
		cur_pwd_len = 0;
	}
	return emRet;
}
/**
 * @functionname: mason_cmd_verify_mnemonic
 * @description: 
 * @para: 
 * @return: 
 */
emRetType mason_cmd_verify_mnemonic(pstStackType pstStack, stackElementType *pelement)
{
	emRetType emRet = ERT_Verify_Init;
	uint8_t *mnemonic = NULL;
	uint16_t mnemonic_len = 0;
	uint8_t time = 0;

	do
	{
		if (!stack_search_by_tag(pstStack, pelement, TLV_T_MNEMONIC))
		{
			emRet = ERT_MnemonicNotMatch;
			break;
		}
		mnemonic = (uint8_t *)(*pelement)->pV;
		mnemonic_len = (*pelement)->L;
		if (ERT_Verify_Success != mason_verify_mnemonic((char *)mnemonic, mnemonic_len))
		{
			emRet = ERT_MnemonicNotMatch;
			break;
		}

		//sleep
		gen_random(&time, 8);
		_delay_us(time * 2);

		mnemonic = NULL;
		mnemonic_len = 0;
		if (!stack_search_by_tag(pstStack, pelement, TLV_T_MNEMONIC))
		{
			emRet = ERT_MnemonicNotMatch;
			break;
		}
		mnemonic = (uint8_t *)(*pelement)->pV;
		mnemonic_len = (*pelement)->L;
		if (ERT_Verify_Success != mason_verify_mnemonic((char *)mnemonic, mnemonic_len))
		{
			emRet = ERT_MnemonicNotMatch;
			break;
		}

		emRet = ERT_Verify_Success;
	} while (0);

	if (mnemonic)
	{
		memset(mnemonic, 0, mnemonic_len);
		mnemonic = NULL;
		mnemonic_len = 0;
	}
	return emRet;
}
/**
 * @functionname: mason_cmd_verify_token
 * @description: 
 * @para: 
 * @return: 
 */
emRetType mason_cmd_verify_token(pstStackType pstStack, stackElementType *pelement)
{
	emRetType emRet = ERT_Verify_Init;
	setting_token_t token = {0};
	uint8_t *token_v = NULL;
	uint16_t token_l = 0;
	uint8_t time = 0;

	do
	{
		if (!stack_search_by_tag(pstStack, pelement, TLV_T_TOKEN))
		{
			emRet = ERT_needToken;
			break;
		}
		token_v = (uint8_t *)(*pelement)->pV;
		token_l = (*pelement)->L;
		if (SETTING_TOKEN_LEN != token_l)
		{
			emRet = ERT_TokenVerifyFail;
			break;
		}
		memcpy(token.token, token_v, token_l);
		token.length = token_l;
		if (ERT_Verify_Success != mason_token_verify(&token))
		{
			mason_token_delete();
			emRet = ERT_TokenVerifyFail;
			break;
		}

		//sleep
		gen_random(&time, 8);
		_delay_us(time * 2);

		memset(&token, 0, sizeof(setting_token_t));
		token_v = NULL;
		token_l = 0;
		if (!stack_search_by_tag(pstStack, pelement, TLV_T_TOKEN))
		{
			emRet = ERT_needToken;
			break;
		}
		token_v = (uint8_t *)(*pelement)->pV;
		token_l = (*pelement)->L;
		if (SETTING_TOKEN_LEN != token_l)
		{
			emRet = ERT_TokenVerifyFail;
			break;
		}
		memcpy(token.token, token_v, token_l);
		token.length = token_l;
		if (ERT_Verify_Success != mason_token_verify(&token))
		{
			mason_token_delete();
			emRet = ERT_TokenVerifyFail;
			break;
		}

		emRet = ERT_Verify_Success;
	} while (0);

	memset(&token, 0, sizeof(setting_token_t));
	if (token_v)
	{
		memset(token_v, 0, token_l);
		token_v = NULL;
		token_l = 0;
	}
	return emRet;
}
/**
 * @functionname: mason_cmd_verify_fing
 * @description: 
 * @para: 
 * @return: 
 */
emRetType mason_cmd_verify_fing(pstStackType pstStack, stackElementType *pelement)
{
	emRetType emRet = ERT_Verify_Init;
	uint8_t *message_sign = NULL;
	uint16_t message_sign_len = 0;
	uint8_t time = 0;

	do
	{
		if (!stack_search_by_tag(pstStack, pelement, TLV_T_MESSAGE_SIGN))
		{
			emRet = ERT_needMessageSign;
			break;
		}
		message_sign = (uint8_t *)(*pelement)->pV;
		message_sign_len = (*pelement)->L;
		// verify message/ messagesign /pubkey
		if (ERT_Verify_Success != mason_usrfing_verify(message_sign, message_sign_len))
		{
			emRet = ERT_UsrFingVerifyFail;
			break;
		}

		//sleep
		gen_random(&time, 8);
		_delay_us(time * 2);

		message_sign = NULL;
		message_sign_len = 0;
		if (!stack_search_by_tag(pstStack, pelement, TLV_T_MESSAGE_SIGN))
		{
			emRet = ERT_needMessageSign;
			break;
		}
		message_sign = (uint8_t *)(*pelement)->pV;
		message_sign_len = (*pelement)->L;
		// verify message/ messagesign /pubkey
		if (ERT_Verify_Success != mason_usrfing_verify(message_sign, message_sign_len))
		{
			emRet = ERT_UsrFingVerifyFail;
			break;
		}

		emRet = ERT_Verify_Success;
	} while (0);

	mason_message_delete();
	if (message_sign)
	{
		memset(message_sign, 0, message_sign_len);
		message_sign = NULL;
		message_sign_len = 0;
	}
	return emRet;
}
/**
 * @functionname: mason_cmd_verify_slip39_seed
 * @description: 
 * @para: 
 * @return: 
 */
emRetType mason_cmd_verify_slip39_seed(pstStackType pstStack, stackElementType *pelement)
{
	emRetType emRet = ERT_Verify_Init;
	uint8_t *slip39_seed = NULL;
	uint16_t slip39_seed_len = 0;
	uint16_t slip39_id = 0;
	uint8_t time = 0;

	do
	{
		if (!stack_search_by_tag(pstStack, pelement, TLV_T_SLIP39_MASTER_SEED))
		{
			emRet = ERT_VerifyValueFail;
			break;
		}
		slip39_seed = (uint8_t *)(*pelement)->pV;
		slip39_seed_len = (*pelement)->L;

		if (!stack_search_by_tag(pstStack, pelement, TLV_T_SLIP39_ID) || (2 != (*pelement)->L))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		buf_to_u16(&slip39_id, (uint8_t *)(*pelement)->pV);
		if (ERT_Verify_Success != mason_verify_slip39_seed(slip39_seed, slip39_seed_len, slip39_id))
		{
			emRet = ERT_VerifyValueFail;
			break;
		}

		//sleep
		gen_random(&time, 8);
		_delay_us(time * 2);

		slip39_seed = NULL;
		slip39_seed_len = 0;
		slip39_id = 0;
		if (!stack_search_by_tag(pstStack, pelement, TLV_T_SLIP39_MASTER_SEED))
		{
			emRet = ERT_VerifyValueFail;
			break;
		}
		slip39_seed = (uint8_t *)(*pelement)->pV;
		slip39_seed_len = (*pelement)->L;

		if (!stack_search_by_tag(pstStack, pelement, TLV_T_SLIP39_ID) || (2 != (*pelement)->L))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		buf_to_u16(&slip39_id, (uint8_t *)(*pelement)->pV);
		if (ERT_Verify_Success != mason_verify_slip39_seed(slip39_seed, slip39_seed_len, slip39_id))
		{
			emRet = ERT_VerifyValueFail;
			break;
		}

		emRet = ERT_Verify_Success;
	} while (0);

	if (slip39_seed)
	{
		memset(slip39_seed, 0, slip39_seed_len);
		slip39_seed = NULL;
		slip39_seed_len = 0;
	}
	return emRet;
}
/**
 * @functionname: mason_cmd0102_get_information
 * @description: 
 * @para: 
 * @return: 
 */
static void mason_cmd0102_get_information(void *pContext)
{
	MASON_CMD_DECLARE_VARIABLE(ERT_OK)

	uint8_t bufVerName[VER_LEN] = {0x00};
	uint8_t bufVerCode[4] = {0x00};
	uint8_t boot_type = 1;
	uint8_t status_buf[4];
	stHDWStatusType status;
	uint8_t switchtype = (uint8_t)gemHDWSwitch;

	mason_cmd_init_outputTLVArray(&stStack);

	do
	{
		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_CMD))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		mason_cmd_append_ele_to_outputTLVArray(&stStack, pstTLV);

		u32_to_buf(bufVerCode, VERSION_BCD);
		GET_VERSION_STR((char *)bufVerName, VER_LEN);
		mason_cmd_append_to_outputTLVArray(&stStack, TLV_T_APP_VER_NAME, VER_LEN - 1, bufVerName);
		mason_cmd_append_to_outputTLVArray(&stStack, TLV_T_APP_VER_CODE, 4U, bufVerCode);
		mason_cmd_append_to_outputTLVArray(&stStack, TLV_T_BOOT_TYPE, 1, &boot_type);

		mason_get_mode(&status);
		u32_to_buf(status_buf, status.emHDWStatus);
		mason_cmd_append_to_outputTLVArray(&stStack, TLV_T_FW_STATUS, sizeof(status.emHDWStatus), status_buf);
		mason_cmd_append_to_outputTLVArray(&stStack, TLV_T_HDW_SWITCH, 1, &switchtype);
	} while (0);

	MASON_CMD_RESP_OUTPUT()
}
/**
 * @functionname: mason_cmd0107_factory_activate
 * @description: 
 * @para: 
 * @return: 
 */
static void mason_cmd0107_factory_activate(void *pContext)
{
	MASON_CMD_DECLARE_VARIABLE(ERT_OK)

	stHDWStatusType status;

	mason_cmd_init_outputTLVArray(&stStack);

	do
	{
		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_CMD))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		mason_cmd_append_ele_to_outputTLVArray(&stStack, pstTLV);

		mason_get_mode(&status);
		if (status.emHDWStatus != E_HDWS_FACTORY && status.emHDWStatus != E_HDWS_CHIP)
		{
			emRet = ERT_INIT_FAIL;
			break;
		}

		mason_set_mode(HDW_STATUS_EMPTY);
		mason_delete_wallet();
		mason_setting_delete();
	} while (0);

	MASON_CMD_RESP_OUTPUT()
}
/**
 * @functionname: mason_cmd0108_reboot
 * @description: 
 * @para: 
 * @return: 
 */
static void mason_cmd0108_reboot(void *pContext)
{
	MASON_CMD_DECLARE_VARIABLE(ERT_OK)

	mason_cmd_init_outputTLVArray(&stStack);

	do
	{
		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_CMD))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		mason_cmd_append_ele_to_outputTLVArray(&stStack, pstTLV);

	} while (0);

	MASON_CMD_RESP_OUTPUT()
	if (ERT_OK == emRet)
	{
		_delay_ms(100);
		wdt_stop();
		REG_SCU_RCR &= 0x7FFF; //Soft Reset
	}
}
/**
 * @functionname: mason_cmd0201_iap_request
 * @description: 
 * @para: 
 * @return: 
 */
static void mason_cmd0201_iap_request(void *pContext)
{
	MASON_CMD_DECLARE_VARIABLE(ERT_OK)

	uint32_t appVerCode = 0UL;
	uint32_t block_length = 0;
	uint8_t *block = NULL;
	uint8_t pckhdr_meta[32] = {0x00};
	uint8_t sha256_buf[SHA256_LEN] = {0};

	mason_cmd_init_outputTLVArray(&stStack);

	do
	{
		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_CMD))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		mason_cmd_append_ele_to_outputTLVArray(&stStack, pstTLV);

		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_APP_VER_CODE))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		block_length = pstTLV->L;
		block = (uint8_t *)(pstTLV->pV);
		if (32 != block_length)
		{
			emRet = ERT_CommFailParam;
			break;
		}

		memcpy(pckhdr_meta, block, block_length);
		buf_to_u32(&appVerCode, pckhdr_meta);

		sha256_api(pckhdr_meta, 4, sha256_buf);
		if (memcmp_ATA(sha256_buf, (pckhdr_meta + 4), 4) || (appVerCode <= VERSION_BCD))
		{
			emRet = ERT_VerConflict;
			break;
		}
	} while (0);

	MASON_CMD_RESP_OUTPUT()
}
/**
 * @functionname: mason_cmd0203_iap_verify
 * @description: 
 * @para: 
 * @return: 
 */
static void mason_cmd0203_iap_verify(void *pContext)
{
	MASON_CMD_DECLARE_VARIABLE(ERT_CommFailParam)

	emFwPackTypeType emFwPackType = E_PACK_ERR;
	uint8_t *pFwPack = NULL;
	uint32_t fwPackLen = 0;
	emRetType verify_emRet = ERT_Verify_Init;

	mason_cmd_init_outputTLVArray(&stStack);

	do
	{
		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_CMD))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		mason_cmd_append_ele_to_outputTLVArray(&stStack, pstTLV);

		if (ERT_Verify_Success != (emRet = mason_cmd_verify_passwd(pstS, &pstTLV)))
		{
			break;
		}
		verify_emRet = emRet;

		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_UPDATE_PACK_TYPE) || (1 != pstTLV->L))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		emFwPackType = (emFwPackTypeType)*pstTLV->pV;
		if (emFwPackType > E_PACK_HDR)
		{
			emRet = ERT_IAP_FAIL;
			break;
		}

		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_UPDATE_PACK))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		fwPackLen = pstTLV->L;
		pFwPack = (uint8_t *)pstTLV->pV;
		if (E_PACK_HDR == emFwPackType)
		{
			if (pstTLV->L != 128)
			{
				emRet = ERT_IAP_FAIL;
				break;
			}
		}
		else
		{
			if (pstTLV->L != PAGE_SIZE + 8 + 8)
			{
				emRet = ERT_IAP_FAIL;
				break;
			}
		}

		if (ERT_OK != (emRet = mason_iap_pack_verify_process(emFwPackType, pFwPack, fwPackLen)))
		{
			break;
		}

		if ((E_PACK_HDR == emFwPackType) && (ERT_Verify_Success == verify_emRet))
		{
			uint32_t addr = 0;
			uint8_t bufAddr[4] = {0x00};
			if (ERT_OK != (emRet = mason_iap_set_app_not_exist()))
			{
				break;
			}
			addr = (FLAG_APP_EXIST == eflash_read_word(FLASH_ADDR_APP_EXIST_4B)
						? FLASH_ADDR_APP_START
						: FLASH_ADDR_BOOT1_START);
			u32_to_buf(bufAddr, addr);
			mason_cmd_append_to_outputTLVArray(&stStack, TLV_T_FLASH_ADDR, sizeof(bufAddr), bufAddr);
		}

		if (ERT_Verify_Success == verify_emRet)
		{
			emRet = ERT_OK;
		}
	} while (0);

	MASON_CMD_RESP_OUTPUT()

	if ((ERT_OK == emRet) && (E_PACK_HDR == emFwPackType) && (ERT_Verify_Success == verify_emRet))
	{
		(void)mason_iap_set_app_not_exist();
		_delay_ms(500);
		//printf("\nClean App && Rebooting..\n");
		wdt_stop();
		REG_SCU_RCR &= 0x7FFF; //Soft Reset
	}
}
/**
 * @functionname: mason_cmd0301_get_entropy
 * @description: 
 * @para: 
 * @return: 
 */
static void mason_cmd0301_get_entropy(void *pContext)
{
	MASON_CMD_DECLARE_VARIABLE(ERT_OK)

	uint16_t entropyBits = 0;
	uint8_t needChecksum = 0;
	uint32_t entropy_length = 0;
	uint8_t *entropy_buffer = NULL;

	mason_cmd_init_outputTLVArray(&stStack);

	do
	{
		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_CMD))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		mason_cmd_append_ele_to_outputTLVArray(&stStack, pstTLV);

		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_ENTROPY_BITS) || (2 != pstTLV->L))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		buf_to_u16(&entropyBits, (uint8_t *)pstTLV->pV);
		entropy_length = entropyBits >> 3;

		if (stack_search_by_tag(pstS, &pstTLV, TLV_T_NEED_CKM) && (1 == pstTLV->L))
		{
			needChecksum = *(uint8_t *)pstTLV->pV;
			if (needChecksum)
			{
				entropy_length += 1;
			}
		}

		entropy_buffer = (uint8_t *)malloc(entropy_length);
		if (entropy_buffer == NULL)
		{
			emRet = ERT_MallocFail;
			break;
		}

		if (!mason_generate_entropy(entropy_buffer, entropyBits, needChecksum))
		{
			emRet = ERT_CMD_FAIL;
			break;
		}
		mason_cmd_append_to_outputTLVArray(&stStack, TLV_T_ENTROPY, entropy_length, entropy_buffer);
	} while (0);

	MASON_CMD_RESP_OUTPUT()

	if (entropy_buffer != NULL)
	{
		free(entropy_buffer);
	}
}
/**
 * @functionname: mason_cmd0302_create_wallet
 * @description: 
 * @para: 
 * @return: 
 */
static void mason_cmd0302_create_wallet(void *pContext)
{
	MASON_CMD_DECLARE_VARIABLE(ERT_CommFailParam)

	uint8_t *mnemonic = NULL;
	uint16_t mnemonic_len = 0;
	uint8_t *entropy = NULL;
	uint16_t entropy_len = 0;
	emRetType verify_emRet = ERT_Verify_Init;

	mason_cmd_init_outputTLVArray(&stStack);

	do
	{
		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_CMD))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		mason_cmd_append_ele_to_outputTLVArray(&stStack, pstTLV);

		if (ERT_Verify_Success != (emRet = mason_cmd_verify_passwd(pstS, &pstTLV)))
		{
			break;
		}
		verify_emRet = emRet;

		if (stack_search_by_tag(pstS, &pstTLV, TLV_T_MNEMONIC))
		{
			mnemonic = (uint8_t *)pstTLV->pV;
			mnemonic_len = pstTLV->L;

			if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_ENTROPY))
			{
				emRet = ERT_needEntropy;
				break;
			}
			entropy = (uint8_t *)pstTLV->pV;
			entropy_len = pstTLV->L;

			if (!mason_create_bip39_wallet(mnemonic, mnemonic_len, entropy, entropy_len))
			{
				emRet = ERT_CommFailParam;
				break;
			}
		}
		else if (stack_search_by_tag(pstS, &pstTLV, TLV_T_SLIP39_MASTER_SEED))
		{
			uint8_t *slip39_seed_data = (uint8_t *)pstTLV->pV;
			uint16_t slip39_seed_len = pstTLV->L;
			uint16_t slip39_id = 0;
			uint8_t slip39_e = 1;

			if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_SLIP39_ID) || (2 != pstTLV->L))
			{
				emRet = ERT_CommFailParam;
				break;
			}
			buf_to_u16(&slip39_id, (uint8_t *)pstTLV->pV);
			if (stack_search_by_tag(pstS, &pstTLV, TLV_T_SLIP39_EXPONENT) && (1 == pstTLV->L))
			{
				slip39_e = *(uint8_t *)pstTLV->pV;
			}

			if (!mason_create_slip39_wallet(slip39_seed_data, slip39_seed_len, slip39_id, slip39_e))
			{
				emRet = ERT_CommFailParam;
				break;
			}
		}
		else
		{
			emRet = ERT_CommFailParam;
			break;
		}
		if (!mason_set_mode(HDW_STATUS_WALLET))
		{
			emRet = ERT_CommFailParam;
			break;
		}

		if (ERT_Verify_Success == verify_emRet)
		{
			emRet = ERT_OK;
		}
	} while (0);

	if (mnemonic)
	{
		memset(mnemonic, 0, mnemonic_len);
		mnemonic = NULL;
		mnemonic_len = 0;
	}
	MASON_CMD_RESP_OUTPUT()
}
/**
 * @functionname: mason_cmd0303_change_wallet_passphrase
 * @description: 
 * @para: 
 * @return: 
 */
static void mason_cmd0303_change_wallet_passphrase(void *pContext)
{
	MASON_CMD_DECLARE_VARIABLE(ERT_CommFailParam)

	uint8_t *passphrase = NULL;
	uint16_t passphrase_len = 0;
	stHDWStatusType status;
	emRetType verify_emRet = ERT_Verify_Init;

	mason_cmd_init_outputTLVArray(&stStack);

	do
	{
		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_CMD))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		mason_cmd_append_ele_to_outputTLVArray(&stStack, pstTLV);

		if (stack_search_by_tag(pstS, &pstTLV, TLV_T_USRPWD_CUR))
		{
			if (ERT_Verify_Success != (emRet = mason_cmd_verify_passwd(pstS, &pstTLV)))
			{
				break;
			}
			verify_emRet = emRet;
		}
		else if (stack_search_by_tag(pstS, &pstTLV, TLV_T_MESSAGE_SIGN))
		{
			uint8_t value = 0;
			mason_usrsettings_element_load(E_USRSETTINGS_PHRASEFP, &value);
			if (!value)
			{
				emRet = ERT_UsrSettingsNotAllow;
				break;
			}
			if (ERT_Verify_Success != (emRet = mason_cmd_verify_fing(pstS, &pstTLV)))
			{
				break;
			}
			verify_emRet = emRet;
		}
		else
		{
			emRet = ERT_needUsrPass;
			break;
		}

		mason_get_mode(&status);
		if (status.emHDWStatus != E_HDWS_WALLET)
		{
			emRet = ERT_CommFailParam;
			break;
		}

		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_PASSPHRASE))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		passphrase = (uint8_t *)pstTLV->pV;
		passphrase_len = pstTLV->L;
		if (!mason_change_wallet_passphrase(passphrase, passphrase_len))
		{
			emRet = ERT_CommFailParam;
			break;
		}

		if (ERT_Verify_Success == verify_emRet)
		{
			emRet = ERT_OK;
		}
	} while (0);

	if (passphrase)
	{
		memset(passphrase, 0, passphrase_len);
		passphrase = NULL;
		passphrase_len = 0;
	}
	MASON_CMD_RESP_OUTPUT()
}
/**
 * @functionname: mason_cmd0305_get_extpubkey
 * @description: command for get specific extended public key by given hdpath and algorithm
 * @para: 
 * @return: 
 */
static void mason_cmd0305_get_extpubkey(void *pContext)
{
	MASON_CMD_DECLARE_VARIABLE(ERT_OK)

	uint8_t *path = NULL;
	uint16_t path_len = 0;
	wallet_path_t wallet_path = {0};
	char path_string[MAX_HDPATH_SIZE + 1] = {0};
	private_key_t derived_private_key = {0};
	chaincode_t derived_chaincode = {0};
	extended_key_t extended_public_key = {0};
	crypto_curve_t curve_type = CRYPTO_CURVE_SECP256K1;
	char base58_ext_key[256] = {0};
	size_t base58_ext_key_len = 256;
	uint8_t switchtype = (uint8_t)gemHDWSwitch;

	mason_cmd_init_outputTLVArray(&stStack);

	do
	{
		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_CMD))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		mason_cmd_append_ele_to_outputTLVArray(&stStack, pstTLV);

		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_HDW_SWITCH) || (1 != pstTLV->L))
		{
			emRet = ERT_HDWalletSwitchNeed;
			break;
		}
		if (switchtype != *(uint8_t *)pstTLV->pV)
		{
			emRet = ERT_HDWalletSwitchNotMatch;
			break;
		}

		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_HD_PATH))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		path_len = pstTLV->L;
		path = (uint8_t *)pstTLV->pV;
		if ((0 == path_len) || (path_len > MAX_HDPATH_SIZE))
		{
			emRet = ERT_HDPathIllegal;
			break;
		}

		if (stack_search_by_tag(pstS, &pstTLV, TLV_T_CURVE_TYPE) && ((1 == pstTLV->L)))
		{
			curve_type = (crypto_curve_t)(*(uint8_t *)pstTLV->pV);
		}

		memcpy((uint8_t *)path_string, path, path_len);
		path_string[path_len] = 0;
		if (!mason_wallet_path_is_pub(path_string, path_len) || !mason_parse_wallet_path_from_string(path_string, path_len, &wallet_path))
		{
			emRet = ERT_HDPathIllegal;
			break;
		}
		if (!mason_bip32_derive_keys(&wallet_path, curve_type, &derived_private_key, &derived_chaincode, &extended_public_key))
		{
			emRet = ERT_HDPathIllegal;
			break;
		}

		b58enc(base58_ext_key, &base58_ext_key_len, (uint8_t *)&extended_public_key, sizeof(extended_public_key));
		base58_ext_key[base58_ext_key_len] = 0;
		mason_cmd_append_to_outputTLVArray(&stStack, TLV_T_EXT_KEY, base58_ext_key_len - 1, (uint8_t *)base58_ext_key);
	} while (0);

	memset(&derived_private_key, 0, sizeof(private_key_t));
	memset(&derived_chaincode, 0, sizeof(chaincode_t));
	MASON_CMD_RESP_OUTPUT()
}
/**
 * @functionname: mason_cmd0306_delete_wallet
 * @description: 
 * @para: 
 * @return: 
 */
static void mason_cmd0306_delete_wallet(void *pContext)
{
	MASON_CMD_DECLARE_VARIABLE(ERT_OK)

	stHDWStatusType status;

	mason_cmd_init_outputTLVArray(&stStack);

	do
	{
		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_CMD))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		mason_cmd_append_ele_to_outputTLVArray(&stStack, pstTLV);

		if (!mason_delete_wallet())
		{
			emRet = ERT_CommFailParam;
			break;
		}
		mason_setting_delete();

		mason_get_mode(&status);
		if (E_HDWS_ATTACK != status.emHDWStatus)
		{
			if (!mason_set_mode(HDW_STATUS_EMPTY))
			{
				emRet = ERT_CommFailParam;
				break;
			}
		}
	} while (0);

	MASON_CMD_RESP_OUTPUT()
}
/**
 * @functionname: mason_cmd0307_sign
 * @description: 
 * @para: 
 * @return: 
 */
static void mason_cmd0307_sign(void *pContext)
{
	MASON_CMD_DECLARE_VARIABLE(ERT_CommFailParam)

	uint8_t *path = NULL;
	uint16_t path_len = 0;
	wallet_path_t wallet_path;
	char path_string[MAX_HDPATH_SIZE + 1] = {0};
	uint8_t *hash = NULL;
	uint16_t hash_len = 0;
	private_key_t derived_private_key;
	chaincode_t derived_chaincode;
	extended_key_t extended_public_key;
	uint8_t signature[128];
	uint16_t signature_len;
	public_key_t derived_public_key = {0};
	crypto_curve_t curve_type = CRYPTO_CURVE_SECP256K1;
	emRetType verify_emRet = ERT_Verify_Init;
	uint8_t switchtype = (uint8_t)gemHDWSwitch;

	mason_cmd_init_outputTLVArray(&stStack);

	do
	{
		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_CMD))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		mason_cmd_append_ele_to_outputTLVArray(&stStack, pstTLV);

		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_HDW_SWITCH) || (1 != pstTLV->L))
		{
			emRet = ERT_HDWalletSwitchNeed;
			break;
		}
		if (switchtype != *(uint8_t *)pstTLV->pV)
		{
			emRet = ERT_HDWalletSwitchNotMatch;
			break;
		}

		if (ERT_Verify_Success != (emRet = mason_cmd_verify_token(pstS, &pstTLV)))
		{
			break;
		}
		verify_emRet = emRet;

		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_HASH))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		hash_len = pstTLV->L;
		hash = (uint8_t *)pstTLV->pV;

		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_HD_PATH))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		path_len = pstTLV->L;
		path = (uint8_t *)pstTLV->pV;
		if ((0 == path_len) || (path_len > MAX_HDPATH_SIZE))
		{
			emRet = ERT_HDPathIllegal;
			break;
		}

		if (stack_search_by_tag(pstS, &pstTLV, TLV_T_CURVE_TYPE) && ((1 == pstTLV->L)))
		{
			curve_type = (crypto_curve_t)(*(uint8_t *)pstTLV->pV);
		}

		memcpy((uint8_t *)path_string, path, path_len);
		path_string[path_len] = 0;
		if (!mason_parse_wallet_path_from_string(path_string, path_len, &wallet_path))
		{
			emRet = ERT_HDPathIllegal;
			break;
		}

		if (!mason_bip32_derive_keys(&wallet_path, curve_type, &derived_private_key, &derived_chaincode, &extended_public_key))
		{
			emRet = ERT_HDPathIllegal;
			break;
		}

		private_key_to_public_key(curve_type, &derived_private_key, &derived_public_key);
		if (!ecdsa_sign(curve_type, hash, hash_len, derived_private_key.data, signature, &signature_len))
		{
			emRet = ERT_ECDSASignFail;
			break;
		}

		if (ERT_Verify_Success == verify_emRet)
		{
			emRet = ERT_OK;
		}
		mason_cmd_append_to_outputTLVArray(&stStack, TLV_T_PUBKEY, derived_public_key.len, derived_public_key.data);
		mason_cmd_append_to_outputTLVArray(&stStack, TLV_T_SIGNATURE, signature_len, signature);
	} while (0);

	memset(&extended_public_key, 0, sizeof(extended_public_key));
	memset(&derived_private_key, 0, sizeof(private_key_t));
	memset(&derived_chaincode, 0, sizeof(chaincode_t));
	MASON_CMD_RESP_OUTPUT()
}
/**
 * @functionname: mason_cmd0308_get_masterkey_fingerprint
 * @description: 
 * @para: 
 * @return: 
 */
static void mason_cmd0308_get_masterkey_fingerprint(void *pContext)
{
	MASON_CMD_DECLARE_VARIABLE(ERT_OK)

	crypto_curve_t curve_type = CRYPTO_CURVE_SECP256K1;
	uint8_t fingerprint[4] = {0};
	uint8_t switchtype = (uint8_t)gemHDWSwitch;

	mason_cmd_init_outputTLVArray(&stStack);

	do
	{
		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_CMD))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		mason_cmd_append_ele_to_outputTLVArray(&stStack, pstTLV);

		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_HDW_SWITCH) || (1 != pstTLV->L))
		{
			emRet = ERT_HDWalletSwitchNeed;
			break;
		}
		if (switchtype != *(uint8_t *)pstTLV->pV)
		{
			emRet = ERT_HDWalletSwitchNotMatch;
			break;
		}

		if (stack_search_by_tag(pstS, &pstTLV, TLV_T_CURVE_TYPE) && ((1 == pstTLV->L)))
		{
			curve_type = (crypto_curve_t)(*(uint8_t *)pstTLV->pV);
		}

		if (!mason_bip32_derive_master_key_fingerprint(curve_type, fingerprint, sizeof(fingerprint)))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		mason_cmd_append_to_outputTLVArray(&stStack, TLV_T_MASTER_KEY_FP, sizeof(fingerprint), fingerprint);
	} while (0);

	MASON_CMD_RESP_OUTPUT()
}
#ifdef MASON_TEST
/**
 * @functionname: mason_cmd0401_generate_public_key_from_private_key
 * @description: 
 * @para: 
 * @return: 
 */
static void mason_cmd0401_generate_public_key_from_private_key(void *pContext)
{
	MASON_CMD_DECLARE_VARIABLE(ERT_OK)

	private_key_t private_key;
	public_key_t public_key;
	crypto_curve_t curve_type = CRYPTO_CURVE_SECP256K1;

	mason_cmd_init_outputTLVArray(&stStack);

	do
	{
		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_CMD))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		mason_cmd_append_ele_to_outputTLVArray(&stStack, pstTLV);

		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_PRVKEY) || (PRIVATE_KEY_LEN != pstTLV->L))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		memcpy(private_key.data, pstTLV->pV, PRIVATE_KEY_LEN);

		if (stack_search_by_tag(pstS, &pstTLV, TLV_T_CURVE_TYPE) && ((1 == pstTLV->L)))
		{
			curve_type = (crypto_curve_t)(*(uint8_t *)pstTLV->pV);
		}

		private_key_to_public_key(curve_type, &private_key, &public_key);
		mason_cmd_append_to_outputTLVArray(&stStack, TLV_T_PUBKEY, public_key.len, public_key.data);
	} while (0);

	MASON_CMD_RESP_OUTPUT()
}
#endif
/**
 * @functionname: mason_cmd0402_derive_deposit_key
 * @description: 
 * @para: 
 * @return: 
 */
static void mason_cmd0402_derive_deposit_key(void *pContext)
{
	MASON_CMD_DECLARE_VARIABLE(ERT_OK)

	private_key_t withdrawal_key = {0};
	private_key_t sign_key = {0};
	uint8_t switchtype = (uint8_t)gemHDWSwitch;
	emRetType verify_emRet = ERT_Verify_Init;

	mason_cmd_init_outputTLVArray(&stStack);

	do
	{
		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_CMD))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		mason_cmd_append_ele_to_outputTLVArray(&stStack, pstTLV);

		if (ERT_Verify_Success != (emRet = mason_cmd_verify_passwd(pstS, &pstTLV)))
		{
			break;
		}
		verify_emRet = emRet;

		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_HDW_SWITCH) || (1 != pstTLV->L))
		{
			emRet = ERT_HDWalletSwitchNeed;
			break;
		}
		if (switchtype != *(uint8_t *)pstTLV->pV)
		{
			emRet = ERT_HDWalletSwitchNotMatch;
			break;
		}

		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_ACCOUNT) || (4 != pstTLV->L))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		uint32_t account = 0;
		buf_to_u32(&account, (uint8_t *)pstTLV->pV);

		if (!mason_eth2_derive_deposit_SK(account, &withdrawal_key, &sign_key))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		mason_cmd_append_to_outputTLVArray(&stStack, TLV_T_ETH2_WITHDRAWAL_KEY, withdrawal_key.len, withdrawal_key.data);
		mason_cmd_append_to_outputTLVArray(&stStack, TLV_T_ETH2_SIGN_KEY, sign_key.len, sign_key.data);

		if (ERT_Verify_Success == verify_emRet)
		{
			emRet = ERT_OK;
		}
	} while (0);
	MASON_CMD_RESP_OUTPUT()
}
/**
 * @functionname: mason_cmd0502_mnemonic_verify
 * @description: 
 * @para: 
 * @return: 
 */
static void mason_cmd0502_mnemonic_verify(void *pContext)
{
	MASON_CMD_DECLARE_VARIABLE(ERT_CommFailParam)

	emRetType verify_emRet = ERT_Verify_Init;

	mason_cmd_init_outputTLVArray(&stStack);

	do
	{
		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_CMD))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		mason_cmd_append_ele_to_outputTLVArray(&stStack, pstTLV);

		if (ERT_Verify_Success != (emRet = mason_cmd_verify_mnemonic(pstS, &pstTLV)) && ERT_Verify_Success != (emRet = mason_cmd_verify_slip39_seed(pstS, &pstTLV)))
		{
			break;
		}
		verify_emRet = emRet;

		if (ERT_Verify_Success == verify_emRet)
		{
			emRet = ERT_OK;
		}
	} while (0);

	MASON_CMD_RESP_OUTPUT()
}
/**
 * @functionname: mason_cmd0701_web_authentication
 * @description: 
 * @para: 
 * @return: 
 */
static void mason_cmd0701_web_authentication(void *pContext)
{
	MASON_CMD_DECLARE_VARIABLE(ERT_OK)

	uint8_t signature[SHA512_LEN];
	uint16_t signature_len = SHA512_LEN;
	uint8_t *encrypt_message = NULL;
	uint16_t encrypt_message_len = 0;
	uint8_t output[64] = {0};
	uint32_t output_len = 0;
	uint8_t web_auth_private_key[PRIVATE_KEY_LEN] = {0};
	uint8_t web_auth_public_key[PUB_KEY_LEN] = {0};
	uint8_t message_sha256_buf[SHA256_LEN];

	mason_cmd_init_outputTLVArray(&stStack);

	do
	{
		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_CMD))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		mason_cmd_append_ele_to_outputTLVArray(&stStack, pstTLV);

		if (ERT_OK != (emRet = mason_storage_read((uint8_t *)web_auth_private_key, PRIVATE_KEY_LEN, FLASH_ADDR_WEB_AUTH_PRI_KEY_32B)))
		{
			break;
		}

		if (ERT_OK != (emRet = mason_storage_read((uint8_t *)web_auth_public_key, PUB_KEY_LEN, FLASH_ADDR_WEB_AUTH_PUB_KEY_64B)))
		{
			break;
		}

		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_ENCRYPT_MSG))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		encrypt_message = (uint8_t *)pstTLV->pV;
		encrypt_message_len = pstTLV->L;

		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_SIGNATURE) || (signature_len != pstTLV->L))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		memcpy(signature, (uint8_t *)pstTLV->pV, pstTLV->L);
		sha256_api(encrypt_message, encrypt_message_len, message_sha256_buf);
		if (!ecdsa_verify(CRYPTO_CURVE_SECP256K1, message_sha256_buf, web_auth_public_key, signature))
		{
			emRet = ERT_ECDSAVerifyFail;
			break;
		}

		if (!crypto_api_sm2_decrypt(web_auth_private_key, encrypt_message, encrypt_message_len, output, &output_len))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		output[output_len] = 0;
		mason_cmd_append_to_outputTLVArray(&stStack, TLV_T_PLAIN_MSG, output_len, output);
	} while (0);

	memset(web_auth_private_key, 0, PRIVATE_KEY_LEN);
	memset(web_auth_public_key, 0, PUB_KEY_LEN);
	MASON_CMD_RESP_OUTPUT()
}
/**
 * @functionname: mason_cmd0802_tamper_test
 * @description: 
 * @para: 
 * @return: 
 */
static void mason_cmd0802_tamper_test(void *pContext)
{
	MASON_CMD_DECLARE_VARIABLE(ERT_OK)

	mason_cmd_init_outputTLVArray(&stStack);

	do
	{
		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_CMD))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		mason_cmd_append_ele_to_outputTLVArray(&stStack, pstTLV);

		if (gpio_low(BIT_DET0, 500))
		{
			mason_cmd_append_to_outputTLVArray(&stStack, TLV_T_ACTIVE_TAMPER, 2, (uint8_t *)"AT");
		}
		if (gpio_high(BIT_DET1 | BIT_DET2 | BIT_DET3, 500))
		{
			mason_cmd_append_to_outputTLVArray(&stStack, TLV_T_PASSIVE_TAMPER, 2, (uint8_t *)"PT");
		}
		else if (gpio_high(BIT_DET1, 500) || gpio_high(BIT_DET2, 500) || gpio_high(BIT_DET3, 500))
		{
			mason_cmd_append_to_outputTLVArray(&stStack, TLV_T_PASSIVE_TAMPER, 2, (uint8_t *)"QT");
		}

	} while (0);

	MASON_CMD_RESP_OUTPUT()
}
/**
 * @functionname: mason_cmd0901_usrpwd_modify
 * @description: 
 * @para: 
 * @return: 
 */
static void mason_cmd0901_usrpwd_modify(void *pContext)
{
	MASON_CMD_DECLARE_VARIABLE(ERT_CommFailParam)

	uint8_t *new_pwd = NULL;
	uint16_t new_pwd_len = 0;
	emRetType verify_emRet = ERT_Verify_Init;

	mason_cmd_init_outputTLVArray(&stStack);

	do
	{
		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_CMD))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		mason_cmd_append_ele_to_outputTLVArray(&stStack, pstTLV);

		if (ERT_Verify_Success != (emRet = mason_cmd_verify_passwd(pstS, &pstTLV)))
		{
			break;
		}
		verify_emRet = emRet;

		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_USRPWD_NEW))
		{
			emRet = ERT_needUsrPass;
			break;
		}
		new_pwd = (uint8_t *)pstTLV->pV;
		new_pwd_len = pstTLV->L;
		if (!mason_usrpwd_store(new_pwd, new_pwd_len))
		{
			emRet = ERT_UsrPassParaERR;
			break;
		}

		if (ERT_Verify_Success == verify_emRet)
		{
			emRet = ERT_OK;
		}
	} while (0);

	if (new_pwd)
	{
		memset(new_pwd, 0, new_pwd_len);
		new_pwd = NULL;
		new_pwd_len = 0;
	}
	MASON_CMD_RESP_OUTPUT()
}
/**
 * @functionname: mason_cmd0902_usrpwd_reset
 * @description: 
 * @para: 
 * @return: 
 */
static void mason_cmd0902_usrpwd_reset(void *pContext)
{
	MASON_CMD_DECLARE_VARIABLE(ERT_CommFailParam)

	stHDWStatusType status;
	uint8_t *new_pwd = NULL;
	uint16_t new_pwd_len = 0;
	emRetType verify_emRet = ERT_Verify_Init;

	mason_cmd_init_outputTLVArray(&stStack);

	do
	{
		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_CMD))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		mason_cmd_append_ele_to_outputTLVArray(&stStack, pstTLV);

		mason_get_mode(&status);
		if (E_HDWS_CHIP == status.emHDWStatus || E_HDWS_FACTORY == status.emHDWStatus || E_HDWS_EMPTY == status.emHDWStatus)
		{
			//allow to reset password
			verify_emRet = ERT_Verify_Success;
		}
		else if (E_HDWS_WALLET == status.emHDWStatus)
		{
			if (ERT_Verify_Success != (emRet = mason_cmd_verify_mnemonic(pstS, &pstTLV)) && ERT_Verify_Success != (emRet = mason_cmd_verify_slip39_seed(pstS, &pstTLV)))
			{
				break;
			}
			verify_emRet = emRet;
		}
		else
		{
			emRet = ERT_CommFailParam;
			break;
		}

		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_USRPWD_NEW))
		{
			emRet = ERT_needUsrPass;
			break;
		}
		new_pwd = (uint8_t *)pstTLV->pV;
		new_pwd_len = pstTLV->L;
		if (!mason_usrpwd_store(new_pwd, new_pwd_len))
		{
			emRet = ERT_UsrPassParaERR;
			break;
		}

		if (ERT_Verify_Success == verify_emRet)
		{
			emRet = ERT_OK;
		}
	} while (0);

	if (new_pwd)
	{
		memset(new_pwd, 0, new_pwd_len);
		new_pwd = NULL;
		new_pwd_len = 0;
	}

	MASON_CMD_RESP_OUTPUT()
}
/**
 * @functionname: mason_cmd0903_usrpwd_verify
 * @description: 
 * @para: 
 * @return: 
 */
static void mason_cmd0903_usrpwd_verify(void *pContext)
{
	MASON_CMD_DECLARE_VARIABLE(ERT_CommFailParam)

	uint8_t *return_token = NULL;
	uint16_t return_token_len = 0;
	emRetType verify_emRet = ERT_Verify_Init;

	mason_cmd_init_outputTLVArray(&stStack);

	do
	{
		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_CMD))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		mason_cmd_append_ele_to_outputTLVArray(&stStack, pstTLV);

		if (ERT_Verify_Success != (emRet = mason_cmd_verify_passwd(pstS, &pstTLV)))
		{
			break;
		}
		verify_emRet = emRet;

		if (stack_search_by_tag(pstS, &pstTLV, TLV_T_RETURN_TOKEN))
		{
			return_token = (uint8_t *)pstTLV->pV;
			return_token_len = pstTLV->L;
			if (1 == return_token_len && (*return_token))
			{
				setting_token_t *token;
				mason_token_gen();
				token = mason_token_get();
				mason_cmd_append_to_outputTLVArray(&stStack, TLV_T_TOKEN, token->length, token->token);
			}
		}

		if (ERT_Verify_Success == verify_emRet)
		{
			emRet = ERT_OK;
		}
	} while (0);

	MASON_CMD_RESP_OUTPUT()
}
/**
 * @functionname: mason_cmd0904_usrsettings
 * @description: 
 * @para: 
 * @return: 
 */
static void mason_cmd0904_usrsettings(void *pContext)
{
	MASON_CMD_DECLARE_VARIABLE(ERT_CommFailParam)

	emRetType verify_emRet = ERT_Verify_Init;
	uint8_t is_read = 0;
	uint8_t type = 0;
	uint8_t value = 0;

	mason_cmd_init_outputTLVArray(&stStack);

	do
	{
		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_CMD))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		mason_cmd_append_ele_to_outputTLVArray(&stStack, pstTLV);

		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_SETTINGS_TYPE) || (1 != pstTLV->L))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		type = *(uint8_t *)pstTLV->pV;

		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_WR_RD) || (1 != pstTLV->L))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		is_read = *(uint8_t *)pstTLV->pV;

		if (is_read)
		{
			if (mason_usrsettings_element_load((emUsrSettingsType)type, &value))
			{
				mason_cmd_append_to_outputTLVArray(&stStack, TLV_T_SETTINGS_VALUE, 1, &value);
			}
			else
			{
				emRet = ERT_UsrSettingsLoadFail;
				break;
			}
		}
		else
		{
			if (ERT_Verify_Success != (emRet = mason_cmd_verify_passwd(pstS, &pstTLV)))
			{
				break;
			}
			verify_emRet = emRet;

			if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_SETTINGS_VALUE) || (1 != pstTLV->L))
			{
				emRet = ERT_CommFailParam;
				break;
			}
			value = *(uint8_t *)pstTLV->pV;

			if (!mason_usrsettings_element_store((emUsrSettingsType)type, value))
			{
				emRet = ERT_UsrSettingsStoreFail;
				break;
			}
		}

		if ((!is_read) && (ERT_Verify_Success == verify_emRet))
		{
			emRet = ERT_OK;
		}
		else if (is_read)
		{
			emRet = ERT_OK;
		}
	} while (0);

	MASON_CMD_RESP_OUTPUT()
}
/**
 * @functionname: mason_cmd0905_message_gen
 * @description: 
 * @para: 
 * @return: 
 */
static void mason_cmd0905_message_gen(void *pContext)
{
	MASON_CMD_DECLARE_VARIABLE(ERT_OK)

	setting_message_t *message;

	mason_cmd_init_outputTLVArray(&stStack);

	do
	{
		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_CMD))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		mason_cmd_append_ele_to_outputTLVArray(&stStack, pstTLV);

		mason_message_gen();
		message = mason_message_get();
		mason_cmd_append_to_outputTLVArray(&stStack, TLV_T_MESSAGE, message->length, message->message);
	} while (0);

	MASON_CMD_RESP_OUTPUT()
}
/**
 * @functionname: mason_cmd0906_usrfing_create
 * @description: 
 * @para: 
 * @return: 
 */
static void mason_cmd0906_usrfing_create(void *pContext)
{
	MASON_CMD_DECLARE_VARIABLE(ERT_CommFailParam)

	uint8_t *fing = NULL;
	uint16_t fing_len = 0;
	emRetType verify_emRet = ERT_Verify_Init;

	mason_cmd_init_outputTLVArray(&stStack);

	do
	{
		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_CMD))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		mason_cmd_append_ele_to_outputTLVArray(&stStack, pstTLV);

		if (ERT_Verify_Success != (emRet = mason_cmd_verify_passwd(pstS, &pstTLV)))
		{
			break;
		}
		verify_emRet = emRet;

		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_USRFING))
		{
			emRet = ERT_needUsrFing;
			break;
		}
		fing = (uint8_t *)pstTLV->pV;
		fing_len = pstTLV->L;
		if (!mason_usrfing_store(fing, fing_len))
		{
			emRet = ERT_UsrFingParaERR;
			break;
		}

		if (ERT_Verify_Success == verify_emRet)
		{
			emRet = ERT_OK;
		}
	} while (0);

	if (fing)
	{
		memset(fing, 0, fing_len);
		fing = NULL;
		fing_len = 0;
	}
	MASON_CMD_RESP_OUTPUT()
}
/**
 * @functionname: mason_cmd0907_usrfing_verify
 * @description: 
 * @para: 
 * @return: 
 */
static void mason_cmd0907_usrfing_verify(void *pContext)
{
	MASON_CMD_DECLARE_VARIABLE(ERT_CommFailParam)

	uint8_t *return_token = NULL;
	uint16_t return_token_len = 0;
	emRetType verify_emRet = ERT_Verify_Init;

	mason_cmd_init_outputTLVArray(&stStack);

	do
	{
		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_CMD))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		mason_cmd_append_ele_to_outputTLVArray(&stStack, pstTLV);

		if (ERT_Verify_Success != (emRet = mason_cmd_verify_fing(pstS, &pstTLV)))
		{
			break;
		}
		verify_emRet = emRet;

		if (stack_search_by_tag(pstS, &pstTLV, TLV_T_RETURN_TOKEN))
		{
			return_token = (uint8_t *)pstTLV->pV;
			return_token_len = pstTLV->L;
			if (1 == return_token_len && (*return_token))
			{
				setting_token_t *token;
				uint8_t value = 0;
				mason_usrsettings_element_load(E_USRSETTINGS_SIGNFP, &value);
				if (!value)
				{
					emRet = ERT_UsrSettingsNotAllow;
					break;
				}
				mason_token_gen();
				token = mason_token_get();
				mason_cmd_append_to_outputTLVArray(&stStack, TLV_T_TOKEN, token->length, token->token);
			}
		}

		if (ERT_Verify_Success == verify_emRet)
		{
			emRet = ERT_OK;
		}
	} while (0);

	MASON_CMD_RESP_OUTPUT()
}
/**
 * @functionname: mason_cmd0908_token_delete
 * @description: 
 * @para: 
 * @return: 
 */
static void mason_cmd0908_token_delete(void *pContext)
{
	MASON_CMD_DECLARE_VARIABLE(ERT_OK)

	mason_cmd_init_outputTLVArray(&stStack);

	do
	{
		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_CMD))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		mason_cmd_append_ele_to_outputTLVArray(&stStack, pstTLV);

		mason_token_delete();
	} while (0);

	MASON_CMD_RESP_OUTPUT()
}
#ifdef MASON_TEST
/**
 * @functionname: mason_cmd0A01_crypto_sign_test
 * @description: 
 * @para: 
 * @return: 
 */
static void mason_cmd0A01_crypto_sign_test(void *pContext)
{
	MASON_CMD_DECLARE_VARIABLE(ERT_OK)

	uint8_t prikey[128] = {0};
	uint8_t signature[128];
	uint16_t signature_len;
	uint8_t hash[SHA512_LEN];
	uint16_t hash_len = SHA512_LEN;
	crypto_curve_t curve_type = CRYPTO_CURVE_SECP256K1;

	mason_cmd_init_outputTLVArray(&stStack);

	do
	{
		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_CMD))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		mason_cmd_append_ele_to_outputTLVArray(&stStack, pstTLV);

		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_PRVKEY) || (pstTLV->L > 128))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		memcpy(prikey, pstTLV->pV, pstTLV->L);

		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_HASH))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		hash_len = pstTLV->L;
		if ((0 == hash_len) || (hash_len > SHA512_LEN))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		memcpy(hash, pstTLV->pV, hash_len);

		if (stack_search_by_tag(pstS, &pstTLV, TLV_T_CURVE_TYPE) && ((1 == pstTLV->L)))
		{
			curve_type = (crypto_curve_t)(*(uint8_t *)pstTLV->pV);
		}

		if (!ecdsa_sign(curve_type, hash, hash_len, prikey, signature, &signature_len))
		{
			emRet = ERT_ECDSASignFail;
			break;
		}
		mason_cmd_append_to_outputTLVArray(&stStack, TLV_T_SIGNATURE, signature_len, signature);

	} while (0);

	memset(prikey, 0, sizeof(prikey));
	MASON_CMD_RESP_OUTPUT()
}
/**
 * @functionname: mason_cmd0A02_crypto_verify_test
 * @description: 
 * @para: 
 * @return: 
 */
static void mason_cmd0A02_crypto_verify_test(void *pContext)
{
	MASON_CMD_DECLARE_VARIABLE(ERT_CommFailParam)

	public_key_t pub_key;
	uint8_t signature[128];
	uint16_t signature_len = 128;
	uint8_t plaintext[512];
	uint16_t plaintext_len = 0;
	uint8_t hash[SHA512_LEN];
	crypto_curve_t curve_type = CRYPTO_CURVE_SECP256K1;

	mason_cmd_init_outputTLVArray(&stStack);

	do
	{
		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_CMD))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		mason_cmd_append_ele_to_outputTLVArray(&stStack, pstTLV);

		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_PUBKEY) || (pstTLV->L > PUBLIC_KEY_LEN))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		memcpy(pub_key.data, pstTLV->pV, pstTLV->L);
		pub_key.len = PUBLIC_KEY_LEN;

		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_PLAIN_MSG))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		plaintext_len = pstTLV->L;
		if ((0 == plaintext_len) || (plaintext_len > 512))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		memcpy(plaintext, pstTLV->pV, plaintext_len);
		sha256_api(plaintext, plaintext_len, hash);

		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_SIGNATURE) || (pstTLV->L > signature_len))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		memcpy(signature, (uint8_t *)pstTLV->pV, pstTLV->L);

		if (stack_search_by_tag(pstS, &pstTLV, TLV_T_CURVE_TYPE) && ((1 == pstTLV->L)))
		{
			curve_type = (crypto_curve_t)(*(uint8_t *)pstTLV->pV);
		}

		if (!ecdsa_verify(curve_type, hash, pub_key.data, signature))
		{
			emRet = ERT_ECDSAVerifyFail;
			break;
		}
		emRet = ERT_OK;
	} while (0);

	MASON_CMD_RESP_OUTPUT()
}
/**
 * @functionname: mason_cmd0A06_hash_test
 * @description: 
 * @para: 
 * @return: 
 */
static void mason_cmd0A06_hash_test(void *pContext)
{
	MASON_CMD_DECLARE_VARIABLE(ERT_CommFailParam)

	uint8_t plaintext[512];
	uint16_t plaintext_len = 0;
	uint8_t hash[SHA512_LEN];
	uint16_t hash_len = 0;
	uint8_t hashfunc = 0;

	mason_cmd_init_outputTLVArray(&stStack);

	do
	{
		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_CMD))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		mason_cmd_append_ele_to_outputTLVArray(&stStack, pstTLV);

		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_PLAIN_MSG))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		plaintext_len = pstTLV->L;
		if ((0 == plaintext_len) || (plaintext_len > 512))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		memcpy(plaintext, pstTLV->pV, plaintext_len);

		sha256_api(plaintext, plaintext_len, hash);

		if (!stack_search_by_tag(pstS, &pstTLV, TLV_T_HASH_FUNC) || (1 != pstTLV->L))
		{
			emRet = ERT_CommFailParam;
			break;
		}
		hashfunc = (*(uint8_t *)pstTLV->pV);
		switch (hashfunc)
		{
		case 0:
		{
			sha256_api(plaintext, plaintext_len, hash);
			hash_len = SHA256_LEN;
		}
		break;
		case 1:
		{
			sha512_api(plaintext, plaintext_len, hash);
			hash_len = SHA512_LEN;
		}
		break;
		default:
			break;
		}
		mason_cmd_append_to_outputTLVArray(&stStack, TLV_T_HASH, hash_len, hash);
		emRet = ERT_OK;
	} while (0);

	MASON_CMD_RESP_OUTPUT()
}
#endif
