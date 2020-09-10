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
#ifndef MASON_ERROR_DEF_H
#define MASON_ERROR_DEF_H

/** Header file reference */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

	/** Variable declarations */
	typedef enum
	{
		ERT_OK = 0,
		ERT_Success = 0,
		ERT_Pass = 0,

		ERT_INIT_FAIL = 0x0100,
		ERT_InitRngFail,
		ERT_InitFlashFail,
		ERT_InitUartFail,
		ERT_InitTimerFail,

		ERT_COMM_FAIL = 0x0200,
		ERT_CommTimeOut,
		ERT_CommInvalidCMD,
		ERT_CommFailEncrypt,
		ERT_CommFailLen,
		ERT_CommFailEtx,
		ERT_CommFailLrc,
		ERT_CommFailTLV,
		ERT_CommFailParam,

		ERT_BIP_FAIL = 0x0300,
		ERT_InvalidKey,
		ERT_GenKeyFail,
		ERT_ECDSASignFail,
		ERT_ECDSAVerifyFail,
		ERT_ED25519SignFail,
		ERT_ED25519VerifyFail,
		ERT_SecpEncryptFail,
		ERT_SecpDecryptFail,
		ERT_SM2EncryptFail,
		ERT_SM2DecryptFail,
		ERT_CKD_Fail,
		ERT_MnemonicNotMatch,
		ERT_CoinTypeInvalid,
		ERT_SignFail,
		ERT_VerifyFail,

		ERT_CMD_FAIL = 0x0400,
		ERT_NeedPreCMD,
		ERT_MsgNeedEncrypt,
		ERT_USERWithoutPermission,
		ERT_TLVArrayExceed,
		ERT_tlvArray_to_buf,
		ERT_HDPathIllegal,
		ERT_VerConflict,
		ERT_HDWalletSwitchNeed,
		ERT_HDWalletSwitchNotMatch,
		ERT_needEntropy,

		ERT_CHIP_FAIL = 0x0500,
		ERT_RngFail,
		ERT_SFlashFail,
		ERT_MallocFail,
		ERT_CheckSumFail,
		ERT_CheckMD5Fail,
		ERT_FuncParamInvalid,
		ERT_3DESFail,
		ERT_StorageFail,
		ERT_GetStatsFail,
		ERT_RecIDFail,
		ERT_UnexpectedFail,
		ERT_RSASubFail,
		ERT_LenTooLong,
		ERT_SNConflict,
		ERT_SNLenInvalid,
		ERT_SNInvalid,

		ERT_IAP_FAIL = 0x0600,
		ERT_FWUpdateFail,
		ERT_PacklenInvalid,
		ERT_IAP_fileDigest,
		ERT_IAP_beyoundRetry,

		ERT_UsrPassFAIL = 0x0700,
		ERT_needUsrPass,
		ERT_UsrPassVerifyFail,
		ERT_UsrPassNotCreate,
		ERT_UsrPassParaERR,
		ERT_needUsrFing,
		ERT_UsrFingVerifyFail,
		ERT_UsrFingNotCreate,
		ERT_UsrFingParaERR,
		ERT_needMessageSign,
		ERT_needToken,
		ERT_TokenVerifyFail,
		ERT_UsrSettingsLoadFail,
		ERT_UsrSettingsStoreFail,
		ERT_UsrSettingsNotAllow,

		ERT_Verify_Init = 0x0800,
		ERT_VerifyValueFail,
		ERT_VerifyLenFail,

		ERT_Verify_Success = 0x5AA5,

		ERT_DebugInvalid = 0xFF00,
		ERT_UnderAttack = 0xFFAA,
		ERT_Unauthorized = 0xFFFF,
		ERT_Total = 0xFFFF
	} emRetType;

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
} /* Extern C */
#endif

#endif
