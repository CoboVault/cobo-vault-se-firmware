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
#ifndef STACK_H
#define STACK_H

/** Avoid duplicate definitions */
#ifdef STACK_GLOBAL
#define STACK_EXT
#else
#define STACK_EXT extern
#endif

/** Header file reference */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h> //memcpy...
#include "TLV.h"

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

/** Macro definitions*/
#define STACK_SIZE			10

/** Variable declarations */
typedef pstTLVType stackElementType;

typedef enum EM_STACK
{
	EM_STACK_OK,
	EM_STACK_FULL,
	EM_STACK_EMPTY,
	EM_STACK_INVALID,
} emStackStatusType;

typedef struct ST_STACK
{
	stackElementType stack[STACK_SIZE];
	int top;
} stStackType, *pstStackType;
// STACK_EXT stStackType stStack;

/** Function declarations */
STACK_EXT void stack_init(pstStackType pstStack);
STACK_EXT bool stack_empty(pstStackType pstStack);
STACK_EXT emStackStatusType stack_push(pstStackType pstStack, stackElementType element);
STACK_EXT emStackStatusType stack_pop(pstStackType pstStack, stackElementType *pelement);
STACK_EXT emStackStatusType stack_top(pstStackType pstStack, stackElementType *pelement);
STACK_EXT emStackStatusType stack_get(pstStackType pstStack, stackElementType *pelement, int index);
STACK_EXT void stack_destroy(pstStackType pstStack);

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
} /* Extern C */
#endif

#endif
