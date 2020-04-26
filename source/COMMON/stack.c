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
#define STACK_GLOBAL

/** Header file reference */
#include "stack.h"

/** Variable definitions */
// STACK_EXT stStackType stStack =
// 	{
// 		{NULL},
// 		-1};

/** Function implementations */
/**
 * @functionname: stack_init
 * @description: 
 * @para: 
 * @return: 
 */
STACK_EXT void stack_init(pstStackType pstStack)
{
	pstStackType pstS = pstStack;
	pstS->top = -1;
}
/**
 * @functionname: stack_empty
 * @description: 
 * @para: 
 * @return: 
 */
STACK_EXT bool stack_empty(pstStackType pstStack)
{
	pstStackType pstS = pstStack;
	if (-1 == pstS->top)
	{
		return true;
	}
	else
	{
		return false;
	}
}
/**
 * @functionname: stack_full
 * @description: 
 * @para: 
 * @return: 
 */
STACK_EXT bool stack_full(pstStackType pstStack)
{
	pstStackType pstS = pstStack;
	if (pstS->top == STACK_SIZE - 1)
	{
		return true;
	}
	else
	{
		return false;
	}
}
/**
 * @functionname: stack_size
 * @description: 
 * @para: 
 * @return: 
 */
STACK_EXT emStackStatusType stack_size(pstStackType pstStack, size_t *psz)
{
	pstStackType pstS = pstStack;
	if (stack_empty(pstS))
	{
		return EM_STACK_EMPTY;
	}
	*psz = pstS->top = 1;

	return EM_STACK_OK;
}
/**
 * @functionname: stack_push
 * @description: 
 * @para: 
 * @return: 
 */
STACK_EXT emStackStatusType stack_push(pstStackType pstStack, stackElementType element)
{
	pstStackType pstS = pstStack;

	if (!stack_full(pstS))
	{
		pstS->top++;
		pstS->stack[pstS->top] = element;
	}
	else
	{
		return EM_STACK_FULL;
	}

	return EM_STACK_OK;
}
/**
 * @functionname: stack_pop
 * @description: 
 * @para: 
 * @return: 
 */
STACK_EXT emStackStatusType stack_pop(pstStackType pstStack, stackElementType *pelement)
{
	pstStackType pstS = pstStack;

	if (!stack_empty(pstS))
	{
		*pelement = pstS->stack[pstS->top];
		pstS->top--;
	}
	else
	{
		return EM_STACK_EMPTY;
	}

	return EM_STACK_OK;
}
/**
 * @functionname: stack_top
 * @description: 
 * @para: 
 * @return: 
 */
STACK_EXT emStackStatusType stack_top(pstStackType pstStack, stackElementType *pelement)
{
	pstStackType pstS = pstStack;

	if (!stack_empty(pstS))
	{
		*pelement = pstS->stack[pstS->top];
	}
	else
	{
		return EM_STACK_EMPTY;
	}

	return EM_STACK_OK;
}
/**
 * @functionname: stack_get
 * @description: 
 * @para: 
 * @return: 
 */
STACK_EXT emStackStatusType stack_get(pstStackType pstStack, stackElementType *pelement, int index)
{
	pstStackType pstS = pstStack;

	if (stack_empty(pstS))
		return EM_STACK_EMPTY;

	if (index > pstS->top)
		return EM_STACK_INVALID;

	*pelement = pstS->stack[index];

	return EM_STACK_OK;
}
/**
 * @functionname: stack_destroy
 * @description: 
 * @para: 
 * @return: 
 */
STACK_EXT void stack_destroy(pstStackType pstStack)
{
	pstStackType pstS = pstStack;
	stackElementType element;

	while(EM_STACK_OK == stack_pop(pstS, &element))
	{
		if (NULL != element)
		{
			free(element);
		}
	}
}

