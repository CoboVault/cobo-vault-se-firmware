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
#ifndef QUEUE_H
#define QUEUE_H

/** Avoid duplicate definitions */
#ifdef QUEUE_GLOBAL
#define QUEUE_EXT
#else
#define QUEUE_EXT extern
#endif

/** Header file reference */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h> //memcpy...
#include "mason_commands.h"

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

/** Macro definitions*/
#define QUEUE_SIZE 10

	// #define QUEUE_LOG_ENABLE

#ifdef QUEUE_LOG_ENABLE
#define QUEUE_LOG(...) \
	printf(__VA_ARGS__)
#else
#define QUEUE_LOG(...)
#endif

	/** Variable declarations */
	typedef pstCMDType queueElementType;

	typedef struct
	{
		volatile queueElementType queue[QUEUE_SIZE];
		volatile uint32_t head, tail, size;
	} stQueueType, *pstQueueType;
	QUEUE_EXT stQueueType stQueue;

	/** Function declarations */
	typedef void (*display_element_callback)(void *);
	QUEUE_EXT void queue_init(volatile stQueueType *pstQueue);
	QUEUE_EXT uint32_t queue_size(volatile stQueueType *pstQueue);
	QUEUE_EXT int queue_is_empty(volatile stQueueType *pstQueue);
	QUEUE_EXT int queue_is_full(volatile stQueueType *pstQueue);
	QUEUE_EXT void enqueue_overwrite(volatile stQueueType *pstQueue, queueElementType element);
	QUEUE_EXT void enqueue_safe(volatile stQueueType *pstQueue, queueElementType element);
	QUEUE_EXT queueElementType dequeue(volatile stQueueType *pstQueue);
	QUEUE_EXT void queue_display(volatile stQueueType *pstQueue, display_element_callback cb);
	QUEUE_EXT void queue_display_detail(volatile stQueueType *pstQueue, display_element_callback cb);
	QUEUE_EXT void queue_display_detail_by_order(volatile stQueueType *pstQueue, display_element_callback cb);

	QUEUE_EXT void display_element(queueElementType *pElement);

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
} /* Extern C */
#endif

#endif
