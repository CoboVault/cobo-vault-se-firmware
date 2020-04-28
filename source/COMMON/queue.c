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
#define QUEUE_GLOBAL

/** Header file reference */
#include "queue.h"
#include "mason_debug.h"

/** Variable definitions */
QUEUE_EXT stQueueType stQueue;

/** Function implementations */
/**
 * @functionname: queue_init
 * @description: 
 * @para: 
 * @return: 
 */
QUEUE_EXT void queue_init(volatile stQueueType *pstQueue)
{
	pstQueue->head = 0;
	pstQueue->tail = 0;
	pstQueue->size = 0;
	memset((void *)pstQueue->queue, (int)NULL, QUEUE_SIZE);
	QUEUE_LOG("queue init! max size = %d\r\n", QUEUE_SIZE);
}
/**
 * @functionname: queue_size
 * @description: 
 * @para: 
 * @return: 
 */
QUEUE_EXT uint32_t queue_size(volatile stQueueType *pstQueue)
{
	QUEUE_LOG("Queue size = %d\r\n", pstQueue->size);
	return (pstQueue->size);
}
/**
 * @functionname: queue_is_empty
 * @description: 
 * @para: pstQueue: pointer of a queue struct
 * @return: 1: queue is empty
			0: queue is not empty
 */
QUEUE_EXT int queue_is_empty(volatile stQueueType *pstQueue)
{
	return ((pstQueue->head == pstQueue->tail) && (!pstQueue->size));
}
/**
* @functionname: queue_is_full
* @description:
* @para:	pstQueue: pointer of a queue struct
* @return:	1: queue is full
			0: queue is not full
*/
QUEUE_EXT int queue_is_full(volatile stQueueType *pstQueue)
{
	return ((pstQueue->head == pstQueue->tail) && (pstQueue->size));
}
/**
* @functionname: enqueue_overwrite
* @description: enqueue an element, will overwrite the oldest element 
* @para:	pstQueue: pointer of a queue struct
			element: element in queue type
* @return:	void
*/
QUEUE_EXT void enqueue_overwrite(volatile stQueueType *pstQueue, queueElementType element)
{
	QUEUE_LOG("enqueue_overwrite!\r\n");
	pstQueue->queue[pstQueue->tail] = element;
	pstQueue->tail++;
	if (pstQueue->tail >= QUEUE_SIZE)
	{
		pstQueue->tail = 0;
	}
	pstQueue->size++;
	if (pstQueue->size > QUEUE_SIZE)
	{
		pstQueue->size = QUEUE_SIZE;
		pstQueue->head = pstQueue->tail;
	}
}
/**
* @functionname: enqueue_safe
* @description: enqueue an element; preconditon: queue is not full
* @para:	pstQueue: pointer of a queue struct
			element: element in queue type
* @return:	void
*/
QUEUE_EXT void enqueue_safe(volatile stQueueType *pstQueue, queueElementType element)
{
	QUEUE_LOG("enqueue_safe!\r\n");
	if (!queue_is_full(pstQueue))
	{
		pstQueue->queue[pstQueue->tail] = element;
		pstQueue->tail++;
		if (pstQueue->tail >= QUEUE_SIZE)
		{
			pstQueue->tail = 0;
		}
		pstQueue->size++;
	}
	else
	{
		QUEUE_LOG("Queue is full!\r\n");
	}
}
/**
* @functionname: dequeue
* @description: dequeue an element; preconditon: queue is not empty
* @para:	pstQueue: pointer of a queue struct
* @return:	queue element in the head position
*/
QUEUE_EXT queueElementType dequeue(volatile stQueueType *pstQueue)
{
	queueElementType e = (queueElementType)NULL;

	QUEUE_LOG("dequeue!\r\n");
	if (!queue_is_empty(pstQueue))
	{
		e = pstQueue->queue[pstQueue->head];
		pstQueue->head++;
		if (pstQueue->head >= QUEUE_SIZE)
		{
			pstQueue->head = 0;
		}
		pstQueue->size--;
		QUEUE_LOG("dequeue element: %d\r\n", *e);
	}
	else
	{
		QUEUE_LOG("Queue is empty!\r\n");
	}

	return e;
}
/**
* @functionname: queue_display
* @description: display queue content
* @para:	pstQueue: pointer of a queue struct
			cb: pointer of a queue element display callback function
* @return: void
*/
QUEUE_EXT void queue_display(volatile stQueueType *pstQueue, display_element_callback cb)
{
	uint32_t index = pstQueue->head;
	uint32_t count = 0;

	QUEUE_LOG("Queue display:\r\n");
	printf("[%5d] ", pstQueue->size);
	while (count++ < pstQueue->size)
	{
		cb((void *)&(pstQueue->queue[index++ % QUEUE_SIZE]));
	}
	printf("\r\n");
}
/**
* @functionname: queue_display_detail
* @description: display queue content detail
* @para:	pstQueue: pointer of a queue struct
			cb: pointer of a queue element display callback function
* @return: void
*/
QUEUE_EXT void queue_display_detail(volatile stQueueType *pstQueue, display_element_callback cb)
{
	uint32_t index = pstQueue->head;
	uint32_t count = 0;

	QUEUE_LOG("Queue display detail:\r\n");
	printf("head = %d, tail = %d\r\n", pstQueue->head, pstQueue->tail);
	printf("[%6d]", pstQueue->size);
	while (count++ < pstQueue->size)
	{
		cb((void *)&(pstQueue->queue[index++ % QUEUE_SIZE]));
	}
	printf("\r\n");
}
/**
* @functionname: queue_display_detail_by_order
* @description: display queue content detail by stored order
* @para:	pstQueue: pointer of a queue struct
			cb: pointer of a queue element display callback function
* @return: void
*/
QUEUE_EXT void queue_display_detail_by_order(volatile stQueueType *pstQueue, display_element_callback cb)
{
	uint32_t index = 0;

	QUEUE_LOG("Queue display detail by stored order:\r\n");
	printf("[1-%4d]", QUEUE_SIZE);
	if (queue_is_empty(pstQueue))
	{
		for (index = 0; index < QUEUE_SIZE; index++)
		{
			printf("\tNULL");
		}
	}
	else
	{
		if (pstQueue->head < pstQueue->tail)
		{
			for (index = 0; index < pstQueue->head; index++)
			{
				printf("\tNULL");
			}
			for (index = pstQueue->head; index < pstQueue->tail; index++)
			{
				cb((void *)&(pstQueue->queue[index % QUEUE_SIZE]));
			}
			for (index = pstQueue->tail; index < QUEUE_SIZE; index++)
			{
				printf("\tNULL");
			}
		}
		else
		{
			for (index = 0; index < pstQueue->tail; index++)
			{
				cb((void *)&(pstQueue->queue[index % QUEUE_SIZE]));
			}
			for (index = pstQueue->tail; index < pstQueue->head; index++)
			{
				printf("\tNULL");
			}
			for (index = pstQueue->head; index < QUEUE_SIZE; index++)
			{
				cb((void *)&(pstQueue->queue[index % QUEUE_SIZE]));
			}
		}
	}
	printf("\r\n");
}
/**
* @functionname: display_element_callback
* @description: You should implement function that fit your own element type
* @para: element
* @return: void
*/
QUEUE_EXT void display_element(queueElementType *pElement)
{
	pstCMDType pstCMD = *pElement;
	printf("dequeue:\n");
	printf("pstCMD->unFlag.flag = %02X\n", pstCMD->unFlag.flag);
	printf("pstCMD->unFlag.stFlag.enc = %02X\n", pstCMD->unFlag.stFlag.enc);
	printf("pstCMD->unFlag.stFlag.ver = %02X\n", pstCMD->unFlag.stFlag.ver);
	printf("pstCMD->unFlag.stFlag.RFU = %02X\n", pstCMD->unFlag.stFlag.RFU);
	dump_data("pstCMD->pV:", pstCMD->pV, pstCMD->len);
}
