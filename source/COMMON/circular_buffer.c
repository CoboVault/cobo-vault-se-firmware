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
#define CIRCULAR_BUFFER_GLOBAL

/** Header file reference */
#include "circular_buffer.h"
// #include <assert.h>
#include <stdlib.h>

/** Function implementations */
/**
 * @functionname: circular_buf_init
 * @description: 
 * @para: 
 * @return: 
 */
cbuf_handle_t circular_buf_init(uint8_t *buffer, size_t size)
{
    cbuf_handle_t cbuf = NULL;

    // assert(buffer && size);

    cbuf = calloc(1, sizeof(circular_buf_t));
    // assert(cbuf);

    cbuf->buffer = buffer;
    cbuf->max = size;
    circular_buf_reset(cbuf);

    // assert(circular_buf_empty(cbuf));

    return cbuf;
}
/**
 * @functionname: circular_buf_reset
 * @description: 
 * @para: 
 * @return: 
 */
void circular_buf_reset(cbuf_handle_t cbuf)
{
    // assert(cbuf);

    cbuf->head = 0;
    cbuf->tail = 0;
    cbuf->full = false;
}
/**
 * @functionname: circular_buf_free
 * @description: 
 * @para: 
 * @return: 
 */
void circular_buf_free(cbuf_handle_t cbuf)
{
    // assert(cbuf);
    free(cbuf);
}
/**
 * @functionname: circular_buf_full
 * @description: 
 * @para: 
 * @return: 
 */
bool circular_buf_full(cbuf_handle_t cbuf)
{
    // assert(cbuf);

    return cbuf->full;
}
/**
 * @functionname: circular_buf_empty
 * @description: 
 * @para: 
 * @return: 
 */
bool circular_buf_empty(cbuf_handle_t cbuf)
{
    // assert(cbuf);

    return (!cbuf->full && (cbuf->head == cbuf->tail));
}
/**
 * @functionname: circular_buf_capacity
 * @description: 
 * @para: 
 * @return: 
 */
size_t circular_buf_capacity(cbuf_handle_t cbuf)
{
    // assert(cbuf);

    return cbuf->max;
}
/**
 * @functionname: circular_buf_size
 * @description: 
 * @para: 
 * @return: 
 */
size_t circular_buf_size(cbuf_handle_t cbuf)
{
    size_t size = 0;

    // assert(cbuf);

    size = cbuf->max;

    if (!cbuf->full)
    {
        if (cbuf->head >= cbuf->tail)
        {
            size = (cbuf->head - cbuf->tail);
        }
        else
        {
            size = (cbuf->max + cbuf->head - cbuf->tail);
        }
    }

    return size;
}
/**
 * @functionname: advance_pointer
 * @description: 
 * @para: 
 * @return: 
 */
static void advance_pointer(cbuf_handle_t cbuf)
{
    // assert(cbuf);

    if (cbuf->full)
    {
        cbuf->tail = (cbuf->tail + 1) % cbuf->max;
    }

    cbuf->head = (cbuf->head + 1) % cbuf->max;
    cbuf->full = (cbuf->head == cbuf->tail);
}
/**
 * @functionname: retreat_pointer
 * @description: 
 * @para: 
 * @return: 
 */
static void retreat_pointer(cbuf_handle_t cbuf)
{
    // assert(cbuf);

    cbuf->full = false;
    cbuf->tail = (cbuf->tail + 1) % cbuf->max;
}
/**
 * @functionname: circular_buf_put
 * @description: 
 * @para: 
 * @return: 
 */
void circular_buf_put(cbuf_handle_t cbuf, uint8_t data)
{
    // assert(cbuf && cbuf->buffer);

    cbuf->buffer[cbuf->head] = data;

    advance_pointer(cbuf);
}
/**
 * @functionname: circular_buf_put2
 * @description: 
 * @para: 
 * @return: 
 */
int circular_buf_put2(cbuf_handle_t cbuf, uint8_t data)
{
    int r = -1;

    // assert(cbuf && cbuf->buffer);

    if (!circular_buf_full(cbuf))
    {
        cbuf->buffer[cbuf->head] = data;
        advance_pointer(cbuf);
        r = 0;
    }

    return r;
}
/**
 * @functionname: circular_buf_get
 * @description: 
 * @para: 
 * @return: 
 */
int circular_buf_get(cbuf_handle_t cbuf, uint8_t *data)
{
    int r = -1;

    // assert(cbuf && data && cbuf->buffer);

    if (!circular_buf_empty(cbuf))
    {
        *data = cbuf->buffer[cbuf->tail];
        retreat_pointer(cbuf);

        r = 0;
    }

    return r;
}
