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
#ifndef CIRCULAR_BUFFER_H
#define CIRCULAR_BUFFER_H

/** Avoid duplicate definitions */
#ifdef CIRCULAR_BUFFER_GLOBAL
#define CIRCULAR_BUFFER_EXT
#else
#define CIRCULAR_BUFFER_EXT extern
#endif

/** Header file reference */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h> //memcpy...

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

    /** Variable declarations */
    // The hidden definition of our circular buffer structure
    struct circular_buf_t
    {
        uint8_t *buffer;
        size_t head;
        size_t tail;
        size_t max; //of the buffer
        bool full;
    };
    // Opaque circular buffer structure
    typedef struct circular_buf_t circular_buf_t;
    // Handle type, the way users interact with the API
    typedef circular_buf_t *cbuf_handle_t;

    /** Function declarations */
    /// Pass in a storage buffer and size
    /// Returns a circular buffer handle
    cbuf_handle_t circular_buf_init(uint8_t *buffer, size_t size);

    /// Free a circular buffer structure.
    /// Does not free data buffer; owner is responsible for that
    void circular_buf_free(cbuf_handle_t cbuf);

    /// Reset the circular buffer to empty, head == tail
    void circular_buf_reset(cbuf_handle_t cbuf);

    /// Put version 1 continues to add data if the buffer is full
    /// Old data is overwritten
    void circular_buf_put(cbuf_handle_t cbuf, uint8_t data);

    /// Put Version 2 rejects new data if the buffer is full
    /// Returns 0 on success, -1 if buffer is full
    int circular_buf_put2(cbuf_handle_t cbuf, uint8_t data);

    /// Retrieve a value from the buffer
    /// Returns 0 on success, -1 if the buffer is empty
    int circular_buf_get(cbuf_handle_t cbuf, uint8_t *data);

    /// Returns true if the buffer is empty
    bool circular_buf_empty(cbuf_handle_t cbuf);

    /// Returns true if the buffer is full
    bool circular_buf_full(cbuf_handle_t cbuf);

    /// Returns the maximum capacity of the buffer
    size_t circular_buf_capacity(cbuf_handle_t cbuf);

    /// Returns the current number of elements in the buffer
    size_t circular_buf_size(cbuf_handle_t cbuf);

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
} /* Extern C */
#endif

#endif
