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
#ifndef VERSION_DEF_H
#define VERSION_DEF_H

/** Avoid duplicate definitions */
#ifdef VERSION_DEF_GLOBAL
#define VERSION_DEF_EXT
#else
#define VERSION_DEF_EXT extern
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

/** Macro definitions*/
#define VER_REL 1 // 0 -- develop mode , 1 -- release mode

#define VER_Major			0
#define VER_Minor			4
#define VER_Release		2
#define VER_Build			10000

#if VER_Major>0x9 || VER_Minor>0x9 || VER_Release>0x9 || VER_Build>0x0FFFFF
#if defined _WIN32 || _WIN64
#pragma message("VERSION define error, please check!")
#else
#error "VERSION define error, please check!"
#endif
#endif

#define _CONCATENATE_AS_DEC(a, b, c) a##b##c
#define _CONCATENATE_AS_HEX(a, b, c) 0x##a##b##c
#define _VER_F3(a, b, c) (_CONCATENATE_AS_HEX(a, b, c))
#define VER_F3 (_VER_F3(VER_Major, VER_Minor, VER_Release))
#define VERSION_BCD (uint32_t)(VER_F3 << 20 | VER_Build)

#define VER_LEN 12 + 1
#define GET_VERSION_STR(buf, len)                                                          \
    do                                                                                     \
    {                                                                                      \
        snprintf(buf, len, "%d.%d.%d.%06d", VER_Major, VER_Minor, VER_Release, VER_Build); \
    } while (0)


/** Compatibility with the cplusplus*/
#ifdef __cplusplus
} /* Extern C */
#endif

#endif
