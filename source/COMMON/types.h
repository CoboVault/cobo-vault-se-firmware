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
#ifndef __types_h
#define __types_h

typedef   signed           char INT8;
typedef   signed short     int  INT16;
typedef   signed           int  INT32;

/* exact-width unsigned integer types */
typedef unsigned           char UINT8;
typedef unsigned short     int  UINT16;
typedef unsigned           int  UINT32;

typedef unsigned           char BYTE;
typedef unsigned short     int  WORD;
typedef unsigned           int  DWORD;
typedef unsigned           char * PBYTE;
typedef unsigned short     int  * PWORD;
typedef unsigned           int  * PDWORD;

typedef unsigned           char  BOOL;

#define TRUE  1
#define FALSE 0

#endif 
