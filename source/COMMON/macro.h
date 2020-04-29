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
#ifndef _MACRO_H_
#define _MACRO_H_

/** General constants macro definitions*/
//#define NULL   0
#define EOF		-1
#define TRUE	1
#define FALSE	0
#define YES		1
#define NO		0
#define ON		1
#define OFF		0
#define ENABLE	1
#define DISABLE	0
#define CRR		1
#define ERR		0
#define RIGHT	1
#define WRONG	0
#define SUCCESS	1
#define FAILURE	0
#define OK		1
#define FAIL	0
#define PI		3.1415926 //3.1415926535897932

#ifndef BIT
#define BIT(x) (1 << (x))
#endif

#ifndef _BV
#define _BV(x) (1 << (x))
#endif
/** General expression definitions*/
#define _CALLOC(a) ((a *)calloc(n, sizeof(a)))
#define _MALLOC(a) ((a *)malloc(sizeof(a)))
#define _MIN(a, b) ((a) < (b) ? (a) : (b))
#define _MAX(a, b) ((a) > (b) ? (a) : (b))
#define _EXCHANGE(a,b) { int t; t=(a); (a)=(b); (b)=t; }
#define _SWAP(a,b) { if((a)==(b))return;(a)^=(b);(b)^=(a);(a)^=(b); }
#define _ToLower(c) ((c) + 32)
#define _ToUpper(c) ((c)-32)

#define SET(Reg, n) Reg |= BIT(n);
#define CLR(Reg, n) Reg &= ~BIT(n);

#define _atomic(Codes) \
	cli();             \
	Codes;             \
	sei();

/**FUNCTION****************************************************************************************
* @functionname:  
* @description:  changeIntToHex(33),return 0x33
* @para:
* @return:
*/
#define changeIntToHex(dec) ((((dec) / 10) << 4) + ((dec) % 10))
/**FUNCTION****************************************************************************************
* @functionname:  
* @description:  converseIntToHex(33),return 21
* @para:
* @return:
*/
#define converseIntToHex(dec) ((((dec) >> 4) * 10) + ((dec) % 16))
/**FUNCTION****************************************************************************************
* @functionname:  
* @description: changeHexToInt(0x33),return 33
* @para:
* @return:
*/
#define changeHexToInt(hex) ((((hex) >> 4) * 10) + ((hex) % 16))
/**FUNCTION****************************************************************************************
* @functionname:  
* @description:  converseHexToInt(0x33),return 51
* @para:
* @return:
*/
#define converseHexToInt(hex) ((((hex) / 10) << 4) + ((hex) % 10))

#endif