/********************************************************************\
 *
 *      FILE:     rmd128mc.c
 *
 *      CONTENTS: A sample C-implementation of the
 *                RIPEMD128-MAC function.
 *      TARGET:   any computer with an ANSI C compiler
 *
 *      AUTHOR:   Antoon Bosselaers, ESAT-COSIC
 *      DATE:     26 March 1998
 *      VERSION:  1.0
 *
 *      Copyright (c) Katholieke Universiteit Leuven
 *      1998, All Rights Reserved
 *
\********************************************************************/

/*  header files */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rmd128mc.h"      

/* constants T0, T1, T2 specific for RIPEMD128-MAC */
static dword T[3][4];

/***********************************************************************/
void MDMACconstT(void)
/*
   calculates T0, T1, T2 required for RIPEMD128-MAC
   this has to be done only once
*/
{
   unsigned int  i, j;
   byte          U[65] = "00abcdefghijklmnopqrstuvwxyz\
ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
   dword         K[8], X[16];

   K[0] = 0x67452301UL;
   K[1] = 0xefcdab89UL;
   K[2] = 0x98badcfeUL;
   K[3] = 0x10325476UL;
   for (i=4; i<8 ;i++)
      K[i] = 0;

   for (i=0; i<3; i++) {
      U[0] = 0x30 + i;
      U[1] = U[0];
      MDMACinit(K, T[i]);
      for (j=0; j<16; j++)
         X[j] = BYTES_TO_DWORD(U+4*j);
      compress(K, T[i], X);
   }

}

/***********************************************************************/
dword *MDMACsetup(byte *key)
/*
   expands 128-bit key into 3*4*32-bit K required for RIPEMD128-MAC
*/
{
   unsigned int i, j;
   dword        U[16];
   dword        KK[8];
   static dword K[12];

   KK[0] = 0x67452301UL;
   KK[1] = 0xefcdab89UL;
   KK[2] = 0x98badcfeUL;
   KK[3] = 0x10325476UL;
   for (i=4; i<8 ;i++)
      KK[i] = 0;

   for (j=0; j<3; j++) {
      MDMACinit(KK, K+4*j);
      for (i=0; i<4 ; i++)  {
         U[i]    = BYTES_TO_DWORD(key+4*i);
         U[i+4]  = T[j][i];
         U[i+8]  = T[(j+1)%3][i];
         U[i+12] = T[(j+2)%3][i];
      }
      compress(KK, K+4*j, U);
      for (i=0; i<4 ; i++)  {
         U[i]    = T[j][i];
         U[i+4]  = T[(j+1)%3][i];
         U[i+8]  = T[(j+2)%3][i];
         U[i+12] = BYTES_TO_DWORD(key+4*i);
      }
      compress(KK, K+4*j, U);
   }

   return K;
}

/********************************************************************/

void MDMACinit(dword *K, dword *MDbuf)
{
   MDbuf[0] = K[0];
   MDbuf[1] = K[1];
   MDbuf[2] = K[2];
   MDbuf[3] = K[3];

   return;
}

/********************************************************************/

void compress(dword *K, dword *MDbuf, dword *X)
{
   dword aa = MDbuf[0],  bb = MDbuf[1],  cc = MDbuf[2],  dd = MDbuf[3];
   dword aaa = MDbuf[0], bbb = MDbuf[1], ccc = MDbuf[2], ddd = MDbuf[3];

   /* round 1 */
   FF(aa, bb, cc, dd, X[ 0]+K[4], 11);
   FF(dd, aa, bb, cc, X[ 1]+K[4], 14);
   FF(cc, dd, aa, bb, X[ 2]+K[4], 15);
   FF(bb, cc, dd, aa, X[ 3]+K[4], 12);
   FF(aa, bb, cc, dd, X[ 4]+K[4],  5);
   FF(dd, aa, bb, cc, X[ 5]+K[4],  8);
   FF(cc, dd, aa, bb, X[ 6]+K[4],  7);
   FF(bb, cc, dd, aa, X[ 7]+K[4],  9);
   FF(aa, bb, cc, dd, X[ 8]+K[4], 11);
   FF(dd, aa, bb, cc, X[ 9]+K[4], 13);
   FF(cc, dd, aa, bb, X[10]+K[4], 14);
   FF(bb, cc, dd, aa, X[11]+K[4], 15);
   FF(aa, bb, cc, dd, X[12]+K[4],  6);
   FF(dd, aa, bb, cc, X[13]+K[4],  7);
   FF(cc, dd, aa, bb, X[14]+K[4],  9);
   FF(bb, cc, dd, aa, X[15]+K[4],  8);
                             
   /* round 2 */
   GG(aa, bb, cc, dd, X[ 7]+K[5],  7);
   GG(dd, aa, bb, cc, X[ 4]+K[5],  6);
   GG(cc, dd, aa, bb, X[13]+K[5],  8);
   GG(bb, cc, dd, aa, X[ 1]+K[5], 13);
   GG(aa, bb, cc, dd, X[10]+K[5], 11);
   GG(dd, aa, bb, cc, X[ 6]+K[5],  9);
   GG(cc, dd, aa, bb, X[15]+K[5],  7);
   GG(bb, cc, dd, aa, X[ 3]+K[5], 15);
   GG(aa, bb, cc, dd, X[12]+K[5],  7);
   GG(dd, aa, bb, cc, X[ 0]+K[5], 12);
   GG(cc, dd, aa, bb, X[ 9]+K[5], 15);
   GG(bb, cc, dd, aa, X[ 5]+K[5],  9);
   GG(aa, bb, cc, dd, X[ 2]+K[5], 11);
   GG(dd, aa, bb, cc, X[14]+K[5],  7);
   GG(cc, dd, aa, bb, X[11]+K[5], 13);
   GG(bb, cc, dd, aa, X[ 8]+K[5], 12);

   /* round 3 */
   HH(aa, bb, cc, dd, X[ 3]+K[6], 11);
   HH(dd, aa, bb, cc, X[10]+K[6], 13);
   HH(cc, dd, aa, bb, X[14]+K[6],  6);
   HH(bb, cc, dd, aa, X[ 4]+K[6],  7);
   HH(aa, bb, cc, dd, X[ 9]+K[6], 14);
   HH(dd, aa, bb, cc, X[15]+K[6],  9);
   HH(cc, dd, aa, bb, X[ 8]+K[6], 13);
   HH(bb, cc, dd, aa, X[ 1]+K[6], 15);
   HH(aa, bb, cc, dd, X[ 2]+K[6], 14);
   HH(dd, aa, bb, cc, X[ 7]+K[6],  8);
   HH(cc, dd, aa, bb, X[ 0]+K[6], 13);
   HH(bb, cc, dd, aa, X[ 6]+K[6],  6);
   HH(aa, bb, cc, dd, X[13]+K[6],  5);
   HH(dd, aa, bb, cc, X[11]+K[6], 12);
   HH(cc, dd, aa, bb, X[ 5]+K[6],  7);
   HH(bb, cc, dd, aa, X[12]+K[6],  5);

   /* round 4 */
   II(aa, bb, cc, dd, X[ 1]+K[7], 11);
   II(dd, aa, bb, cc, X[ 9]+K[7], 12);
   II(cc, dd, aa, bb, X[11]+K[7], 14);
   II(bb, cc, dd, aa, X[10]+K[7], 15);
   II(aa, bb, cc, dd, X[ 0]+K[7], 14);
   II(dd, aa, bb, cc, X[ 8]+K[7], 15);
   II(cc, dd, aa, bb, X[12]+K[7],  9);
   II(bb, cc, dd, aa, X[ 4]+K[7],  8);
   II(aa, bb, cc, dd, X[13]+K[7],  9);
   II(dd, aa, bb, cc, X[ 3]+K[7], 14);
   II(cc, dd, aa, bb, X[ 7]+K[7],  5);
   II(bb, cc, dd, aa, X[15]+K[7],  6);
   II(aa, bb, cc, dd, X[14]+K[7],  8);
   II(dd, aa, bb, cc, X[ 5]+K[7],  6);
   II(cc, dd, aa, bb, X[ 6]+K[7],  5);
   II(bb, cc, dd, aa, X[ 2]+K[7], 12);

   /* parallel round 1 */
   III(aaa, bbb, ccc, ddd, X[ 5]+K[4],  8); 
   III(ddd, aaa, bbb, ccc, X[14]+K[4],  9);
   III(ccc, ddd, aaa, bbb, X[ 7]+K[4],  9);
   III(bbb, ccc, ddd, aaa, X[ 0]+K[4], 11);
   III(aaa, bbb, ccc, ddd, X[ 9]+K[4], 13);
   III(ddd, aaa, bbb, ccc, X[ 2]+K[4], 15);
   III(ccc, ddd, aaa, bbb, X[11]+K[4], 15);
   III(bbb, ccc, ddd, aaa, X[ 4]+K[4],  5);
   III(aaa, bbb, ccc, ddd, X[13]+K[4],  7);
   III(ddd, aaa, bbb, ccc, X[ 6]+K[4],  7);
   III(ccc, ddd, aaa, bbb, X[15]+K[4],  8);
   III(bbb, ccc, ddd, aaa, X[ 8]+K[4], 11);
   III(aaa, bbb, ccc, ddd, X[ 1]+K[4], 14);
   III(ddd, aaa, bbb, ccc, X[10]+K[4], 14);
   III(ccc, ddd, aaa, bbb, X[ 3]+K[4], 12);
   III(bbb, ccc, ddd, aaa, X[12]+K[4],  6);
                                  
   /* parallel round 2 */
   HHH(aaa, bbb, ccc, ddd, X[ 6]+K[5],  9);
   HHH(ddd, aaa, bbb, ccc, X[11]+K[5], 13);
   HHH(ccc, ddd, aaa, bbb, X[ 3]+K[5], 15);
   HHH(bbb, ccc, ddd, aaa, X[ 7]+K[5],  7);
   HHH(aaa, bbb, ccc, ddd, X[ 0]+K[5], 12);
   HHH(ddd, aaa, bbb, ccc, X[13]+K[5],  8);
   HHH(ccc, ddd, aaa, bbb, X[ 5]+K[5],  9);
   HHH(bbb, ccc, ddd, aaa, X[10]+K[5], 11);
   HHH(aaa, bbb, ccc, ddd, X[14]+K[5],  7);
   HHH(ddd, aaa, bbb, ccc, X[15]+K[5],  7);
   HHH(ccc, ddd, aaa, bbb, X[ 8]+K[5], 12);
   HHH(bbb, ccc, ddd, aaa, X[12]+K[5],  7);
   HHH(aaa, bbb, ccc, ddd, X[ 4]+K[5],  6);
   HHH(ddd, aaa, bbb, ccc, X[ 9]+K[5], 15);
   HHH(ccc, ddd, aaa, bbb, X[ 1]+K[5], 13);
   HHH(bbb, ccc, ddd, aaa, X[ 2]+K[5], 11);

   /* parallel round 3 */   
   GGG(aaa, bbb, ccc, ddd, X[15]+K[6],  9);
   GGG(ddd, aaa, bbb, ccc, X[ 5]+K[6],  7);
   GGG(ccc, ddd, aaa, bbb, X[ 1]+K[6], 15);
   GGG(bbb, ccc, ddd, aaa, X[ 3]+K[6], 11);
   GGG(aaa, bbb, ccc, ddd, X[ 7]+K[6],  8);
   GGG(ddd, aaa, bbb, ccc, X[14]+K[6],  6);
   GGG(ccc, ddd, aaa, bbb, X[ 6]+K[6],  6);
   GGG(bbb, ccc, ddd, aaa, X[ 9]+K[6], 14);
   GGG(aaa, bbb, ccc, ddd, X[11]+K[6], 12);
   GGG(ddd, aaa, bbb, ccc, X[ 8]+K[6], 13);
   GGG(ccc, ddd, aaa, bbb, X[12]+K[6],  5);
   GGG(bbb, ccc, ddd, aaa, X[ 2]+K[6], 14);
   GGG(aaa, bbb, ccc, ddd, X[10]+K[6], 13);
   GGG(ddd, aaa, bbb, ccc, X[ 0]+K[6], 13);
   GGG(ccc, ddd, aaa, bbb, X[ 4]+K[6],  7);
   GGG(bbb, ccc, ddd, aaa, X[13]+K[6],  5);

   /* parallel round 4 */
   FFF(aaa, bbb, ccc, ddd, X[ 8]+K[7], 15);
   FFF(ddd, aaa, bbb, ccc, X[ 6]+K[7],  5);
   FFF(ccc, ddd, aaa, bbb, X[ 4]+K[7],  8);
   FFF(bbb, ccc, ddd, aaa, X[ 1]+K[7], 11);
   FFF(aaa, bbb, ccc, ddd, X[ 3]+K[7], 14);
   FFF(ddd, aaa, bbb, ccc, X[11]+K[7], 14);
   FFF(ccc, ddd, aaa, bbb, X[15]+K[7],  6);
   FFF(bbb, ccc, ddd, aaa, X[ 0]+K[7], 14);
   FFF(aaa, bbb, ccc, ddd, X[ 5]+K[7],  6);
   FFF(ddd, aaa, bbb, ccc, X[12]+K[7],  9);
   FFF(ccc, ddd, aaa, bbb, X[ 2]+K[7], 12);
   FFF(bbb, ccc, ddd, aaa, X[13]+K[7],  9);
   FFF(aaa, bbb, ccc, ddd, X[ 9]+K[7], 12);
   FFF(ddd, aaa, bbb, ccc, X[ 7]+K[7],  5);
   FFF(ccc, ddd, aaa, bbb, X[10]+K[7], 15);
   FFF(bbb, ccc, ddd, aaa, X[14]+K[7],  8);

   /* combine results */
   ddd += cc + MDbuf[1];               /* final result for MDbuf[0] */
   MDbuf[1] = MDbuf[2] + dd + aaa;
   MDbuf[2] = MDbuf[3] + aa + bbb;
   MDbuf[3] = MDbuf[0] + bb + ccc;
   MDbuf[0] = ddd;

   return;
}

/********************************************************************/

void MDMACfinish(dword *K, dword *MDbuf, byte *strptr,
                 dword lswlen, dword mswlen)
{
   unsigned int i;                                 /* counter       */
   dword        X[16];                             /* message words */

   memset(X, 0, 16*sizeof(dword));

   /* put bytes from strptr into X */
   for (i=0; i<(lswlen&63); i++) {
      /* byte i goes into word X[i div 4] at pos.  8*(i mod 4)  */
      X[i>>2] ^= (dword) *strptr++ << (8 * (i&3));
   }

   /* append the bit m_n == 1 */
   X[(lswlen>>2)&15] ^= (dword)1 << (8*(lswlen&3) + 7);

   if ((lswlen & 63) > 55) {
      /* length goes to next block */
      compress(K, MDbuf, X);
      memset(X, 0, 16*sizeof(dword));
   }

   /* append length in bits*/
   X[14] = lswlen << 3;
   X[15] = (lswlen >> 29) | (mswlen << 3);
   compress(K, MDbuf, X);

   /* last block */
   for (i=0; i<4; i++) {
      X[i]    = K[8+i];
      X[i+4]  = K[8+i] ^ T[0][i];
      X[i+8]  = K[8+i] ^ T[1][i];
      X[i+12] = K[8+i] ^ T[2][i];
   }
   compress(K, MDbuf, X);

   return;
}

/*********************** end of file rmd128mc.c *********************/
