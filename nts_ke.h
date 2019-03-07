/*
  chronyd/chronyc - Programs for keeping computer clocks accurate.

 **********************************************************************
 * Copyright (C) Miroslav Lichvar  2018
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 * 
 **********************************************************************

  =======================================================================

  Header file of the NTS Key Establishment protocol
  */

#ifndef GOT_NTS_KE_H
#define GOT_NTS_KE_H

#include "addressing.h"

typedef struct NKE_Instance_Record *NKE_Instance;

#define NKE_MAX_KEY_LENGTH 32
#define NKE_MAX_COOKIE_LENGTH 256

typedef struct {
  int length;
  char key[NKE_MAX_KEY_LENGTH];
} NKE_Key;

typedef struct {
  int length;
  unsigned char cookie[NKE_MAX_COOKIE_LENGTH];
} NKE_Cookie;

extern void NKE_Initialise(void);
extern void NKE_Finalise(void);

extern NKE_Instance NKE_CreateInstance(void);
extern int NKE_OpenClientConnection(NKE_Instance inst, IPAddr *addr, int port,
                                    const char *name);
extern int NKE_GetCookies(NKE_Instance inst, NKE_Cookie *cookies, int max_cookies);
extern int NKE_GetKeys(NKE_Instance inst, NKE_Key *c2s, NKE_Key *s2c);
extern void NKE_Disconnect(NKE_Instance inst);
extern void NKE_DestroyInstance(NKE_Instance inst);

extern void NKE_test(void);

#endif
