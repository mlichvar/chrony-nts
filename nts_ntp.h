/*
  chronyd/chronyc - Programs for keeping computer clocks accurate.

 **********************************************************************
 * Copyright (C) Miroslav Lichvar  2019
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

  Header file of the NTS for NTP implementation
  */

#ifndef GOT_NTS_NTP_H
#define GOT_NTS_NTP_H

#include "ntp.h"

#define NTP_EF_NTS_UNIQUE_IDENTIFIER    0x0104
#define NTP_EF_NTS_COOKIE               0x0204
#define NTP_EF_NTS_COOKIE_PLACEHOLDER   0x0304
#define NTP_EF_NTS_AUTH_AND_EEF         0x0404

typedef struct NTS_ClientInstance_Record *NTS_ClientInstance;

extern void NTS_Initialise(void);
extern void NTS_Finalise(void);

extern int NTS_CheckRequestAuth(NTP_Packet *packet, NTP_PacketInfo *info);
extern int NTS_GenerateResponseAuth(NTP_Packet *request, NTP_PacketInfo *req_info,
                                    NTP_Packet *response, NTP_PacketInfo *res_info);

extern NTS_ClientInstance NTS_CreateClientInstance(IPAddr *address, int port, const char *name);
extern void NTS_DestroyClientInstance(NTS_ClientInstance inst);
extern int NTS_PrepareForAuth(NTS_ClientInstance inst);
extern int NTS_GenerateRequestAuth(NTS_ClientInstance inst, NTP_Packet *packet,
                                   NTP_PacketInfo *info);
extern int NTS_CheckResponseAuth(NTS_ClientInstance inst, NTP_Packet *packet,
                                 NTP_PacketInfo *info);

#endif
