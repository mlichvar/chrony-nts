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

  Adding and parsing NTP extension fields
  */

#include "config.h"

#include "sysincl.h"

#include "ntp_ext.h"

struct ExtFieldHeader {
  uint16_t type;
  uint16_t length;
};

/* ================================================== */

int
NEF_AddField(NTP_Packet *packet, NTP_PacketInfo *info,
             int type, void *body, int body_length)
{
  struct ExtFieldHeader *header;
  int length = info->length;

  if (length < NTP_HEADER_LENGTH || length % 4 != 0 ||
      length + body_length + sizeof (*header) > sizeof (*packet))
    return 0;

  header = (struct ExtFieldHeader *)((unsigned char *)packet + length);
  header->type = htons(type);
  header->length = htons(sizeof (*header) + body_length);
  memcpy(header + 1, body, body_length);

  info->length += sizeof (*header) + body_length;

  return 1;
}

/* ================================================== */

int
NEF_ParseField(NTP_Packet *packet, int length, int parsed,
               int *type, void **body, int *body_length)
{
  int remainder, ef_length;
  struct ExtFieldHeader *header;

  if (length < NTP_HEADER_LENGTH || length % 4 != 0)
    return 0;

  /* Only NTPv4 packets have extension fields */
  if (NTP_LVM_TO_VERSION(packet->lvm) != 4)
    return 0;

  /* Skip the header */
  if (parsed < NTP_HEADER_LENGTH)
    parsed = NTP_HEADER_LENGTH;
  
  assert(parsed % 4 == 0);

  remainder = length - parsed;

  /* Check if the remaining data is a MAC.  RFC 7822 specifies the maximum
     length of MAC in a NTPv4 packet in order to allow deterministic parsing
     of extension fields. */
  if (remainder <= NTP_MAX_V4_MAC_LENGTH)
    return 0;

  /* Check if the length is valid for an NTPv4 extension field */
  if (remainder % 4 != 0 || remainder < NTP_MIN_EF_LENGTH)
    return 0;

  header = (struct ExtFieldHeader *)((unsigned char *)packet + parsed);
  ef_length = ntohs(header->length);

  if (ef_length < NTP_MIN_EF_LENGTH || ef_length > remainder ||
      ef_length % 4 != 0)
    return 0;

  if (type)
    *type = ntohs(header->type);
  if (body)
    *body = header + 1;
  if (body_length)
    *body_length = ef_length - sizeof (struct ExtFieldHeader);

  parsed += ef_length;

  assert(parsed <= length);

  return parsed;
}
