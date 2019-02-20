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

  Implementation of NTS for NTP
  */

#include "config.h"

#include "sysincl.h"

#include "logging.h"
#include "memory.h"
#include "ntp_ext.h"
#include "nts_ke.h"
#include "nts_ntp.h"
#include "util.h"

#define MAX_COOKIES 8
#define UNIQ_ID_LENGTH 32

#define MAX_SERVER_KEYS 3

struct NTS_ClientInstance_Record {
  NKE_Instance *nke;
  NKE_Key c2s;
  NKE_Key s2c;
  NKE_Cookie cookies[MAX_COOKIES];
  int num_cookies;
  int cookie_index;
  unsigned char uniq_id[UNIQ_ID_LENGTH];
};

struct ServerKey {
  char key[32];
  uint32_t id;
};

struct NTS_ServerInstance_Record {
  NKE_Instance *nke;
  struct ServerKey keys[MAX_SERVER_KEYS];
  int num_keys;
  int key_index;
};

typedef struct NTS_ServerInstance_Record *NTS_ServerInstance;

struct AuthAndEEF {
  void *nonce;
  void *ciphertext;
  int nonce_length;
  int ciphertext_length;
};

static int
get_padded_length(int length)
{
  if (length % 4U)
    length += 4 - length % 4U;
  return length;
}

static int
parse_auth_and_eef(unsigned char *ef_body, int ef_body_length,
                   struct AuthAndEEF *auth)
{
  if (ef_body_length < 4)
    return 0;

  auth->nonce_length = ntohs(*((uint16_t *)ef_body + 0));
  auth->ciphertext_length = ntohs(*((uint16_t *)ef_body + 1));

  if (get_padded_length(auth->nonce_length) +
      get_padded_length(auth->ciphertext_length) > ef_body_length)
    return 0;

  auth->nonce = ef_body + 4;
  auth->ciphertext = ef_body + 4 + get_padded_length(auth->nonce_length);

  return 1;
}

void
NTS_Initialise(void)
{
}

void
NTS_Finalise(void)
{
}

int
NTS_CheckRequestAuth(NTP_Packet *packet, NTP_PacketInfo *info)
{
  int ef_type, ef_body_length, ef_parsed, parsed, cookie_length;
  void *ef_body, *cookie;
  struct AuthAndEEF auth_and_eef;

  if (info->ext_fields == 0 || info->mode != MODE_CLIENT)
    return 0;

  parsed = 0;
  cookie = NULL;

  while (1) {
    ef_parsed = NEF_ParseField(packet, info->length, parsed,
                               &ef_type, &ef_body, &ef_body_length);
    if (ef_parsed < parsed)
      break;
    parsed = ef_parsed;

    switch (ef_type) {
      case NTP_EF_NTS_COOKIE:
        if (cookie)
          /* Exactly one cookie is expected */
          return 0;
        cookie = ef_body;
        cookie_length = ef_body_length;
        break;
      case NTP_EF_NTS_COOKIE_PLACEHOLDER:
        break;
      case NTP_EF_NTS_AUTH_AND_EEF:
        if (!parse_auth_and_eef(ef_body, ef_body_length, &auth_and_eef))
          return 0;
        break;
      default:
        break;
    }
  }

  if (cookie && cookie_length)
    ;

  return 1;
}

static int
add_response_cookie(NTP_Packet *packet, NTP_PacketInfo *info)
{
  char cookie[100];

  memset(cookie, 0, sizeof (cookie));

  return NEF_AddField(packet, info, NTP_EF_NTS_COOKIE, &cookie, sizeof (cookie));
}

int
NTS_GenerateResponseAuth(NTP_Packet *request, NTP_PacketInfo *req_info,
                         NTP_Packet *response, NTP_PacketInfo *res_info)
{
  int ef_type, ef_body_length, ef_parsed, parsed;
  void *ef_body;

  if (req_info->mode != MODE_CLIENT || res_info->mode != MODE_SERVER)
    return 0;

  parsed = 0;

  while (1) {
    ef_parsed = NEF_ParseField(request, req_info->length, parsed,
                               &ef_type, &ef_body, &ef_body_length);
    if (ef_parsed < parsed)
      break;
    parsed = ef_parsed;

    switch (ef_type) {
      case NTP_EF_NTS_UNIQUE_IDENTIFIER:
        /* Copy the ID from the request */
        if (!NEF_AddField(response, res_info, ef_type, ef_body, ef_body_length))
          return 0;
      case NTP_EF_NTS_COOKIE:
      case NTP_EF_NTS_COOKIE_PLACEHOLDER:
        if (!add_response_cookie(response, res_info))
          return 0;
      default:
        break;
    }
  }

  return 1;
}

NTS_ClientInstance
NTS_CreateClientInstance(void)
{
  NTS_ClientInstance inst;

  inst = MallocNew(struct NTS_ClientInstance_Record);

  memset(inst, 0, sizeof (*inst));
  inst->num_cookies = 0;
  memset(inst->uniq_id, 0, sizeof (inst->uniq_id));

#if 1
  int i;
  for (i = 0; i < MAX_COOKIES; i++)
    inst->cookies[i].length = 100;
  inst->num_cookies = MAX_COOKIES;
#endif

  return inst;
}

void
NTS_DestroyClientInstance(NTS_ClientInstance inst)
{
  Free(inst);
}

int
NTS_GenerateRequestAuth(NTS_ClientInstance inst, NTP_Packet *packet,
                        NTP_PacketInfo *info)
{
  NKE_Cookie *cookie;
  unsigned char auth[100];
  int i;

  if (inst->num_cookies <= 0)
    return 0;

  cookie = &inst->cookies[inst->cookie_index];

  UTI_GetRandomBytes(&inst->uniq_id, sizeof (inst->uniq_id)); 

  if (!NEF_AddField(packet, info, NTP_EF_NTS_UNIQUE_IDENTIFIER,
                    &inst->uniq_id, sizeof (inst->uniq_id)))
    return 0;

  if (!NEF_AddField(packet, info, NTP_EF_NTS_COOKIE,
                    cookie->cookie, cookie->length))
    return 0;

  for (i = 0; i < MAX_COOKIES - inst->num_cookies; i++) {
    if (!NEF_AddField(packet, info, NTP_EF_NTS_COOKIE_PLACEHOLDER,
                      cookie->cookie, cookie->length))
      return 0;
  }

  memset(auth, 0, sizeof (auth));
  if (!NEF_AddField(packet, info, NTP_EF_NTS_AUTH_AND_EEF,
                    auth, sizeof (auth)))
    return 0;

  inst->num_cookies--;
  inst->cookie_index = (inst->cookie_index + 1) % MAX_COOKIES;

  return 1;
}

int
NTS_CheckResponseAuth(NTS_ClientInstance inst, NTP_Packet *packet,
                      NTP_PacketInfo *info)
{
  if (info->ext_fields == 0 || info->mode != MODE_SERVER)
    return 0;

  return 0;
}
