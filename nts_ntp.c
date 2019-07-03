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

#include "ntp_sources.h"

#include "siv_cmac.h"

#define MAX_COOKIES 8
#define NONCE_LENGTH 16
#define UNIQ_ID_LENGTH 32

struct NTS_ClientInstance_Record {
  IPAddr address;
  int port;
  char *name;
  NKE_Instance nke;
  NKE_Cookie cookies[MAX_COOKIES];
  int num_cookies;
  int cookie_index;
  struct siv_cmac_aes128_ctx siv_c2s;
  struct siv_cmac_aes128_ctx siv_s2c;
  unsigned char nonce[NONCE_LENGTH];
  unsigned char uniq_id[UNIQ_ID_LENGTH];
};

struct AuthAndEEF {
  void *nonce;
  void *ciphertext;
  int nonce_length;
  int ciphertext_length;
};

struct {
  struct siv_cmac_aes128_ctx siv_s2c;
  unsigned char nonce[NONCE_LENGTH];
  NKE_Cookie cookies[MAX_COOKIES];
  int num_cookies;
} server_inst;

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
  int ef_type, ef_body_length, ef_parsed, parsed, has_auth = 0, has_cookie = 0;
  int i, requested_cookies = 0;
  void *ef_body;
  struct AuthAndEEF auth_and_eef;
  NKE_Cookie cookie;
  NKE_Key c2s, s2c;
  struct siv_cmac_aes128_ctx siv_c2s;
  NTP_Packet plaintext;

  if (info->ext_fields == 0 || info->mode != MODE_CLIENT)
    return 0;

  parsed = 0;

  while (1) {
    ef_parsed = NEF_ParseField(packet, info->length, parsed,
                               &ef_type, &ef_body, &ef_body_length);
    if (ef_parsed < parsed)
      break;
    parsed = ef_parsed;

    switch (ef_type) {
      case NTP_EF_NTS_COOKIE:
        if (has_cookie || ef_body_length > sizeof (cookie.cookie))
          return 0;
        cookie.length = ef_body_length;
        memcpy(cookie.cookie, ef_body, ef_body_length);
        if (!NKE_DecodeCookie(&cookie, &c2s, &s2c))
          return 0;
        has_cookie = 1;
        requested_cookies++;
        break;
      case NTP_EF_NTS_COOKIE_PLACEHOLDER:
        requested_cookies++;
        break;
      case NTP_EF_NTS_AUTH_AND_EEF:
        if (!has_cookie)
          return 0;
        if (!parse_auth_and_eef(ef_body, ef_body_length, &auth_and_eef))
          return 0;
        assert(c2s.length == 32);
        siv_cmac_aes128_set_key(&siv_c2s, (uint8_t *)c2s.key);
        if (!siv_cmac_aes128_decrypt_message(&siv_c2s,
                                             auth_and_eef.nonce_length, auth_and_eef.nonce,
                                             info->length - ef_body_length - 4, (uint8_t *)packet,
                                             auth_and_eef.ciphertext_length - SIV_DIGEST_SIZE,
                                             plaintext.extensions, auth_and_eef.ciphertext)) {
          DEBUG_LOG("SIV decrypt failed");
          return 0;
        }
        has_auth = 1;
        break;
      default:
        break;
    }
  }

  if (!has_auth)
    return 0;

  //TODO: process plaintext?

  assert(s2c.length == 32);
  siv_cmac_aes128_set_key(&server_inst.siv_s2c, (uint8_t *)s2c.key);

  UTI_GetRandomBytes(server_inst.nonce, sizeof (server_inst.nonce));

  server_inst.num_cookies = MIN(MAX_COOKIES, requested_cookies);
  for (i = 0; i < server_inst.num_cookies; i++)
    NKE_GenerateCookie(&c2s, &s2c, &server_inst.cookies[i]);

  return 1;
}

int
NTS_GenerateResponseAuth(NTP_Packet *request, NTP_PacketInfo *req_info,
                         NTP_Packet *response, NTP_PacketInfo *res_info)
{
  int i, ef_type, ef_body_length, ef_parsed, parsed;
  void *ef_body;
  NTP_Packet plaintext;
  NTP_PacketInfo plaintext_info;
  uint8_t auth[4 + NONCE_LENGTH + SIV_DIGEST_SIZE + MAX_COOKIES * (4 + NKE_MAX_COOKIE_LENGTH)];
  int auth_length, ciphertext_length;

  if (req_info->mode != MODE_CLIENT || res_info->mode != MODE_SERVER)
    return 0;

  //TODO: check if server_inst corresponds to this response

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
      default:
        break;
    }
  }

  //TODO: refactor this mess

  plaintext_info = *res_info;
  for (i = 0; i < server_inst.num_cookies; i++) {
    if (!NEF_AddField(&plaintext, &plaintext_info, NTP_EF_NTS_COOKIE,
                      &server_inst.cookies[i].cookie, server_inst.cookies[i].length))
      return 0;
  }

  ciphertext_length = SIV_DIGEST_SIZE + (plaintext_info.length - res_info->length);
  auth_length = 4 + sizeof (server_inst.nonce) + ciphertext_length;

  //TODO: make sure response is not longer than request

  assert(auth_length <= sizeof (auth));

  *(uint16_t *)&auth[0] = htons(sizeof (server_inst.nonce));
  *(uint16_t *)&auth[2] = htons(ciphertext_length);
  memcpy(&auth[4], server_inst.nonce, sizeof (server_inst.nonce));

  siv_cmac_aes128_encrypt_message(&server_inst.siv_s2c,
                                  sizeof (server_inst.nonce), server_inst.nonce,
                                  res_info->length, (uint8_t *)response,
                                  ciphertext_length,
                                  auth + (auth_length - ciphertext_length),
                                  (uint8_t *)&plaintext + res_info->length);

  if (!NEF_AddField(response, res_info, NTP_EF_NTS_AUTH_AND_EEF,
                    auth, auth_length))
    return 0;

  return 1;
}

NTS_ClientInstance
NTS_CreateClientInstance(IPAddr *address, int port, const char *name)
{
  NTS_ClientInstance inst;

  inst = MallocNew(struct NTS_ClientInstance_Record);

  memset(inst, 0, sizeof (*inst));
  inst->address = *address;
  inst->port = port;
  inst->name = name ? strdup(name) : NULL;
  inst->num_cookies = 0;
  memset(inst->uniq_id, 0, sizeof (inst->uniq_id));

  inst->nke = NULL;

  return inst;
}

void
NTS_DestroyClientInstance(NTS_ClientInstance inst)
{
  if (inst->nke)
    NKE_DestroyInstance(inst->nke);

  Free(inst->name);
  Free(inst);
}

static int
needs_nke(NTS_ClientInstance inst)
{
  return inst->num_cookies == 0;
}

static void
get_nke_data(NTS_ClientInstance inst)
{
  NTP_Remote_Address old_ntp_address, new_ntp_address;
  NKE_Key c2s, s2c;

  assert(needs_nke(inst));

  if (!inst->nke)
    inst->nke = NKE_CreateInstance();

  inst->cookie_index = 0;
  inst->num_cookies = NKE_GetCookies(inst->nke, inst->cookies, MAX_COOKIES);

  if (inst->num_cookies == 0) {
    if (NKE_IsClosed(inst->nke))
      NKE_OpenClientConnection(inst->nke, &inst->address, inst->port, inst->name);
    return;
  }

  if (NKE_GetNtpAddress(inst->nke, &new_ntp_address)) {
    //TODO
    old_ntp_address.ip_addr = inst->address;
    old_ntp_address.port = 123;
    NSR_ReplaceSource(&old_ntp_address, &new_ntp_address);
  }

  if (!NKE_GetKeys(inst->nke, &c2s, &s2c)) {
    inst->num_cookies = 0;
    return;
  }

  assert(c2s.length == 2 * AES128_KEY_SIZE);
  assert(s2c.length == 2 * AES128_KEY_SIZE);

  DEBUG_LOG("c2s key: %x s2c key: %x", *(unsigned int *)c2s.key, *(unsigned int *)s2c.key);
  siv_cmac_aes128_set_key(&inst->siv_c2s, (uint8_t *)c2s.key);
  siv_cmac_aes128_set_key(&inst->siv_s2c, (uint8_t *)s2c.key);

  NKE_DestroyInstance(inst->nke);
  inst->nke = NULL;
}

int
NTS_PrepareForAuth(NTS_ClientInstance inst)
{
  if (!needs_nke(inst))
    return 1;

  get_nke_data(inst);

  if (needs_nke(inst))
    return 0;

  UTI_GetRandomBytes(&inst->uniq_id, sizeof (inst->uniq_id)); 
  UTI_GetRandomBytes(&inst->nonce, sizeof (inst->nonce)); 

  return 1;
}

int
NTS_GenerateRequestAuth(NTS_ClientInstance inst, NTP_Packet *packet,
                        NTP_PacketInfo *info)
{
  NKE_Cookie *cookie;
  int i;
  struct {
    uint16_t nonce_length;
    uint16_t ciphertext_length;
    uint8_t nonce[NONCE_LENGTH];
    uint8_t ciphertext[SIV_DIGEST_SIZE];
  } auth;
  
  if (needs_nke(inst))
    return 0;

  cookie = &inst->cookies[inst->cookie_index];

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

  auth.nonce_length = htons(NONCE_LENGTH);
  auth.ciphertext_length = htons(sizeof (auth.ciphertext));
  memcpy(auth.nonce, inst->nonce, sizeof (auth.nonce));
  siv_cmac_aes128_encrypt_message(&inst->siv_c2s, sizeof (inst->nonce), inst->nonce,
                                  info->length, (uint8_t *)packet,
                                  SIV_DIGEST_SIZE, auth.ciphertext, (uint8_t *)"");

#if 0
  unsigned char x[100];
  printf("decrypt: %d\n",
         siv_cmac_aes128_decrypt_message(&inst->siv_c2s, sizeof (inst->nonce), inst->nonce,
                                  info->length, (uint8_t *)packet,
                                  sizeof (auth.ciphertext) - SIV_DIGEST_SIZE,
                                  x, auth.ciphertext));
#endif
  if (!NEF_AddField(packet, info, NTP_EF_NTS_AUTH_AND_EEF,
                    &auth, sizeof (auth)))
    return 0;

  inst->num_cookies--;
  inst->cookie_index = (inst->cookie_index + 1) % MAX_COOKIES;

  return 1;
}

static int
extract_cookies(NTS_ClientInstance inst, NTP_Packet *packet, int length)
{
  int ef_type, ef_body_length, ef_parsed, parsed, index;
  void *ef_body;

  parsed = 0;

  while (1) {
    ef_parsed = NEF_ParseField(packet, length, parsed,
                               &ef_type, &ef_body, &ef_body_length);
    if (ef_parsed <= parsed)
      break;
    parsed = ef_parsed;

    if (ef_type != NTP_EF_NTS_COOKIE)
      continue;

    if (inst->num_cookies >= MAX_COOKIES ||
        ef_body_length > sizeof (inst->cookies[0].cookie))
      break;

    index = (inst->cookie_index + inst->num_cookies) % MAX_COOKIES;
    memcpy(inst->cookies[index].cookie, ef_body, ef_body_length);
    inst->cookies[index].length = ef_body_length;

    inst->num_cookies++;

    DEBUG_LOG("Extracted cookie");
  }

  return 1;
}

int
NTS_CheckResponseAuth(NTS_ClientInstance inst, NTP_Packet *packet,
                      NTP_PacketInfo *info)
{
  int ef_type, ef_body_length, ef_parsed, parsed, has_uniq_id = 0, has_auth = 0;
  void *ef_body;
  struct AuthAndEEF auth_and_eef;
  NTP_Packet plaintext;

  if (info->ext_fields == 0 || info->mode != MODE_SERVER)
    return 0;

  parsed = NTP_HEADER_LENGTH;

  while (1) {
    ef_parsed = NEF_ParseField(packet, info->length, parsed,
                               &ef_type, &ef_body, &ef_body_length);
    if (ef_parsed < parsed)
      break;
    parsed = ef_parsed;

    switch (ef_type) {
      case NTP_EF_NTS_UNIQUE_IDENTIFIER:
        if (ef_body_length != sizeof (inst->uniq_id) ||
            memcmp(inst->uniq_id, inst->uniq_id, sizeof (inst->uniq_id))) {
          DEBUG_LOG("Invalid uniq id");
          return 0;
        }
        has_uniq_id = 1;
        break;
      case NTP_EF_NTS_COOKIE:
        DEBUG_LOG("Unencrypted cookie");
        break;
      case NTP_EF_NTS_AUTH_AND_EEF:
        if (ef_parsed != info->length) {
          DEBUG_LOG("Auth not last EF");
          return 0;
        }

        if (!parse_auth_and_eef(ef_body, ef_body_length, &auth_and_eef))
          return 0;

        //TODO: check nonce length
        if (auth_and_eef.ciphertext_length < SIV_DIGEST_SIZE ||
            auth_and_eef.ciphertext_length > sizeof (plaintext.extensions))
          return 0;

        if (!siv_cmac_aes128_decrypt_message(&inst->siv_s2c,
                                             auth_and_eef.nonce_length, auth_and_eef.nonce,
                                             info->length - ef_body_length - 4, (uint8_t *)packet,
                                             auth_and_eef.ciphertext_length - SIV_DIGEST_SIZE,
                                             plaintext.extensions, auth_and_eef.ciphertext)) {
          DEBUG_LOG("decrypt failed");
          return 0;
        }

        has_auth = 1;
        break;
      default:
        break;
    }
  }

  if (!has_uniq_id || !has_auth) {
    DEBUG_LOG("Missing NTS EF");
    return 0;
  }

  //TODO
  plaintext.lvm = packet->lvm;
  if (!extract_cookies(inst, &plaintext,
                       NTP_HEADER_LENGTH + auth_and_eef.ciphertext_length - SIV_DIGEST_SIZE)) {
    DEBUG_LOG("Couldn't extract cookies");
    return 0;
  }

  return 1;
}
