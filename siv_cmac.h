/* siv.h

   AES-SIV, RFC5297

   Copyright (C) 2017 Nikos Mavrogiannopoulos

   This file is part of GNU Nettle.

   GNU Nettle is free software: you can redistribute it and/or
   modify it under the terms of either:

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at your
       option) any later version.

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at your
       option) any later version.

   or both in parallel, as here.

   GNU Nettle is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see http://www.gnu.org/licenses/.
*/

#ifndef NETTLE_SIV_H_INCLUDED
#define NETTLE_SIV_H_INCLUDED

#include "nettle/nettle-types.h"
#include "nettle/aes.h"

/* For SIV, the block size of the block cipher shall be 128 bits. */
#define SIV_BLOCK_SIZE  16
#define SIV_DIGEST_SIZE 16
#define SIV_MIN_NONCE_SIZE 0

/*
 * SIV mode requires the aad and plaintext when building the IV, which
 * prevents streaming processing and it incompatible with the AEAD API.
 */

/* AES_SIV_CMAC_256 */
struct siv_aes128_cmac_ctx {
    struct aes128_ctx         cipher;
    uint8_t s2vk[AES128_KEY_SIZE];
};

void
siv_aes128_cmac_set_key(struct siv_aes128_cmac_ctx *ctx, const uint8_t *key);

void
siv_aes128_cmac_encrypt_message(struct siv_aes128_cmac_ctx *ctx,
				size_t nlength, const uint8_t *nonce,
				size_t alength, const uint8_t *adata,
				size_t tlength,
				size_t clength, uint8_t *dst, const uint8_t *src);

int
siv_aes128_cmac_decrypt_message(struct siv_aes128_cmac_ctx *ctx,
				size_t nlength, const uint8_t *nonce,
				size_t alength, const uint8_t *adata,
				size_t tlength,
				size_t mlength, uint8_t *dst, const uint8_t *src);

#endif /* NETTLE_SIV_H_INCLUDED */
