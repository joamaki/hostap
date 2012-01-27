/*
 * Privacy preserving discovery protocol - Common functions
 * Copyright 2008, TML / Helsinki University of Technology
 * Author(s):      Jussi Mäki <joamaki@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */


#include "includes.h"

#include "common.h"
#include "crypto/md5.h"
#include "crypto/sha1.h"
#include "crypto/sha256.h"
#include "crypto/aes.h"
#include "crypto/crypto.h"
#include "defs.h"

#include "wpa_common.h"
#include "ppdp_common.h"

const u8 ppdp_oui[] = { 0xAA, 0xBB, 0xCC, 0x00 };

static const char bin2hex_tbl[] = {'0', '1', '2', '3', '4',
				    '5', '6', '7', '8', '9',
				    'a', 'b', 'c', 'd', 'e',
				    'f' };

/* Convert binary data to hexadecimal string */
char * bin2hex (const u8 *src,
		size_t len,
		char *out)
{
	char *pos = out;
	size_t left = len;

	while (left > 0) {
		*pos++ = bin2hex_tbl[*src >> 4];
		*pos++ = bin2hex_tbl[*src & 0xf];
		src++;
		left--;
	}
	*pos = '\0';
	return out;
}

void ppdp_derive_keys (const u8 *psk,
		       const u8 *sta_nonce,
		       const u8 *ap_nonce,
		       u8 *authkey_out,
		       u8 *enckey_out)
{
	const u8 *elems[3];
	size_t lens[3];

	/* Derive authentication and encryption keys */
	elems[0] = (u8 *)"privacy key 1";
	elems[1] = sta_nonce;
	elems[2] = ap_nonce;
	lens[0] = os_strlen((char *)elems[0]);
	lens[1] = lens[2] = PPDP_NONCE_LEN;
	hmac_sha1_vector(psk, PMK_LEN, 3, elems, lens, authkey_out);

	elems[0] = (u8 *)"privacy key 2";
	elems[1] = sta_nonce;
	elems[2] = ap_nonce;
	hmac_sha1_vector(psk, PMK_LEN, 3, elems, lens, enckey_out);
}

int ppdp_encrypt_ssid (const u8 *key,
		       const u8 *rssid,
		       u8 *erssid_out)
{
	void *aes_ctx = aes_encrypt_init(key, 16);
	if (!aes_ctx) {
		wpa_printf(MSG_ERROR, "ppdp_encrypt_ssid: AES encrypt init failed!");
		return -1;
	}

	aes_encrypt(aes_ctx, rssid, erssid_out);
	aes_encrypt_deinit(aes_ctx);
	return 0;
}

int ppdp_decrypt_ssid (const u8 *key,
		       const u8 *erssid,
		       u8 *rssid_out)
{
	void *aes_ctx = aes_decrypt_init(key, 16);
	if (!aes_ctx) {
		wpa_printf(MSG_ERROR, "ppdp_decrypt_ssid: AES decrypt init failed!");
		return -1;
	}

	aes_decrypt(aes_ctx, erssid, rssid_out);
	aes_decrypt_deinit(aes_ctx);
	return 0;
}

void ppdp_calculate_msgauth(const u8 *authkey,
			    const u8 *sta_nonce,
			    const u8 *ap_nonce,
			    const u8 *erssid,
			    u8 *msgauth_out)
{
	const u8 *elems[3];
	size_t lens[3];

	elems[0] = sta_nonce;
	lens[0] = PPDP_NONCE_LEN;
	elems[1] = ap_nonce;
	lens[1] = PPDP_NONCE_LEN;
	elems[2] = erssid;
	lens[2] = PPDP_RSSID_LEN;
	hmac_sha1_vector(authkey, 20, 3, elems, lens, msgauth_out);
}
