/*
 * Privacy preserving discovery protocol - Common functions
 * Copyright 2008, TML / Helsinki University of Technology
 * Author(s):      Jussi Mäki <joamaki@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __PPDP_COMMON_H
#define __PPDP_COMMON_H

#define PPDP_NONCE_LEN 16
#define PPDP_MSGAUTH_LEN 20
#define PPDP_RSSID_LEN 16
#define PPDP_OUI_LEN 3
#define PPDP_OUI 0x00aabbcc

#define PPDP_PROBE_RESP_LEN (PPDP_OUI_LEN + 2*PPDP_NONCE_LEN + PPDP_RSSID_LEN + PPDP_MSGAUTH_LEN /* 88 */)
#define PPDP_PROBE_REQ_LEN (PPDP_OUI_LEN + PPDP_NONCE_LEN /* 20 */)

#define PPDP_KEY_LEN 20

#include "includes.h"
#include "common.h"

extern const u8 ppdp_oui[];

void ppdp_derive_keys (const u8 *psk,
		       const u8 *sta_nonce,
		       const u8 *ap_nonce,
		       u8 *authkey_out,
		       u8 *enckey_out);

int ppdp_encrypt_ssid (const u8 *rssid,
		       const u8 *key,
		       u8 *erssid_out);


int ppdp_decrypt_ssid (const u8 *erssid,
		       const u8 *enckey,
		       u8 *rssid_out);


void ppdp_calculate_msgauth(const u8 *authkey,
			    const u8 *sta_nonce,
			    const u8 *ap_nonce,
			    const u8 *erssid,
			    u8 *msgauth_out);

char * bin2hex (const u8 *src,
		size_t len,
		char *out);

static inline void ppdp_dump(const u8 *psk, const u8 *sta_nonce, const u8 *ap_nonce,
			     const u8 *erssid, const u8 *msgauth,
			     const u8 *authkey, const u8 *enckey)
{
	char buf[256];
	printf("ppdp_dump:\n");
	printf("psk: %s\n", bin2hex(psk, 32, buf));
	printf("sta_nonce: %s\n", bin2hex(sta_nonce, 16, buf));
	printf("ap_nonce: %s\n", bin2hex(ap_nonce, 16, buf));
	printf("erssid: %s\n", bin2hex(erssid, 32, buf));
	printf("msgauth: %s\n", bin2hex(msgauth, 20, buf));
	printf("authkey: %s\n", bin2hex(authkey, 20, buf));
	printf("enckey: %s\n", bin2hex(enckey, 20, buf));
}

#endif /* __PPDP_COMMON_H */
