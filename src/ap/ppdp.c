/*
 * Privacy preserving discovery protocol
 * Copyright 2008, TML / Helsinki University of Technology
 * Author(s):      Jussi Mäki <joamaki@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "hostapd.h"
#include "ieee802_11.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"    
#include "crypto/sha1.h"
#include "crypto/aes.h"
#include "ap_config.h"
#include "sta_info.h"

#include "common/ppdp_common.h"
#include "ppdp.h"

struct rssid_cache_entry {
	u8 sta[ETH_ALEN];
	char rssid[PPDP_RSSID_LEN];
};

/* N.B. that if there are more than RSSID_CACHE_SIZE new stations
 * associating at the same time some of the stations
 * might receive a probe response with the wrong rssid if the
 * rssid already got reallocated.
 */

// TODO: Larger cache with hashing + timestamps
// Resolve collisions with open addressing and
// overwriting of expired entries?

#define RSSID_CACHE_SIZE 32
static int rssid_cache_latest;
static struct rssid_cache_entry rssid_cache[RSSID_CACHE_SIZE];

static char* rssid_cache_get(const u8 *sta) {
	int i;
	for (i = 0; i < RSSID_CACHE_SIZE; i++) {
		struct rssid_cache_entry *e = &rssid_cache[i];
		if (os_memcmp(sta, e->sta, ETH_ALEN) == 0)
			return e->rssid;
	}
	return NULL;
}

static char* rssid_cache_put(const u8 *sta, char *rssid) {
	struct rssid_cache_entry e;
	os_memcpy(e.sta, sta, sizeof(e.sta));
	os_memcpy(e.rssid, rssid, sizeof(e.rssid));

	rssid_cache[rssid_cache_latest] = e;
	rssid = rssid_cache[rssid_cache_latest].rssid;
	rssid_cache_latest = (rssid_cache_latest+1)%RSSID_CACHE_SIZE;
	return rssid;
}

char* ppdp_get_rssid(const u8 *sta)
{
	char *rssid = NULL;

	rssid = rssid_cache_get(sta);
	if (!rssid) {
		char rssid_tmp[PPDP_RSSID_LEN+1];
		u8 rnd[PPDP_RSSID_LEN/2];
		os_get_random(rnd, PPDP_RSSID_LEN/2);
		os_snprintf(rssid_tmp, PPDP_RSSID_LEN+1,
			    "%02x%02x%02x%02x%02x%02x%02x%02x",
			    rnd[0], rnd[1], rnd[2], rnd[3],
			    rnd[4], rnd[5], rnd[6], rnd[7]);
		rssid = rssid_cache_put(sta, rssid_tmp);
	}
	return rssid;
}

Boolean ppdp_is_probe_req(const u8 *start,
			  size_t len)
{
	size_t left = len;
	const u8 *pos = start;

	printf("ppdp_is_probe_req\n");

	while (left >= 2) {
		u8 id, elen;
		id = *pos++;
		elen = *pos++;
		left -= 2;

		if (elen > left)
			return FALSE;

		if (id == WLAN_EID_VENDOR_SPECIFIC &&
		    elen == PPDP_PROBE_REQ_LEN &&
		    !os_memcmp(pos, ppdp_oui, 4)) {
			printf("PPDP: is probe req.\n");
			return TRUE;
		}
		left -= elen;
		pos += elen;
	}
	return FALSE;

}

static ParseRes ppdp_parse_probe_req(const u8 *start,
				     size_t len,
				     u8 sta_nonce_out[])
{
	size_t left = len;
	const u8 *pos = start, *tpos;

	printf("PPDP: Parsing probe request!\n");

	while (left >= 2) {
		u8 id, elen;
		id = *pos++;
		elen = *pos++;
		left -= 2;

		if (elen > left)
			return ParseFailed;

		tpos = pos;
		if (id == WLAN_EID_VENDOR_SPECIFIC) {
			printf("vendor specific eid with oui: %02x:%02x:%02x\n",
			*tpos, *(tpos+1), *(tpos+2));

			if (!os_memcmp(tpos, ppdp_oui, 4)) {
				printf("it's ours!\n");
				printf("eid: %x\n", *(tpos+3));
				}
			}

		if (id == WLAN_EID_VENDOR_SPECIFIC &&
		    elen == PPDP_PROBE_REQ_LEN &&
		    !os_memcmp(tpos, ppdp_oui, 4)) {
			tpos += 4;
			os_memcpy(sta_nonce_out, tpos, PPDP_NONCE_LEN);
			printf("Parse OK!\n");
			return ParseOK;
		}

		left -= elen;
		pos += elen;
	}
	return ParseFailed;
}

u8 * ppdp_eid_probe_resp(struct hostapd_data *hapd,
			 struct sta_info *sta,
			 const struct ieee80211_mgmt *mgmt,
			 size_t len,
			 u8 *pos, u8 *epos)

{
	u8 erssid[PPDP_RSSID_LEN+1];
	u8 sta_nonce[PPDP_NONCE_LEN];
	u8 ap_nonce[PPDP_NONCE_LEN];

	u8 authkey[PPDP_KEY_LEN];
	u8 enckey[PPDP_KEY_LEN];
	u8 msgauth[PPDP_MSGAUTH_LEN];

	const u8 *ies = mgmt->u.probe_req.variable;

	char *rssid = NULL;
	
	if (sta) {
		rssid = sta->rssid;
	} else {
		rssid = ppdp_get_rssid(mgmt->sa);
	}


	printf("in ppdp_eid_probe_resp\n");

	if (NULL == hapd->conf->ssid.wpa_psk)
		return pos;

	if (pos+PPDP_PROBE_RESP_LEN+2 > epos) {
		wpa_printf(MSG_ERROR, "PPDP: No room in probe response for PPDP!");
		return pos;
	}

	if (ppdp_parse_probe_req(ies, len - (IEEE80211_HDRLEN + sizeof(mgmt->u.probe_req)), sta_nonce) != ParseOK)
		return pos;

	printf("OK generating response...\n");

	os_get_random(ap_nonce, PPDP_NONCE_LEN);

	ppdp_derive_keys(hapd->conf->ssid.wpa_psk->psk, sta_nonce, ap_nonce, authkey, enckey);

	if (ppdp_encrypt_ssid(enckey, (u8 *)rssid, erssid) != 0) {
		return pos;
	}

	*pos++ = WLAN_EID_VENDOR_SPECIFIC;
	*pos++ = PPDP_PROBE_RESP_LEN;

	os_memcpy(pos, ppdp_oui, 4);
	pos += 4;

	os_memcpy(pos, sta_nonce, 16);
	pos += 16;

	os_memcpy(pos, ap_nonce, 16);
	pos += 16;

	os_memcpy(pos, erssid, PPDP_RSSID_LEN);
	pos += PPDP_RSSID_LEN;

	ppdp_calculate_msgauth(authkey, sta_nonce, ap_nonce, erssid, msgauth);
	os_memcpy(pos, msgauth, PPDP_MSGAUTH_LEN);
	pos += PPDP_MSGAUTH_LEN;

	// DEBUG
	ppdp_dump(hapd->conf->ssid.wpa_psk->psk, sta_nonce, ap_nonce, erssid, msgauth, authkey, enckey);
	{
		u8 buf[256] = {0,};
		ppdp_decrypt_ssid(enckey, erssid, buf);
		printf("er-ssid decrypted: %s\n", buf);
	}

	return pos;
}
