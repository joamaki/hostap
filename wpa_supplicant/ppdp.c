/*
 * Privacy preserving discovery protocol
 * Copyright 2008, TML / Helsinki University of Technology
 * Author(s):      Jussi Maki <joamaki@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "config.h"
#include "config_ssid.h"
#include "crypto/sha1.h"
#include "crypto/aes.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"

#include "notify.h"
#include "bss.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "common/ppdp_common.h"
#include "ppdp.h"



/* Checks if the PPDP response authenticates. Returns 0 on success */
static int ppdp_authenticate(const u8 *psk,
			     const u8 *bssid,
			     const u8 *sta_nonce,
			     const u8 *ap_nonce,
			     const u8 *erssid,
			     const u8 *msgauth,
			     u8 *rssid_out)
{
	u8 msgauth2[PPDP_MSGAUTH_LEN];
	u8 authkey[PPDP_KEY_LEN];
	u8 enckey[PPDP_KEY_LEN];

	ppdp_derive_keys(psk, sta_nonce, ap_nonce, authkey, enckey);

	ppdp_calculate_msgauth(authkey, sta_nonce, ap_nonce, erssid, msgauth2);

	if (os_memcmp(msgauth, msgauth2, PPDP_MSGAUTH_LEN) == 0) {
		ppdp_decrypt_ssid(enckey, erssid, rssid_out);
		return 0;
	}
	return -1;
}

static struct ppdp_rssid_list *
ppdp_get_rssid_entry (struct wpa_supplicant *wpa_s, const u8 *bssid)
{
	struct ppdp_rssid_list *r = wpa_s->ppdp_rssid_list;

	while (r != NULL) {
		if (os_memcmp(r->bssid, bssid, ETH_ALEN) == 0)
			return r;
		r = r->next;
	}
	return NULL;

}

/* Get RSSID for given BSS, returns NULL if not available */
u8 * ppdp_get_rssid (struct wpa_supplicant *wpa_s, u8 *bssid)
{
	struct ppdp_rssid_list *r = ppdp_get_rssid_entry(wpa_s, bssid);
	if (r != NULL)
		return r->rssid;
	else
		return NULL;
}

static void ppdp_put_rssid (struct wpa_supplicant *wpa_s, const u8 *bssid, const u8 *rssid)
{
	struct ppdp_rssid_list *r;

	r = ppdp_get_rssid_entry(wpa_s, bssid);
	if (r != NULL) {
		os_memcpy(r->rssid, rssid, PPDP_RSSID_LEN);
		return;
	}

	r = os_zalloc(sizeof(struct ppdp_rssid_list));
	if (r == NULL)
		return;

	os_memcpy(r->bssid, bssid, ETH_ALEN);
	os_memcpy(r->rssid, rssid, PPDP_RSSID_LEN);
	r->next = wpa_s->ppdp_rssid_list;

	wpa_s->ppdp_rssid_list = r;
}

void ppdp_add_probe_ie(struct wpabuf *buf)
{
      wpabuf_put_u8(buf, WLAN_EID_VENDOR_SPECIFIC);
      wpabuf_put_u8(buf, PPDP_PROBE_REQ_LEN);
      wpabuf_put_be24(buf, PPDP_OUI);
      wpabuf_put_u8(buf, 0);

      u8 nonce[PPDP_NONCE_LEN];
      os_get_random(nonce, PPDP_NONCE_LEN);
      wpabuf_put_data(buf, nonce, PPDP_NONCE_LEN);
}


void ppdp_handle_response(struct wpa_supplicant *wpa_s,
			  const u8 *bssid,
			  const u8 *sta_nonce,
			  const u8 *ap_nonce,
			  const u8 *erssid,
			  const u8 *msgauth)
{
	struct wpa_ssid *ssid = NULL;
	int i;

	if (wpa_s->conf == NULL)
		return;

	/* Check for a match in all configured networks in priority order */
	for (i = 0; i < wpa_s->conf->num_prio; i++) {
		struct wpa_ssid *group = wpa_s->conf->pssid[i];
		for (ssid = group; ssid; ssid = ssid->pnext) {
			u8 rssid[PPDP_RSSID_LEN];

			if (!ssid->psk_set) continue;

			if (ppdp_authenticate(ssid->psk, bssid, sta_nonce,
					      ap_nonce, erssid,	msgauth,
					      rssid) == 0) {
				/* Found matching network! */
				ppdp_put_rssid(wpa_s, bssid, rssid);
				return;
			}

		}
	}
}

static void ppdp_process_bss(struct wpa_supplicant *wpa_s, struct wpa_bss *bss)
{
	struct wpabuf *buf = wpa_bss_get_vendor_ie_multi(bss, PPDP_OUI);
	const u8 *pos = wpabuf_head(buf);
	size_t expected = 2*PPDP_NONCE_LEN + PPDP_RSSID_LEN + PPDP_MSGAUTH_LEN;

	if (wpabuf_len(buf) != expected) {
		wpa_printf(MSG_DEBUG, "PPDP: Invalid message (length %lu, expected %lu)",
			wpabuf_len(buf), expected);
		wpabuf_free(buf);
		return;
	}

 	const u8 *sta_nonce = pos;
	pos += PPDP_NONCE_LEN;

	const u8 *ap_nonce = pos;
	pos += PPDP_NONCE_LEN;

	const u8 *erssid = pos;
	pos += PPDP_RSSID_LEN;

	const u8 *msgauth = pos;
	pos += PPDP_MSGAUTH_LEN;

	wpabuf_free(buf);

	ppdp_handle_response(wpa_s, bss->bssid, sta_nonce, ap_nonce, erssid, msgauth);
}

void ppdp_notify_scan_results(struct wpa_supplicant *wpa_s)
{
	struct wpa_bss *bss;
      	wpa_printf(MSG_DEBUG, "PPDP: Scan results received");
	dl_list_for_each(bss, &wpa_s->bss, struct wpa_bss, list) {
		ppdp_process_bss(wpa_s, bss);
      	}
}

