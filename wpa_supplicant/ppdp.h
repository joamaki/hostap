/*
 * Privacy preserving discovery protocol
 * Copyright 2008, TML / Helsinki University of Technology
 * Author(s):      Jussi Maki <joamaki@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __PPDP_H
#define __PPDP_H

#include "includes.h"
#include "common.h"
#include "common/ppdp_common.h"

struct ppdp_rssid_list {
	struct ppdp_rssid_list *next;
	u8 bssid[ETH_ALEN];
	u8 rssid[PPDP_RSSID_LEN+1];
};

u8 * ppdp_get_rssid (struct wpa_supplicant *wpa_s, u8 *bssid);

struct wpabuf *ppdp_build_probe_ie(void);

void ppdp_notify_scan_results(struct wpa_supplicant *wpa_s);

#endif /* __PPDP_H */
