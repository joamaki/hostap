/*
 * Privacy preserving discovery protocol
 * Copyright 2008, TML / Helsinki University of Technology
 * Author(s):      Jussi Mäki <joamaki@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __PPDP_H
#define __PPDP_H

#include "common/ppdp_common.h"

void ppdp_generate_rssid(char *rssid_out);

Boolean ppdp_is_probe_req(const u8 *start,
			  size_t len);

u8 * ppdp_eid_probe_resp(struct hostapd_data *hapd,
			 const struct ieee80211_mgmt *mgmt,
			 size_t len,
			 u8 *pos, u8 *epos);

#endif
