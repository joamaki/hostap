/*
 * wlantest control interface
 * Copyright (c) 2010, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#ifndef WLANTEST_CTRL_H
#define WLANTEST_CTRL_H

#define WLANTEST_SOCK_NAME "w1.fi.wlantest"
#define WLANTEST_CTRL_MAX_CMD_LEN 1000
#define WLANTEST_CTRL_MAX_RESP_LEN 1000

enum wlantest_ctrl_cmd {
	WLANTEST_CTRL_SUCCESS,
	WLANTEST_CTRL_FAILURE,
	WLANTEST_CTRL_INVALID_CMD,
	WLANTEST_CTRL_UNKNOWN_CMD,
	WLANTEST_CTRL_PING,
	WLANTEST_CTRL_TERMINATE,
	WLANTEST_CTRL_LIST_BSS,
	WLANTEST_CTRL_LIST_STA,
	WLANTEST_CTRL_FLUSH,
	WLANTEST_CTRL_CLEAR_STA_COUNTERS,
	WLANTEST_CTRL_CLEAR_BSS_COUNTERS,
	WLANTEST_CTRL_GET_STA_COUNTER,
	WLANTEST_CTRL_GET_BSS_COUNTER,
	WLANTEST_CTRL_INJECT,
	WLANTEST_CTRL_VERSION,
	WLANTEST_CTRL_ADD_PASSPHRASE,
	WLANTEST_CTRL_INFO_STA,
	WLANTEST_CTRL_INFO_BSS,
	WLANTEST_CTRL_SEND,
	WLANTEST_CTRL_CLEAR_TDLS_COUNTERS,
	WLANTEST_CTRL_GET_TDLS_COUNTER,
};

enum wlantest_ctrl_attr {
	WLANTEST_ATTR_BSSID,
	WLANTEST_ATTR_STA_ADDR,
	WLANTEST_ATTR_STA_COUNTER,
	WLANTEST_ATTR_BSS_COUNTER,
	WLANTEST_ATTR_COUNTER,
	WLANTEST_ATTR_INJECT_FRAME,
	WLANTEST_ATTR_INJECT_SENDER_AP,
	WLANTEST_ATTR_INJECT_PROTECTION,
	WLANTEST_ATTR_VERSION,
	WLANTEST_ATTR_PASSPHRASE,
	WLANTEST_ATTR_STA_INFO,
	WLANTEST_ATTR_BSS_INFO,
	WLANTEST_ATTR_INFO,
	WLANTEST_ATTR_FRAME,
	WLANTEST_ATTR_TDLS_COUNTER,
	WLANTEST_ATTR_STA2_ADDR,
	WLANTEST_ATTR_WEPKEY,
};

enum wlantest_bss_counter {
	WLANTEST_BSS_COUNTER_VALID_BIP_MMIE,
	WLANTEST_BSS_COUNTER_INVALID_BIP_MMIE,
	WLANTEST_BSS_COUNTER_MISSING_BIP_MMIE,
	WLANTEST_BSS_COUNTER_BIP_DEAUTH,
	WLANTEST_BSS_COUNTER_BIP_DISASSOC,
	NUM_WLANTEST_BSS_COUNTER
};

enum wlantest_sta_counter {
	WLANTEST_STA_COUNTER_AUTH_TX,
	WLANTEST_STA_COUNTER_AUTH_RX,
	WLANTEST_STA_COUNTER_ASSOCREQ_TX,
	WLANTEST_STA_COUNTER_REASSOCREQ_TX,
	WLANTEST_STA_COUNTER_PTK_LEARNED,
	WLANTEST_STA_COUNTER_VALID_DEAUTH_TX,
	WLANTEST_STA_COUNTER_VALID_DEAUTH_RX,
	WLANTEST_STA_COUNTER_INVALID_DEAUTH_TX,
	WLANTEST_STA_COUNTER_INVALID_DEAUTH_RX,
	WLANTEST_STA_COUNTER_VALID_DISASSOC_TX,
	WLANTEST_STA_COUNTER_VALID_DISASSOC_RX,
	WLANTEST_STA_COUNTER_INVALID_DISASSOC_TX,
	WLANTEST_STA_COUNTER_INVALID_DISASSOC_RX,
	WLANTEST_STA_COUNTER_VALID_SAQUERYREQ_TX,
	WLANTEST_STA_COUNTER_VALID_SAQUERYREQ_RX,
	WLANTEST_STA_COUNTER_INVALID_SAQUERYREQ_TX,
	WLANTEST_STA_COUNTER_INVALID_SAQUERYREQ_RX,
	WLANTEST_STA_COUNTER_VALID_SAQUERYRESP_TX,
	WLANTEST_STA_COUNTER_VALID_SAQUERYRESP_RX,
	WLANTEST_STA_COUNTER_INVALID_SAQUERYRESP_TX,
	WLANTEST_STA_COUNTER_INVALID_SAQUERYRESP_RX,
	WLANTEST_STA_COUNTER_PING_OK,
	WLANTEST_STA_COUNTER_ASSOCRESP_COMEBACK,
	WLANTEST_STA_COUNTER_REASSOCRESP_COMEBACK,
	WLANTEST_STA_COUNTER_PING_OK_FIRST_ASSOC,
	WLANTEST_STA_COUNTER_VALID_DEAUTH_RX_ACK,
	WLANTEST_STA_COUNTER_VALID_DISASSOC_RX_ACK,
	WLANTEST_STA_COUNTER_INVALID_DEAUTH_RX_ACK,
	WLANTEST_STA_COUNTER_INVALID_DISASSOC_RX_ACK,
	WLANTEST_STA_COUNTER_DEAUTH_RX_ASLEEP,
	WLANTEST_STA_COUNTER_DEAUTH_RX_AWAKE,
	WLANTEST_STA_COUNTER_DISASSOC_RX_ASLEEP,
	WLANTEST_STA_COUNTER_DISASSOC_RX_AWAKE,
	WLANTEST_STA_COUNTER_PROT_DATA_TX,
	WLANTEST_STA_COUNTER_DEAUTH_RX_RC6,
	WLANTEST_STA_COUNTER_DEAUTH_RX_RC7,
	WLANTEST_STA_COUNTER_DISASSOC_RX_RC6,
	WLANTEST_STA_COUNTER_DISASSOC_RX_RC7,
	NUM_WLANTEST_STA_COUNTER
};

enum wlantest_tdls_counter {
	WLANTEST_TDLS_COUNTER_VALID_DIRECT_LINK,
	WLANTEST_TDLS_COUNTER_INVALID_DIRECT_LINK,
	WLANTEST_TDLS_COUNTER_VALID_AP_PATH,
	WLANTEST_TDLS_COUNTER_INVALID_AP_PATH,
	WLANTEST_TDLS_COUNTER_SETUP_REQ,
	WLANTEST_TDLS_COUNTER_SETUP_RESP_OK,
	WLANTEST_TDLS_COUNTER_SETUP_RESP_FAIL,
	WLANTEST_TDLS_COUNTER_SETUP_CONF_OK,
	WLANTEST_TDLS_COUNTER_SETUP_CONF_FAIL,
	WLANTEST_TDLS_COUNTER_TEARDOWN,
	NUM_WLANTEST_TDLS_COUNTER
};

enum wlantest_inject_frame {
	WLANTEST_FRAME_AUTH,
	WLANTEST_FRAME_ASSOCREQ,
	WLANTEST_FRAME_REASSOCREQ,
	WLANTEST_FRAME_DEAUTH,
	WLANTEST_FRAME_DISASSOC,
	WLANTEST_FRAME_SAQUERYREQ,
};

/**
 * enum wlantest_inject_protection - WLANTEST_CTRL_INJECT protection
 * @WLANTEST_INJECT_NORMAL: Use normal rules (protect if key is set)
 * @WLANTEST_INJECT_PROTECTED: Force protection (fail if not possible)
 * @WLANTEST_INJECT_UNPROTECTED: Force unprotected
 * @WLANTEST_INJECT_INCORRECT_KEY: Force protection with incorrect key
 */
enum wlantest_inject_protection {
	WLANTEST_INJECT_NORMAL,
	WLANTEST_INJECT_PROTECTED,
	WLANTEST_INJECT_UNPROTECTED,
	WLANTEST_INJECT_INCORRECT_KEY,
};

enum wlantest_sta_info {
	WLANTEST_STA_INFO_PROTO,
	WLANTEST_STA_INFO_PAIRWISE,
	WLANTEST_STA_INFO_KEY_MGMT,
	WLANTEST_STA_INFO_RSN_CAPAB,
	WLANTEST_STA_INFO_STATE,
	WLANTEST_STA_INFO_GTK,
};

enum wlantest_bss_info {
	WLANTEST_BSS_INFO_PROTO,
	WLANTEST_BSS_INFO_PAIRWISE,
	WLANTEST_BSS_INFO_GROUP,
	WLANTEST_BSS_INFO_GROUP_MGMT,
	WLANTEST_BSS_INFO_KEY_MGMT,
	WLANTEST_BSS_INFO_RSN_CAPAB,
};

#endif /* WLANTEST_CTRL_H */
