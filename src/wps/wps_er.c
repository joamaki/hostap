/*
 * Wi-Fi Protected Setup - External Registrar
 * Copyright (c) 2009, Jouni Malinen <j@w1.fi>
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

#include "includes.h"

#include "common.h"
#include "uuid.h"
#include "eloop.h"
#include "wps_i.h"
#include "wps_upnp.h"
#include "wps_upnp_i.h"


/* TODO:
 * SSDP M-SEARCH multicast TX for WFA
 * create AP entry
 * fetch wps_device info based on LOCATION: from SSDP NOTIFY
 * parse wps_device info into AP entry (name, SCPD/control/eventSub URLs, etc.
 * subscribe to events
 * send notification of new AP device with wpa_msg
 * re-send notifications with wpa_msg if ER re-started (to update wpa_gui-qt4)
 * (also re-send SSDP M-SEARCH in this case to find new APs)
 * parse UPnP event messages
 */

static void wps_er_ap_timeout(void *eloop_data, void *user_ctx);


struct wps_er_ap {
	struct wps_er_ap *next;
	struct in_addr addr;
	char *location;

};

struct wps_er {
	struct wps_registrar *reg;
	char ifname[17];
	char *mac_addr_text; /* mac addr of network i.f. we use */
	u8 mac_addr[ETH_ALEN]; /* mac addr of network i.f. we use */
	char *ip_addr_text; /* IP address of network i.f. we use */
	unsigned ip_addr; /* IP address of network i.f. we use (host order) */
	int multicast_sd;
	int ssdp_sd;
	struct wps_er_ap *ap;
};


static void wps_er_pin_needed_cb(void *ctx, const u8 *uuid_e,
				 const struct wps_device_data *dev)
{
	wpa_printf(MSG_DEBUG, "WPS ER: PIN needed");
}


static struct wps_er_ap * wps_er_ap_get(struct wps_er *er,
					struct in_addr *addr)
{
	struct wps_er_ap *ap;
	for (ap = er->ap; ap; ap = ap->next) {
		if (ap->addr.s_addr == addr->s_addr)
			break;
	}
	return ap;
}


static void wps_er_ap_free(struct wps_er *er, struct wps_er_ap *ap)
{
	wpa_printf(MSG_DEBUG, "WPS ER: Removing AP entry for %s (%s)",
		   inet_ntoa(ap->addr), ap->location);
	eloop_cancel_timeout(wps_er_ap_timeout, er, ap);
	os_free(ap->location);
	os_free(ap);
}


static void wps_er_ap_timeout(void *eloop_data, void *user_ctx)
{
	struct wps_er *er = eloop_data;
	struct wps_er_ap *ap = user_ctx;
	wpa_printf(MSG_DEBUG, "WPS ER: AP advertisement timed out");
	wps_er_ap_free(er, ap);
}


static void wps_er_ap_add(struct wps_er *er, struct in_addr *addr,
			  const char *location, int max_age)
{
	struct wps_er_ap *ap;

	ap = wps_er_ap_get(er, addr);
	if (ap) {
		/* Update advertisement timeout */
		eloop_cancel_timeout(wps_er_ap_timeout, er, ap);
		eloop_register_timeout(max_age, 0, wps_er_ap_timeout, er, ap);
		return;
	}

	ap = os_zalloc(sizeof(*ap));
	if (ap == NULL)
		return;
	ap->location = os_strdup(location);
	if (ap->location == NULL) {
		os_free(ap);
		return;
	}
	ap->next = er->ap;
	er->ap = ap;

	ap->addr.s_addr = addr->s_addr;
	eloop_register_timeout(max_age, 0, wps_er_ap_timeout, er, ap);

	wpa_printf(MSG_DEBUG, "WPS ER: Added AP entry for %s (%s)",
		   inet_ntoa(ap->addr), ap->location);

	/* TODO: get device data and subscribe for events */
}


static void wps_er_ap_remove(struct wps_er *er, struct in_addr *addr)
{
	struct wps_er_ap *prev = NULL, *ap = er->ap;

	while (ap) {
		if (ap->addr.s_addr == addr->s_addr) {
			if (prev)
				prev->next = ap->next;
			else
				er->ap = ap->next;
			wps_er_ap_free(er, ap);
			return;
		}
		prev = ap;
		ap = ap->next;
	}
}


static void wps_er_ap_remove_all(struct wps_er *er)
{
	struct wps_er_ap *prev, *ap;

	ap = er->ap;
	er->ap = NULL;

	while (ap) {
		prev = ap;
		ap = ap->next;
		wps_er_ap_free(er, prev);
	}
}


static void wps_er_ssdp_rx(int sd, void *eloop_ctx, void *sock_ctx)
{
	struct wps_er *er = eloop_ctx;
	struct sockaddr_in addr; /* client address */
	socklen_t addr_len;
	int nread;
	char buf[MULTICAST_MAX_READ], *pos, *pos2, *start;
	int wfa = 0, byebye = 0;
	int max_age = -1;
	char *location = NULL;

	addr_len = sizeof(addr);
	nread = recvfrom(sd, buf, sizeof(buf) - 1, 0,
			 (struct sockaddr *) &addr, &addr_len);
	if (nread <= 0)
		return;
	buf[nread] = '\0';

	wpa_printf(MSG_DEBUG, "WPS ER: Received SSDP from %s",
		   inet_ntoa(addr.sin_addr));
	wpa_hexdump_ascii(MSG_MSGDUMP, "WPS ER: Received SSDP contents",
			  (u8 *) buf, nread);

	if (sd == er->multicast_sd) {
		/* Reply to M-SEARCH */
		if (os_strncmp(buf, "HTTP/1.1 200 OK", 15) != 0)
			return; /* unexpected response header */
	} else {
		/* Unsolicited message (likely NOTIFY or M-SEARCH) */
		if (os_strncmp(buf, "NOTIFY ", 7) != 0)
			return; /* only process notifications */
	}

	for (start = buf; start && *start; start = pos) {
		pos = os_strchr(start, '\n');
		if (pos) {
			if (pos[-1] == '\r')
				pos[-1] = '\0';
			*pos++ = '\0';
		}
		if (os_strstr(start, "schemas-wifialliance-org:device:"
			      "WFADevice:1"))
			wfa = 1;
		if (os_strstr(start, "schemas-wifialliance-org:service:"
			      "WFAWLANConfig:1"))
			wfa = 1;
		if (os_strncasecmp(start, "LOCATION:", 9) == 0) {
			start += 9;
			while (*start == ' ')
				start++;
			location = start;
		} else if (os_strncasecmp(start, "NTS:", 4) == 0) {
			if (os_strstr(start, "ssdp:byebye"))
				byebye = 1;
		} else if (os_strncasecmp(start, "CACHE-CONTROL:", 14) == 0) {
			start += 9;
			while (*start == ' ')
				start++;
			pos2 = os_strstr(start, "max-age=");
			if (pos2 == NULL)
				continue;
			pos2 += 8;
			max_age = atoi(pos2);
		}
	}

	if (!wfa)
		return; /* Not WPS advertisement/reply */

	if (byebye) {
		wps_er_ap_remove(er, &addr.sin_addr);
		return;
	}

	if (!location)
		return; /* Unknown location */

	if (max_age < 1)
		return; /* No max-age reported */

	wpa_printf(MSG_DEBUG, "WPS ER: AP discovered: %s "
		   "(packet source: %s  max-age: %d)",
		   location, inet_ntoa(addr.sin_addr), max_age);

	wps_er_ap_add(er, &addr.sin_addr, location, max_age);
}


static void wps_er_send_ssdp_msearch(struct wps_er *er)
{
	struct wpabuf *msg;
	struct sockaddr_in dest;

	msg = wpabuf_alloc(500);
	if (msg == NULL)
		return;

	wpabuf_put_str(msg,
		       "M-SEARCH * HTTP/1.1\r\n"
		       "HOST: 239.255.255.250:1900\r\n"
		       "MAN: \"ssdp:discover\"\r\n"
		       "MX: 3\r\n"
		       "ST: urn:schemas-wifialliance-org:device:WFADevice:1"
		       "\r\n"
		       "\r\n");

	os_memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = inet_addr(UPNP_MULTICAST_ADDRESS);
	dest.sin_port = htons(UPNP_MULTICAST_PORT);

	if (sendto(er->multicast_sd, wpabuf_head(msg), wpabuf_len(msg), 0,
		   (struct sockaddr *) &dest, sizeof(dest)) < 0)
		wpa_printf(MSG_DEBUG, "WPS ER: M-SEARCH sendto failed: "
			   "%d (%s)", errno, strerror(errno));

	wpabuf_free(msg);
}


struct wps_er *
wps_er_init(struct wps_context *wps, const char *ifname)
{
	struct wps_er *er;
	struct wps_registrar_config rcfg;

	er = os_zalloc(sizeof(*er));
	if (er == NULL)
		return NULL;

	er->multicast_sd = -1;
	er->ssdp_sd = -1;

	os_strlcpy(er->ifname, ifname, sizeof(er->ifname));
	os_memset(&rcfg, 0, sizeof(rcfg));
	rcfg.pin_needed_cb = wps_er_pin_needed_cb;
	rcfg.cb_ctx = er;

	er->reg = wps_registrar_init(wps, &rcfg);
	if (er->reg == NULL) {
		wps_er_deinit(er);
		return NULL;
	}

	if (get_netif_info(ifname,
			   &er->ip_addr, &er->ip_addr_text,
			   er->mac_addr, &er->mac_addr_text)) {
		wpa_printf(MSG_INFO, "WPS UPnP: Could not get IP/MAC address "
			   "for %s. Does it have IP address?", ifname);
		wps_er_deinit(er);
		return NULL;
	}

	if (add_ssdp_network(ifname)) {
		wps_er_deinit(er);
		return NULL;
	}

	er->multicast_sd = ssdp_open_multicast_sock(er->ip_addr);
	if (er->multicast_sd < 0) {
		wps_er_deinit(er);
		return NULL;
	}

	er->ssdp_sd = ssdp_listener_open();
	if (er->ssdp_sd < 0) {
		wps_er_deinit(er);
		return NULL;
	}
	if (eloop_register_sock(er->multicast_sd, EVENT_TYPE_READ,
				wps_er_ssdp_rx, er, NULL) ||
	    eloop_register_sock(er->ssdp_sd, EVENT_TYPE_READ,
				wps_er_ssdp_rx, er, NULL)) {
		wps_er_deinit(er);
		return NULL;
	}

	wpa_printf(MSG_DEBUG, "WPS ER: Start (ifname=%s ip_addr=%s "
		   "mac_addr=%s)",
		   er->ifname, er->ip_addr_text, er->mac_addr_text);

	wps_er_send_ssdp_msearch(er);

	return er;
}


void wps_er_deinit(struct wps_er *er)
{
	if (er == NULL)
		return;
	wps_er_ap_remove_all(er);
	if (er->multicast_sd >= 0) {
		eloop_unregister_sock(er->multicast_sd, EVENT_TYPE_READ);
		close(er->multicast_sd);
	}
	if (er->ssdp_sd >= 0) {
		eloop_unregister_sock(er->ssdp_sd, EVENT_TYPE_READ);
		close(er->ssdp_sd);
	}
	wps_registrar_deinit(er->reg);
	os_free(er->ip_addr_text);
	os_free(er->mac_addr_text);
	os_free(er);
}