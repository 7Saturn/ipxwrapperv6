/* IPXWrapper - Router header
 * Copyright (C) 2011-2026 Daniel Collins <solemnwarning@solemnwarning.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifndef IPXWRAPPER_ROUTER_H
#define IPXWRAPPER_ROUTER_H

#include <windows.h>
#include <winsock2.h>
#include <wsipx.h>
#include <stdbool.h>
#include <stdint.h>

#include "addr.h"

#define BCAST_NET  addr32_in((unsigned char[]){0xFF,0xFF,0xFF,0xFF})
#define BCAST_NODE addr48_in((unsigned char[]){0xFF,0xFF,0xFF,0xFF,0xFF,0xFF})
#define ZERO_NET   addr32_in((unsigned char[]){0x00,0x00,0x00,0x00})

extern SOCKET shared_socket;
extern SOCKET private_socket;

/* Send a packet to the DOSBox server we are connected (or connecting) to,
 * using the UDP socket matching the IP version of its address.
 *
 * Returns like sendto(): the number of bytes sent, or -1 on error with the
 * reason available from WSAGetLastError().
*/
int dosbox_sendto(const void *data, int data_size);

/* Returns true if the DOSBox server is (or, if not yet known, will be) reached
 * using IPv6 rather than IPv4.
*/
bool dosbox_server_is_ipv6(void);

void router_init(void);
void router_cleanup(void);
void router_wake(void);

void wait_for_ready(DWORD timeout);

void deliver_packet(
    uint8_t type,
	addr32_t src_net,
	addr48_t src_node,
	uint16_t src_socket,
	addr32_t dest_net,
	addr48_t dest_node,
	uint16_t dest_socket,
	const void *data,
	size_t data_size);

#endif /* !IPXWRAPPER_ROUTER_H */
