/* IPXWrapper - IP version (IPv4/IPv6) helper functions
 * Copyright (C) 2026 IPXWrapper contributors
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

#ifndef IPXWRAPPER_IPVER_H
#define IPXWRAPPER_IPVER_H

/* Everything in here is used by the DOSBox UDP encapsulation, which is the
 * only encapsulation that can run over IPv6 as well as IPv4.
 *
 * The functions which need parts of the Windows API that are missing on old
 * versions of Windows (GetAdaptersAddresses, getaddrinfo, ...) load them at
 * run time, so IPXWrapper still starts on systems which pre-date IPv6. There
 * it simply behaves as an IPv4-only program, as it always did.
*/

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Bits returned by ipver_detect_available(). */
#define IPVER_HAVE_V4 (1 << 0)
#define IPVER_HAVE_V6 (1 << 1)

/* Size of a buffer which can hold any string written by
 * ipver_sockaddr_string(): 39 characters of IPv6 address, '%', a scope ID of
 * up to 10 digits and the terminator.
*/
#define IPVER_ADDR_STRING_SIZE 52

/* Maximum number of server addresses ipver_resolve() will return. */
#define IPVER_MAX_ADDRS 8

/* Returns true if the given IPv4/IPv6 address (network byte order) is one a
 * DOSBox server could be reached from, i.e. it is not a loopback, link-local
 * or otherwise special address.
 *
 * Link-local addresses are deliberately not counted: (nearly) every Windows
 * system has an IPv6 link-local address on each network adapter, even if the
 * network offers no IPv6 at all.
*/
bool ipver_v4_addr_usable(const unsigned char addr[4]);
bool ipver_v6_addr_usable(const unsigned char addr[16]);

/* Find out which IP versions this computer has usable addresses for.
 *
 * Returns a combination of IPVER_HAVE_V4 and IPVER_HAVE_V6, which may be zero
 * if the computer isn't connected to any network at all.
*/
unsigned int ipver_detect_available(void);

/* Returns true if the operating system has the functions required for IPv6
 * name resolution (getaddrinfo and friends, Windows XP and later).
*/
bool ipver_have_getaddrinfo(void);

/* Resolve a host name or literal IPv4/IPv6 address.
 *
 * host   - Host name or address. An IPv6 address may be enclosed in square
 *          brackets, as is usual when it is written together with a port.
 * port   - Port number (host byte order) to store in the returned addresses.
 * family - AF_INET or AF_INET6 to get only addresses of that IP version, or
 *          AF_UNSPEC for both.
 * addrs, addrlens - Arrays of at least max_addrs elements to be filled.
 *
 * The addresses are returned in the order of preference of the operating
 * system (see RFC 6724), so on a computer with working IPv6 the IPv6
 * addresses of a host usually come first.
 *
 * Returns the number of addresses stored. On failure, returns zero and the
 * error can be obtained using WSAGetLastError().
*/
int ipver_resolve(const char *host, unsigned short port, int family,
	SOCKADDR_STORAGE *addrs, int *addrlens, int max_addrs);

/* Format the IP address in an AF_INET or AF_INET6 sockaddr, without port.
 * buf must be at least IPVER_ADDR_STRING_SIZE bytes. Returns buf.
*/
char *ipver_sockaddr_string(char *buf, const struct sockaddr *addr);

/* Returns true if both sockaddr structures hold the same address family, IP
 * address and port.
*/
bool ipver_sockaddr_equal(const struct sockaddr *a, const struct sockaddr *b);

#ifdef __cplusplus
}
#endif

#endif /* !IPXWRAPPER_IPVER_H */
