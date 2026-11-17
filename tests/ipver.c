/* IPXWrapper test suite
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

/* Unit tests for src/ipver.c - the IPv4/IPv6 helper functions used by the
 * DOSBox UDP encapsulation.
 *
 * None of these tests needs a network connection (only literal addresses are
 * "resolved"), and none of them needs IPv6 to be installed.
*/

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "tap/basic.h"
#include "../src/ipver.h"

/* Build an IPv6 sockaddr from 16 address bytes. */
static struct sockaddr_in6 make_sa6(const unsigned char *addr, unsigned short port, unsigned long scope_id)
{
	struct sockaddr_in6 sa6;
	memset(&sa6, 0, sizeof(sa6));
	
	sa6.sin6_family = AF_INET6;
	memcpy(&(sa6.sin6_addr), addr, 16);
	sa6.sin6_port     = htons(port);
	sa6.sin6_scope_id = scope_id;
	
	return sa6;
}

static struct sockaddr_in make_sa4(const unsigned char *addr, unsigned short port)
{
	struct sockaddr_in sa4;
	memset(&sa4, 0, sizeof(sa4));
	
	sa4.sin_family = AF_INET;
	memcpy(&(sa4.sin_addr), addr, 4);
	sa4.sin_port = htons(port);
	
	return sa4;
}

static void test_v6_string(const unsigned char *addr, unsigned long scope_id, const char *expect)
{
	struct sockaddr_in6 sa6 = make_sa6(addr, 213, scope_id);
	
	char buf[IPVER_ADDR_STRING_SIZE];
	ipver_sockaddr_string(buf, (struct sockaddr*)(&sa6));
	
	is_string(expect, buf, "ipver_sockaddr_string() => %s", expect);
}

/* Resolve a literal address and check the first result. expect == NULL means
 * resolving is expected to fail.
*/
static void test_resolve(const char *host, int family, int expect_family, const char *expect)
{
	SOCKADDR_STORAGE addrs[IPVER_MAX_ADDRS];
	int addrlens[IPVER_MAX_ADDRS];
	
	int n = ipver_resolve(host, 213, family, addrs, addrlens, IPVER_MAX_ADDRS);
	
	if(expect == NULL)
	{
		is_int(0, n, "ipver_resolve(\"%s\", family %d) fails", host, family);
		return;
	}
	
	if(!ok(n >= 1, "ipver_resolve(\"%s\", family %d) returns an address", host, family))
	{
		diag("WSAGetLastError() = %d", WSAGetLastError());
		skip_block(3, "nothing was resolved");
		return;
	}
	
	char buf[IPVER_ADDR_STRING_SIZE];
	ipver_sockaddr_string(buf, (struct sockaddr*)(&(addrs[0])));
	
	is_int(expect_family, addrs[0].ss_family, "...of the expected address family");
	is_string(expect, buf, "...which is the expected address");
	
	/* The port is at the same place in sockaddr_in and sockaddr_in6. */
	is_int(213, ntohs(((struct sockaddr_in*)(&(addrs[0])))->sin_port), "...with the port filled in");
}

int main()
{
	WSADATA wsaData;
	if(WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		bail("WSAStartup failed");
	}
	
	plan_lazy();
	
	/* ipver_v4_addr_usable() */
	
	ok( ipver_v4_addr_usable((unsigned char[]){192, 168,   0,   2}), "192.168.0.2 is usable");
	ok( ipver_v4_addr_usable((unsigned char[]){ 10,   0,   0,   1}), "10.0.0.1 is usable");
	ok( ipver_v4_addr_usable((unsigned char[]){ 93, 184, 216,  34}), "93.184.216.34 is usable");
	ok(!ipver_v4_addr_usable((unsigned char[]){127,   0,   0,   1}), "127.0.0.1 (loopback) is not usable");
	ok(!ipver_v4_addr_usable((unsigned char[]){169, 254,  12,  34}), "169.254.12.34 (link-local) is not usable");
	ok(!ipver_v4_addr_usable((unsigned char[]){  0,   0,   0,   0}), "0.0.0.0 is not usable");
	ok(!ipver_v4_addr_usable((unsigned char[]){224,   0,   0,   1}), "224.0.0.1 (multicast) is not usable");
	
	/* ipver_v6_addr_usable() */
	
	const unsigned char V6_GLOBAL[16]    = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 };
	const unsigned char V6_ULA[16]       = { 0xfd, 0x12, 0x34, 0x56, 0x78, 0x9a, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x02 };
	const unsigned char V6_6TO4[16]      = { 0x20, 0x02, 0xc0, 0x00, 0x02, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 };
	const unsigned char V6_LINKLOCAL[16] = { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55 };
	const unsigned char V6_LOOPBACK[16]  = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
	const unsigned char V6_ANY[16]       = { 0 };
	const unsigned char V6_MULTICAST[16] = { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 };
	const unsigned char V6_TEREDO[16]    = { 0x20, 0x01, 0x00, 0x00, 0x41, 0x36, 0xe3, 0x78, 0x80, 0x00, 0x63, 0xbf, 0x3f, 0xff, 0xfd, 0xd2 };
	
	ok( ipver_v6_addr_usable(V6_GLOBAL),    "2001:db8::1 (global) is usable");
	ok( ipver_v6_addr_usable(V6_ULA),       "fd12:3456:789a:1::2 (unique local) is usable");
	ok( ipver_v6_addr_usable(V6_6TO4),      "2002:c000:201::1 (6to4) is usable");
	ok(!ipver_v6_addr_usable(V6_LINKLOCAL), "fe80::211:22ff:fe33:4455 (link-local) is not usable");
	ok(!ipver_v6_addr_usable(V6_LOOPBACK),  "::1 (loopback) is not usable");
	ok(!ipver_v6_addr_usable(V6_ANY),       ":: (unspecified) is not usable");
	ok(!ipver_v6_addr_usable(V6_MULTICAST), "ff02::1 (multicast) is not usable");
	ok(!ipver_v6_addr_usable(V6_TEREDO),    "2001:0:4136:e378:... (Teredo) is not usable");
	
	/* ipver_sockaddr_string() */
	
	{
		struct sockaddr_in sa4 = make_sa4((unsigned char[]){192, 168, 0, 2}, 213);
		
		char buf[IPVER_ADDR_STRING_SIZE];
		is_string("192.168.0.2", ipver_sockaddr_string(buf, (struct sockaddr*)(&sa4)), "ipver_sockaddr_string() => 192.168.0.2");
	}
	
	test_v6_string(V6_GLOBAL,    0, "2001:db8::1");
	test_v6_string(V6_ULA,       0, "fd12:3456:789a:1::2");
	test_v6_string(V6_LOOPBACK,  0, "::1");
	test_v6_string(V6_ANY,       0, "::");
	test_v6_string(V6_LINKLOCAL, 12, "fe80::211:22ff:fe33:4455%12");
	test_v6_string(V6_TEREDO,    0, "2001:0:4136:e378:8000:63bf:3fff:fdd2");
	
	/* Longest run of zeroes wins, a single zero group is not shortened. */
	test_v6_string((unsigned char[]){ 0x20, 0x01, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1 }, 0, "2001:0:0:1::1");
	test_v6_string((unsigned char[]){ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1 }, 0, "2001:db8:0:1:1:1:1:1");
	test_v6_string((unsigned char[]){ 0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0 }, 0, "2001:db8:1:1:1:1::");
	
	/* The biggest possible string must fit into the buffer. */
	{
		const unsigned char FULL[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
		struct sockaddr_in6 sa6 = make_sa6(FULL, 213, 4294967295UL);
		
		char buf[IPVER_ADDR_STRING_SIZE + 8];
		memset(buf, 'X', sizeof(buf));
		
		ipver_sockaddr_string(buf, (struct sockaddr*)(&sa6));
		
		is_string("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%4294967295", buf, "ipver_sockaddr_string() with maximum length address");
		ok(strlen(buf) < IPVER_ADDR_STRING_SIZE, "...fits into IPVER_ADDR_STRING_SIZE bytes");
	}
	
	/* ipver_sockaddr_equal() */
	
	{
		struct sockaddr_in  a4  = make_sa4((unsigned char[]){192, 168, 0, 2}, 213);
		struct sockaddr_in  b4  = make_sa4((unsigned char[]){192, 168, 0, 2}, 213);
		struct sockaddr_in  c4  = make_sa4((unsigned char[]){192, 168, 0, 3}, 213);
		struct sockaddr_in  d4  = make_sa4((unsigned char[]){192, 168, 0, 2}, 214);
		
		struct sockaddr_in6 a6  = make_sa6(V6_GLOBAL, 213, 0);
		struct sockaddr_in6 b6  = make_sa6(V6_GLOBAL, 213, 0);
		struct sockaddr_in6 c6  = make_sa6(V6_ULA,    213, 0);
		struct sockaddr_in6 d6  = make_sa6(V6_GLOBAL, 214, 0);
		struct sockaddr_in6 ll1 = make_sa6(V6_LINKLOCAL, 213, 1);
		struct sockaddr_in6 ll2 = make_sa6(V6_LINKLOCAL, 213, 2);
		
		#define SA(x) ((struct sockaddr*)(&(x)))
		
		ok( ipver_sockaddr_equal(SA(a4), SA(b4)),   "Equal IPv4 addresses are equal");
		ok(!ipver_sockaddr_equal(SA(a4), SA(c4)),   "IPv4 addresses with different IPs are not equal");
		ok(!ipver_sockaddr_equal(SA(a4), SA(d4)),   "IPv4 addresses with different ports are not equal");
		
		ok( ipver_sockaddr_equal(SA(a6), SA(b6)),   "Equal IPv6 addresses are equal");
		ok(!ipver_sockaddr_equal(SA(a6), SA(c6)),   "IPv6 addresses with different IPs are not equal");
		ok(!ipver_sockaddr_equal(SA(a6), SA(d6)),   "IPv6 addresses with different ports are not equal");
		ok(!ipver_sockaddr_equal(SA(ll1), SA(ll2)), "IPv6 link-local addresses on different interfaces are not equal");
		
		ok(!ipver_sockaddr_equal(SA(a4), SA(a6)),   "An IPv4 and an IPv6 address are not equal");
		
		#undef SA
	}
	
	/* ipver_resolve() */
	
	test_resolve("192.0.2.1",     AF_UNSPEC, AF_INET, "192.0.2.1");
	test_resolve("192.0.2.1",     AF_INET,   AF_INET, "192.0.2.1");
	test_resolve("  192.0.2.1\t", AF_UNSPEC, AF_INET, "192.0.2.1");
	
	test_resolve("",   AF_UNSPEC, 0, NULL);
	test_resolve("  ", AF_UNSPEC, 0, NULL);
	
	if(ipver_have_getaddrinfo())
	{
		test_resolve("2001:db8::1",   AF_UNSPEC, AF_INET6, "2001:db8::1");
		test_resolve("2001:db8::1",   AF_INET6,  AF_INET6, "2001:db8::1");
		test_resolve("[2001:db8::1]", AF_UNSPEC, AF_INET6, "2001:db8::1");
		test_resolve(" [2001:db8::1] ", AF_INET6, AF_INET6, "2001:db8::1");
		
		/* Forcing an IP version must not yield the other one. */
		test_resolve("192.0.2.1",   AF_INET6, 0, NULL);
		test_resolve("2001:db8::1", AF_INET,  0, NULL);
	}
	else{
		diag("getaddrinfo() not available, testing the fallback for old versions of Windows");
		
		test_resolve("2001:db8::1", AF_INET6, 0, NULL);
		test_resolve("192.0.2.1",   AF_INET6, 0, NULL);
	}
	
	/* ipver_detect_available() depends on the computer the test runs on,
	 * so all we can check is that it returns nothing but the known bits.
	*/
	
	{
		unsigned int available = ipver_detect_available();
		
		ok((available & ~(IPVER_HAVE_V4 | IPVER_HAVE_V6)) == 0, "ipver_detect_available() returns a valid value");
		diag("This computer has: %s%s%s",
			(available & IPVER_HAVE_V4) ? "IPv4 " : "",
			(available & IPVER_HAVE_V6) ? "IPv6 " : "",
			(available == 0)            ? "no usable IP addresses" : "");
	}
	
	WSACleanup();
	
	return 0;
}
