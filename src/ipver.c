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

/* The rest of IPXWrapper is compiled for the Windows 2000 API. The structure
 * definitions needed in here (IP_ADAPTER_ADDRESSES, addrinfo) were added with
 * later versions of Windows, so ask the headers for them. This is safe,
 * because no *function* newer than Windows 2000 is imported by this file -
 * they are all looked up using GetProcAddress() at run time.
*/
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600

#define WINSOCK_API_LINKAGE

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ipver.h"

/* Signatures of the functions we load at run time. */

typedef ULONG WINAPI (*GetAdaptersAddresses_t)(ULONG, ULONG, PVOID, PIP_ADAPTER_ADDRESSES, PULONG);

typedef int  WSAAPI (*getaddrinfo_t)(const char*, const char*, const struct addrinfo*, struct addrinfo**);
typedef void WSAAPI (*freeaddrinfo_t)(struct addrinfo*);

/* Plain Winsock 1.1 functions, also fetched from ws2_32.dll at run time. This
 * way this file does not depend on how the program it is linked into gets at
 * the Winsock API (ipxwrapper.dll uses its own stubs for that).
*/
typedef struct hostent* WSAAPI (*gethostbyname_t)(const char*);
typedef void            WSAAPI (*WSASetLastError_t)(int);

/* Returns a handle to the (already loaded or loadable) system DLL. The handle
 * is deliberately never released, the DLLs in question stay loaded anyway.
*/
static HMODULE _system_dll(const char *name)
{
	HMODULE dll = GetModuleHandleA(name);
	if(dll == NULL)
	{
		dll = LoadLibraryA(name);
	}
	
	return dll;
}

static FARPROC _system_func(const char *dll_name, const char *func_name)
{
	HMODULE dll = _system_dll(dll_name);
	if(dll == NULL)
	{
		return NULL;
	}
	
	return GetProcAddress(dll, func_name);
}

static void _set_wsa_error(int error)
{
	WSASetLastError_t sys_WSASetLastError = (WSASetLastError_t)(_system_func("ws2_32.dll", "WSASetLastError"));
	if(sys_WSASetLastError != NULL)
	{
		sys_WSASetLastError(error);
	}
}

bool ipver_v4_addr_usable(const unsigned char addr[4])
{
	if(addr[0] == 0)
	{
		/* 0.0.0.0/8 - "This network", not a real address. */
		return false;
	}
	
	if(addr[0] == 127)
	{
		/* 127.0.0.0/8 - Loopback. */
		return false;
	}
	
	if(addr[0] == 169 && addr[1] == 254)
	{
		/* 169.254.0.0/16 - Link-local addresses, which Windows assigns
		 * by itself when it gets no answer from a DHCP server.
		*/
		return false;
	}
	
	if(addr[0] >= 224)
	{
		/* Multicast and reserved addresses. */
		return false;
	}
	
	return true;
}

bool ipver_v6_addr_usable(const unsigned char addr[16])
{
	static const unsigned char ZERO[15] = { 0 };
	
	if(memcmp(addr, ZERO, 15) == 0 && (addr[15] == 0 || addr[15] == 1))
	{
		/* :: (unspecified) or ::1 (loopback). */
		return false;
	}
	
	if(addr[0] == 0xFF)
	{
		/* ff00::/8 - Multicast. */
		return false;
	}
	
	if(addr[0] == 0xFE && (addr[1] & 0xC0) == 0x80)
	{
		/* fe80::/10 - Link-local, see comment in ipver.h. */
		return false;
	}
	
	if(addr[0] == 0x20 && addr[1] == 0x01 && addr[2] == 0x00 && addr[3] == 0x00)
	{
		/* 2001::/32 - Teredo. Older versions of Windows set up such a
		 * tunnel address on their own on IPv4-only networks. Windows
		 * itself only uses it as a last resort, and so do we.
		*/
		return false;
	}
	
	return true;
}

unsigned int ipver_detect_available(void)
{
	GetAdaptersAddresses_t sys_GetAdaptersAddresses
		= (GetAdaptersAddresses_t)(_system_func("iphlpapi.dll", "GetAdaptersAddresses"));
	
	if(sys_GetAdaptersAddresses == NULL)
	{
		/* Windows 2000 or older. Those have no (production quality)
		 * IPv6 implementation, so there can only be IPv4.
		*/
		return IPVER_HAVE_V4;
	}
	
	/* The usual dance: we cannot know the size of the buffer needed in
	 * advance, and it may grow between two calls.
	*/
	
	IP_ADAPTER_ADDRESSES *adapters = NULL;
	ULONG bufsize = 16 * 1024;
	ULONG err     = ERROR_BUFFER_OVERFLOW;
	
	for(int attempt = 0; attempt < 5 && err == ERROR_BUFFER_OVERFLOW; ++attempt)
	{
		IP_ADAPTER_ADDRESSES *new_buf = realloc(adapters, bufsize);
		if(new_buf == NULL)
		{
			break;
		}
		
		adapters = new_buf;
		
		err = sys_GetAdaptersAddresses(AF_UNSPEC,
			GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME,
			NULL, adapters, &bufsize);
	}
	
	if(err == ERROR_NO_DATA)
	{
		/* No adapters with addresses at all. */
		free(adapters);
		return 0;
	}
	else if(err != ERROR_SUCCESS)
	{
		/* We cannot tell. IPv4 is what the caller would have had to
		 * assume before this function existed.
		*/
		free(adapters);
		return IPVER_HAVE_V4;
	}
	
	unsigned int available = 0;
	
	for(IP_ADAPTER_ADDRESSES *adapter = adapters; adapter != NULL; adapter = adapter->Next)
	{
		if(adapter->OperStatus != IfOperStatusUp || adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
		{
			/* Cable unplugged, WiFi not connected, disabled, ... */
			continue;
		}
		
		for(IP_ADAPTER_UNICAST_ADDRESS *ua = adapter->FirstUnicastAddress; ua != NULL; ua = ua->Next)
		{
			if(ua->DadState != IpDadStatePreferred && ua->DadState != IpDadStateDeprecated)
			{
				/* Address isn't (yet, or any more) in use. */
				continue;
			}
			
			const struct sockaddr *sa = ua->Address.lpSockaddr;
			
			if(sa->sa_family == AF_INET)
			{
				const struct sockaddr_in *sa4 = (const struct sockaddr_in*)(sa);
				
				if(ipver_v4_addr_usable((const unsigned char*)(&(sa4->sin_addr))))
				{
					available |= IPVER_HAVE_V4;
				}
			}
			else if(sa->sa_family == AF_INET6)
			{
				const struct sockaddr_in6 *sa6 = (const struct sockaddr_in6*)(sa);
				
				if(ipver_v6_addr_usable((const unsigned char*)(&(sa6->sin6_addr))))
				{
					available |= IPVER_HAVE_V6;
				}
			}
		}
	}
	
	free(adapters);
	
	return available;
}

bool ipver_have_getaddrinfo(void)
{
	return _system_func("ws2_32.dll", "getaddrinfo") != NULL
		&& _system_func("ws2_32.dll", "freeaddrinfo") != NULL;
}

int ipver_resolve(const char *host, unsigned short port, int family,
	SOCKADDR_STORAGE *addrs, int *addrlens, int max_addrs)
{
	/* Copy the host name, without surrounding whitespace and without the
	 * square brackets which may enclose an IPv6 address.
	*/
	
	char hostname[256];
	
	{
		const char *begin = host;
		const char *end   = host + strlen(host);
		
		while(begin < end && (*begin == ' ' || *begin == '\t'))
		{
			++begin;
		}
		
		while(end > begin && (end[-1] == ' ' || end[-1] == '\t'))
		{
			--end;
		}
		
		if((end - begin) >= 2 && *begin == '[' && end[-1] == ']')
		{
			++begin;
			--end;
		}
		
		size_t len = end - begin;
		
		if(len == 0 || len >= sizeof(hostname))
		{
			_set_wsa_error(WSAHOST_NOT_FOUND);
			return 0;
		}
		
		memcpy(hostname, begin, len);
		hostname[len] = '\0';
	}
	
	getaddrinfo_t  sys_getaddrinfo  = (getaddrinfo_t)(_system_func("ws2_32.dll", "getaddrinfo"));
	freeaddrinfo_t sys_freeaddrinfo = (freeaddrinfo_t)(_system_func("ws2_32.dll", "freeaddrinfo"));
	
	if(sys_getaddrinfo == NULL || sys_freeaddrinfo == NULL)
	{
		/* Windows 2000 or older: Do what IPXWrapper did before it
		 * learned about IPv6.
		*/
		
		if(family == AF_INET6)
		{
			_set_wsa_error(WSAEAFNOSUPPORT);
			return 0;
		}
		
		gethostbyname_t sys_gethostbyname = (gethostbyname_t)(_system_func("ws2_32.dll", "gethostbyname"));
		if(sys_gethostbyname == NULL)
		{
			_set_wsa_error(WSASYSNOTREADY);
			return 0;
		}
		
		struct hostent *he = sys_gethostbyname(hostname);
		if(he == NULL || he->h_addrtype != AF_INET || he->h_length != 4 || max_addrs < 1)
		{
			/* gethostbyname() has set the error. */
			return 0;
		}
		
		struct sockaddr_in *sa4 = (struct sockaddr_in*)(&(addrs[0]));
		
		memset(&(addrs[0]), 0, sizeof(addrs[0]));
		sa4->sin_family = AF_INET;
		memcpy(&(sa4->sin_addr), he->h_addr, 4);
		sa4->sin_port = (unsigned short)((port << 8) | (port >> 8)); /* htons() */
		
		addrlens[0] = sizeof(*sa4);
		
		return 1;
	}
	
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	
	hints.ai_family   = family;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	
	char service[8];
	snprintf(service, sizeof(service), "%u", (unsigned int)(port));
	
	struct addrinfo *result = NULL;
	
	int err = sys_getaddrinfo(hostname, service, &hints, &result);
	if(err != 0)
	{
		/* The error codes of getaddrinfo() are WinSock error codes. */
		_set_wsa_error(err);
		return 0;
	}
	
	int n_addrs = 0;
	
	for(struct addrinfo *ai = result; ai != NULL && n_addrs < max_addrs; ai = ai->ai_next)
	{
		if(ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
		{
			continue;
		}
		
		if(ai->ai_addrlen > sizeof(SOCKADDR_STORAGE))
		{
			continue;
		}
		
		memset(&(addrs[n_addrs]), 0, sizeof(addrs[n_addrs]));
		memcpy(&(addrs[n_addrs]), ai->ai_addr, ai->ai_addrlen);
		
		addrlens[n_addrs] = (int)(ai->ai_addrlen);
		
		++n_addrs;
	}
	
	sys_freeaddrinfo(result);
	
	if(n_addrs == 0)
	{
		_set_wsa_error(WSANO_DATA);
	}
	
	return n_addrs;
}

char *ipver_sockaddr_string(char *buf, const struct sockaddr *addr)
{
	if(addr->sa_family == AF_INET)
	{
		const unsigned char *a = (const unsigned char*)(&(((const struct sockaddr_in*)(addr))->sin_addr));
		
		snprintf(buf, IPVER_ADDR_STRING_SIZE, "%u.%u.%u.%u",
			(unsigned int)(a[0]), (unsigned int)(a[1]), (unsigned int)(a[2]), (unsigned int)(a[3]));
	}
	else if(addr->sa_family == AF_INET6)
	{
		const struct sockaddr_in6 *sa6 = (const struct sockaddr_in6*)(addr);
		const unsigned char *a = (const unsigned char*)(&(sa6->sin6_addr));
		
		/* Formatting done by hand rather than using inet_ntop(), which
		 * only exists from Windows Vista onwards.
		 *
		 * An IPv6 address is written as 8 groups of 16 bits each. The
		 * longest run of two or more zero groups is replaced by "::"
		 * (RFC 5952).
		*/
		
		unsigned int groups[8];
		for(int i = 0; i < 8; ++i)
		{
			groups[i] = ((unsigned int)(a[i * 2]) << 8) | a[i * 2 + 1];
		}
		
		int best_start = -1, best_len = 0;
		
		for(int i = 0; i < 8;)
		{
			if(groups[i] != 0)
			{
				++i;
				continue;
			}
			
			int start = i;
			while(i < 8 && groups[i] == 0)
			{
				++i;
			}
			
			if((i - start) > best_len && (i - start) >= 2)
			{
				best_start = start;
				best_len   = i - start;
			}
		}
		
		char *p = buf;
		
		for(int i = 0; i < 8;)
		{
			if(i == best_start)
			{
				*(p++) = ':';
				*(p++) = ':';
				
				i += best_len;
				continue;
			}
			
			if(i > 0 && p[-1] != ':')
			{
				*(p++) = ':';
			}
			
			p += sprintf(p, "%x", groups[i]);
			++i;
		}
		
		*p = '\0';
		
		if(sa6->sin6_scope_id != 0)
		{
			/* Link-local address, bound to one network adapter. */
			sprintf(p, "%%%lu", (unsigned long)(sa6->sin6_scope_id));
		}
	}
	else{
		strcpy(buf, "(unknown address family)");
	}
	
	return buf;
}

bool ipver_sockaddr_equal(const struct sockaddr *a, const struct sockaddr *b)
{
	if(a->sa_family != b->sa_family)
	{
		return false;
	}
	
	if(a->sa_family == AF_INET)
	{
		const struct sockaddr_in *a4 = (const struct sockaddr_in*)(a);
		const struct sockaddr_in *b4 = (const struct sockaddr_in*)(b);
		
		return a4->sin_port == b4->sin_port
			&& memcmp(&(a4->sin_addr), &(b4->sin_addr), sizeof(a4->sin_addr)) == 0;
	}
	else if(a->sa_family == AF_INET6)
	{
		const struct sockaddr_in6 *a6 = (const struct sockaddr_in6*)(a);
		const struct sockaddr_in6 *b6 = (const struct sockaddr_in6*)(b);
		
		/* The scope ID tells apart equal link-local addresses on
		 * different network adapters.
		*/
		
		return a6->sin6_port == b6->sin6_port
			&& a6->sin6_scope_id == b6->sin6_scope_id
			&& memcmp(&(a6->sin6_addr), &(b6->sin6_addr), sizeof(a6->sin6_addr)) == 0;
	}
	
	return false;
}
