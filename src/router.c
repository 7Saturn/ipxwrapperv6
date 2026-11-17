/* IPXWrapper - Router code
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

#define WINSOCK_API_LINKAGE

#include <winsock2.h>
#include <windows.h>
#include <uthash.h>
#include <time.h>
#include <pcap.h>
#include <Win32-Extensions.h>

#include "router.h"
#include "coalesce.h"
#include "common.h"
#include "funcprof.h"
#include "ipxwrapper.h"
#include "interface.h"
#include "ipver.h"
#include "addrcache.h"
#include "ethernet.h"
#include "spx.h"

#define IPX_SOCK_ECHO 2

/* Maximum number of packets to dispatch per iteration of the router loop. */
#define MAX_RECV_PER_LOOP 50

static bool router_running   = false;
static WSAEVENT router_event = WSA_INVALID_EVENT;
static HANDLE router_thread  = NULL;

/* The shared socket uses the UDP port number specified in the configuration,
 * every IPXWrapper instance will share it and use it to receive broadcast
 * packets.
 *
 * The private socket uses a randomly allocated UDP port number and is used to
 * send packets and receive unicast, it is unique to a single IPXWrapper
 * instance.
 *
 * When running in WinPcap mode, only the private socket will be opened and it
 * will be bound to loopback rather than INADDR_ANY since it is only used for
 * forwarding IPX packets on to local sockets.
 *
 * When running in DOSBox mode, only the private socket will be opened and
 * bound to a random port on INADDR_ANY to communicate with the DOSBox server
 * and also relay packets to local sockets.
 *
 * If the DOSBox server is to be reached by IPv6, a second socket is opened
 * for that (dosbox_socket6), bound to a random port on the IPv6 "any" address.
 * The private socket cannot be used, as an IPv4 socket cannot send to IPv6
 * destinations. It is still needed for relaying packets to local sockets,
 * which is always done via the IPv4 loopback address.
*/

SOCKET shared_socket  = -1;
SOCKET private_socket = -1;
uint16_t private_port = 0; /**< Local port of private UDP socket (network byte order) */

/* IPv6 socket for talking to the DOSBox server, see above. Only created when
   (and if) the address of an IPv6 server has been resolved. */
static SOCKET dosbox_socket6 = -1;

/* Address of the DOSBox server we are currently registering with or connected
   to. May hold an IPv4 (sockaddr_in) or IPv6 (sockaddr_in6) address. */
static SOCKADDR_STORAGE dosbox_server_addr;
static int dosbox_server_addrlen = 0;

/* A server name can resolve to several addresses, typically one IPv6 and one
   IPv4 address. These are the "candidates". They are tried one after the
   other, in the order of preference given by the operating system, until the
   server answers a registration request on one of them. */
static SOCKADDR_STORAGE dosbox_candidate_addrs[IPVER_MAX_ADDRS];
static int dosbox_candidate_addrlens[IPVER_MAX_ADDRS];
static int dosbox_n_candidates = 0;
static int dosbox_candidate_idx = 0;

static HANDLE dosbox_ready_event = NULL;

static uint64_t dosbox_next_connection_attempt_at;
static const unsigned int dosbox_connect_retry_interval_ms = 10000;

static uint64_t dosbox_next_registration_request_at;
static unsigned int dosbox_registration_retry_interval_ms;
static uint64_t dosbox_registration_timeout_at;

static const unsigned int INITIAL_DOSBOX_REGISTRATION_RETRY_INTERVAL_MS = 250;
static const unsigned int MAX_DOSBOX_REGISTRATION_RETRY_INTERVAL_MS = 8000;

static const unsigned int DOSBOX_REGISTRATION_TIMEOUT_MS = 30000;

/* When there is more than one candidate address, switch to the next one if
   the current one did not answer within this time. With the retry intervals
   above, each candidate is sent 3 registration requests before moving on.
  
   This must be well below IPX_READY_TIMEOUT (the time socket functions wait
   for the connection at program start), so that there is enough of it left
   to succeed with the second address if the first one is dead - typically an
   IPv6 address on a network whose IPv6 doesn't actually work.
  
   All candidates are tried in turn until DOSBOX_REGISTRATION_TIMEOUT_MS has
   passed overall, so a server which is slow to answer still gets its chance. */
static const unsigned int DOSBOX_CANDIDATE_TIMEOUT_MS = 1000;

static uint64_t dosbox_candidate_timeout_at;

static void _send_dosbox_registration_request(void);
static bool _resolve_dosbox_server(void);
static void _select_dosbox_candidate(int idx, uint64_t now);
static DWORD router_main(void *arg);

/* Initialise a UDP socket. */
static void _init_socket(SOCKET *sock, uint16_t port, BOOL broadcast, BOOL reuseaddr)
{
	/* Socket used for sending and receiving packets on the network. */
	
	if((*sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		log_printf(LOG_ERROR, "Error creating UDP socket: %s", w32_error(WSAGetLastError()));
		abort();
	}
	
	/* Enable broadcast and address reuse. */
	
	setsockopt(*sock, SOL_SOCKET, SO_BROADCAST, (char*)&broadcast, sizeof(BOOL));
	setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, (char*)&reuseaddr, sizeof(BOOL));
	
	/* Set send/receive buffer size to 512KiB. */
	
	int bufsize = 524288;
	
	setsockopt(*sock, SOL_SOCKET, SO_RCVBUF, (char*)&bufsize, sizeof(int));
	setsockopt(*sock, SOL_SOCKET, SO_SNDBUF, (char*)&bufsize, sizeof(int));
	
	struct sockaddr_in addr;
	
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port        = htons(port);
	
	if(bind(*sock, (struct sockaddr*)&addr, sizeof(addr)) == -1)
	{
		log_printf(LOG_ERROR, "Error binding UDP socket: %s", w32_error(WSAGetLastError()));
		abort();
	}
	
	if(WSAEventSelect(*sock, router_event, FD_READ) == -1)
	{
		log_printf(LOG_ERROR, "WSAEventSelect error: %s", w32_error(WSAGetLastError()));
		abort();
	}
}

/* Create the IPv6 UDP socket used to communicate with a DOSBox server, unless
   it exists already.
  
   Unlike _init_socket() this does not abort on failure: IPv6 may simply not
   be installed on this computer, in which case we carry on using IPv4.
  
   Returns true if the socket is ready for use. */
static bool _init_dosbox_socket6(void)
{
	if (dosbox_socket6 != -1) {
		return true;
	}
	
	SOCKET sock = r_socket(AF_INET6, SOCK_DGRAM, 0);
	if (sock == -1) {
		log_printf(LOG_WARNING, "Cannot create IPv6 UDP socket: %s", w32_error(WSAGetLastError()));
		return false;
	}
	
	/* The socket shall handle IPv6 only. IPv4 has its own socket. This is
	   the default on Windows anyway, and the only possible behaviour on
	   versions before Vista (where the option doesn't exist and setting
	   it fails, which is why any error is ignored here). */
	
	DWORD v6only = 1;
	r_setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (char*)(&v6only), sizeof(v6only));
	
	/* Set send/receive buffer size to 512KiB, like _init_socket(). */
	
	int bufsize = 524288;
	
	r_setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)(&bufsize), sizeof(int));
	r_setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)(&bufsize), sizeof(int));
	
	/* Bind to a random port on the "any" address (all zeroes). */
	
	struct sockaddr_in6 addr;
	memset(&addr, 0, sizeof(addr));
	
	addr.sin6_family = AF_INET6;
	addr.sin6_port   = htons(0);
	
	if (r_bind(sock, (struct sockaddr*)(&addr), sizeof(addr)) == -1) {
		log_printf(LOG_WARNING, "Cannot bind IPv6 UDP socket: %s", w32_error(WSAGetLastError()));
		
		r_closesocket(sock);
		return false;
	}
	
	/* Have the router thread woken when a packet arrives. This also makes
	   the socket non-blocking. */
	
	if (WSAEventSelect(sock, router_event, FD_READ) == -1) {
		log_printf(LOG_WARNING, "WSAEventSelect error on IPv6 UDP socket: %s", w32_error(WSAGetLastError()));
		
		r_closesocket(sock);
		return false;
	}
	
	dosbox_socket6 = sock;
	
	return true;
}

int dosbox_sendto(const void *data, int data_size)
{
	SOCKET sock = dosbox_server_addr.ss_family == AF_INET6
		? dosbox_socket6
		: private_socket;
	
	return r_sendto(sock, (const char*)(data), data_size, 0, (struct sockaddr*)(&dosbox_server_addr), dosbox_server_addrlen);
}

bool dosbox_server_is_ipv6(void)
{
	if (dosbox_state == DOSBOX_DISCONNECTED) {
		/* Server address not resolved yet. We only know for sure which
		   IP version it is going to be if the user forced one. */
		return main_config.dosbox_ip_version == DOSBOX_IP_VERSION_6;
	}
	
	return dosbox_server_addr.ss_family == AF_INET6;
}

/* Initialise the UDP socket and router worker thread.
 * Aborts on failure.
*/
void router_init(void)
{
	/* Event object used for notification of new packets and exit signal. */
	
	if((router_event = WSACreateEvent()) == WSA_INVALID_EVENT)
	{
		log_printf(LOG_ERROR, "Error creating WSA event object: %s", w32_error(WSAGetLastError()));
		abort();
	}
	
	if(ipx_encap_type == ENCAP_TYPE_PCAP)
	{
		if((private_socket = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		{
			log_printf(LOG_ERROR, "Error creating retransmit socket: %s", w32_error(WSAGetLastError()));
			abort();
		}
		
		struct sockaddr_in addr;
		addr.sin_family      = AF_INET;
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr.sin_port        = htons(0);
		
		if(bind(private_socket, (struct sockaddr*)(&addr), sizeof(addr)) == -1)
		{
			log_printf(LOG_ERROR, "Error binding retransmit socket: %s", w32_error(WSAGetLastError()));
			abort();
		}
	}
	else if(ipx_encap_type == ENCAP_TYPE_DOSBOX)
	{
		dosbox_ready_event = CreateEvent(NULL, TRUE, FALSE, NULL);
		if(dosbox_ready_event == NULL)
		{
			log_printf(LOG_ERROR, "Error creating event object: %s", w32_error(GetLastError()));
			abort();
		}
		
		_init_socket(&private_socket, 0, FALSE, FALSE);
		
		dosbox_next_connection_attempt_at = 0;
	}
	else{
		_init_socket(&shared_socket, main_config.udp_port, TRUE, TRUE);
		_init_socket(&private_socket, 0, TRUE, FALSE);
	}

	{
		struct sockaddr_in private_addr;
		int addrlen = sizeof(private_addr);

		if(r_getsockname(private_socket, (struct sockaddr*)(&private_addr), &addrlen) == SOCKET_ERROR)
		{
			log_printf(LOG_ERROR, "Unable to identify private UDP port address: %s", w32_error(WSAGetLastError()));
		}
		else{
			private_port = private_addr.sin_port;
		}
	}
	
	router_running = true;
	
	if(!(router_thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)(&router_main), NULL, 0, NULL)))
	{
		log_printf(LOG_ERROR, "Cannot create router worker thread: %s", w32_error(GetLastError()));
		abort();
	}
}

void router_cleanup(void)
{
	/* Signal the router thread to exit. */
	
	router_running = false;
	SetEvent(router_event);
	
	/* Wait for it to exit, kill if it takes too long. */
	
	if(WaitForSingleObject(router_thread, 3000) == WAIT_TIMEOUT)
	{
		log_printf(LOG_WARNING, "Router thread didn't exit in 3 seconds, killing");
		TerminateThread(router_thread, 0);
	}
	
	CloseHandle(router_thread);
	router_thread = NULL;
	
	/* Release resources. */
	
	coalesce_cleanup();
	
	if(private_socket != -1)
	{
		closesocket(private_socket);
		private_socket = -1;
	}
	
	if(shared_socket != -1)
	{
		closesocket(shared_socket);
		shared_socket = -1;
	}
	
	if (dosbox_socket6 != -1) {
		r_closesocket(dosbox_socket6);
		dosbox_socket6 = -1;
	}
	
	if(router_event != WSA_INVALID_EVENT)
	{
		WSACloseEvent(router_event);
		router_event = WSA_INVALID_EVENT;
	}
}

void router_wake(void)
{
	SetEvent(router_event);
}

void deliver_packet(
	uint8_t type,
	addr32_t src_net,
	addr48_t src_node,
	uint16_t src_socket,
	addr32_t dest_net,
	addr48_t dest_node,
	uint16_t dest_socket,
	const void *data,
	size_t data_size)
{
	FPROF_RECORD_SCOPE(&(ipxwrapper_fstats[IPXWRAPPER_FSTATS_deliver_packet]));
	
	if(type == IPX_TYPE_SPX)
	{
		spx_process_packet(src_net, src_node, src_socket, dest_net, dest_node, dest_socket, data, data_size);
		return;
	}
	
	{
		IPX_STRING_ADDR(src_addr, src_net, src_node, src_socket);
		IPX_STRING_ADDR(dest_addr, dest_net, dest_node, dest_socket);
		
		log_printf(LOG_DEBUG, "Delivering %u byte payload from %s to %s",
			(unsigned int)(data_size), src_addr, dest_addr);
	}
	
	lock_sockets();
	
	ipx_socket *sock, *tmp;
	HASH_ITER(hh, socket_by_fd, sock, tmp)
	{
		if(sock->flags & IPX_IS_SPX)
		{
			/* Socket is SPX */
			continue;
		}
		
		if(!(sock->flags & IPX_BOUND))
		{
			/* Socket isn't bound */
			continue;
		}
		
		if(!(sock->flags & IPX_RECV))
		{
			/* Socket is shut down for receive operations. */
			continue;
		}
		
		if((sock->flags & IPX_FILTER) && sock->f_ptype != type)
		{
			/* Socket has packet type filtering enabled and this
			 * packet is of the wrong type.
			*/
			continue;
		}
		
		if((dest_net != addr32_in(sock->addr.sa_netnum) && dest_net != BCAST_NET)
			|| (dest_node != addr48_in(sock->addr.sa_nodenum) && dest_node != BCAST_NODE)
			|| dest_socket != sock->addr.sa_socket)
		{
			/* Packet destination address is neither the local
			 * address of this socket nor broadcast.
			*/
			continue;
		}
		
		if((dest_net == BCAST_NET || dest_node == BCAST_NODE)
			&& !(sock->flags & IPX_RECV_BCAST))
		{
			/* Packet destination address includes a broadcast part
			 * and this socket has explicitly disabled reception of
			 * broadcasts.
			*/
			continue;
		}
		
		if((dest_net == BCAST_NET || dest_node == BCAST_NODE)
			&& (main_config.w95_bug && !(sock->flags & IPX_BROADCAST)))
		{
			/* Packet destination address includes a broadcast part,
			 * socket has not enabled the SO_BROADCAST option and
			 * the Windows 95 SO_BROADCAST bug is being emulated.
			*/
			continue;
		}
		
		if((sock->flags & IPX_CONNECTED)
			&& (src_net != addr32_in(sock->remote_addr.sa_netnum)
			|| src_node != addr48_in(sock->remote_addr.sa_nodenum)
			|| src_socket != sock->remote_addr.sa_socket))
		{
			/* Socket is "connected" and the source address isn't
			 * the remote address of the socket.
			*/
			continue;
		}
		
		log_printf(LOG_DEBUG, "...relaying to local port %hu", ntohs(sock->port));
		
		size_t packet_size = (sizeof(ipx_packet) + data_size) - 1;
		
		ipx_packet *packet = malloc(packet_size);
		if(!packet)
		{
			log_printf(LOG_ERROR, "Cannot allocate memory!");
			continue;
		}
		
		packet->ptype = type;
		
		addr32_out(packet->dest_net, dest_net);
		addr48_out(packet->dest_node, dest_node);
		packet->dest_socket = dest_socket;
		
		addr32_out(packet->src_net, src_net);
		addr48_out(packet->src_node, src_node);
		packet->src_socket = src_socket;
		
		packet->size = data_size;
		memcpy(packet->data, data, data_size);
		
		struct sockaddr_in send_addr;
		
		send_addr.sin_family      = AF_INET;
		send_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		send_addr.sin_port        = sock->port;
		
		if(sendto(private_socket, (void*)(packet), packet_size, 0, (struct sockaddr*)(&send_addr), sizeof(send_addr)) == -1)
		{
			log_printf(LOG_ERROR, "Error relaying packet: %s", w32_error(WSAGetLastError()));
		}
		else{
			__atomic_add_fetch(&recv_packets, 1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&recv_bytes, data_size, __ATOMIC_RELAXED);
		}
		
		free(packet);
	}
	
	unlock_sockets();
}

static void _handle_udp_recv(ipx_packet *packet, size_t packet_size, struct sockaddr_in src_ip)
{
	FPROF_RECORD_SCOPE(&(ipxwrapper_fstats[IPXWRAPPER_FSTATS__handle_udp_recv]));
	
	size_t data_size = ntohs(packet->size);
	
	if(packet_size < sizeof(ipx_packet) - 1 || data_size > MAX_DATA_SIZE || data_size + sizeof(ipx_packet) - 1 != packet_size)
	{
		/* Packet size field is incorrect. */
		return;
	}
	
	if(packet->src_socket == 0)
	{
		/* A source socket of zero indicates internal IPXWrapper
		 * traffic. The ptype determines what should be done.
		 * 
		 * The destination address of any such packet will usually be
		 * all zeroes to prevent older versions of IPXWrapper from
		 * passing them on to applications, since they can't bind to
		 * socket zero. This is also what prevents them from generating
		 * such packets.
		*/
		
		if(packet->ptype == IPX_MAGIC_SPXLOOKUP)
		{
			/* Older versions of IPXWrapper implemented SPX as a direct TCP connection, using this
			 * IPX_MAGIC_SPXLOOKUP packet to discover any hosts with a listening SPX socket bound
			 * to the requested address. We now implement real SPX on top of IPX, so just warn if
			 * we see a message from an older version of IPXWrapper trying to use SPX.
			*/
			
			IPX_STRING_ADDR(src_addr, addr32_in(packet->src_net), addr48_in(packet->src_node), packet->src_socket);
			log_printf(LOG_WARNING, "Recieved IPX_MAGIC_SPXLOOKUP packet from %s (%s) running an older version of IPXWrapper, dropping", src_addr, inet_ntoa(src_ip.sin_addr));
		}
		else{
			log_printf(LOG_DEBUG, "Recieved magic packet unknown ptype %u, dropping", (unsigned int)(packet->ptype));
		}
		
		return;
	}
	
	if(min_log_level <= LOG_DEBUG)
	{
		IPX_STRING_ADDR(src_addr, addr32_in(packet->src_net), addr48_in(packet->src_node), packet->src_socket);
		IPX_STRING_ADDR(dest_addr, addr32_in(packet->dest_net), addr48_in(packet->dest_node), packet->dest_socket);
		
		log_printf(LOG_DEBUG, "Recieved packet from %s (%s) for %s", src_addr, inet_ntoa(src_ip.sin_addr), dest_addr);
	}
	
	/* Check that the source IP of the UDP packet is within the subnet of a
	 * valid interface. IPX broadcast packets will be accepted on any
	 * enabled interface, unicast only on the interface with the destination
	 * address.
	*/
	
	ipx_interface_t *allow_interfaces;
	BOOL source_ok = FALSE;
	
	if(addr48_in(packet->dest_node) == BCAST_NODE)
	{
		allow_interfaces = get_ipx_interfaces();
	}
	else{
		allow_interfaces = ipx_interface_by_addr(
			addr32_in(packet->dest_net), addr48_in(packet->dest_node));
	}
	
	ipx_interface_t *i;
	DL_FOREACH(allow_interfaces, i)
	{
		ipx_interface_ip_t *ip;
		DL_FOREACH(i->ipaddr, ip)
		{
			if((ip->ipaddr & ip->netmask) == (src_ip.sin_addr.s_addr & ip->netmask))
			{
				source_ok = TRUE;
			}
		}
	}
	
	free_ipx_interface_list(&allow_interfaces);
	
	if(!source_ok)
	{
		log_printf(LOG_DEBUG, "Packet did not come from an expected subnet, dropping");
		return;
	}
	
	/* Packet appears to have arrived from where we expect. Cache the source
	 * IP address and destination IPX address so future send operations to
	 * that IPX address can be unicast.
	*/
	
	addr_cache_set(
		(struct sockaddr*)(&src_ip), sizeof(src_ip),
		addr32_in(packet->src_net), addr48_in(packet->src_node), packet->src_socket
	);
	
	deliver_packet(packet->ptype,
		addr32_in(packet->src_net),
		addr48_in(packet->src_node),
		packet->src_socket,
		
		addr32_in(packet->dest_net),
		addr48_in(packet->dest_node),
		packet->dest_socket,
		
		packet->data,
		data_size);
}

static void _handle_dosbox_registration_response(novell_ipx_packet *packet, size_t packet_size)
{
	if(packet_size < sizeof(novell_ipx_packet)
		|| ntohs(packet->length) != packet_size
		|| ntohs(packet->checksum) != 0xFFFF)
		/* || packet->type != 2) */
	{
		/* Doesn't look valid. */
		log_printf(LOG_ERROR, "Got invalid registration response from DOSBox server, ignoring");
	}
	
	dosbox_local_netnum  = addr32_in(packet->dest_net);
	dosbox_local_nodenum = addr48_in(packet->dest_node);
	
	dosbox_state = DOSBOX_CONNECTED;
	
	ipx_interfaces_reload();
	
	char local_netnum_s[ADDR32_STRING_SIZE];
	addr32_string(local_netnum_s, dosbox_local_netnum);
	
	char local_nodenum_s[ADDR48_STRING_SIZE];
	addr48_string(local_nodenum_s, dosbox_local_nodenum);
	
	char server_addr_s[IPVER_ADDR_STRING_SIZE];
	ipver_sockaddr_string(server_addr_s, (struct sockaddr*)(&dosbox_server_addr));
	
	log_printf(LOG_INFO, "Connected to DOSBox server %s (%s), local address: %s/%s",
		server_addr_s,
		(dosbox_server_addr.ss_family == AF_INET6 ? "IPv6" : "IPv4"),
		local_netnum_s, local_nodenum_s);
	
	SetEvent(dosbox_ready_event);
}

static void _send_dosbox_ping_ack(addr48_t reply_to)
{
	novell_ipx_packet ack_pkt;
	
	ack_pkt.checksum = 0xFFFF;
	ack_pkt.length = htons(sizeof(ack_pkt));
	ack_pkt.hops = 0;
	ack_pkt.type = 0;
	
	memset(ack_pkt.dest_net, 0, sizeof(ack_pkt.dest_net));
	addr48_out(ack_pkt.dest_node, reply_to);
	ack_pkt.dest_socket = htons(IPX_SOCK_ECHO);
	
	memset(ack_pkt.src_net, 0, sizeof(ack_pkt.src_net));
	addr48_out(ack_pkt.src_node, dosbox_local_nodenum);
	ack_pkt.src_socket = htons(IPX_SOCK_ECHO);
	
	if (dosbox_sendto(&ack_pkt, sizeof(ack_pkt)) < 0) {
		log_printf(LOG_ERROR, "Error sending DOSBox ping ack: %s", w32_error(WSAGetLastError()));
	}
}

static void _handle_dosbox_recv(novell_ipx_packet *packet, size_t packet_size)
{
	FPROF_RECORD_SCOPE(&(ipxwrapper_fstats[IPXWRAPPER_FSTATS__handle_dosbox_recv]));
	
	if(packet_size < sizeof(novell_ipx_packet) || ntohs(packet->length) != packet_size)
	{
		/* Doesn't look valid. */
		log_printf(LOG_ERROR, "Recieved invalid IPX packet from DOSBox server, ignoring");
		return;
	}
	
	if(packet->dest_socket == htons(IPX_SOCK_ECHO)
		&& addr48_in(packet->dest_node) == BCAST_NODE)
	{
		log_printf(LOG_DEBUG, "DEBUG: dosbox ping detected, sending ack");
		_send_dosbox_ping_ack(addr48_in(packet->src_node));
		return;
	}
	
	if(packet->src_socket == 0 && packet->type == IPX_MAGIC_COALESCED)
	{
		/* Sanity check the lengths of each inner packet. */
		
		log_printf(LOG_DEBUG, "Recieved coalesced packet (%zu bytes)", packet_size);
		
		novell_ipx_packet *inner_packets = (novell_ipx_packet*)(packet->data);
		size_t remaining_data = packet_size - sizeof(novell_ipx_packet);
		
		novell_ipx_packet *end = (novell_ipx_packet*)(packet->data + remaining_data);
		
		for(novell_ipx_packet *p = inner_packets; p < end;)
		{
			if(remaining_data < sizeof(novell_ipx_packet) || ntohs(p->length) > remaining_data)
			{
				/* Doesn't look valid. */
				log_printf(LOG_ERROR, "Recieved invalid IPX packet from DOSBox server, ignoring");
				return;
			}
			
			p = (novell_ipx_packet*)((char*)(p) + ntohs(p->length));
		}
		
		/* Deliver the inner packets. */
		
		for(novell_ipx_packet *p = inner_packets; p < end;)
		{
			if(min_log_level <= LOG_DEBUG)
			{
				IPX_STRING_ADDR(src_addr, addr32_in(p->src_net), addr48_in(p->src_node), p->src_socket);
				IPX_STRING_ADDR(dest_addr, addr32_in(p->dest_net), addr48_in(p->dest_node), p->dest_socket);
				
				log_printf(LOG_DEBUG, "Recieved packet from %s for %s", src_addr, dest_addr);
			}
			
			size_t data_size = ntohs(p->length) - sizeof(novell_ipx_packet);
			
			deliver_packet(
				p->type,
				
				addr32_in(p->src_net),
				addr48_in(p->src_node),
				p->src_socket,
				
				addr32_in(p->dest_net),
				addr48_in(p->dest_node),
				p->dest_socket,
				
				p->data,
				data_size);
			
			p = (novell_ipx_packet*)((char*)(p) + ntohs(p->length));
		}
	}
	else{
		if(min_log_level <= LOG_DEBUG)
		{
			IPX_STRING_ADDR(src_addr, addr32_in(packet->src_net), addr48_in(packet->src_node), packet->src_socket);
			IPX_STRING_ADDR(dest_addr, addr32_in(packet->dest_net), addr48_in(packet->dest_node), packet->dest_socket);
			
			log_printf(LOG_DEBUG, "Recieved packet from %s for %s", src_addr, dest_addr);
		}
		
		size_t data_size = ntohs(packet->length) - sizeof(novell_ipx_packet);
		
		deliver_packet(
			packet->type,
			
			addr32_in(packet->src_net),
			addr48_in(packet->src_node),
			packet->src_socket,
			
			addr32_in(packet->dest_net),
			addr48_in(packet->dest_node),
			packet->dest_socket,
			
			packet->data,
			data_size);
	}
}

static int _do_udp_recv(int fd)
{
	/* Big enough for the source address of any IP version. */
	SOCKADDR_STORAGE addr;
	int addrlen = sizeof(addr);
	
	char buf[MAX_PKT_SIZE];
	int len = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*)(&addr), &addrlen);
	if(len == -1)
	{
		DWORD err = WSAGetLastError();
		
		switch(err)
		{
			case WSAEWOULDBLOCK: return 0;
			case WSAECONNRESET: return 1;
			default: return -1;
		}
	}
	
	__atomic_add_fetch(&recv_packets_udp, 1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&recv_bytes_udp, len, __ATOMIC_RELAXED);
	
	if(ipx_encap_type == ENCAP_TYPE_DOSBOX)
	{
		if (!ipver_sockaddr_equal((struct sockaddr*)(&addr), (struct sockaddr*)(&dosbox_server_addr))) {
			/* Ignore packet from wrong address. */
			return 1;
		}
		
		if(dosbox_state == DOSBOX_REGISTERING)
		{
			_handle_dosbox_registration_response((novell_ipx_packet*)(buf), len);
		}
		else if(dosbox_state == DOSBOX_CONNECTED)
		{
			_handle_dosbox_recv((novell_ipx_packet*)(buf), len);
		}
		else{
			/* Unreachable. */
			abort();
		}
	}
	else{
		/* The sockets used for IPXWrapper's own UDP encapsulation are
		   IPv4 sockets, so this can only be an IPv4 address. */
		struct sockaddr_in *addr4 = (struct sockaddr_in*)(&addr);
		
		if (addr4->sin_port != private_port || !ipv4_address_is_local(addr4->sin_addr.s_addr)) {
			_handle_udp_recv((ipx_packet*)(buf), len, *addr4);
		}
	}
	
	return 1;
}

static void _handle_pcap_frame(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
{
	FPROF_RECORD_SCOPE(&(ipxwrapper_fstats[IPXWRAPPER_FSTATS__handle_pcap_frame]));
	
	ipx_interface_t *iface = (ipx_interface_t*)(user);
	
	const novell_ipx_packet *ipx;
	size_t ipx_len;
	
	switch(main_config.frame_type)
	{
		case FRAME_TYPE_ETH_II:
			if(!ethII_frame_unpack(&ipx, &ipx_len, pkt_data, pkt_header->caplen))
			{
				return;
			}
			
			break;
			
		case FRAME_TYPE_NOVELL:
			if(!novell_frame_unpack(&ipx, &ipx_len, pkt_data, pkt_header->caplen))
			{
				return;
			}
			
			break;
			
		case FRAME_TYPE_LLC:
			if(!llc_frame_unpack(&ipx, &ipx_len, pkt_data, pkt_header->caplen))
			{
				return;
			}
			
			break;
	}
	
	if(ipx->checksum != 0xFFFF)
	{
		/* The "checksum" field doesn't have the magic IPX value. */
		return;
	}
	
	if(ntohs(ipx->length) > ipx_len)
	{
		/* The "length" field in the IPX header is too big. */
		return;
	}
	
	{
		addr48_t dest  = addr48_in(ipx->dest_node);
		addr48_t bcast = addr48_in((unsigned char[]){0xFF,0xFF,0xFF,0xFF,0xFF,0xFF});
		
		if(dest != iface->mac_addr && dest != bcast)
		{
			/* The destination node number isn't that of the card or
			 * the broadcast address.
			*/
			return;
		}
	}
	
	deliver_packet(ipx->type,
		addr32_in(ipx->src_net),
		addr48_in(ipx->src_node),
		ipx->src_socket,
		
		addr32_in(ipx->dest_net),
		addr48_in(ipx->dest_node),
		ipx->dest_socket,
		
		ipx->data,
		(ntohs(ipx->length) - sizeof(novell_ipx_packet)));
}

static void _send_dosbox_registration_request(void)
{
	novell_ipx_packet reg_pkt;
	
	reg_pkt.checksum = 0xFFFF;
	reg_pkt.length = htons(sizeof(novell_ipx_packet));
	reg_pkt.hops = 0;
	reg_pkt.type = 2;
	
	memset(reg_pkt.dest_net, 0, sizeof(reg_pkt.dest_net));
	memset(reg_pkt.dest_node, 0, sizeof(reg_pkt.dest_node));
	reg_pkt.dest_socket = htons(IPX_SOCK_ECHO);
	
	memset(reg_pkt.src_net, 0, sizeof(reg_pkt.src_net));
	memset(reg_pkt.src_node, 0, sizeof(reg_pkt.src_node));
	reg_pkt.src_socket = htons(IPX_SOCK_ECHO);
	
	if (dosbox_sendto(&reg_pkt, sizeof(reg_pkt)) < 0) {
		log_printf(LOG_ERROR, "Error sending DOSBox IPX registration request: %s", w32_error(WSAGetLastError()));
		
		/* If the system cannot even send to this address (e.g. "network
		   unreachable" for an IPv6 address without any IPv6 route),
		   there is no point in waiting for an answer for the full
		   DOSBOX_CANDIDATE_TIMEOUT_MS. Move on to the next candidate
		   address soon - but not instantly, so we don't spin through
		   the candidates at full speed if none of them can be sent to. */
		
		uint64_t give_up_at = get_ticks() + INITIAL_DOSBOX_REGISTRATION_RETRY_INTERVAL_MS;
		
		if (give_up_at < dosbox_candidate_timeout_at) {
			dosbox_candidate_timeout_at = give_up_at;
		}
	}
}

/* Resolve the configured DOSBox server address into the list of candidate
   addresses (dosbox_candidate_addrs), honouring the IP version chosen by the
   user.
  
   Returns true if there is at least one candidate. Otherwise the reason has
   been logged. */
static bool _resolve_dosbox_server(void)
{
	int family = AF_UNSPEC;
	const char *family_desc = "";
	
	if (main_config.dosbox_ip_version == DOSBOX_IP_VERSION_4) {
		family      = AF_INET;
		family_desc = " (restricted to IPv4)";
	}
	else if (main_config.dosbox_ip_version == DOSBOX_IP_VERSION_6) {
		family      = AF_INET6;
		family_desc = " (restricted to IPv6)";
	}
	
	SOCKADDR_STORAGE addrs[IPVER_MAX_ADDRS];
	int addrlens[IPVER_MAX_ADDRS];
	
	int n_addrs = ipver_resolve(main_config.dosbox_server_addr, main_config.dosbox_server_port, family, addrs, addrlens, IPVER_MAX_ADDRS);
	if (n_addrs == 0) {
		DWORD error = WSAGetLastError();
		log_printf(LOG_ERROR, "Error resolving %s%s: %s (%u)",
			main_config.dosbox_server_addr, family_desc, w32_error(error), (unsigned int)(error));
		
		return false;
	}
	
	/* Keep the addresses we are able to send to. */
	
	dosbox_n_candidates = 0;
	
	for (int i = 0; i < n_addrs; ++i) {
		if (addrs[i].ss_family == AF_INET6) {
			if (!_init_dosbox_socket6()) {
				/* No IPv6 on this computer (reason already logged). */
				continue;
			}
			
			if (main_config.dosbox_server_port6 != 0) {
                // The server listens on a different port for IPv6 than for IPv4.
				((struct sockaddr_in6*)(&(addrs[i])))->sin6_port = htons(main_config.dosbox_server_port6);
			}
		}
		
		dosbox_candidate_addrs[dosbox_n_candidates]    = addrs[i];
		dosbox_candidate_addrlens[dosbox_n_candidates] = addrlens[i];
		
		++dosbox_n_candidates;
	}
	
	if (dosbox_n_candidates == 0) {
		log_printf(LOG_ERROR, "DOSBox server %s%s has IPv6 addresses only, but IPv6 cannot be used on this computer",
			main_config.dosbox_server_addr, family_desc);
		
		return false;
	}
	
	return true;
}

/* Make one of the candidate addresses the current DOSBox server address and
   restart the registration with it. */
static void _select_dosbox_candidate(int idx, uint64_t now)
{
	dosbox_candidate_idx = idx;
	
	dosbox_server_addr    = dosbox_candidate_addrs[idx];
	dosbox_server_addrlen = dosbox_candidate_addrlens[idx];
	
	char addr_s[IPVER_ADDR_STRING_SIZE];
	ipver_sockaddr_string(addr_s, (struct sockaddr*)(&dosbox_server_addr));
	
	/* The port is at the same place in sockaddr_in and sockaddr_in6. */
	unsigned int port = ntohs(((struct sockaddr_in*)(&dosbox_server_addr))->sin_port);
	
	log_printf(LOG_INFO, "Resolved DOSBox server address %s port %u (address %d of %d), connecting...",
		addr_s, port, (idx + 1), dosbox_n_candidates);
	
	dosbox_next_registration_request_at   = 0;
	dosbox_registration_retry_interval_ms = INITIAL_DOSBOX_REGISTRATION_RETRY_INTERVAL_MS;
	
	dosbox_candidate_timeout_at = now + DOSBOX_CANDIDATE_TIMEOUT_MS;
}

static DWORD router_main(void *arg)
{
	DWORD exit_status = 0;
	
	ipx_interface_t *interfaces = NULL;
	
	HANDLE *wait_events = &router_event;
	int n_events = 1;
	
	if(ipx_encap_type == ENCAP_TYPE_PCAP)
	{
		interfaces = get_ipx_interfaces();
		ipx_interface_t *i;
		
		DL_FOREACH(interfaces, i)
		{
			++n_events;
		}
		
		wait_events = malloc(n_events * sizeof(HANDLE));
		if(!wait_events)
		{
			log_printf(LOG_ERROR, "Could not allocate memory!");
			
			free_ipx_interface_list(&interfaces);
			return 1;
		}
		
		n_events = 1;
		wait_events[0] = router_event;
		
		DL_FOREACH(interfaces, i)
		{
			wait_events[n_events++] = pcap_getevent(i->pcap);
		}
	}
	
	mclock_point_t next_spx_retransmit = mclock_now();
	
	while(1)
	{
		DWORD wait_ms = 1000;
		
		if(ipx_encap_type == ENCAP_TYPE_DOSBOX)
		{
			lock_sockets();
			coalesce_flush_waiting();
			unlock_sockets();
			
			if(dosbox_state == DOSBOX_DISCONNECTED)
			{
				uint64_t now = get_ticks();
				
				if(now >= dosbox_next_connection_attempt_at)
				{
					wait_ms = 0;
				}
				else{
					wait_ms = dosbox_next_connection_attempt_at - now;
					wait_ms = min(wait_ms, 1000);
				}
			}
			else if(dosbox_state == DOSBOX_REGISTERING)
			{
				uint64_t now = get_ticks();
				
				if(now >= dosbox_next_registration_request_at)
				{
					wait_ms = 0;
				}
				else{
					wait_ms = dosbox_next_registration_request_at - now;
					wait_ms = min(wait_ms, 1000);
				}
				
				if (dosbox_n_candidates > 1) {
					/* Also wake up in time to switch to the
					 * next candidate address.
					*/
					
					DWORD switch_in_ms = now >= dosbox_candidate_timeout_at
						? 0
						: dosbox_candidate_timeout_at - now;
					
					wait_ms = min(wait_ms, switch_in_ms);
				}
			}
		}
		
		uint32_t next_spx_retransmit_in = mclock_ms_until(next_spx_retransmit, mclock_now());
		if(next_spx_retransmit_in < wait_ms)
		{
			wait_ms = next_spx_retransmit_in;
		}
		
		WaitForMultipleObjects(n_events, wait_events, FALSE, wait_ms);
		WSAResetEvent(router_event);
		
		if(!router_running)
		{
			break;
		}
		
		if(ipx_encap_type == ENCAP_TYPE_PCAP)
		{
			ipx_interface_t *i;
			DL_FOREACH(interfaces, i)
			{
				if(pcap_dispatch(i->pcap, -1, &_handle_pcap_frame, (u_char*)(i)) == -1)
				{
					log_printf(LOG_ERROR, "Could not dispatch frames on WinPcap interface: %s", pcap_geterr(i->pcap));
					log_printf(LOG_WARNING, "No more IPX packets will be received");
					
					exit_status = 1;
					break;
				}
			}
		}
		else if(ipx_encap_type == ENCAP_TYPE_DOSBOX)
		{
			int status = 0;
			
			for(int i = 0; i < MAX_RECV_PER_LOOP; ++i)
			{
				status = _do_udp_recv(private_socket);
				
				if (status >= 0 && dosbox_socket6 != -1) {
					/* Same logic as for the shared/private sockets below:
					   stop on an error, or when both sockets have run dry. */
					
					int status6 = _do_udp_recv(dosbox_socket6);
					
					if (status6 != 0) {
						status = status6;
					}
				}
				
				if(status <= 0)
				{
					break;
				}
			}
			
			if(status < 0)
			{
				exit_status = 1;
				break;
			}
		}
		else{
			int status = 0;
			
			for(int i = 0; i < MAX_RECV_PER_LOOP; ++i)
			{
				int s1 = _do_udp_recv(shared_socket);
				int s2 = _do_udp_recv(private_socket);
				
				if(s1 < 0 || s2 < 0)
				{
					status = -1;
					break;
				}
				else if(s1 == 0 && s2 == 0)
				{
					break;
				}
			}
			
			if(status < 0)
			{
				exit_status = 1;
				break;
			}
		}
		
		if(ipx_encap_type == ENCAP_TYPE_DOSBOX && dosbox_state == DOSBOX_DISCONNECTED)
		{
			if(get_ticks() >= dosbox_next_connection_attempt_at)
			{
				bool resolved = _resolve_dosbox_server();
				
				uint64_t now = get_ticks();
				
				if (resolved) {
					_select_dosbox_candidate(0, now);
					
					dosbox_registration_timeout_at = now + DOSBOX_REGISTRATION_TIMEOUT_MS;
					
					dosbox_state = DOSBOX_REGISTERING;
				}
				else {
					dosbox_next_connection_attempt_at = now + dosbox_connect_retry_interval_ms;
				}
			}
		}
		
		if(ipx_encap_type == ENCAP_TYPE_DOSBOX && dosbox_state == DOSBOX_REGISTERING)
		{
			uint64_t now = get_ticks();
			
			if(now >= dosbox_registration_timeout_at)
			{
				log_printf(LOG_ERROR, "Connection to DOSBox server %s timed out", main_config.dosbox_server_addr);
				dosbox_state = DOSBOX_DISCONNECTED;
			}
			else if (dosbox_n_candidates > 1 && now >= dosbox_candidate_timeout_at) {
				/* No answer from this address of the server (e.g.
				   IPv6 address, but no working IPv6 route). Try
				   the next one, starting over after the last. */
				
				_select_dosbox_candidate((dosbox_candidate_idx + 1) % dosbox_n_candidates, now);
			}
			
			if(now >= dosbox_next_registration_request_at)
			{
				_send_dosbox_registration_request();
				
				dosbox_next_registration_request_at = now + dosbox_registration_retry_interval_ms;
				
				dosbox_registration_retry_interval_ms *= 2;
				dosbox_registration_retry_interval_ms = min(dosbox_registration_retry_interval_ms, MAX_DOSBOX_REGISTRATION_RETRY_INTERVAL_MS);
			}
		}

		next_spx_retransmit = spx_retransmit_lost();
	}
	
	if(ipx_encap_type == ENCAP_TYPE_PCAP)
	{
		free(wait_events);
		free_ipx_interface_list(&interfaces);
	}
	
	return exit_status;
}

void wait_for_ready(DWORD timeout)
{
	if(dosbox_ready_event != NULL)
	{
		WaitForSingleObject(dosbox_ready_event, timeout);
	}
}
