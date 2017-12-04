#ifndef __TCP_H__
#define __TCP_H__

#include "types.h"
#include "ip.h"
#include "checksum.h"

#include <endian.h>

// format of standard tcp header 
struct tcphdr {
	u16 sport;		// source port 
	u16 dport;		// destination port
	u32 seq;			// sequence number
	u32 ack;			// acknowledgement number
# if __BYTE_ORDER == __LITTLE_ENDIAN
	u8 x2:4;			// (unused)
	u8 off:4;			// data offset
# elif __BYTE_ORDER == __BIG_ENDIAN
	u8 off:4;			// data offset
	u8 x2:4;			// (unused)
# endif
	u8 flags;
# define TCP_FIN	0x01
# define TCP_SYN	0x02
# define TCP_RST	0x04
# define TCP_PSH	0x08
# define TCP_ACK	0x10
# define TCP_URG	0x20
	u16 rwnd;			// receiving window
	u16 checksum;		// checksum
	u16 urp;			// urgent pointer
} __attribute__((packed));

#define TCP_HDR_OFFSET 5
#define TCP_BASE_HDR_SIZE 20
#define TCP_HDR_SIZE(tcp) (tcp->off * 4)

#define TCP_DEFAULT_WINDOW 65535

static inline struct tcphdr *packet_to_tcp_hdr(char *packet)
{
	struct iphdr *ip = packet_to_ip_hdr(packet);
	return (struct tcphdr *)((char *)ip + IP_HDR_SIZE(ip));
}

static inline u16 tcp_checksum(struct iphdr *ip, struct tcphdr *tcp)
{
	u16 tmp = tcp->checksum;
	tcp->checksum = 0;

	u16 reserv_proto = ip->protocol;
	u16 tcp_len = ntohs(ip->tot_len) - IP_HDR_SIZE(ip);

	u32 sum = ip->saddr + ip->daddr + htons(reserv_proto) + htons(tcp_len);
	u16 cksum = checksum((u16 *)tcp, (int)tcp_len, sum);

	tcp->checksum = tmp;

	return cksum;
}

void tcp_copy_flags_to_str(u8 flags, char buf[]);

#endif
