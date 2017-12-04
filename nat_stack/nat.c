#include "nat.h"
#include "ip.h"
#include "icmp.h"
#include "tcp.h"
#include "rtable.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static struct nat_table nat;

// hash address and port
int nat_hash(u32 addr, u16 port)
{
	int val = hash8((char *)&addr, 4) ^ hash8((char *)&port, 2);

	return val;
}

// check whether the flow is finished according to FIN bit and sequence number
int is_flow_finished(struct nat_connection *conn)
{
	return conn->internal_fin && conn->external_fin && 
			conn->internal_ack == conn->external_seq_end && 
			conn->external_ack == conn->internal_seq_end;
}

// get the interface from iface name
static iface_info_t *if_name_to_iface(const char *if_name)
{
	iface_info_t *iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		if (strcmp(iface->name, if_name) == 0)
			return iface;
	}

	log(ERROR, "Could not find the desired interface according to if_name '%s'", if_name);
	return NULL;
}

// lookup the corresponding map from mapping_list according to external_port
struct nat_mapping *nat_lookup_external(struct list_head *mapping_list, u16 external_port)
{
	struct nat_mapping *entry;

	list_for_each_entry(entry, mapping_list, list) {
		if (entry->external_port == external_port)
			return entry;
	}

	return NULL;
}

// lookup the corresponding map from mapping_list according to internal_ip and
// internal_port
struct nat_mapping *nat_lookup_internal(struct list_head *mapping_list,
		u32 internal_ip, u16 internal_port)
{
	struct nat_mapping *entry;

	list_for_each_entry(entry, mapping_list, list) {
		if (entry->internal_port == internal_port && entry->internal_ip == internal_ip)
			return entry;
	}

	return NULL;
}

// select an external port from the port pool
u16 assign_external_port()
{
	u16 port = 0;

	for (int i = NAT_PORT_MIN; i <= NAT_PORT_MAX; i++) {
		if (nat.assigned_ports[i] == 0) {
			nat.assigned_ports[i] = 1;
            return i;
		}
	}

	return port;
}

// free the port
void free_port(u16 port)
{
	nat.assigned_ports[port] = 0;
}

// insert the new connection into mapping_list
// the internal_ip & internal_port are from the SYN packet of the connection
// the external_ip is the ip address of the external interface, the
// external_port is assigned by nat
struct nat_mapping *nat_insert_mapping(struct list_head *mapping_list, u32 internal_ip, u16 internal_port)
{
    struct nat_mapping *mapping_entry= nat_lookup_internal(mapping_list, internal_ip, internal_port);
    if (mapping_entry != NULL) {
        return mapping_entry;
    }
    
	u32 external_ip = nat.external_iface->ip;
	u16 external_port = assign_external_port();
    if (external_port == 0) {
		return NULL;
	}
    
	mapping_entry = malloc(sizeof(struct nat_mapping));
	mapping_entry->internal_ip = internal_ip;
	mapping_entry->internal_port = internal_port;
	mapping_entry->external_ip = external_ip;
	mapping_entry->external_port = external_port;
	list_add_tail(&mapping_entry->list, mapping_list);

	return mapping_entry;
}

// determine the direction of the packet, DIR_IN / DIR_OUT / DIR_INVALID
static int get_packet_direction(char *packet)
{
	struct iphdr *ip = packet_to_ip_hdr(packet);
    rt_entry_t* route = longest_prefix_match(be32toh(ip->daddr));
	if (route == NULL)
		return DIR_INVALID;
	iface_info_t *iface = route->iface;	
	if (iface->ip == be32toh(ip->daddr))
		return DIR_IN;
	return DIR_OUT;
}

// update statistics of the tcp connection
void nat_update_tcp_connection(char *packet, struct nat_mapping *mapping, int dir)
{
    struct tcphdr *tcp = packet_to_tcp_hdr(packet);
	struct iphdr *ip = packet_to_ip_hdr(packet);
    mapping->update_time = time(NULL);
    struct nat_connection *conn = &mapping->conn;
	u32 seq_end = be16toh(tcp->seq) + be16toh(ip->tot_len) - IP_HDR_SIZE(ip) - TCP_HDR_SIZE(tcp); 
	log(DEBUG, "ip:"IP_FMT", fin:%d, seq_end:%d, ack:%d",BE_IP_FMT_STR(ip->saddr), tcp->flags & TCP_FIN, seq_end, be16toh(tcp->ack));

    if (dir == DIR_IN) {
        conn->external_fin = conn->external_fin | (tcp->flags & TCP_FIN);
        conn->external_seq_end = seq_end;
        conn->external_ack = be16toh(tcp->ack);
    } else if(dir == DIR_OUT) {
        conn->internal_fin = conn->internal_fin | (tcp->flags & TCP_FIN);
        conn->internal_seq_end = seq_end;
        conn->internal_ack = be16toh(tcp->ack);
    }
}

// find the mapping corresponding to the packet from nat table 
struct nat_mapping *nat_get_mapping_from_packet(char *packet, int len, iface_info_t *iface, int dir)
{
    struct tcphdr *tcp = packet_to_tcp_hdr(packet);
    struct iphdr *ip = packet_to_ip_hdr(packet);

    if (dir == DIR_OUT) {
        u8 hash = nat_hash(ip->daddr, tcp->dport);
        return nat_lookup_internal(&nat.nat_mapping_list[hash], be32toh(ip->saddr), be16toh(tcp->sport));
    } else {
        u8 hash = nat_hash(ip->saddr, tcp->sport);
        return nat_lookup_external(&nat.nat_mapping_list[hash], be16toh(tcp->dport));
    }
}

// do translation for the packet: replace the ip/port, recalculate ip & tcp
// checksum, update the statistics of the tcp connection
void do_translation(iface_info_t *iface, char *packet, int len, int dir)
{
    struct tcphdr *tcp = packet_to_tcp_hdr(packet);
    struct iphdr *ip = packet_to_ip_hdr(packet);

    struct nat_mapping *mapping = nat_get_mapping_from_packet(packet, len, iface, dir);
    if (mapping == NULL && dir == DIR_OUT){
        u8 hash = nat_hash(ip->daddr, tcp->dport);
        mapping = nat_insert_mapping(&nat.nat_mapping_list[hash], be32toh(ip->saddr), be16toh(tcp->sport));
        if (mapping == NULL) {
            log(ERROR, "don't have enough port, drop it");
            icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
            free(packet);
			return ;
        }
    }

    if (dir == DIR_IN) {
        ip->daddr = htobe32(mapping->internal_ip);
        tcp->dport = htobe16(mapping->internal_port);
    }
    if (dir == DIR_OUT) {
        ip->saddr = htobe32(mapping->external_ip);
        tcp->sport = htobe16(mapping->external_port);
    }
	tcp->checksum = tcp_checksum(ip, tcp);
    ip->checksum = ip_checksum(ip);

    nat_update_tcp_connection(packet, mapping, dir);
    ip_send_packet(packet, len);
}

void nat_translate_packet(iface_info_t *iface, char *packet, int len)
{
	int dir = get_packet_direction(packet);
	if (dir == DIR_INVALID) {
		log(ERROR, "invalid packet direction, drop it.");
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
		free(packet);
		return ;
	}

	struct iphdr *ip = packet_to_ip_hdr(packet);
	if (ip->protocol != IPPROTO_TCP) {
		log(ERROR, "received non-TCP packet (0x%0hhx), drop it", ip->protocol);
		free(packet);
		return ;
	}

	do_translation(iface, packet, len, dir);
}

// nat timeout thread: find the finished flows, remove them and free port
// resource
void *nat_timeout()
{
	while(1) {
        sleep(1);
		pthread_mutex_lock(&nat.lock);
		for (int i = 0; i < HASH_8BITS; i++) {
			struct list_head *head = &nat.nat_mapping_list[i];
			struct nat_mapping *mapping_entry, *q;
			list_for_each_entry_safe(mapping_entry, q, head, list) {
				if (is_flow_finished(&mapping_entry->conn) || time(NULL) - mapping_entry->update_time > 60) {
					log(DEBUG, "delete the flow between "IP_FMT" <---> nat node", LE_IP_FMT_STR(mapping_entry->internal_ip));
					list_delete_entry(&mapping_entry->list);
					free_port(mapping_entry->external_port);
					free(mapping_entry);
				}
			}
		}
		pthread_mutex_unlock(&nat.lock);
	}
}

// initialize nat table
void nat_table_init()
{
	memset(&nat, 0, sizeof(nat));

	for (int i = 0; i < HASH_8BITS; i++)
		init_list_head(&nat.nat_mapping_list[i]);

	nat.internal_iface = if_name_to_iface("n1-eth0");
	nat.external_iface = if_name_to_iface("n1-eth1");
	if (!nat.internal_iface || !nat.external_iface) {
		log(ERROR, "Could not find the desired interfaces for nat.");
		exit(1);
	}

	memset(nat.assigned_ports, 0, sizeof(nat.assigned_ports));

	pthread_mutex_init(&nat.lock, NULL);

	pthread_create(&nat.thread, NULL, nat_timeout, NULL);
}

// destroy nat table
void nat_table_destroy()
{
	pthread_mutex_lock(&nat.lock);

	for (int i = 0; i < HASH_8BITS; i++) {
		struct list_head *head = &nat.nat_mapping_list[i];
		struct nat_mapping *mapping_entry, *q;
		list_for_each_entry_safe(mapping_entry, q, head, list) {
			list_delete_entry(&mapping_entry->list);
			free(mapping_entry);
		}
	}

	pthread_kill(nat.thread, SIGTERM);

	pthread_mutex_unlock(&nat.lock);
}
