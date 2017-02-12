/*
 * Copyright (c) 2007-2015 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/openvswitch.h>
#include <linux/netfilter_ipv6.h>
#include <linux/sctp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in6.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>

#include <net/dst.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/checksum.h>
#include <net/dsfield.h>
#include <net/mpls.h>
#include <net/sctp/checksum.h>
#include <net/arp.h>

#include "datapath.h"
#include "conntrack.h"
#include "gso.h"
#include "vlan.h"
#include "vport.h"

static int do_execute_actions(struct datapath *dp, struct sk_buff *skb,
			      struct sw_flow_key *key,
			      const struct nlattr *attr, int len);

struct deferred_action {
	struct sk_buff *skb;
	const struct nlattr *actions;

	/* Store pkt_key clone when creating deferred action. */
	struct sw_flow_key pkt_key;
};

#define MAX_L2_LEN	(VLAN_ETH_HLEN + 3 * MPLS_HLEN)
struct ovs_frag_data {
	unsigned long dst;
	struct vport *vport;
	struct ovs_gso_cb cb;
	__be16 inner_protocol;
	__u16 vlan_tci;
	__be16 vlan_proto;
	unsigned int l2_len;
	u8 l2_data[MAX_L2_LEN];
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
static DEFINE_PER_CPU(struct ovs_frag_data, ovs_frag_data_storage);
#endif

#define DEFERRED_ACTION_FIFO_SIZE 10
struct action_fifo {
	int head;
	int tail;
	/* Deferred action fifo queue storage. */
	struct deferred_action fifo[DEFERRED_ACTION_FIFO_SIZE];
};

static struct action_fifo __percpu *action_fifos;
#define EXEC_ACTIONS_LEVEL_LIMIT 4   /* limit used to detect packet
				      *	looping by the network stack
				      */
static DEFINE_PER_CPU(int, exec_actions_level);

static void action_fifo_init(struct action_fifo *fifo)
{
	fifo->head = 0;
	fifo->tail = 0;
}

static bool action_fifo_is_empty(const struct action_fifo *fifo)
{
	return (fifo->head == fifo->tail);
}

static struct deferred_action *action_fifo_get(struct action_fifo *fifo)
{
	if (action_fifo_is_empty(fifo))
		return NULL;

	return &fifo->fifo[fifo->tail++];
}

static struct deferred_action *action_fifo_put(struct action_fifo *fifo)
{
	if (fifo->head >= DEFERRED_ACTION_FIFO_SIZE - 1)
		return NULL;

	return &fifo->fifo[fifo->head++];
}

/* Return queue entry if fifo is not full */
static struct deferred_action *add_deferred_actions(struct sk_buff *skb,
						    const struct sw_flow_key *key,
						    const struct nlattr *attr)
{
	struct action_fifo *fifo;
	struct deferred_action *da;

	fifo = this_cpu_ptr(action_fifos);
	da = action_fifo_put(fifo);
	if (da) {
		da->skb = skb;
		da->actions = attr;
		da->pkt_key = *key;
	}

	return da;
}

static void invalidate_flow_key(struct sw_flow_key *key)
{
	key->eth.type = htons(0);
}

static bool is_flow_key_valid(const struct sw_flow_key *key)
{
	return !!key->eth.type;
}

static int push_mpls(struct sk_buff *skb, struct sw_flow_key *key,
		     const struct ovs_action_push_mpls *mpls)
{
	__be32 *new_mpls_lse;
	struct ethhdr *hdr;

	/* Networking stack do not allow simultaneous Tunnel and MPLS GSO. */
	if (skb_encapsulation(skb))
		return -ENOTSUPP;

	if (skb_cow_head(skb, MPLS_HLEN) < 0)
		return -ENOMEM;

	skb_push(skb, MPLS_HLEN);
	memmove(skb_mac_header(skb) - MPLS_HLEN, skb_mac_header(skb),
		skb->mac_len);
	skb_reset_mac_header(skb);

	new_mpls_lse = (__be32 *)skb_mpls_header(skb);
	*new_mpls_lse = mpls->mpls_lse;

	if (skb->ip_summed == CHECKSUM_COMPLETE)
		skb->csum = csum_add(skb->csum, csum_partial(new_mpls_lse,
							     MPLS_HLEN, 0));

	hdr = eth_hdr(skb);
	hdr->h_proto = mpls->mpls_ethertype;
	if (!ovs_skb_get_inner_protocol(skb))
		ovs_skb_set_inner_protocol(skb, skb->protocol);
	skb->protocol = mpls->mpls_ethertype;

	invalidate_flow_key(key);
	return 0;
}

static int pop_mpls(struct sk_buff *skb, struct sw_flow_key *key,
		    const __be16 ethertype)
{
	struct ethhdr *hdr;
	int err;

	err = skb_ensure_writable(skb, skb->mac_len + MPLS_HLEN);
	if (unlikely(err))
		return err;

	skb_postpull_rcsum(skb, skb_mpls_header(skb), MPLS_HLEN);

	memmove(skb_mac_header(skb) + MPLS_HLEN, skb_mac_header(skb),
		skb->mac_len);

	__skb_pull(skb, MPLS_HLEN);
	skb_reset_mac_header(skb);

	/* skb_mpls_header() is used to locate the ethertype
	 * field correctly in the presence of VLAN tags.
	 */
	hdr = (struct ethhdr *)(skb_mpls_header(skb) - ETH_HLEN);
	hdr->h_proto = ethertype;
	if (eth_p_mpls(skb->protocol))
		skb->protocol = ethertype;

	invalidate_flow_key(key);
	return 0;
}

static int set_mpls(struct sk_buff *skb, struct sw_flow_key *flow_key,
		    const __be32 *mpls_lse, const __be32 *mask)
{
	__be32 *stack;
	__be32 lse;
	int err;

	err = skb_ensure_writable(skb, skb->mac_len + MPLS_HLEN);
	if (unlikely(err))
		return err;

	stack = (__be32 *)skb_mpls_header(skb);
	lse = OVS_MASKED(*stack, *mpls_lse, *mask);
	if (skb->ip_summed == CHECKSUM_COMPLETE) {
		__be32 diff[] = { ~(*stack), lse };

		skb->csum = ~csum_partial((char *)diff, sizeof(diff),
					  ~skb->csum);
	}

	*stack = lse;
	flow_key->mpls.top_lse = lse;
	return 0;
}

static int pop_vlan(struct sk_buff *skb, struct sw_flow_key *key)
{
	int err;

	err = skb_vlan_pop(skb);
	if (skb_vlan_tag_present(skb))
		invalidate_flow_key(key);
	else
		key->eth.tci = 0;
	return err;
}

static int pop_gtpv1(struct sk_buff *skb, struct sw_flow_key *key)
{
	size_t gtp_tun_len;

	/* before decapsulating, check if this 'skb' is a GTPv1 packet carrying a G-PDU */
	if (check_extract_gtp(skb, NULL) != 0)
	{
		return -EINVAL;
	}
	if (((struct iphdr*)GTPv1_PAYLOAD(skb))->version != 4)	// decapsulate only IPv4 traffic
	{
		return -EINVAL;
	}

	/* remove all the gtp tunnel related headers, leaving exact room to hold the Ethernet header */
	gtp_tun_len = skb->len - (ntohs(GTPv1_HDR(skb)->tot_len) + ETH_HLEN);
	__skb_pull(skb, gtp_tun_len);

	/* update the L2, L3, and L4 headers corresponding to the extracted G-PDU packet */
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	skb_set_transport_header(skb, skb_network_offset(skb) + (ip_hdr(skb)->ihl * 4));

	/* zero out the Ethernet header as it is dirty of the old gtp tunnel related headers */
	memset(skb_mac_header(skb), 0, ETH_HLEN);
	//ip_send_check(ip_hdr(skb));				// compute ip checksum in case it's wrong
	/* update 'key' corresponding to the extracted G-PDU packet */
	memset(&(key->gtp_u), 0, sizeof(key->gtp_u));

	return 0;
}

static int push_gtpv1(struct sk_buff *skb, struct sw_flow_key *key, const struct ovs_action_push_gtpv1 *gtpv1)
{
	// length in bytes comprising all the gtp tunnel related headers
	const size_t gtp_tun_len = ETH_HLEN + IPV4_HLEN_PLAIN + UDP_HLEN + GTPU_HLEN_PLAIN;
	struct iphdr *outer_iphdr;		// tunnel IPv4 header
	struct udphdr *outer_udphdr;	// tunnel UDP header
	struct gtpv1hdr *gtphdr;		// GTPv1 header
	__be16 inner_ip_totlen;			// in network byte order

	if (ip_hdr(skb)->version != 4)		// encapsulate only IPv4 traffic
	{
		return -EINVAL;
	}
	if (check_extract_gtp(skb, NULL) == 0)	// before encapsulating, check if the packet is already GTPv1 tunneled
	{
		return -EINVAL;
	}

	/* we will need it later, as this IPv4 packet gets encapsulated */
	inner_ip_totlen = ip_hdr(skb)->tot_len;

	/* reserve a maximum amount of headroom for containing the GTP tunnel headers */
	if (skb_cow(skb, LL_MAX_HEADER + gtp_tun_len) < 0)
		return -ENOMEM;

	/* Update the 'data' ptr in such a way that the old ethernet header gets perfectly overwrited,
	 * zeroing out the space required by the gtp tunnel headers (including the "old" ethernet header).
	 */
	memset(__skb_push(skb, gtp_tun_len - ETH_HLEN), 0, gtp_tun_len);

	/* update header offsets as the original packet has been expanded */
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);	// the new network header becomes the tunnel's ip header
	skb_set_transport_header(skb, skb_network_offset(skb) + IPV4_HLEN_PLAIN);	// the new transport header becomes the tunnel's udp header

	/* Get ptrs to all the gtp tunnel headers inside the expanded 'skb'. */
	outer_iphdr = ip_hdr(skb);
	outer_udphdr = udp_hdr(skb);
	gtphdr = GTPv1_HDR(skb);

	/* fill the tunnel's IP header */
	outer_iphdr->ihl = 5;			// 5 words (20 bytes) header
	outer_iphdr->version = 4;		// IPv4
	outer_iphdr->tos = 0;
	outer_iphdr->tot_len = htons(IPV4_HLEN_PLAIN + UDP_HLEN + GTPU_HLEN_PLAIN + ntohs(inner_ip_totlen));
	outer_iphdr->id = 0;
	outer_iphdr->frag_off = 0;
	outer_iphdr->ttl = 255;			// maximum TTL
	outer_iphdr->protocol = IPPROTO_UDP;			// follows UDP tunnel header
	outer_iphdr->saddr = htonl(gtpv1->ipv4.src);	// tunnel's src address
	outer_iphdr->daddr = htonl(gtpv1->ipv4.dst);	// tunnel's dst address

	/* fill the tunnel's UDP header */
	outer_udphdr->source = htons(GTPv1_PORT);
	outer_udphdr->dest = htons(GTPv1_PORT);
	outer_udphdr->len = htons(UDP_HLEN + GTPU_HLEN_PLAIN + ntohs(inner_ip_totlen));
	outer_udphdr->check = 0;

	/* fill the GTPv1 header */
	gtphdr->version = 1;					// GTPv1
	gtphdr->ptype = 1;						// protocol type is GTP (0 for GTP')
	gtphdr->reserved = 0;
	gtphdr->ehf = 0;
	gtphdr->snf = 0;
	gtphdr->pnf = 0;
	gtphdr->type = GTP_MSG_TYPE_GPDU;		// G-PDU msg type
	gtphdr->tot_len = inner_ip_totlen;		// IPv4's 'tot_len' header field is already in network byte order
	gtphdr->teid = htonl(gtpv1->teid);		// Tunnel ID

	ip_send_check(ip_hdr(skb));				// compute the tunnel's ip checksum

	/* update 'key' corresponding to this 'gtpv1' encapsulation */
	key->gtp_u.ipv4_dst = htonl(gtpv1->ipv4.dst);
	key->gtp_u.teid = htonl(gtpv1->teid);

	return 0;
}

static int push_vlan(struct sk_buff *skb, struct sw_flow_key *key,
		     const struct ovs_action_push_vlan *vlan)
{
	if (skb_vlan_tag_present(skb))
		invalidate_flow_key(key);
	else
		key->eth.tci = vlan->vlan_tci;
	return skb_vlan_push(skb, vlan->vlan_tpid,
			     ntohs(vlan->vlan_tci) & ~VLAN_TAG_PRESENT);
}

/* 'src' is already properly masked. */
static void ether_addr_copy_masked(u8 *dst_, const u8 *src_, const u8 *mask_)
{
	u16 *dst = (u16 *)dst_;
	const u16 *src = (const u16 *)src_;
	const u16 *mask = (const u16 *)mask_;

	OVS_SET_MASKED(dst[0], src[0], mask[0]);
	OVS_SET_MASKED(dst[1], src[1], mask[1]);
	OVS_SET_MASKED(dst[2], src[2], mask[2]);
}

static int set_eth_addr(struct sk_buff *skb, struct sw_flow_key *flow_key,
			const struct ovs_key_ethernet *key,
			const struct ovs_key_ethernet *mask)
{
	int err;

	err = skb_ensure_writable(skb, ETH_HLEN);
	if (unlikely(err))
		return err;

	skb_postpull_rcsum(skb, eth_hdr(skb), ETH_ALEN * 2);

	ether_addr_copy_masked(eth_hdr(skb)->h_source, key->eth_src,
			       mask->eth_src);
	ether_addr_copy_masked(eth_hdr(skb)->h_dest, key->eth_dst,
			       mask->eth_dst);

	ovs_skb_postpush_rcsum(skb, eth_hdr(skb), ETH_ALEN * 2);

	ether_addr_copy(flow_key->eth.src, eth_hdr(skb)->h_source);
	ether_addr_copy(flow_key->eth.dst, eth_hdr(skb)->h_dest);
	return 0;
}

static void update_ip_l4_checksum(struct sk_buff *skb, struct iphdr *nh,
				  __be32 addr, __be32 new_addr)
{
	int transport_len = skb->len - skb_transport_offset(skb);

	if (nh->frag_off & htons(IP_OFFSET))
		return;

	if (nh->protocol == IPPROTO_TCP) {
		if (likely(transport_len >= sizeof(struct tcphdr)))
			inet_proto_csum_replace4(&tcp_hdr(skb)->check, skb,
						 addr, new_addr, 1);
	} else if (nh->protocol == IPPROTO_UDP) {
		if (likely(transport_len >= sizeof(struct udphdr))) {
			struct udphdr *uh = udp_hdr(skb);

			if (uh->check || skb->ip_summed == CHECKSUM_PARTIAL) {
				inet_proto_csum_replace4(&uh->check, skb,
							 addr, new_addr, 1);
				if (!uh->check)
					uh->check = CSUM_MANGLED_0;
			}
		}
	}

}

static void set_ip_addr(struct sk_buff *skb, struct iphdr *nh,
			__be32 *addr, __be32 new_addr)
{
	update_ip_l4_checksum(skb, nh, *addr, new_addr);
	csum_replace4(&nh->check, *addr, new_addr);
	skb_clear_hash(skb);
	*addr = new_addr;
}

static void update_ipv6_checksum(struct sk_buff *skb, u8 l4_proto,
				 __be32 addr[4], const __be32 new_addr[4])
{
	int transport_len = skb->len - skb_transport_offset(skb);

	if (l4_proto == NEXTHDR_TCP) {
		if (likely(transport_len >= sizeof(struct tcphdr)))
			inet_proto_csum_replace16(&tcp_hdr(skb)->check, skb,
						  addr, new_addr, 1);
	} else if (l4_proto == NEXTHDR_UDP) {
		if (likely(transport_len >= sizeof(struct udphdr))) {
			struct udphdr *uh = udp_hdr(skb);

			if (uh->check || skb->ip_summed == CHECKSUM_PARTIAL) {
				inet_proto_csum_replace16(&uh->check, skb,
							  addr, new_addr, 1);
				if (!uh->check)
					uh->check = CSUM_MANGLED_0;
			}
		}
	} else if (l4_proto == NEXTHDR_ICMP) {
		if (likely(transport_len >= sizeof(struct icmp6hdr)))
			inet_proto_csum_replace16(&icmp6_hdr(skb)->icmp6_cksum,
						  skb, addr, new_addr, 1);
	}
}

static void mask_ipv6_addr(const __be32 old[4], const __be32 addr[4],
			   const __be32 mask[4], __be32 masked[4])
{
	masked[0] = OVS_MASKED(old[0], addr[0], mask[0]);
	masked[1] = OVS_MASKED(old[1], addr[1], mask[1]);
	masked[2] = OVS_MASKED(old[2], addr[2], mask[2]);
	masked[3] = OVS_MASKED(old[3], addr[3], mask[3]);
}

static void set_ipv6_addr(struct sk_buff *skb, u8 l4_proto,
			  __be32 addr[4], const __be32 new_addr[4],
			  bool recalculate_csum)
{
	if (likely(recalculate_csum))
		update_ipv6_checksum(skb, l4_proto, addr, new_addr);

	skb_clear_hash(skb);
	memcpy(addr, new_addr, sizeof(__be32[4]));
}

static void set_ipv6_fl(struct ipv6hdr *nh, u32 fl, u32 mask)
{
	/* Bits 21-24 are always unmasked, so this retains their values. */
	OVS_SET_MASKED(nh->flow_lbl[0], (u8)(fl >> 16), (u8)(mask >> 16));
	OVS_SET_MASKED(nh->flow_lbl[1], (u8)(fl >> 8), (u8)(mask >> 8));
	OVS_SET_MASKED(nh->flow_lbl[2], (u8)fl, (u8)mask);
}

static void set_ip_ttl(struct sk_buff *skb, struct iphdr *nh, u8 new_ttl,
		       u8 mask)
{
	new_ttl = OVS_MASKED(nh->ttl, new_ttl, mask);

	csum_replace2(&nh->check, htons(nh->ttl << 8), htons(new_ttl << 8));
	nh->ttl = new_ttl;
}

static int set_ipv4(struct sk_buff *skb, struct sw_flow_key *flow_key,
		    const struct ovs_key_ipv4 *key,
		    const struct ovs_key_ipv4 *mask)
{
	struct iphdr *nh;
	__be32 new_addr;
	int err;

	err = skb_ensure_writable(skb, skb_network_offset(skb) +
				  sizeof(struct iphdr));
	if (unlikely(err))
		return err;

	nh = ip_hdr(skb);

	/* Setting an IP addresses is typically only a side effect of
	 * matching on them in the current userspace implementation, so it
	 * makes sense to check if the value actually changed.
	 */
	if (mask->ipv4_src) {
		new_addr = OVS_MASKED(nh->saddr, key->ipv4_src, mask->ipv4_src);

		if (unlikely(new_addr != nh->saddr)) {
			set_ip_addr(skb, nh, &nh->saddr, new_addr);
			flow_key->ipv4.addr.src = new_addr;
		}
	}
	if (mask->ipv4_dst) {
		new_addr = OVS_MASKED(nh->daddr, key->ipv4_dst, mask->ipv4_dst);

		if (unlikely(new_addr != nh->daddr)) {
			set_ip_addr(skb, nh, &nh->daddr, new_addr);
			flow_key->ipv4.addr.dst = new_addr;
		}
	}
	if (mask->ipv4_tos) {
		ipv4_change_dsfield(nh, ~mask->ipv4_tos, key->ipv4_tos);
		flow_key->ip.tos = nh->tos;
	}
	if (mask->ipv4_ttl) {
		set_ip_ttl(skb, nh, key->ipv4_ttl, mask->ipv4_ttl);
		flow_key->ip.ttl = nh->ttl;
	}

	return 0;
}

static bool is_ipv6_mask_nonzero(const __be32 addr[4])
{
	return !!(addr[0] | addr[1] | addr[2] | addr[3]);
}

static int set_ipv6(struct sk_buff *skb, struct sw_flow_key *flow_key,
		    const struct ovs_key_ipv6 *key,
		    const struct ovs_key_ipv6 *mask)
{
	struct ipv6hdr *nh;
	int err;

	err = skb_ensure_writable(skb, skb_network_offset(skb) +
				  sizeof(struct ipv6hdr));
	if (unlikely(err))
		return err;

	nh = ipv6_hdr(skb);

	/* Setting an IP addresses is typically only a side effect of
	 * matching on them in the current userspace implementation, so it
	 * makes sense to check if the value actually changed.
	 */
	if (is_ipv6_mask_nonzero(mask->ipv6_src)) {
		__be32 *saddr = (__be32 *)&nh->saddr;
		__be32 masked[4];

		mask_ipv6_addr(saddr, key->ipv6_src, mask->ipv6_src, masked);

		if (unlikely(memcmp(saddr, masked, sizeof(masked)))) {
			set_ipv6_addr(skb, key->ipv6_proto, saddr, masked,
				      true);
			memcpy(&flow_key->ipv6.addr.src, masked,
			       sizeof(flow_key->ipv6.addr.src));
		}
	}
	if (is_ipv6_mask_nonzero(mask->ipv6_dst)) {
		unsigned int offset = 0;
		int flags = IP6_FH_F_SKIP_RH;
		bool recalc_csum = true;
		__be32 *daddr = (__be32 *)&nh->daddr;
		__be32 masked[4];

		mask_ipv6_addr(daddr, key->ipv6_dst, mask->ipv6_dst, masked);

		if (unlikely(memcmp(daddr, masked, sizeof(masked)))) {
			if (ipv6_ext_hdr(nh->nexthdr))
				recalc_csum = (ipv6_find_hdr(skb, &offset,
							     NEXTHDR_ROUTING,
							     NULL, &flags)
					       != NEXTHDR_ROUTING);

			set_ipv6_addr(skb, key->ipv6_proto, daddr, masked,
				      recalc_csum);
			memcpy(&flow_key->ipv6.addr.dst, masked,
			       sizeof(flow_key->ipv6.addr.dst));
		}
	}
	if (mask->ipv6_tclass) {
		ipv6_change_dsfield(nh, ~mask->ipv6_tclass, key->ipv6_tclass);
		flow_key->ip.tos = ipv6_get_dsfield(nh);
	}
	if (mask->ipv6_label) {
		set_ipv6_fl(nh, ntohl(key->ipv6_label),
			    ntohl(mask->ipv6_label));
		flow_key->ipv6.label =
		    *(__be32 *)nh & htonl(IPV6_FLOWINFO_FLOWLABEL);
	}
	if (mask->ipv6_hlimit) {
		OVS_SET_MASKED(nh->hop_limit, key->ipv6_hlimit,
			       mask->ipv6_hlimit);
		flow_key->ip.ttl = nh->hop_limit;
	}
	return 0;
}

/* Must follow skb_ensure_writable() since that can move the skb data. */
static void set_tp_port(struct sk_buff *skb, __be16 *port,
			__be16 new_port, __sum16 *check)
{
	inet_proto_csum_replace2(check, skb, *port, new_port, 0);
	*port = new_port;
}

static int set_udp(struct sk_buff *skb, struct sw_flow_key *flow_key,
		   const struct ovs_key_udp *key,
		   const struct ovs_key_udp *mask)
{
	struct udphdr *uh;
	__be16 src, dst;
	int err;

	err = skb_ensure_writable(skb, skb_transport_offset(skb) +
				  sizeof(struct udphdr));
	if (unlikely(err))
		return err;

	uh = udp_hdr(skb);
	/* Either of the masks is non-zero, so do not bother checking them. */
	src = OVS_MASKED(uh->source, key->udp_src, mask->udp_src);
	dst = OVS_MASKED(uh->dest, key->udp_dst, mask->udp_dst);

	if (uh->check && skb->ip_summed != CHECKSUM_PARTIAL) {
		if (likely(src != uh->source)) {
			set_tp_port(skb, &uh->source, src, &uh->check);
			flow_key->tp.src = src;
		}
		if (likely(dst != uh->dest)) {
			set_tp_port(skb, &uh->dest, dst, &uh->check);
			flow_key->tp.dst = dst;
		}

		if (unlikely(!uh->check))
			uh->check = CSUM_MANGLED_0;
	} else {
		uh->source = src;
		uh->dest = dst;
		flow_key->tp.src = src;
		flow_key->tp.dst = dst;
	}

	skb_clear_hash(skb);

	return 0;
}

static int set_tcp(struct sk_buff *skb, struct sw_flow_key *flow_key,
		   const struct ovs_key_tcp *key,
		   const struct ovs_key_tcp *mask)
{
	struct tcphdr *th;
	__be16 src, dst;
	int err;

	err = skb_ensure_writable(skb, skb_transport_offset(skb) +
				  sizeof(struct tcphdr));
	if (unlikely(err))
		return err;

	th = tcp_hdr(skb);
	src = OVS_MASKED(th->source, key->tcp_src, mask->tcp_src);
	if (likely(src != th->source)) {
		set_tp_port(skb, &th->source, src, &th->check);
		flow_key->tp.src = src;
	}
	dst = OVS_MASKED(th->dest, key->tcp_dst, mask->tcp_dst);
	if (likely(dst != th->dest)) {
		set_tp_port(skb, &th->dest, dst, &th->check);
		flow_key->tp.dst = dst;
	}
	skb_clear_hash(skb);

	return 0;
}

static int set_sctp(struct sk_buff *skb, struct sw_flow_key *flow_key,
		    const struct ovs_key_sctp *key,
		    const struct ovs_key_sctp *mask)
{
	unsigned int sctphoff = skb_transport_offset(skb);
	struct sctphdr *sh;
	__le32 old_correct_csum, new_csum, old_csum;
	int err;

	err = skb_ensure_writable(skb, sctphoff + sizeof(struct sctphdr));
	if (unlikely(err))
		return err;

	sh = sctp_hdr(skb);
	old_csum = sh->checksum;
	old_correct_csum = sctp_compute_cksum(skb, sctphoff);

	sh->source = OVS_MASKED(sh->source, key->sctp_src, mask->sctp_src);
	sh->dest = OVS_MASKED(sh->dest, key->sctp_dst, mask->sctp_dst);

	new_csum = sctp_compute_cksum(skb, sctphoff);

	/* Carry any checksum errors through. */
	sh->checksum = old_csum ^ old_correct_csum ^ new_csum;

	skb_clear_hash(skb);
	flow_key->tp.src = sh->source;
	flow_key->tp.dst = sh->dest;

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
static int ovs_vport_output(OVS_VPORT_OUTPUT_PARAMS)
{
	struct ovs_frag_data *data = get_pcpu_ptr(ovs_frag_data_storage);
	struct vport *vport = data->vport;

	if (skb_cow_head(skb, data->l2_len) < 0) {
		kfree_skb(skb);
		return -ENOMEM;
	}

	__skb_dst_copy(skb, data->dst);
	*OVS_GSO_CB(skb) = data->cb;
	ovs_skb_set_inner_protocol(skb, data->inner_protocol);
	skb->vlan_tci = data->vlan_tci;
	skb->vlan_proto = data->vlan_proto;

	/* Reconstruct the MAC header.  */
	skb_push(skb, data->l2_len);
	memcpy(skb->data, &data->l2_data, data->l2_len);
	ovs_skb_postpush_rcsum(skb, skb->data, data->l2_len);
	skb_reset_mac_header(skb);

	ovs_vport_send(vport, skb);
	return 0;
}

static unsigned int
ovs_dst_get_mtu(const struct dst_entry *dst)
{
	return dst->dev->mtu;
}

static struct dst_ops ovs_dst_ops = {
	.family = AF_UNSPEC,
	.mtu = ovs_dst_get_mtu,
};

/* prepare_frag() is called once per (larger-than-MTU) frame; its inverse is
 * ovs_vport_output(), which is called once per fragmented packet.
 */
static void prepare_frag(struct vport *vport, struct sk_buff *skb)
{
	unsigned int hlen = skb_network_offset(skb);
	struct ovs_frag_data *data;

	data = get_pcpu_ptr(ovs_frag_data_storage);
	data->dst = (unsigned long) skb_dst(skb);
	data->vport = vport;
	data->cb = *OVS_GSO_CB(skb);
	data->inner_protocol = ovs_skb_get_inner_protocol(skb);
	data->vlan_tci = skb->vlan_tci;
	data->vlan_proto = skb->vlan_proto;
	data->l2_len = hlen;
	memcpy(&data->l2_data, skb->data, hlen);

	memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));
	skb_pull(skb, hlen);
}

static void ovs_fragment(struct vport *vport, struct sk_buff *skb, u16 mru,
			 __be16 ethertype)
{
	if (skb_network_offset(skb) > MAX_L2_LEN) {
		OVS_NLERR(1, "L2 header too long to fragment");
		goto err;
	}

	if (ethertype == htons(ETH_P_IP)) {
		struct dst_entry ovs_dst;
		unsigned long orig_dst;

		prepare_frag(vport, skb);
		dst_init(&ovs_dst, &ovs_dst_ops, NULL, 1,
			 DST_OBSOLETE_NONE, DST_NOCOUNT);
		ovs_dst.dev = vport->dev;

		orig_dst = (unsigned long) skb_dst(skb);
		skb_dst_set_noref(skb, &ovs_dst);
		IPCB(skb)->frag_max_size = mru;

		ip_do_fragment(skb->sk, skb, ovs_vport_output);
		refdst_drop(orig_dst);
	} else if (ethertype == htons(ETH_P_IPV6)) {
		const struct nf_ipv6_ops *v6ops = nf_get_ipv6_ops();
		unsigned long orig_dst;
		struct rt6_info ovs_rt;

		if (!v6ops) {
			goto err;
		}

		prepare_frag(vport, skb);
		memset(&ovs_rt, 0, sizeof(ovs_rt));
		dst_init(&ovs_rt.dst, &ovs_dst_ops, NULL, 1,
			 DST_OBSOLETE_NONE, DST_NOCOUNT);
		ovs_rt.dst.dev = vport->dev;

		orig_dst = (unsigned long) skb_dst(skb);
		skb_dst_set_noref(skb, &ovs_rt.dst);
		IP6CB(skb)->frag_max_size = mru;

		v6ops->fragment(skb->sk, skb, ovs_vport_output);
		refdst_drop(orig_dst);
	} else {
		WARN_ONCE(1, "Failed fragment ->%s: eth=%04x, MRU=%d, MTU=%d.",
			  ovs_vport_name(vport), ntohs(ethertype), mru,
			  vport->dev->mtu);
		goto err;
	}

	return;
err:
	kfree_skb(skb);
}
#else /* < 3.10 */
static void ovs_fragment(struct vport *vport, struct sk_buff *skb, u16 mru,
			 __be16 ethertype)
{
	WARN_ONCE(1, "Fragment unavailable ->%s: eth=%04x, MRU=%d, MTU=%d.",
		  ovs_vport_name(vport), ntohs(ethertype), mru,
		  vport->dev->mtu);
	kfree_skb(skb);
}
#endif

/* ARP handler of an ARP task extracted from the global workqueue,
 * executed by one of the NR_CPUS 'events/X' (X is the CPU core ID) worker threads.
 */
/*static void arp_work_handler(struct work_struct *work_todo)
{
	struct arp_defere_work *arp_work = container_of(work_todo, struct arp_defere_work, work);

	rcu_read_lock_bh();
		neigh_event_send(arp_work->nbr, arp_work->skb);		// send an ARP request
	rcu_read_unlock_bh();
}*/

/* Initialize an ARP translation task, enqueue it in the global workqueue,
 * and mark it as ready for being scheduled.
 * The task handler is 'arp_work_handler()'.
 */
/*static void enqueue_arp_task(struct arp_defere_work *arp_work, struct neighbour *nbr, struct sk_buff *skb)
{
	struct sk_buff *pkt_copy;
	struct dst_entry *dst;

	dst = skb_dst(skb);
	if (dst->pending_confirm)
	{
		unsigned long now = jiffies;
		dst->pending_confirm = 0;
		if (nbr->confirmed != now)
			nbr->confirmed = now;
	}

	pkt_copy = skb_copy(skb, GFP_ATOMIC);				// copy the original 'skb' as it's transmitted right away
	if (unlikely(!pkt_copy))
		return;

	INIT_WORK(&(arp_work->work), arp_work_handler);		// initialize the work, assigning it the function handler to be executed, and ..
	arp_work->nbr = nbr;								// the data to work on ..
	arp_work->skb = pkt_copy;							// ...
	schedule_work(&(arp_work->work));					// put the arp processing task in the global workqueue
}*/

/* Given the IPv4 dst address of the packet (skb), find out its associated MAC address,
 * which based on the IP routing lookup, it either could be of the dst host itself (on the LAN),
 * or of the gateway host (the dst host is on a different network).
 * Finally, populate the packet's (skb) Ethernet header.
 *
 * +------------------------------------------------------------------------------------+
 * | In case of using 'enqueue_arp_task()' (asynchronous ARP discovery):				|
 * |	The 'skb' packet that triggered the ARP request, is transmitted right away,		|
 * |	regardless of the ARP translation outcome.										|
 * |	So, per each ARP cache-miss, the original packet is copied and forwarded		|
 * |	with a broadcast MAC address, while its copy is used for the ARP translation.	|
 * |	On ARP cache-hit, the original packet is sent (without being copied)			|
 * |	with the corresponding MAC address.												|
 * +------------------------------------------------------------------------------------+
 *
 * Return value: '0' in case of success, error otherwise.
 */
static int fill_ethdr(struct sk_buff *skb, const struct vport *vport)
{
	const int error = -1;
	const __be32 ipv4_dst = ip_hdr(skb)->daddr;
	struct ethhdr *ethdr;
	struct rtable *rtbl;
	struct neighbour *nbr;
	struct dst_entry *dst;
	//struct arp_defere_work arp_work;
	__be32 nexthop_ip;
	bool arp_cache_miss;
	uint8_t broadcast_mac[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	arp_cache_miss = false;

	rtbl = ip_route_output(dev_net(vport->dev), ipv4_dst, 0, 0, 0);		// routing lookup
	if (IS_ERR(rtbl))
		return error;
	dst = &(rtbl->dst);
	skb->dev = dst->dev;		// net_device used to reach the neighbour
	nexthop_ip = rtbl->rt_uses_gateway ? rtbl->rt_gateway : ipv4_dst;	// set the correct next-hop IP depending on the lookup

	/* set the corresponding 'dst_entry' for this 'skb' */
	if (dst->flags & DST_NOCACHE)
	{
		if (likely(atomic_inc_not_zero(&(dst->__refcnt))))
			skb_dst_set(skb, dst);
	}
	else
		skb_dst_set_noref(skb, dst);

	nbr = __ipv4_neigh_lookup_noref(dst->dev, nexthop_ip);		// ARP cache lookup
	if (unlikely(!nbr))															// ARP cache-miss
	{
		arp_cache_miss = true;
		nbr = __neigh_create(&arp_tbl, &(nexthop_ip), dst->dev, false);			// create ARP entry
		if (IS_ERR(nbr))
			return error;

		if (dst->pending_confirm)
		{
			unsigned long now = jiffies;
			dst->pending_confirm = 0;
			if (nbr->confirmed != now)
				nbr->confirmed = now;
		}
		/* send ARP request to solve the MAC address associated with 'nexthop_ip' IPv4 address */
		//enqueue_arp_task(&(arp_work), nbr, skb);
		nbr->nud_state = NUD_INCOMPLETE;				// first ARP discovery for this neighbour
		arp_send(ARPOP_REQUEST, ETH_P_ARP, nexthop_ip, dst->dev,
			ip_hdr(skb)->saddr, NULL, dst->dev->dev_addr, NULL);
	}
	//else ARP cache-hit

	ethdr = eth_hdr(skb);
	ethdr->h_proto = htons(ETH_P_IP);		// follows IPv4
	memcpy(ethdr->h_source, vport->dev->dev_addr, ETH_ALEN);

	if (nbr->nud_state & NUD_VALID)
	{
		memcpy(ethdr->h_dest, nbr->ha, ETH_ALEN);
	}
	else
	{
		memcpy(ethdr->h_dest, broadcast_mac, ETH_ALEN);
		if (likely(!arp_cache_miss))			// a hit in the ARP cache is likelier than a miss
		{
			if (dst->pending_confirm)
			{
				unsigned long now = jiffies;
				dst->pending_confirm = 0;
				if (nbr->confirmed != now)
					nbr->confirmed = now;
			}
			/* send ARP request to confirm the cached MAC address associated with 'nexthop_ip' IPv4 address */
			//enqueue_arp_task(&(arp_work), nbr, skb);
			nbr->nud_state = NUD_PROBE;				// prepare for explicit ARP
			arp_send(ARPOP_REQUEST, ETH_P_ARP, nexthop_ip, dst->dev,
				ip_hdr(skb)->saddr, NULL, dst->dev->dev_addr, NULL);
		}
	}

	return 0;		/* SUCCESS, we did it! */
}

static void do_output(struct datapath *dp, struct sk_buff *skb, int out_port, struct sw_flow_key *key)
{
	struct vport *vport = ovs_vport_rcu(dp, out_port);
	struct ethhdr *ethdr = eth_hdr(skb);

	if (likely(vport))
	{
		u16 mru = OVS_CB(skb)->mru;

		if (likely(!mru || (skb->len <= mru + ETH_HLEN)))
		{
			if (/*IF_GTP_FLOW(*key)*/ethdr->h_proto == 0 && ETH_ADDR_IS_ZERO(ethdr->h_source) && ETH_ADDR_IS_ZERO(ethdr->h_dest))
			{
				if (fill_ethdr(skb, vport) != 0)
					return kfree_skb(skb);
			}

			ovs_vport_send(vport, skb);
		}
		else if (!IF_GTP_FLOW(*key))
		{
			if (mru <= vport->dev->mtu)
			{
				__be16 ethertype = key->eth.type;

				if (!is_flow_key_valid(key))
				{
					if (eth_p_mpls(skb->protocol))
						ethertype = ovs_skb_get_inner_protocol(skb);
					else
						ethertype = vlan_get_protocol(skb);
				}
				ovs_fragment(vport, skb, mru, ethertype);
			}
			else
			{
				OVS_NLERR(true, "Cannot fragment IP frames");
				kfree_skb(skb);
			}
		}
	}
	else
		kfree_skb(skb);
}
static int output_userspace(struct datapath *dp, struct sk_buff *skb,
			    struct sw_flow_key *key, const struct nlattr *attr,
			    const struct nlattr *actions, int actions_len)
{
	struct ip_tunnel_info info;
	struct dp_upcall_info upcall;
	const struct nlattr *a;
	int rem;

	memset(&upcall, 0, sizeof(upcall));
	upcall.cmd = OVS_PACKET_CMD_ACTION;
	upcall.mru = OVS_CB(skb)->mru;

	for (a = nla_data(attr), rem = nla_len(attr); rem > 0;
		 a = nla_next(a, &rem)) {
		switch (nla_type(a)) {
		case OVS_USERSPACE_ATTR_USERDATA:
			upcall.userdata = a;
			break;

		case OVS_USERSPACE_ATTR_PID:
			upcall.portid = nla_get_u32(a);
			break;

		case OVS_USERSPACE_ATTR_EGRESS_TUN_PORT: {
			/* Get out tunnel info. */
			struct vport *vport;

			vport = ovs_vport_rcu(dp, nla_get_u32(a));
			if (vport) {
				int err;

				upcall.egress_tun_info = &info;
				err = ovs_vport_get_egress_tun_info(vport, skb,
								    &upcall);
				if (err)
					upcall.egress_tun_info = NULL;
			}

			break;
		}

		case OVS_USERSPACE_ATTR_ACTIONS: {
			/* Include actions. */
			upcall.actions = actions;
			upcall.actions_len = actions_len;
			break;
		}

		} /* End of switch. */
	}

	return ovs_dp_upcall(dp, skb, key, &upcall);
}

static int sample(struct datapath *dp, struct sk_buff *skb,
		  struct sw_flow_key *key, const struct nlattr *attr,
		  const struct nlattr *actions, int actions_len)
{
	const struct nlattr *acts_list = NULL;
	const struct nlattr *a;
	int rem;

	for (a = nla_data(attr), rem = nla_len(attr); rem > 0;
		 a = nla_next(a, &rem)) {
		u32 probability;

		switch (nla_type(a)) {
		case OVS_SAMPLE_ATTR_PROBABILITY:
			probability = nla_get_u32(a);
			if (!probability || prandom_u32() > probability)
				return 0;
			break;

		case OVS_SAMPLE_ATTR_ACTIONS:
			acts_list = a;
			break;
		}
	}

	rem = nla_len(acts_list);
	a = nla_data(acts_list);

	/* Actions list is empty, do nothing */
	if (unlikely(!rem))
		return 0;

	/* The only known usage of sample action is having a single user-space
	 * action. Treat this usage as a special case.
	 * The output_userspace() should clone the skb to be sent to the
	 * user space. This skb will be consumed by its caller.
	 */
	if (likely(nla_type(a) == OVS_ACTION_ATTR_USERSPACE &&
		   nla_is_last(a, rem)))
		return output_userspace(dp, skb, key, a, actions, actions_len);

	skb = skb_clone(skb, GFP_ATOMIC);
	if (!skb)
		/* Skip the sample action when out of memory. */
		return 0;

	if (!add_deferred_actions(skb, key, a)) {
		if (net_ratelimit())
			pr_warn("%s: deferred actions limit reached, dropping sample action\n",
				ovs_dp_name(dp));

		kfree_skb(skb);
	}
	return 0;
}

static void execute_hash(struct sk_buff *skb, struct sw_flow_key *key,
			 const struct nlattr *attr)
{
	struct ovs_action_hash *hash_act = nla_data(attr);
	u32 hash = 0;

	/* OVS_HASH_ALG_L4 is the only possible hash algorithm.  */
	hash = skb_get_hash(skb);
	hash = jhash_1word(hash, hash_act->hash_basis);
	if (!hash)
		hash = 0x1;

	key->ovs_flow_hash = hash;
}

static int execute_set_action(struct sk_buff *skb,
			      struct sw_flow_key *flow_key,
			      const struct nlattr *a)
{
	/* Only tunnel set execution is supported without a mask. */
	if (nla_type(a) == OVS_KEY_ATTR_TUNNEL_INFO) {
		struct ovs_tunnel_info *tun = nla_data(a);

		ovs_skb_dst_drop(skb);
		ovs_dst_hold((struct dst_entry *)tun->tun_dst);
		ovs_skb_dst_set(skb, (struct dst_entry *)tun->tun_dst);
		return 0;
	}

	return -EINVAL;
}

/* Mask is at the midpoint of the data. */
#define get_mask(a, type) ((const type)nla_data(a) + 1)

static int execute_masked_set_action(struct sk_buff *skb,
				     struct sw_flow_key *flow_key,
				     const struct nlattr *a)
{
	int err = 0;

	switch (nla_type(a)) {
	case OVS_KEY_ATTR_PRIORITY:
		OVS_SET_MASKED(skb->priority, nla_get_u32(a),
			       *get_mask(a, u32 *));
		flow_key->phy.priority = skb->priority;
		break;

	case OVS_KEY_ATTR_SKB_MARK:
		OVS_SET_MASKED(skb->mark, nla_get_u32(a), *get_mask(a, u32 *));
		flow_key->phy.skb_mark = skb->mark;
		break;

	case OVS_KEY_ATTR_TUNNEL_INFO:
		/* Masked data not supported for tunnel. */
		err = -EINVAL;
		break;

	case OVS_KEY_ATTR_ETHERNET:
		err = set_eth_addr(skb, flow_key, nla_data(a),
				   get_mask(a, struct ovs_key_ethernet *));
		break;

	case OVS_KEY_ATTR_IPV4:
		err = set_ipv4(skb, flow_key, nla_data(a),
			       get_mask(a, struct ovs_key_ipv4 *));
		break;

	case OVS_KEY_ATTR_IPV6:
		err = set_ipv6(skb, flow_key, nla_data(a),
			       get_mask(a, struct ovs_key_ipv6 *));
		break;

	case OVS_KEY_ATTR_TCP:
		err = set_tcp(skb, flow_key, nla_data(a),
			      get_mask(a, struct ovs_key_tcp *));
		break;

	case OVS_KEY_ATTR_UDP:
		err = set_udp(skb, flow_key, nla_data(a),
			      get_mask(a, struct ovs_key_udp *));
		break;

	case OVS_KEY_ATTR_SCTP:
		err = set_sctp(skb, flow_key, nla_data(a),
			       get_mask(a, struct ovs_key_sctp *));
		break;

	case OVS_KEY_ATTR_MPLS:
		err = set_mpls(skb, flow_key, nla_data(a), get_mask(a,
								    __be32 *));
		break;

	case OVS_KEY_ATTR_CT_STATE:
	case OVS_KEY_ATTR_CT_ZONE:
	case OVS_KEY_ATTR_CT_MARK:
	case OVS_KEY_ATTR_CT_LABELS:
		err = -EINVAL;
		break;
	}

	return err;
}

static int execute_recirc(struct datapath *dp, struct sk_buff *skb,
			  struct sw_flow_key *key,
			  const struct nlattr *a, int rem)
{
	struct deferred_action *da;

	if (!is_flow_key_valid(key)) {
		int err;

		err = ovs_flow_key_update(skb, key);
		if (err)
			return err;
	}
	BUG_ON(!is_flow_key_valid(key));

	if (!nla_is_last(a, rem)) {
		/* Recirc action is the not the last action
		 * of the action list, need to clone the skb.
		 */
		skb = skb_clone(skb, GFP_ATOMIC);

		/* Skip the recirc action when out of memory, but
		 * continue on with the rest of the action list.
		 */
		if (!skb)
			return 0;
	}

	da = add_deferred_actions(skb, key, NULL);
	if (da) {
		da->pkt_key.recirc_id = nla_get_u32(a);
	} else {
		kfree_skb(skb);

		if (net_ratelimit())
			pr_warn("%s: deferred action limit reached, drop recirc action\n",
				ovs_dp_name(dp));
	}

	return 0;
}

/* Execute a list of actions against 'skb'. */
static int do_execute_actions(struct datapath *dp, struct sk_buff *skb,
							  struct sw_flow_key *key, const struct nlattr *attr,
							  int len)
{
	/* Every output action needs a separate clone of 'skb', but the common
	 * case is just a single output action, so that doing a clone and
	 * then freeing the original skbuff is wasteful.  So the following code
	 * is slightly obscure just to avoid that.
	 */
	int prev_port = -1;
	const struct nlattr *a;
	int rem;

	// iterate over all the netlink attributes actions in the sequence
	for (a = attr, rem = len; rem > 0; a = nla_next(a, &rem))
	{
		int err = 0;

		if (unlikely(prev_port != -1)) {
			struct sk_buff *out_skb = skb_clone(skb, GFP_ATOMIC);

			if (out_skb)
				do_output(dp, out_skb, prev_port, key);

			prev_port = -1;
		}

		switch (nla_type(a)) {
		case OVS_ACTION_ATTR_OUTPUT:
			prev_port = nla_get_u32(a);
			break;

		case OVS_ACTION_ATTR_USERSPACE:
			output_userspace(dp, skb, key, a, attr, len);
			break;

		case OVS_ACTION_ATTR_HASH:
			execute_hash(skb, key, a);
			break;

		case OVS_ACTION_ATTR_PUSH_MPLS:
			err = push_mpls(skb, key, nla_data(a));
			break;

		case OVS_ACTION_ATTR_POP_MPLS:
			err = pop_mpls(skb, key, nla_get_be16(a));
			break;

		case OVS_ACTION_ATTR_PUSH_GTPV1:
			err = push_gtpv1(skb, key, nla_data(a));
		break;

		case OVS_ACTION_ATTR_POP_GTPV1:
			err = pop_gtpv1(skb, key);
		break;

		case OVS_ACTION_ATTR_PUSH_VLAN:
			err = push_vlan(skb, key, nla_data(a));
			break;

		case OVS_ACTION_ATTR_POP_VLAN:
			err = pop_vlan(skb, key);
			break;

		case OVS_ACTION_ATTR_RECIRC:
			err = execute_recirc(dp, skb, key, a, rem);
			if (nla_is_last(a, rem)) {
				/* If this is the last action, the skb has
				 * been consumed or freed.
				 * Return immediately.
				 */
				return err;
			}
			break;

		case OVS_ACTION_ATTR_SET:
			err = execute_set_action(skb, key, nla_data(a));
			break;

		case OVS_ACTION_ATTR_SET_MASKED:
		case OVS_ACTION_ATTR_SET_TO_MASKED:
			err = execute_masked_set_action(skb, key, nla_data(a));
			break;

		case OVS_ACTION_ATTR_SAMPLE:
			err = sample(dp, skb, key, a, attr, len);
			break;

		case OVS_ACTION_ATTR_CT:
			if (!is_flow_key_valid(key)) {
				err = ovs_flow_key_update(skb, key);
				if (err)
					return err;
			}

			err = ovs_ct_execute(ovs_dp_get_net(dp), skb, key,
					     nla_data(a));

			/* Hide stolen IP fragments from user space. */
			if (err)
				return err == -EINPROGRESS ? 0 : err;
			break;
		}

		if (unlikely(err)) {
			kfree_skb(skb);
			return err;
		}
	}

	if (prev_port != -1)
		do_output(dp, skb, prev_port, key);
	else
		consume_skb(skb);

	return 0;
}

static void process_deferred_actions(struct datapath *dp)
{
	struct action_fifo *fifo = this_cpu_ptr(action_fifos);
	bool is_gtp;

	/* Do not touch the FIFO in case there is no deferred actions. */
	if (action_fifo_is_empty(fifo))
		return;

	/* Finishing executing all deferred actions. */
	do {
		is_gtp = false;
		struct deferred_action *da = action_fifo_get(fifo);
		struct sk_buff *skb = da->skb;
		struct sw_flow_key *key = &da->pkt_key;
		const struct nlattr *actions = da->actions;

		if (actions)
			do_execute_actions(dp, skb, key, actions,
					   nla_len(actions));
		else
			ovs_dp_process_packet(skb, key);
	} while (!action_fifo_is_empty(fifo));

	/* Reset FIFO for the next packet.  */
	action_fifo_init(fifo);
}

/* Execute a list of actions against 'skb'. */
int ovs_execute_actions(struct datapath *dp, struct sk_buff *skb,
			const struct sw_flow_actions *acts,
			struct sw_flow_key *key)
{
	int level = this_cpu_read(exec_actions_level);
	int err;

	if (unlikely(level >= EXEC_ACTIONS_LEVEL_LIMIT)) {
		if (net_ratelimit())
			pr_warn("%s: packet loop detected, dropping.\n",
				ovs_dp_name(dp));

		kfree_skb(skb);
		return -ELOOP;
	}

	this_cpu_inc(exec_actions_level);
	err = do_execute_actions(dp, skb, key,
				 acts->actions, acts->actions_len);

	if (!level)
		process_deferred_actions(dp);

	this_cpu_dec(exec_actions_level);

	/* This return status currently does not reflect the errors
	 * encounted during deferred actions execution. Probably needs to
	 * be fixed in the future.
	 */
	return err;
}

int action_fifos_init(void)
{
	action_fifos = alloc_percpu(struct action_fifo);
	if (!action_fifos)
		return -ENOMEM;

	return 0;
}

void action_fifos_exit(void)
{
	free_percpu(action_fifos);
}
