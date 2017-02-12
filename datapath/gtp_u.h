#ifndef GTPU_H
#define GTPU_H

#include <linux/kernel.h>
#include <linux/openvswitch.h>
#include <linux/types.h>
#include "../lib/openvswitch_gtpu.h"

#define GTPU_HLEN_PLAIN 8			// plain(without extensions) GTPv1 header length is 8 bytes long
#define IPV4_HLEN_PLAIN 20			// plain(without 'Options' field) IPv4 header length is 20 bytes long
#define ETH_HLEN_ALIGNED 16			// ETH_HLEN(14) + 2 bytes of padding
#define UDP_HLEN 8					// udp header length is 8 bytes long
#define SCTP_HLEN 12				// sctp header length is 12 bytes long
#define ICMP_HLEN 8					// icmp header length is 8 bytes long
#define GTPv1_PORT 2152				// the 2152 UDP port specifies the GTP-U (GTPv1) multiplexing
/* GTPv1 message type for G-PDU. G-PDU is a vanilla user plane message, which carries 
 * the original packet (T-PDU). In G-PDU message, GTP-U header is followed by a T-PDU.
 */
#define GTP_MSG_TYPE_GPDU 0xff
#define GTPv1_HDR(skb) ((struct gtpv1hdr*)(skb_transport_header(skb) + UDP_HLEN))		// get a pointer to the GTPv1 header
#define GTPv1_PAYLOAD(skb) gtpv1_pload_ptr_get(GTPv1_HDR(skb))	// get a pointer to the GTPv1 payload

struct gtpv1hdr_ext
{
	uint8_t len;          /* Length of the extension in 4-octet units */
	uint8_t content[];    /* Content of the extension */
} __attribute__((__packed__));

struct gtpv1hdr
{
	/* Mandatory fields */
	uint8_t	pnf			: 1,		/* PN - N-PDU number flag */
			snf			: 1,		/* S - Sequence number flag */
			ehf			: 1,		/* E - Extension header flag */
			reserved	: 1,
			ptype		: 1,		/* Protocol type */
			version		: 3;
	uint8_t type;					/* Message type */
	uint16_t tot_len;				/* Total len, payload + optional hdr fields */
	uint32_t teid;					// Tunnel ID

	/* Optional fields */
	uint16_t    seq_num;     /* Present if [E,S or PN] are set, valid if S */
	uint16_t    npdu;        /* Present if [E,S or PN] are set, valid if PN */
	uint8_t     nee;         /* Present if [E,S or PN] are set, valid if E */
	struct gtpv1hdr_ext ext[];
} __attribute__((__packed__));

__always_inline static int gtpv1_ext_has_ext(struct gtpv1hdr_ext *ext)
{
	if (!ext || !ext->len)
		return 0;

	return (!!ext->content[(ext->len * 4) - 1]);
}

__always_inline static uint16_t gtpv1_pload_offt(struct gtpv1hdr *gtp)
{
	struct gtpv1hdr_ext *ext = NULL;
	uint16_t offt = 0;
	int i = 0;

	if (unlikely(!gtp))
		return 0;

	if (unlikely(!gtp->tot_len))
		return 0;

	offt += 8; /* Mandatory fields */

	if (gtp->pnf || gtp->snf || gtp->ehf)
	{
		offt += 4;

		if (gtp->ehf && gtp->nee)
		{
			ext = gtp->ext;

			do
			{
				offt += (ext->len * 4);
				ext += offt;
			} while (gtpv1_ext_has_ext(ext) && (i++ < 10)); /* Safe exit */
		}
	}

	return offt;
}

__always_inline static uint8_t *gtpv1_pload_ptr_get(struct gtpv1hdr *gtp)
{
	if (unlikely(!gtp))
		return NULL;

	return (((uint8_t *)gtp) + gtpv1_pload_offt(gtp));
}

#endif /* gtp_u.h */