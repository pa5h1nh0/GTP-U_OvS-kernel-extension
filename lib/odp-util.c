/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include <arpa/inet.h>
#include "odp-util.h"
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <stdlib.h>
#include <string.h>

#include "byte-order.h"
#include "coverage.h"
#include "dpif.h"
#include "dynamic-string.h"
#include "flow.h"
#include "netlink.h"
#include "ofpbuf.h"
#include "packets.h"
#include "simap.h"
#include "timeval.h"
#include "tun-metadata.h"
#include "unaligned.h"
#include "util.h"
#include "uuid.h"
#include "openvswitch/vlog.h"
#include "openvswitch_gtpu.h"			/* GTPv1 */

VLOG_DEFINE_THIS_MODULE(odp_util);

/* The interface between userspace and kernel uses an "OVS_*" prefix.
 * Since this is fairly non-specific for the OVS userspace components,
 * "ODP_*" (Open vSwitch Datapath) is used as the prefix for
 * interactions with the datapath.
 */

/* The set of characters that may separate one action or one key attribute
 * from another. */
static const char *delimiters = ", \t\r\n";
static const char *delimiters_end = ", \t\r\n)";

struct attr_len_tbl {
    int len;
    const struct attr_len_tbl *next;
    int next_max;
};
#define ATTR_LEN_INVALID  -1
#define ATTR_LEN_VARIABLE -2
#define ATTR_LEN_NESTED   -3

static int parse_odp_key_mask_attr(const char *, const struct simap *port_names,
                              struct ofpbuf *, struct ofpbuf *);
static void format_odp_key_attr(const struct nlattr *a,
                                const struct nlattr *ma,
                                const struct hmap *portno_names, struct ds *ds,
                                bool verbose);

struct geneve_scan {
    struct geneve_opt d[63];
    int len;
};

static int scan_geneve(const char *s, struct geneve_scan *key,
                       struct geneve_scan *mask);
static void format_geneve_opts(const struct geneve_opt *opt,
                               const struct geneve_opt *mask, int opts_len,
                               struct ds *, bool verbose);

static struct nlattr *generate_all_wildcard_mask(const struct attr_len_tbl tbl[],
                                                 int max, struct ofpbuf *,
                                                 const struct nlattr *key);
static void format_u128(struct ds *ds, const ovs_u128 *value,
                        const ovs_u128 *mask, bool verbose);
static int scan_u128(const char *s, ovs_u128 *value, ovs_u128 *mask);

/* Returns one the following for the action with the given OVS_ACTION_ATTR_*
 * 'type':
 *
 *   - For an action whose argument has a fixed length, returned that
 *     nonnegative length in bytes.
 *
 *   - For an action with a variable-length argument, returns ATTR_LEN_VARIABLE.
 *
 *   - For an invalid 'type', returns ATTR_LEN_INVALID. */
static int
odp_action_len(uint16_t type)
{
    if (type > OVS_ACTION_ATTR_GTPV1_MAX) {
        return -1;
    }

    switch (type) {
    case OVS_ACTION_ATTR_OUTPUT: return sizeof(uint32_t);
    case OVS_ACTION_ATTR_TUNNEL_PUSH: return ATTR_LEN_VARIABLE;
    case OVS_ACTION_ATTR_TUNNEL_POP: return sizeof(uint32_t);
    case OVS_ACTION_ATTR_USERSPACE: return ATTR_LEN_VARIABLE;
    case OVS_ACTION_ATTR_PUSH_VLAN: return sizeof(struct ovs_action_push_vlan);
    case OVS_ACTION_ATTR_POP_VLAN: return 0;
    case OVS_ACTION_ATTR_PUSH_MPLS: return sizeof(struct ovs_action_push_mpls);
    case OVS_ACTION_ATTR_POP_MPLS: return sizeof(ovs_be16);
    case OVS_ACTION_ATTR_RECIRC: return sizeof(uint32_t);
    case OVS_ACTION_ATTR_HASH: return sizeof(struct ovs_action_hash);
    case OVS_ACTION_ATTR_SET: return ATTR_LEN_VARIABLE;
    case OVS_ACTION_ATTR_SET_MASKED: return ATTR_LEN_VARIABLE;
    case OVS_ACTION_ATTR_SAMPLE: return ATTR_LEN_VARIABLE;
    case OVS_ACTION_ATTR_CT: return ATTR_LEN_VARIABLE;
	case OVS_ACTION_ATTR_PUSH_GTPV1: return sizeof(struct ovs_action_push_gtpv1);
	case OVS_ACTION_ATTR_POP_GTPV1: return 0;

    case OVS_ACTION_ATTR_UNSPEC:
    case __OVS_ACTION_ATTR_GTPV1_MAX:
        return ATTR_LEN_INVALID;
    }

    return ATTR_LEN_INVALID;
}

/* Returns a string form of 'attr'.  The return value is either a statically
 * allocated constant string or the 'bufsize'-byte buffer 'namebuf'.  'bufsize'
 * should be at least OVS_KEY_ATTR_BUFSIZE. */
enum { OVS_KEY_ATTR_BUFSIZE = 3 + INT_STRLEN(unsigned int) + 1 };
static const char *
ovs_key_attr_to_string(uint16_t attr, char *namebuf, size_t bufsize)
{
    switch (attr) {
    case OVS_KEY_ATTR_UNSPEC: return "unspec";
    case OVS_KEY_ATTR_ENCAP: return "encap";
    case OVS_KEY_ATTR_PRIORITY: return "skb_priority";
    case OVS_KEY_ATTR_SKB_MARK: return "skb_mark";
    case OVS_KEY_ATTR_CT_STATE: return "ct_state";
    case OVS_KEY_ATTR_CT_ZONE: return "ct_zone";
    case OVS_KEY_ATTR_CT_MARK: return "ct_mark";
    case OVS_KEY_ATTR_CT_LABELS: return "ct_label";
    case OVS_KEY_ATTR_TUNNEL: return "tunnel";
    case OVS_KEY_ATTR_IN_PORT: return "in_port";
    case OVS_KEY_ATTR_ETHERNET: return "eth";
    case OVS_KEY_ATTR_VLAN: return "vlan";
    case OVS_KEY_ATTR_ETHERTYPE: return "eth_type";
    case OVS_KEY_ATTR_IPV4: return "ipv4";
    case OVS_KEY_ATTR_IPV6: return "ipv6";
    case OVS_KEY_ATTR_TCP: return "tcp";
    case OVS_KEY_ATTR_TCP_FLAGS: return "tcp_flags";
    case OVS_KEY_ATTR_UDP: return "udp";
    case OVS_KEY_ATTR_SCTP: return "sctp";
    case OVS_KEY_ATTR_ICMP: return "icmp";
    case OVS_KEY_ATTR_ICMPV6: return "icmpv6";
    case OVS_KEY_ATTR_ARP: return "arp";
    case OVS_KEY_ATTR_ND: return "nd";
    case OVS_KEY_ATTR_MPLS: return "mpls";
    case OVS_KEY_ATTR_DP_HASH: return "dp_hash";
    case OVS_KEY_ATTR_RECIRC_ID: return "recirc_id";
	case OVS_KEY_ATTR_GTPV1: return "gtp";

    case __OVS_KEY_ATTR_GTPV1_MAX:
    default:
        snprintf(namebuf, bufsize, "key%u", (unsigned int) attr);
        return namebuf;
    }
}

static void
format_generic_odp_action(struct ds *ds, const struct nlattr *a)
{
    size_t len = nl_attr_get_size(a);

    ds_put_format(ds, "action%"PRId16, nl_attr_type(a));
    if (len) {
        const uint8_t *unspec;
        unsigned int i;

        unspec = nl_attr_get(a);
        for (i = 0; i < len; i++) {
            ds_put_char(ds, i ? ' ': '(');
            ds_put_format(ds, "%02x", unspec[i]);
        }
        ds_put_char(ds, ')');
    }
}

static void
format_odp_sample_action(struct ds *ds, const struct nlattr *attr)
{
    static const struct nl_policy ovs_sample_policy[] = {
        [OVS_SAMPLE_ATTR_PROBABILITY] = { .type = NL_A_U32 },
        [OVS_SAMPLE_ATTR_ACTIONS] = { .type = NL_A_NESTED }
    };
    struct nlattr *a[ARRAY_SIZE(ovs_sample_policy)];
    double percentage;
    const struct nlattr *nla_acts;
    int len;

    ds_put_cstr(ds, "sample");

    if (!nl_parse_nested(attr, ovs_sample_policy, a, ARRAY_SIZE(a))) {
        ds_put_cstr(ds, "(error)");
        return;
    }

    percentage = (100.0 * nl_attr_get_u32(a[OVS_SAMPLE_ATTR_PROBABILITY])) /
                        UINT32_MAX;

    ds_put_format(ds, "(sample=%.1f%%,", percentage);

    ds_put_cstr(ds, "actions(");
    nla_acts = nl_attr_get(a[OVS_SAMPLE_ATTR_ACTIONS]);
    len = nl_attr_get_size(a[OVS_SAMPLE_ATTR_ACTIONS]);
    format_odp_actions(ds, nla_acts, len);
    ds_put_format(ds, "))");
}

static const char *
slow_path_reason_to_string(uint32_t reason)
{
    switch ((enum slow_path_reason) reason) {
#define SPR(ENUM, STRING, EXPLANATION) case ENUM: return STRING;
        SLOW_PATH_REASONS
#undef SPR
    }

    return NULL;
}

const char *
slow_path_reason_to_explanation(enum slow_path_reason reason)
{
    switch (reason) {
#define SPR(ENUM, STRING, EXPLANATION) case ENUM: return EXPLANATION;
        SLOW_PATH_REASONS
#undef SPR
    }

    return "<unknown>";
}

static int
parse_odp_flags(const char *s, const char *(*bit_to_string)(uint32_t),
                uint32_t *res_flags, uint32_t allowed, uint32_t *res_mask)
{
    return parse_flags(s, bit_to_string, ')', NULL, NULL,
                       res_flags, allowed, res_mask);
}

static void
format_odp_userspace_action(struct ds *ds, const struct nlattr *attr)
{
    static const struct nl_policy ovs_userspace_policy[] = {
        [OVS_USERSPACE_ATTR_PID] = { .type = NL_A_U32 },
        [OVS_USERSPACE_ATTR_USERDATA] = { .type = NL_A_UNSPEC,
                                          .optional = true },
        [OVS_USERSPACE_ATTR_EGRESS_TUN_PORT] = { .type = NL_A_U32,
                                                 .optional = true },
        [OVS_USERSPACE_ATTR_ACTIONS] = { .type = NL_A_UNSPEC,
                                                 .optional = true },
    };
    struct nlattr *a[ARRAY_SIZE(ovs_userspace_policy)];
    const struct nlattr *userdata_attr;
    const struct nlattr *tunnel_out_port_attr;

    if (!nl_parse_nested(attr, ovs_userspace_policy, a, ARRAY_SIZE(a))) {
        ds_put_cstr(ds, "userspace(error)");
        return;
    }

    ds_put_format(ds, "userspace(pid=%"PRIu32,
                  nl_attr_get_u32(a[OVS_USERSPACE_ATTR_PID]));

    userdata_attr = a[OVS_USERSPACE_ATTR_USERDATA];

    if (userdata_attr) {
        const uint8_t *userdata = nl_attr_get(userdata_attr);
        size_t userdata_len = nl_attr_get_size(userdata_attr);
        bool userdata_unspec = true;
        union user_action_cookie cookie;

        if (userdata_len >= sizeof cookie.type
            && userdata_len <= sizeof cookie) {

            memset(&cookie, 0, sizeof cookie);
            memcpy(&cookie, userdata, userdata_len);

            userdata_unspec = false;

            if (userdata_len == sizeof cookie.sflow
                && cookie.type == USER_ACTION_COOKIE_SFLOW) {
                ds_put_format(ds, ",sFlow("
                              "vid=%"PRIu16",pcp=%"PRIu8",output=%"PRIu32")",
                              vlan_tci_to_vid(cookie.sflow.vlan_tci),
                              vlan_tci_to_pcp(cookie.sflow.vlan_tci),
                              cookie.sflow.output);
            } else if (userdata_len == sizeof cookie.slow_path
                       && cookie.type == USER_ACTION_COOKIE_SLOW_PATH) {
                ds_put_cstr(ds, ",slow_path(");
                format_flags(ds, slow_path_reason_to_string,
                             cookie.slow_path.reason, ',');
                ds_put_format(ds, ")");
            } else if (userdata_len == sizeof cookie.flow_sample
                       && cookie.type == USER_ACTION_COOKIE_FLOW_SAMPLE) {
                ds_put_format(ds, ",flow_sample(probability=%"PRIu16
                              ",collector_set_id=%"PRIu32
                              ",obs_domain_id=%"PRIu32
                              ",obs_point_id=%"PRIu32")",
                              cookie.flow_sample.probability,
                              cookie.flow_sample.collector_set_id,
                              cookie.flow_sample.obs_domain_id,
                              cookie.flow_sample.obs_point_id);
            } else if (userdata_len >= sizeof cookie.ipfix
                       && cookie.type == USER_ACTION_COOKIE_IPFIX) {
                ds_put_format(ds, ",ipfix(output_port=%"PRIu32")",
                              cookie.ipfix.output_odp_port);
            } else {
                userdata_unspec = true;
            }
        }

        if (userdata_unspec) {
            size_t i;
            ds_put_format(ds, ",userdata(");
            for (i = 0; i < userdata_len; i++) {
                ds_put_format(ds, "%02x", userdata[i]);
            }
            ds_put_char(ds, ')');
        }
    }

    if (a[OVS_USERSPACE_ATTR_ACTIONS]) {
        ds_put_cstr(ds, ",actions");
    }

    tunnel_out_port_attr = a[OVS_USERSPACE_ATTR_EGRESS_TUN_PORT];
    if (tunnel_out_port_attr) {
        ds_put_format(ds, ",tunnel_out_port=%"PRIu32,
                      nl_attr_get_u32(tunnel_out_port_attr));
    }

    ds_put_char(ds, ')');
}

static void
format_vlan_tci(struct ds *ds, ovs_be16 tci, ovs_be16 mask, bool verbose)
{
    if (verbose || vlan_tci_to_vid(tci) || vlan_tci_to_vid(mask)) {
        ds_put_format(ds, "vid=%"PRIu16, vlan_tci_to_vid(tci));
        if (vlan_tci_to_vid(mask) != VLAN_VID_MASK) { /* Partially masked. */
            ds_put_format(ds, "/0x%"PRIx16, vlan_tci_to_vid(mask));
        };
        ds_put_char(ds, ',');
    }
    if (verbose || vlan_tci_to_pcp(tci) || vlan_tci_to_pcp(mask)) {
        ds_put_format(ds, "pcp=%d", vlan_tci_to_pcp(tci));
        if (vlan_tci_to_pcp(mask) != (VLAN_PCP_MASK >> VLAN_PCP_SHIFT)) {
            ds_put_format(ds, "/0x%x", vlan_tci_to_pcp(mask));
        }
        ds_put_char(ds, ',');
    }
    if (!(tci & htons(VLAN_CFI))) {
        ds_put_cstr(ds, "cfi=0");
        ds_put_char(ds, ',');
    }
    ds_chomp(ds, ',');
}

static void
format_mpls_lse(struct ds *ds, ovs_be32 mpls_lse)
{
    ds_put_format(ds, "label=%"PRIu32",tc=%d,ttl=%d,bos=%d",
                  mpls_lse_to_label(mpls_lse),
                  mpls_lse_to_tc(mpls_lse),
                  mpls_lse_to_ttl(mpls_lse),
                  mpls_lse_to_bos(mpls_lse));
}

static void
format_mpls(struct ds *ds, const struct ovs_key_mpls *mpls_key,
            const struct ovs_key_mpls *mpls_mask, int n)
{
    if (n == 1) {
        ovs_be32 key = mpls_key->mpls_lse;

        if (mpls_mask == NULL) {
            format_mpls_lse(ds, key);
        } else {
            ovs_be32 mask = mpls_mask->mpls_lse;

            ds_put_format(ds, "label=%"PRIu32"/0x%x,tc=%d/%x,ttl=%d/0x%x,bos=%d/%x",
                          mpls_lse_to_label(key), mpls_lse_to_label(mask),
                          mpls_lse_to_tc(key), mpls_lse_to_tc(mask),
                          mpls_lse_to_ttl(key), mpls_lse_to_ttl(mask),
                          mpls_lse_to_bos(key), mpls_lse_to_bos(mask));
        }
    } else {
        int i;

        for (i = 0; i < n; i++) {
            ds_put_format(ds, "lse%d=%#"PRIx32,
                          i, ntohl(mpls_key[i].mpls_lse));
            if (mpls_mask) {
                ds_put_format(ds, "/%#"PRIx32, ntohl(mpls_mask[i].mpls_lse));
            }
            ds_put_char(ds, ',');
        }
        ds_chomp(ds, ',');
    }
}

static void
format_odp_recirc_action(struct ds *ds, uint32_t recirc_id)
{
    ds_put_format(ds, "recirc(%#"PRIx32")", recirc_id);
}

static void
format_odp_hash_action(struct ds *ds, const struct ovs_action_hash *hash_act)
{
    ds_put_format(ds, "hash(");

    if (hash_act->hash_alg == OVS_HASH_ALG_L4) {
        ds_put_format(ds, "hash_l4(%"PRIu32")", hash_act->hash_basis);
    } else {
        ds_put_format(ds, "Unknown hash algorithm(%"PRIu32")",
                      hash_act->hash_alg);
    }
    ds_put_format(ds, ")");
}

static const void *
format_udp_tnl_push_header(struct ds *ds, const struct udp_header *udp)
{
    ds_put_format(ds, "udp(src=%"PRIu16",dst=%"PRIu16",csum=0x%"PRIx16"),",
                  ntohs(udp->udp_src), ntohs(udp->udp_dst),
                  ntohs(udp->udp_csum));

    return udp + 1;
}

static void
format_odp_tnl_push_header(struct ds *ds, struct ovs_action_push_tnl *data)
{
    const struct eth_header *eth;
    const void *l3;
    const void *l4;
    const struct udp_header *udp;

    eth = (const struct eth_header *)data->header;

    l3 = eth + 1;

    /* Ethernet */
    ds_put_format(ds, "header(size=%"PRIu8",type=%"PRIu8",eth(dst=",
                  data->header_len, data->tnl_type);
    ds_put_format(ds, ETH_ADDR_FMT, ETH_ADDR_ARGS(eth->eth_dst));
    ds_put_format(ds, ",src=");
    ds_put_format(ds, ETH_ADDR_FMT, ETH_ADDR_ARGS(eth->eth_src));
    ds_put_format(ds, ",dl_type=0x%04"PRIx16"),", ntohs(eth->eth_type));

    if (eth->eth_type == htons(ETH_TYPE_IP)) {
        /* IPv4 */
        const struct ip_header *ip;
        ip = (const struct ip_header *) l3;
        ds_put_format(ds, "ipv4(src="IP_FMT",dst="IP_FMT",proto=%"PRIu8
                      ",tos=%#"PRIx8",ttl=%"PRIu8",frag=0x%"PRIx16"),",
                      IP_ARGS(get_16aligned_be32(&ip->ip_src)),
                      IP_ARGS(get_16aligned_be32(&ip->ip_dst)),
                      ip->ip_proto, ip->ip_tos,
                      ip->ip_ttl,
                      ntohs(ip->ip_frag_off));
        l4 = (ip + 1);
    } else {
        const struct ip6_hdr *ip6;
        ip6 = (const struct ip6_hdr *) l3;
        ds_put_format(ds, "ipv6(src=");
        ipv6_format_addr(&ip6->ip6_src, ds);
        ds_put_format(ds, ",dst=");
        ipv6_format_addr(&ip6->ip6_dst, ds);
        ds_put_format(ds, ",label=%i,proto=%"PRIu8",tclass=0x%"PRIx8
                          ",hlimit=%"PRIu8"),",
                      ntohl(ip6->ip6_flow) & IPV6_LABEL_MASK, ip6->ip6_nxt,
                      (ntohl(ip6->ip6_flow) >> 20) & 0xff, ip6->ip6_hlim);
        l4 = (ip6 + 1);
    }

    udp = (const struct udp_header *) l4;

    if (data->tnl_type == OVS_VPORT_TYPE_VXLAN) {
        const struct vxlanhdr *vxh;

        vxh = format_udp_tnl_push_header(ds, udp);

        ds_put_format(ds, "vxlan(flags=0x%"PRIx32",vni=0x%"PRIx32")",
                      ntohl(get_16aligned_be32(&vxh->vx_flags)),
                      ntohl(get_16aligned_be32(&vxh->vx_vni)) >> 8);
    } else if (data->tnl_type == OVS_VPORT_TYPE_GENEVE) {
        const struct genevehdr *gnh;

        gnh = format_udp_tnl_push_header(ds, udp);

        ds_put_format(ds, "geneve(%s%svni=0x%"PRIx32,
                      gnh->oam ? "oam," : "",
                      gnh->critical ? "crit," : "",
                      ntohl(get_16aligned_be32(&gnh->vni)) >> 8);
 
        if (gnh->opt_len) {
            ds_put_cstr(ds, ",options(");
            format_geneve_opts(gnh->options, NULL, gnh->opt_len * 4,
                               ds, false);
            ds_put_char(ds, ')');
        }

        ds_put_char(ds, ')');
    } else if (data->tnl_type == OVS_VPORT_TYPE_GRE) {
        const struct gre_base_hdr *greh;
        ovs_16aligned_be32 *options;

        greh = (const struct gre_base_hdr *) l4;

        ds_put_format(ds, "gre((flags=0x%"PRIx16",proto=0x%"PRIx16")",
                           ntohs(greh->flags), ntohs(greh->protocol));
        options = (ovs_16aligned_be32 *)(greh + 1);
        if (greh->flags & htons(GRE_CSUM)) {
            ds_put_format(ds, ",csum=0x%"PRIx16, ntohs(*((ovs_be16 *)options)));
            options++;
        }
        if (greh->flags & htons(GRE_KEY)) {
            ds_put_format(ds, ",key=0x%"PRIx32, ntohl(get_16aligned_be32(options)));
            options++;
        }
        if (greh->flags & htons(GRE_SEQ)) {
            ds_put_format(ds, ",seq=0x%"PRIx32, ntohl(get_16aligned_be32(options)));
            options++;
        }
        ds_put_format(ds, ")");
    }
    ds_put_format(ds, ")");
}

static void
format_odp_tnl_push_action(struct ds *ds, const struct nlattr *attr)
{
    struct ovs_action_push_tnl *data;

    data = (struct ovs_action_push_tnl *) nl_attr_get(attr);

    ds_put_format(ds, "tnl_push(tnl_port(%"PRIu32"),", data->tnl_port);
    format_odp_tnl_push_header(ds, data);
    ds_put_format(ds, ",out_port(%"PRIu32"))", data->out_port);
}

static const struct nl_policy ovs_conntrack_policy[] = {
    [OVS_CT_ATTR_COMMIT] = { .type = NL_A_FLAG, .optional = true, },
    [OVS_CT_ATTR_ZONE] = { .type = NL_A_U16, .optional = true, },
    [OVS_CT_ATTR_MARK] = { .type = NL_A_UNSPEC, .optional = true,
                           .min_len = sizeof(uint32_t) * 2 },
    [OVS_CT_ATTR_LABELS] = { .type = NL_A_UNSPEC, .optional = true,
                             .min_len = sizeof(struct ovs_key_ct_labels) * 2 },
    [OVS_CT_ATTR_HELPER] = { .type = NL_A_STRING, .optional = true,
                             .min_len = 1, .max_len = 16 },
};

static void
format_odp_conntrack_action(struct ds *ds, const struct nlattr *attr)
{
    struct nlattr *a[ARRAY_SIZE(ovs_conntrack_policy)];
    const ovs_u128 *label;
    const uint32_t *mark;
    const char *helper;
    uint16_t zone;
    bool commit;

    if (!nl_parse_nested(attr, ovs_conntrack_policy, a, ARRAY_SIZE(a))) {
        ds_put_cstr(ds, "ct(error)");
        return;
    }

    commit = a[OVS_CT_ATTR_COMMIT] ? true : false;
    zone = a[OVS_CT_ATTR_ZONE] ? nl_attr_get_u16(a[OVS_CT_ATTR_ZONE]) : 0;
    mark = a[OVS_CT_ATTR_MARK] ? nl_attr_get(a[OVS_CT_ATTR_MARK]) : NULL;
    label = a[OVS_CT_ATTR_LABELS] ? nl_attr_get(a[OVS_CT_ATTR_LABELS]): NULL;
    helper = a[OVS_CT_ATTR_HELPER] ? nl_attr_get(a[OVS_CT_ATTR_HELPER]) : NULL;

    ds_put_format(ds, "ct");
    if (commit || zone || mark || label || helper) {
        ds_put_cstr(ds, "(");
        if (commit) {
            ds_put_format(ds, "commit,");
        }
        if (zone) {
            ds_put_format(ds, "zone=%"PRIu16",", zone);
        }
        if (mark) {
            ds_put_format(ds, "mark=%#"PRIx32"/%#"PRIx32",", *mark,
                          *(mark + 1));
        }
        if (label) {
            ds_put_format(ds, "label=");
            format_u128(ds, label, label + 1, true);
            ds_put_char(ds, ',');
        }
        if (helper) {
            ds_put_format(ds, "helper=%s,", helper);
        }
        ds_chomp(ds, ',');
        ds_put_cstr(ds, ")");
    }
}

static void
format_odp_action(struct ds *ds, const struct nlattr *a)
{
    int expected_len;
    uint16_t type = nl_attr_type(a);
    size_t size;

    expected_len = odp_action_len(nl_attr_type(a));
    if (expected_len != ATTR_LEN_VARIABLE &&
        nl_attr_get_size(a) != expected_len) {
        ds_put_format(ds, "bad length %"PRIuSIZE", expected %d for: ",
                      nl_attr_get_size(a), expected_len);
        format_generic_odp_action(ds, a);
        return;
    }

    switch (type) {
    case OVS_ACTION_ATTR_OUTPUT:
        ds_put_format(ds, "%"PRIu32, nl_attr_get_u32(a));
        break;
    case OVS_ACTION_ATTR_TUNNEL_POP:
        ds_put_format(ds, "tnl_pop(%"PRIu32")", nl_attr_get_u32(a));
        break;
    case OVS_ACTION_ATTR_TUNNEL_PUSH:
        format_odp_tnl_push_action(ds, a);
        break;
    case OVS_ACTION_ATTR_USERSPACE:
        format_odp_userspace_action(ds, a);
        break;
    case OVS_ACTION_ATTR_RECIRC:
        format_odp_recirc_action(ds, nl_attr_get_u32(a));
        break;
    case OVS_ACTION_ATTR_HASH:
        format_odp_hash_action(ds, nl_attr_get(a));
        break;
    case OVS_ACTION_ATTR_SET_MASKED:
        a = nl_attr_get(a);
        size = nl_attr_get_size(a) / 2;
        ds_put_cstr(ds, "set(");

        /* Masked set action not supported for tunnel key, which is bigger. */
        if (size <= sizeof(struct ovs_key_ipv6)) {
            struct nlattr attr[1 + DIV_ROUND_UP(sizeof(struct ovs_key_ipv6),
                                                sizeof(struct nlattr))];
            struct nlattr mask[1 + DIV_ROUND_UP(sizeof(struct ovs_key_ipv6),
                                                sizeof(struct nlattr))];

            mask->nla_type = attr->nla_type = nl_attr_type(a);
            mask->nla_len = attr->nla_len = NLA_HDRLEN + size;
            memcpy(attr + 1, (char *)(a + 1), size);
            memcpy(mask + 1, (char *)(a + 1) + size, size);
            format_odp_key_attr(attr, mask, NULL, ds, false);
        } else {
            format_odp_key_attr(a, NULL, NULL, ds, false);
        }
        ds_put_cstr(ds, ")");
        break;
    case OVS_ACTION_ATTR_SET:
        ds_put_cstr(ds, "set(");
        format_odp_key_attr(nl_attr_get(a), NULL, NULL, ds, true);
        ds_put_cstr(ds, ")");
        break;
    case OVS_ACTION_ATTR_PUSH_VLAN: {
        const struct ovs_action_push_vlan *vlan = nl_attr_get(a);
        ds_put_cstr(ds, "push_vlan(");
        if (vlan->vlan_tpid != htons(ETH_TYPE_VLAN)) {
            ds_put_format(ds, "tpid=0x%04"PRIx16",", ntohs(vlan->vlan_tpid));
        }
        format_vlan_tci(ds, vlan->vlan_tci, OVS_BE16_MAX, false);
        ds_put_char(ds, ')');
        break;
    }
    case OVS_ACTION_ATTR_POP_VLAN:
        ds_put_cstr(ds, "pop_vlan");
        break;
	case OVS_ACTION_ATTR_PUSH_GTPV1:
	{
		const struct ovs_action_push_gtpv1 *gtpv1 = nl_attr_get(a);
		uint32_t teid = ntohl(gtpv1->teid);

		ds_put_cstr(ds, "push_gtp(");
		ds_put_format(ds, "src="IP_FMT, IP_ARGS(ntohl(gtpv1->ipv4.src)));
		ds_put_char(ds, ',');
		ds_put_format(ds, "dst="IP_FMT, IP_ARGS(ntohl(gtpv1->ipv4.dst)));
		ds_put_char(ds, ',');
		ds_put_format(ds, "teid=%"PRIu32, teid);
		ds_put_char(ds, ')');
		break;
	}
	case OVS_ACTION_ATTR_POP_GTPV1:
		ds_put_cstr(ds, "pop_gtp");
	break;
    case OVS_ACTION_ATTR_PUSH_MPLS: {
        const struct ovs_action_push_mpls *mpls = nl_attr_get(a);
        ds_put_cstr(ds, "push_mpls(");
        format_mpls_lse(ds, mpls->mpls_lse);
        ds_put_format(ds, ",eth_type=0x%"PRIx16")", ntohs(mpls->mpls_ethertype));
        break;
    }
    case OVS_ACTION_ATTR_POP_MPLS: {
        ovs_be16 ethertype = nl_attr_get_be16(a);
        ds_put_format(ds, "pop_mpls(eth_type=0x%"PRIx16")", ntohs(ethertype));
        break;
    }
    case OVS_ACTION_ATTR_SAMPLE:
        format_odp_sample_action(ds, a);
        break;
    case OVS_ACTION_ATTR_CT:
        format_odp_conntrack_action(ds, a);
        break;
    case OVS_ACTION_ATTR_UNSPEC:
    case __OVS_ACTION_ATTR_GTPV1_MAX:
    default:
        format_generic_odp_action(ds, a);
        break;
    }
}

void
format_odp_actions(struct ds *ds, const struct nlattr *actions,
                   size_t actions_len)
{
    if (actions_len) {
        const struct nlattr *a;
        unsigned int left;

        NL_ATTR_FOR_EACH (a, left, actions, actions_len) {
            if (a != actions) {
                ds_put_char(ds, ',');
            }
            format_odp_action(ds, a);
        }
        if (left) {
            int i;

            if (left == actions_len) {
                ds_put_cstr(ds, "<empty>");
            }
            ds_put_format(ds, ",***%u leftover bytes*** (", left);
            for (i = 0; i < left; i++) {
                ds_put_format(ds, "%02x", ((const uint8_t *) a)[i]);
            }
            ds_put_char(ds, ')');
        }
    } else {
        ds_put_cstr(ds, "drop");
    }
}

/* Separate out parse_odp_userspace_action() function. */
static int
parse_odp_userspace_action(const char *s, struct ofpbuf *actions)
{
    uint32_t pid;
    union user_action_cookie cookie;
    struct ofpbuf buf;
    odp_port_t tunnel_out_port;
    int n = -1;
    void *user_data = NULL;
    size_t user_data_size = 0;
    bool include_actions = false;
    int res;

    if (!ovs_scan(s, "userspace(pid=%"SCNi32"%n", &pid, &n)) {
        return -EINVAL;
    }

    ofpbuf_init(&buf, 16);

    {
        uint32_t output;
        uint32_t probability;
        uint32_t collector_set_id;
        uint32_t obs_domain_id;
        uint32_t obs_point_id;
        int vid, pcp;
        int n1 = -1;
        if (ovs_scan(&s[n], ",sFlow(vid=%i,"
                     "pcp=%i,output=%"SCNi32")%n",
                     &vid, &pcp, &output, &n1)) {
            uint16_t tci;

            n += n1;
            tci = vid | (pcp << VLAN_PCP_SHIFT);
            if (tci) {
                tci |= VLAN_CFI;
            }

            cookie.type = USER_ACTION_COOKIE_SFLOW;
            cookie.sflow.vlan_tci = htons(tci);
            cookie.sflow.output = output;
            user_data = &cookie;
            user_data_size = sizeof cookie.sflow;
        } else if (ovs_scan(&s[n], ",slow_path(%n",
                            &n1)) {
            n += n1;
            cookie.type = USER_ACTION_COOKIE_SLOW_PATH;
            cookie.slow_path.unused = 0;
            cookie.slow_path.reason = 0;

            res = parse_odp_flags(&s[n], slow_path_reason_to_string,
                                  &cookie.slow_path.reason,
                                  SLOW_PATH_REASON_MASK, NULL);
            if (res < 0 || s[n + res] != ')') {
                goto out;
            }
            n += res + 1;

            user_data = &cookie;
            user_data_size = sizeof cookie.slow_path;
        } else if (ovs_scan(&s[n], ",flow_sample(probability=%"SCNi32","
                            "collector_set_id=%"SCNi32","
                            "obs_domain_id=%"SCNi32","
                            "obs_point_id=%"SCNi32")%n",
                            &probability, &collector_set_id,
                            &obs_domain_id, &obs_point_id, &n1)) {
            n += n1;

            cookie.type = USER_ACTION_COOKIE_FLOW_SAMPLE;
            cookie.flow_sample.probability = probability;
            cookie.flow_sample.collector_set_id = collector_set_id;
            cookie.flow_sample.obs_domain_id = obs_domain_id;
            cookie.flow_sample.obs_point_id = obs_point_id;
            user_data = &cookie;
            user_data_size = sizeof cookie.flow_sample;
        } else if (ovs_scan(&s[n], ",ipfix(output_port=%"SCNi32")%n",
                            &output, &n1) ) {
            n += n1;
            cookie.type = USER_ACTION_COOKIE_IPFIX;
            cookie.ipfix.output_odp_port = u32_to_odp(output);
            user_data = &cookie;
            user_data_size = sizeof cookie.ipfix;
        } else if (ovs_scan(&s[n], ",userdata(%n",
                            &n1)) {
            char *end;

            n += n1;
            end = ofpbuf_put_hex(&buf, &s[n], NULL);
            if (end[0] != ')') {
                res = -EINVAL;
                goto out;
            }
            user_data = buf.data;
            user_data_size = buf.size;
            n = (end + 1) - s;
        }
    }

    {
        int n1 = -1;
        if (ovs_scan(&s[n], ",actions%n", &n1)) {
            n += n1;
            include_actions = true;
        }
    }

    {
        int n1 = -1;
        if (ovs_scan(&s[n], ",tunnel_out_port=%"SCNi32")%n",
                     &tunnel_out_port, &n1)) {
            odp_put_userspace_action(pid, user_data, user_data_size,
                                     tunnel_out_port, include_actions, actions);
            res = n + n1;
        } else if (s[n] == ')') {
            odp_put_userspace_action(pid, user_data, user_data_size,
                                     ODPP_NONE, include_actions, actions);
            res = n + 1;
        } else {
            res = -EINVAL;
        }
    }
out:
    ofpbuf_uninit(&buf);
    return res;
}

static int
ovs_parse_tnl_push(const char *s, struct ovs_action_push_tnl *data)
{
    struct eth_header *eth;
    struct ip_header *ip;
    struct ovs_16aligned_ip6_hdr *ip6;
    struct udp_header *udp;
    struct gre_base_hdr *greh;
    uint16_t gre_proto, gre_flags, dl_type, udp_src, udp_dst, csum;
    ovs_be32 sip, dip;
    uint32_t tnl_type = 0, header_len = 0, ip_len = 0;
    void *l3, *l4;
    int n = 0;

    if (!ovs_scan_len(s, &n, "tnl_push(tnl_port(%"SCNi32"),", &data->tnl_port)) {
        return -EINVAL;
    }
    eth = (struct eth_header *) data->header;
    l3 = (data->header + sizeof *eth);
    ip = (struct ip_header *) l3;
    ip6 = (struct ovs_16aligned_ip6_hdr *) l3;
    if (!ovs_scan_len(s, &n, "header(size=%"SCNi32",type=%"SCNi32","
                         "eth(dst="ETH_ADDR_SCAN_FMT",",
                         &data->header_len,
                         &data->tnl_type,
                         ETH_ADDR_SCAN_ARGS(eth->eth_dst))) {
        return -EINVAL;
    }

    if (!ovs_scan_len(s, &n, "src="ETH_ADDR_SCAN_FMT",",
                  ETH_ADDR_SCAN_ARGS(eth->eth_src))) {
        return -EINVAL;
    }
    if (!ovs_scan_len(s, &n, "dl_type=0x%"SCNx16"),", &dl_type)) {
        return -EINVAL;
    }
    eth->eth_type = htons(dl_type);

    if (eth->eth_type == htons(ETH_TYPE_IP)) {
        /* IPv4 */
        uint16_t ip_frag_off;
        if (!ovs_scan_len(s, &n, "ipv4(src="IP_SCAN_FMT",dst="IP_SCAN_FMT",proto=%"SCNi8
                          ",tos=%"SCNi8",ttl=%"SCNi8",frag=0x%"SCNx16"),",
                          IP_SCAN_ARGS(&sip),
                          IP_SCAN_ARGS(&dip),
                          &ip->ip_proto, &ip->ip_tos,
                          &ip->ip_ttl, &ip_frag_off)) {
            return -EINVAL;
        }
        put_16aligned_be32(&ip->ip_src, sip);
        put_16aligned_be32(&ip->ip_dst, dip);
        ip->ip_frag_off = htons(ip_frag_off);
        ip_len = sizeof *ip;
    } else {
        char sip6_s[IPV6_SCAN_LEN + 1];
        char dip6_s[IPV6_SCAN_LEN + 1];
        struct in6_addr sip6, dip6;
        uint8_t tclass;
        uint32_t label;
        if (!ovs_scan_len(s, &n, "ipv6(src="IPV6_SCAN_FMT",dst="IPV6_SCAN_FMT
                             ",label=%i,proto=%"SCNi8",tclass=0x%"SCNx8
                             ",hlimit=%"SCNi8"),",
                             sip6_s, dip6_s, &label, &ip6->ip6_nxt,
                             &tclass, &ip6->ip6_hlim)
            || (label & ~IPV6_LABEL_MASK) != 0
            || inet_pton(AF_INET6, sip6_s, &sip6) != 1
            || inet_pton(AF_INET6, dip6_s, &dip6) != 1) {
            return -EINVAL;
        }
        put_16aligned_be32(&ip6->ip6_flow, htonl(6 << 28) |
                           htonl(tclass << 20) | htonl(label));
        memcpy(&ip6->ip6_src, &sip6, sizeof(ip6->ip6_src));
        memcpy(&ip6->ip6_dst, &dip6, sizeof(ip6->ip6_dst));
        ip_len = sizeof *ip6;
    }

    /* Tunnel header */
    l4 = ((uint8_t *) l3 + ip_len);
    udp = (struct udp_header *) l4;
    greh = (struct gre_base_hdr *) l4;
    if (ovs_scan_len(s, &n, "udp(src=%"SCNi16",dst=%"SCNi16",csum=0x%"SCNx16"),",
                         &udp_src, &udp_dst, &csum)) {
        uint32_t vx_flags, vni;

        udp->udp_src = htons(udp_src);
        udp->udp_dst = htons(udp_dst);
        udp->udp_len = 0;
        udp->udp_csum = htons(csum);

        if (ovs_scan_len(s, &n, "vxlan(flags=0x%"SCNx32",vni=0x%"SCNx32"))",
                            &vx_flags, &vni)) {
            struct vxlanhdr *vxh = (struct vxlanhdr *) (udp + 1);

            put_16aligned_be32(&vxh->vx_flags, htonl(vx_flags));
            put_16aligned_be32(&vxh->vx_vni, htonl(vni << 8));
            tnl_type = OVS_VPORT_TYPE_VXLAN;
            header_len = sizeof *eth + ip_len +
                         sizeof *udp + sizeof *vxh;
        } else if (ovs_scan_len(s, &n, "geneve(")) {
            struct genevehdr *gnh = (struct genevehdr *) (udp + 1);

            memset(gnh, 0, sizeof *gnh);
            header_len = sizeof *eth + ip_len +
                         sizeof *udp + sizeof *gnh;

            if (ovs_scan_len(s, &n, "oam,")) {
                gnh->oam = 1;
            }
            if (ovs_scan_len(s, &n, "crit,")) {
                gnh->critical = 1;
            }
            if (!ovs_scan_len(s, &n, "vni=%"SCNi32, &vni)) {
                return -EINVAL;
            }
            if (ovs_scan_len(s, &n, ",options(")) {
                struct geneve_scan options;
                int len;

                memset(&options, 0, sizeof options);
                len = scan_geneve(s + n, &options, NULL);
                if (!len) {
                    return -EINVAL;
                }

                memcpy(gnh->options, options.d, options.len);
                gnh->opt_len = options.len / 4;
                header_len += options.len;

                n += len;
            }
            if (!ovs_scan_len(s, &n, "))")) {
                return -EINVAL;
            }

            gnh->proto_type = htons(ETH_TYPE_TEB);
            put_16aligned_be32(&gnh->vni, htonl(vni << 8));
            tnl_type = OVS_VPORT_TYPE_GENEVE;
        } else {
            return -EINVAL;
        }
    } else if (ovs_scan_len(s, &n, "gre((flags=0x%"SCNx16",proto=0x%"SCNx16")",
                         &gre_flags, &gre_proto)){

        tnl_type = OVS_VPORT_TYPE_GRE;
        greh->flags = htons(gre_flags);
        greh->protocol = htons(gre_proto);
        ovs_16aligned_be32 *options = (ovs_16aligned_be32 *) (greh + 1);

        if (greh->flags & htons(GRE_CSUM)) {
            if (!ovs_scan_len(s, &n, ",csum=0x%"SCNx16, &csum)) {
                return -EINVAL;
            }

            memset(options, 0, sizeof *options);
            *((ovs_be16 *)options) = htons(csum);
            options++;
        }
        if (greh->flags & htons(GRE_KEY)) {
            uint32_t key;

            if (!ovs_scan_len(s, &n, ",key=0x%"SCNx32, &key)) {
                return -EINVAL;
            }

            put_16aligned_be32(options, htonl(key));
            options++;
        }
        if (greh->flags & htons(GRE_SEQ)) {
            uint32_t seq;

            if (!ovs_scan_len(s, &n, ",seq=0x%"SCNx32, &seq)) {
                return -EINVAL;
            }
            put_16aligned_be32(options, htonl(seq));
            options++;
        }

        if (!ovs_scan_len(s, &n, "))")) {
            return -EINVAL;
        }

        header_len = sizeof *eth + ip_len +
                     ((uint8_t *) options - (uint8_t *) greh);
    } else {
        return -EINVAL;
    }

    /* check tunnel meta data. */
    if (data->tnl_type != tnl_type) {
        return -EINVAL;
    }
    if (data->header_len != header_len) {
        return -EINVAL;
    }

    /* Out port */
    if (!ovs_scan_len(s, &n, ",out_port(%"SCNi32"))", &data->out_port)) {
        return -EINVAL;
    }

    return n;
}

static int
parse_conntrack_action(const char *s_, struct ofpbuf *actions)
{
    const char *s = s_;

    if (ovs_scan(s, "ct")) {
        const char *helper = NULL;
        size_t helper_len = 0;
        bool commit = false;
        uint16_t zone = 0;
        struct {
            uint32_t value;
            uint32_t mask;
        } ct_mark = { 0, 0 };
        struct {
            ovs_u128 value;
            ovs_u128 mask;
        } ct_label;
        size_t start;
        char *end;

        memset(&ct_label, 0, sizeof(ct_label));

        s += 2;
        if (ovs_scan(s, "(")) {
            s++;
            end = strchr(s, ')');
            if (!end) {
                return -EINVAL;
            }

            while (s != end) {
                int n = -1;

                s += strspn(s, delimiters);
                if (ovs_scan(s, "commit%n", &n)) {
                    commit = true;
                    s += n;
                    continue;
                }
                if (ovs_scan(s, "zone=%"SCNu16"%n", &zone, &n)) {
                    s += n;
                    continue;
                }
                if (ovs_scan(s, "mark=%"SCNx32"%n", &ct_mark.value, &n)) {
                    s += n;
                    n = -1;
                    if (ovs_scan(s, "/%"SCNx32"%n", &ct_mark.mask, &n)) {
                        s += n;
                    } else {
                        ct_mark.mask = UINT32_MAX;
                    }
                    continue;
                }
                if (ovs_scan(s, "label=%n", &n)) {
                    int retval;

                    s += n;
                    retval = scan_u128(s, &ct_label.value, &ct_label.mask);
                    if (retval < 0) {
                        return retval;
                    }
                    s += retval;
                    continue;
                }
                if (ovs_scan(s, "helper=%n", &n)) {
                    s += n;
                    helper_len = strcspn(s, delimiters_end);
                    if (!helper_len || helper_len > 15) {
                        return -EINVAL;
                    }
                    helper = s;
                    s += helper_len;
                    continue;
                }

                return -EINVAL;
            }
            s++;
        }

        start = nl_msg_start_nested(actions, OVS_ACTION_ATTR_CT);
        if (commit) {
            nl_msg_put_flag(actions, OVS_CT_ATTR_COMMIT);
        }
        if (zone) {
            nl_msg_put_u16(actions, OVS_CT_ATTR_ZONE, zone);
        }
        if (ct_mark.mask) {
            nl_msg_put_unspec(actions, OVS_CT_ATTR_MARK, &ct_mark,
                              sizeof(ct_mark));
        }
        if (!ovs_u128_is_zero(&ct_label.mask)) {
            nl_msg_put_unspec(actions, OVS_CT_ATTR_LABELS, &ct_label,
                              sizeof ct_label);
        }
        if (helper) {
            nl_msg_put_string__(actions, OVS_CT_ATTR_HELPER, helper,
                                helper_len);
        }
        nl_msg_end_nested(actions, start);
    }

    return s - s_;
}

static int parse_odp_gtpu_action(const char *s, const struct simap *port_names,
								 struct ofpbuf *actions)
{
	/* if the action string specifies just a plain decimal number,
	 * it is interpreted as a "forward to this port number" action
	 */
	{
		uint32_t port;
		int n;

		if (ovs_scan(s, "%"SCNi32"%n", &port, &n)) {
			nl_msg_put_u32(actions, OVS_ACTION_ATTR_OUTPUT, port);
			return n;
		}
	}

	if (port_names) {
		int len = strcspn(s, delimiters);
		struct simap_node *node;

		node = simap_find_len(port_names, s, len);
		if (node) {
			nl_msg_put_u32(actions, OVS_ACTION_ATTR_OUTPUT, node->data);
			return len;
		}
	}

	{
		struct ovs_action_push_gtpv1 push;
		uint32_t tun_src, tun_dst, teid;
		int n;

		if (ovs_scan(s, "push_gtp(src="IP_SCAN_FMT",dst="IP_SCAN_FMT",teid=%u)%n",
					 IP_SCAN_ARGS(&tun_src), IP_SCAN_ARGS(&tun_dst), &teid, &n) ||
			ovs_scan(s, "push_gtp(dst="IP_SCAN_FMT",src="IP_SCAN_FMT",teid=%u)%n",
					 IP_SCAN_ARGS(&tun_dst), IP_SCAN_ARGS(&tun_src), &teid, &n) ||
			ovs_scan(s, "push_gtp(teid=%u,src="IP_SCAN_FMT",dst="IP_SCAN_FMT")%n",
					 &teid, IP_SCAN_ARGS(&tun_src), IP_SCAN_ARGS(&tun_dst), &n) ||
			ovs_scan(s, "push_gtp(teid=%u,dst="IP_SCAN_FMT",src="IP_SCAN_FMT")%n",
					 &teid, IP_SCAN_ARGS(&tun_dst), IP_SCAN_ARGS(&tun_src), &n))
		{
			push.ipv4.src = htonl(tun_src);
			push.ipv4.dst = htonl(tun_dst);
			push.teid = htonl(teid);

			nl_msg_put_unspec(actions, OVS_ACTION_ATTR_PUSH_GTPV1, &push, sizeof push);
			return n;
		}
	}

	if (!strncmp(s, "pop_gtp", 7))
	{
		nl_msg_put_flag(actions, OVS_ACTION_ATTR_POP_GTPV1);
		return 7;
	}

	return -EINVAL;
}

static int
parse_odp_action(const char *s, const struct simap *port_names,
                 struct ofpbuf *actions)
{
    /* if the action string specifies just a plain decimal number,
	 * it is interpreted as a "forward to this port number" action
	 */
	{
        uint32_t port;
        int n;

        if (ovs_scan(s, "%"SCNi32"%n", &port, &n)) {
            nl_msg_put_u32(actions, OVS_ACTION_ATTR_OUTPUT, port);
            return n;
        }
    }

    if (port_names) {
        int len = strcspn(s, delimiters);
        struct simap_node *node;

        node = simap_find_len(port_names, s, len);
        if (node) {
            nl_msg_put_u32(actions, OVS_ACTION_ATTR_OUTPUT, node->data);
            return len;
        }
    }

    {
        uint32_t recirc_id;
        int n = -1;

        if (ovs_scan(s, "recirc(%"PRIu32")%n", &recirc_id, &n)) {
            nl_msg_put_u32(actions, OVS_ACTION_ATTR_RECIRC, recirc_id);
            return n;
        }
    }

    if (!strncmp(s, "userspace(", 10)) {
        return parse_odp_userspace_action(s, actions);
    }

    if (!strncmp(s, "set(", 4)) {
        size_t start_ofs;
        int retval;
        struct nlattr mask[128 / sizeof(struct nlattr)];
        struct ofpbuf maskbuf;
        struct nlattr *nested, *key;
        size_t size;

        /* 'mask' is big enough to hold any key. */
        ofpbuf_use_stack(&maskbuf, mask, sizeof mask);

        start_ofs = nl_msg_start_nested(actions, OVS_ACTION_ATTR_SET);
        retval = parse_odp_key_mask_attr(s + 4, port_names, actions, &maskbuf);
        if (retval < 0) {
            return retval;
        }
        if (s[retval + 4] != ')') {
            return -EINVAL;
        }

        nested = ofpbuf_at_assert(actions, start_ofs, sizeof *nested);
        key = nested + 1;

        size = nl_attr_get_size(mask);
        if (size == nl_attr_get_size(key)) {
            /* Change to masked set action if not fully masked. */
            if (!is_all_ones(mask + 1, size)) {
                key->nla_len += size;
                ofpbuf_put(actions, mask + 1, size);
                /* 'actions' may have been reallocated by ofpbuf_put(). */
                nested = ofpbuf_at_assert(actions, start_ofs, sizeof *nested);
                nested->nla_type = OVS_ACTION_ATTR_SET_MASKED;
            }
        }

        nl_msg_end_nested(actions, start_ofs);
        return retval + 5;
    }

    {
        struct ovs_action_push_vlan push;
        int tpid = ETH_TYPE_VLAN;
        int vid, pcp;
        int cfi = 1;
        int n = -1;

        if (ovs_scan(s, "push_vlan(vid=%i,pcp=%i)%n", &vid, &pcp, &n)
            || ovs_scan(s, "push_vlan(vid=%i,pcp=%i,cfi=%i)%n",
                        &vid, &pcp, &cfi, &n)
            || ovs_scan(s, "push_vlan(tpid=%i,vid=%i,pcp=%i)%n",
                        &tpid, &vid, &pcp, &n)
            || ovs_scan(s, "push_vlan(tpid=%i,vid=%i,pcp=%i,cfi=%i)%n",
                        &tpid, &vid, &pcp, &cfi, &n)) {
            push.vlan_tpid = htons(tpid);
            push.vlan_tci = htons((vid << VLAN_VID_SHIFT)
                                  | (pcp << VLAN_PCP_SHIFT)
                                  | (cfi ? VLAN_CFI : 0));
            nl_msg_put_unspec(actions, OVS_ACTION_ATTR_PUSH_VLAN,
                              &push, sizeof push);

            return n;
        }
    }

    if (!strncmp(s, "pop_vlan", 8)) {
        nl_msg_put_flag(actions, OVS_ACTION_ATTR_POP_VLAN);
        return 8;
    }

    {
        double percentage;
        int n = -1;

        if (ovs_scan(s, "sample(sample=%lf%%,actions(%n", &percentage, &n)
            && percentage >= 0. && percentage <= 100.0) {
            size_t sample_ofs, actions_ofs;
            double probability;

            probability = floor(UINT32_MAX * (percentage / 100.0) + .5);
            sample_ofs = nl_msg_start_nested(actions, OVS_ACTION_ATTR_SAMPLE);
            nl_msg_put_u32(actions, OVS_SAMPLE_ATTR_PROBABILITY,
                           (probability <= 0 ? 0
                            : probability >= UINT32_MAX ? UINT32_MAX
                            : probability));

            actions_ofs = nl_msg_start_nested(actions,
                                              OVS_SAMPLE_ATTR_ACTIONS);
            for (;;) {
                int retval;

                n += strspn(s + n, delimiters);
                if (s[n] == ')') {
                    break;
                }

                retval = parse_odp_action(s + n, port_names, actions);
                if (retval < 0) {
                    return retval;
                }
                n += retval;
            }
            nl_msg_end_nested(actions, actions_ofs);
            nl_msg_end_nested(actions, sample_ofs);

            return s[n + 1] == ')' ? n + 2 : -EINVAL;
        }
    }

    {
        uint32_t port;
        int n;

        if (ovs_scan(s, "tnl_pop(%"SCNi32")%n", &port, &n)) {
            nl_msg_put_u32(actions, OVS_ACTION_ATTR_TUNNEL_POP, port);
            return n;
        }
    }

    {
        int retval;

        retval = parse_conntrack_action(s, actions);
        if (retval) {
            return retval;
        }
    }

    {
        struct ovs_action_push_tnl data;
        int n;

        n = ovs_parse_tnl_push(s, &data);
        if (n > 0) {
            odp_put_tnl_push_action(actions, &data);
            return n;
        } else if (n < 0) {
            return n;
        }
    }
    return -EINVAL;
}

int odp_gtpu_actions_from_string(const char *s, const struct simap *port_names,
	struct ofpbuf *actions)
{
	size_t old_size;

	if (!strcasecmp(s, "drop")) {
		return 0;
	}

	old_size = actions->size;
	for (;;) {
		int retval;

		s += strspn(s, delimiters);
		if (!*s) {
			return 0;
		}

		retval = parse_odp_gtpu_action(s, port_names, actions);

		if (retval < 0 || !strchr(delimiters, s[retval])) {
			actions->size = old_size;
			return -retval;
		}
		s += retval;
	}

	return 0;
}

/* Parses the string representation of datapath actions, in the format output
 * by format_odp_action().  Returns 0 if successful, otherwise a positive errno
 * value.  On success, the ODP actions are appended to 'actions' as a series of
 * Netlink attributes.  On failure, no data is appended to 'actions'.  Either
 * way, 'actions''s data might be reallocated. */
int odp_actions_from_string(const char *s, const struct simap *port_names,
                        struct ofpbuf *actions)
{
    size_t old_size;

    if (!strcasecmp(s, "drop")) {
        return 0;
    }

    old_size = actions->size;
    for (;;) {
        int retval;

        s += strspn(s, delimiters);
        if (!*s) {
            return 0;
        }

		retval = parse_odp_action(s, port_names, actions);

        if (retval < 0 || !strchr(delimiters, s[retval])) {
            actions->size = old_size;
            return -retval;
        }
        s += retval;
    }

    return 0;
}

static const struct attr_len_tbl ovs_vxlan_ext_attr_lens[OVS_VXLAN_EXT_MAX + 1] = {
    [OVS_VXLAN_EXT_GBP]                 = { .len = 4 },
};

static const struct attr_len_tbl ovs_tun_key_attr_lens[OVS_TUNNEL_KEY_ATTR_MAX + 1] = {
    [OVS_TUNNEL_KEY_ATTR_ID]            = { .len = 8 },
    [OVS_TUNNEL_KEY_ATTR_IPV4_SRC]      = { .len = 4 },
    [OVS_TUNNEL_KEY_ATTR_IPV4_DST]      = { .len = 4 },
    [OVS_TUNNEL_KEY_ATTR_TOS]           = { .len = 1 },
    [OVS_TUNNEL_KEY_ATTR_TTL]           = { .len = 1 },
    [OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT] = { .len = 0 },
    [OVS_TUNNEL_KEY_ATTR_CSUM]          = { .len = 0 },
    [OVS_TUNNEL_KEY_ATTR_TP_SRC]        = { .len = 2 },
    [OVS_TUNNEL_KEY_ATTR_TP_DST]        = { .len = 2 },
    [OVS_TUNNEL_KEY_ATTR_OAM]           = { .len = 0 },
    [OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS]   = { .len = ATTR_LEN_VARIABLE },
    [OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS]    = { .len = ATTR_LEN_NESTED,
                                            .next = ovs_vxlan_ext_attr_lens ,
                                            .next_max = OVS_VXLAN_EXT_MAX},
    [OVS_TUNNEL_KEY_ATTR_IPV6_SRC]      = { .len = 16 },
    [OVS_TUNNEL_KEY_ATTR_IPV6_DST]      = { .len = 16 },
};

static const struct attr_len_tbl ovs_flow_key_attr_lens[OVS_KEY_ATTR_GTPV1_MAX + 1] = {
    [OVS_KEY_ATTR_ENCAP]     = { .len = ATTR_LEN_NESTED },
    [OVS_KEY_ATTR_PRIORITY]  = { .len = 4 },
    [OVS_KEY_ATTR_SKB_MARK]  = { .len = 4 },
    [OVS_KEY_ATTR_DP_HASH]   = { .len = 4 },
    [OVS_KEY_ATTR_RECIRC_ID] = { .len = 4 },
    [OVS_KEY_ATTR_TUNNEL]    = { .len = ATTR_LEN_NESTED,
                                 .next = ovs_tun_key_attr_lens,
                                 .next_max = OVS_TUNNEL_KEY_ATTR_MAX },
    [OVS_KEY_ATTR_IN_PORT]   = { .len = 4  },
    [OVS_KEY_ATTR_ETHERNET]  = { .len = sizeof(struct ovs_key_ethernet) },
    [OVS_KEY_ATTR_VLAN]      = { .len = 2 },
    [OVS_KEY_ATTR_ETHERTYPE] = { .len = 2 },
    [OVS_KEY_ATTR_MPLS]      = { .len = ATTR_LEN_VARIABLE },
    [OVS_KEY_ATTR_IPV4]      = { .len = sizeof(struct ovs_key_ipv4) },
    [OVS_KEY_ATTR_IPV6]      = { .len = sizeof(struct ovs_key_ipv6) },
    [OVS_KEY_ATTR_TCP]       = { .len = sizeof(struct ovs_key_tcp) },
    [OVS_KEY_ATTR_TCP_FLAGS] = { .len = 2 },
    [OVS_KEY_ATTR_UDP]       = { .len = sizeof(struct ovs_key_udp) },
    [OVS_KEY_ATTR_SCTP]      = { .len = sizeof(struct ovs_key_sctp) },
    [OVS_KEY_ATTR_ICMP]      = { .len = sizeof(struct ovs_key_icmp) },
    [OVS_KEY_ATTR_ICMPV6]    = { .len = sizeof(struct ovs_key_icmpv6) },
    [OVS_KEY_ATTR_ARP]       = { .len = sizeof(struct ovs_key_arp) },
    [OVS_KEY_ATTR_ND]        = { .len = sizeof(struct ovs_key_nd) },
    [OVS_KEY_ATTR_CT_STATE]  = { .len = 4 },
    [OVS_KEY_ATTR_CT_ZONE]   = { .len = 2 },
    [OVS_KEY_ATTR_CT_MARK]   = { .len = 4 },
    [OVS_KEY_ATTR_CT_LABELS] = { .len = sizeof(struct ovs_key_ct_labels) },
	[OVS_KEY_ATTR_GTPV1]	 = { .len = sizeof(struct ovs_key_gtpv1) },
};

/* Returns the correct length of the payload for a flow key attribute of the
 * specified 'type', ATTR_LEN_INVALID if 'type' is unknown, ATTR_LEN_VARIABLE
 * if the attribute's payload is variable length, or ATTR_LEN_NESTED if the
 * payload is a nested type. */
static int
odp_key_attr_len(const struct attr_len_tbl tbl[], int max_len, uint16_t type)
{
    if (type > max_len) {
        return ATTR_LEN_INVALID;
    }

    return tbl[type].len;
}

static void
format_generic_odp_key(const struct nlattr *a, struct ds *ds)
{
    size_t len = nl_attr_get_size(a);
    if (len) {
        const uint8_t *unspec;
        unsigned int i;

        unspec = nl_attr_get(a);
        for (i = 0; i < len; i++) {
            if (i) {
                ds_put_char(ds, ' ');
            }
            ds_put_format(ds, "%02x", unspec[i]);
        }
    }
}

static const char *
ovs_frag_type_to_string(enum ovs_frag_type type)
{
    switch (type) {
    case OVS_FRAG_TYPE_NONE:
        return "no";
    case OVS_FRAG_TYPE_FIRST:
        return "first";
    case OVS_FRAG_TYPE_LATER:
        return "later";
    case __OVS_FRAG_TYPE_MAX:
    default:
        return "<error>";
    }
}

static enum odp_key_fitness
odp_tun_key_from_attr__(const struct nlattr *attr,
                        const struct nlattr *flow_attrs, size_t flow_attr_len,
                        const struct flow_tnl *src_tun, struct flow_tnl *tun,
                        bool udpif)
{
    unsigned int left;
    const struct nlattr *a;
    bool ttl = false;
    bool unknown = false;

    NL_NESTED_FOR_EACH(a, left, attr) {
        uint16_t type = nl_attr_type(a);
        size_t len = nl_attr_get_size(a);
        int expected_len = odp_key_attr_len(ovs_tun_key_attr_lens,
                                            OVS_TUNNEL_ATTR_MAX, type);

        if (len != expected_len && expected_len >= 0) {
            return ODP_FIT_ERROR;
        }

        switch (type) {
        case OVS_TUNNEL_KEY_ATTR_ID:
            tun->tun_id = nl_attr_get_be64(a);
            tun->flags |= FLOW_TNL_F_KEY;
            break;
        case OVS_TUNNEL_KEY_ATTR_IPV4_SRC:
            tun->ip_src = nl_attr_get_be32(a);
            break;
        case OVS_TUNNEL_KEY_ATTR_IPV4_DST:
            tun->ip_dst = nl_attr_get_be32(a);
            break;
        case OVS_TUNNEL_KEY_ATTR_IPV6_SRC:
            tun->ipv6_src = nl_attr_get_in6_addr(a);
            break;
        case OVS_TUNNEL_KEY_ATTR_IPV6_DST:
            tun->ipv6_dst = nl_attr_get_in6_addr(a);
            break;
        case OVS_TUNNEL_KEY_ATTR_TOS:
            tun->ip_tos = nl_attr_get_u8(a);
            break;
        case OVS_TUNNEL_KEY_ATTR_TTL:
            tun->ip_ttl = nl_attr_get_u8(a);
            ttl = true;
            break;
        case OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT:
            tun->flags |= FLOW_TNL_F_DONT_FRAGMENT;
            break;
        case OVS_TUNNEL_KEY_ATTR_CSUM:
            tun->flags |= FLOW_TNL_F_CSUM;
            break;
        case OVS_TUNNEL_KEY_ATTR_TP_SRC:
            tun->tp_src = nl_attr_get_be16(a);
            break;
        case OVS_TUNNEL_KEY_ATTR_TP_DST:
            tun->tp_dst = nl_attr_get_be16(a);
            break;
        case OVS_TUNNEL_KEY_ATTR_OAM:
            tun->flags |= FLOW_TNL_F_OAM;
            break;
        case OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS: {
            static const struct nl_policy vxlan_opts_policy[] = {
                [OVS_VXLAN_EXT_GBP] = { .type = NL_A_U32 },
            };
            struct nlattr *ext[ARRAY_SIZE(vxlan_opts_policy)];

            if (!nl_parse_nested(a, vxlan_opts_policy, ext, ARRAY_SIZE(ext))) {
                return ODP_FIT_ERROR;
            }

            if (ext[OVS_VXLAN_EXT_GBP]) {
                uint32_t gbp = nl_attr_get_u32(ext[OVS_VXLAN_EXT_GBP]);

                tun->gbp_id = htons(gbp & 0xFFFF);
                tun->gbp_flags = (gbp >> 16) & 0xFF;
            }

            break;
        }
        case OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS:
            if (tun_metadata_from_geneve_nlattr(a, flow_attrs, flow_attr_len,
                                                src_tun, udpif, tun)) {
                return ODP_FIT_ERROR;
            }
            break;

        default:
            /* Allow this to show up as unexpected, if there are unknown
             * tunnel attribute, eventually resulting in ODP_FIT_TOO_MUCH. */
            unknown = true;
            break;
        }
    }

    if (!ttl) {
        return ODP_FIT_ERROR;
    }
    if (unknown) {
        return ODP_FIT_TOO_MUCH;
    }
    return ODP_FIT_PERFECT;
}

enum odp_key_fitness
odp_tun_key_from_attr(const struct nlattr *attr, bool udpif,
                      struct flow_tnl *tun)
{
    memset(tun, 0, sizeof *tun);
    return odp_tun_key_from_attr__(attr, NULL, 0, NULL, tun, udpif);
}

static void
tun_key_to_attr(struct ofpbuf *a, const struct flow_tnl *tun_key,
                const struct flow_tnl *tun_flow_key,
                const struct ofpbuf *key_buf)
{
    size_t tun_key_ofs;

    tun_key_ofs = nl_msg_start_nested(a, OVS_KEY_ATTR_TUNNEL);

    /* tun_id != 0 without FLOW_TNL_F_KEY is valid if tun_key is a mask. */
    if (tun_key->tun_id || tun_key->flags & FLOW_TNL_F_KEY) {
        nl_msg_put_be64(a, OVS_TUNNEL_KEY_ATTR_ID, tun_key->tun_id);
    }
    if (tun_key->ip_src) {
        nl_msg_put_be32(a, OVS_TUNNEL_KEY_ATTR_IPV4_SRC, tun_key->ip_src);
    }
    if (tun_key->ip_dst) {
        nl_msg_put_be32(a, OVS_TUNNEL_KEY_ATTR_IPV4_DST, tun_key->ip_dst);
    }
    if (ipv6_addr_is_set(&tun_key->ipv6_src)) {
        nl_msg_put_in6_addr(a, OVS_TUNNEL_KEY_ATTR_IPV6_SRC, &tun_key->ipv6_src);
    }
    if (ipv6_addr_is_set(&tun_key->ipv6_dst)) {
        nl_msg_put_in6_addr(a, OVS_TUNNEL_KEY_ATTR_IPV6_DST, &tun_key->ipv6_dst);
    }
    if (tun_key->ip_tos) {
        nl_msg_put_u8(a, OVS_TUNNEL_KEY_ATTR_TOS, tun_key->ip_tos);
    }
    nl_msg_put_u8(a, OVS_TUNNEL_KEY_ATTR_TTL, tun_key->ip_ttl);
    if (tun_key->flags & FLOW_TNL_F_DONT_FRAGMENT) {
        nl_msg_put_flag(a, OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT);
    }
    if (tun_key->flags & FLOW_TNL_F_CSUM) {
        nl_msg_put_flag(a, OVS_TUNNEL_KEY_ATTR_CSUM);
    }
    if (tun_key->tp_src) {
        nl_msg_put_be16(a, OVS_TUNNEL_KEY_ATTR_TP_SRC, tun_key->tp_src);
    }
    if (tun_key->tp_dst) {
        nl_msg_put_be16(a, OVS_TUNNEL_KEY_ATTR_TP_DST, tun_key->tp_dst);
    }
    if (tun_key->flags & FLOW_TNL_F_OAM) {
        nl_msg_put_flag(a, OVS_TUNNEL_KEY_ATTR_OAM);
    }
    if (tun_key->gbp_flags || tun_key->gbp_id) {
        size_t vxlan_opts_ofs;

        vxlan_opts_ofs = nl_msg_start_nested(a, OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS);
        nl_msg_put_u32(a, OVS_VXLAN_EXT_GBP,
                       (tun_key->gbp_flags << 16) | ntohs(tun_key->gbp_id));
        nl_msg_end_nested(a, vxlan_opts_ofs);
    }
    tun_metadata_to_geneve_nlattr(tun_key, tun_flow_key, key_buf, a);

    nl_msg_end_nested(a, tun_key_ofs);
}

static bool
odp_mask_attr_is_wildcard(const struct nlattr *ma)
{
    return is_all_zeros(nl_attr_get(ma), nl_attr_get_size(ma));
}

static bool
odp_mask_is_exact(enum ovs_key_attr attr, const void *mask, size_t size)
{
    if (attr == OVS_KEY_ATTR_TCP_FLAGS) {
        return TCP_FLAGS(*(ovs_be16 *)mask) == TCP_FLAGS(OVS_BE16_MAX);
    }
    if (attr == OVS_KEY_ATTR_IPV6) {
        const struct ovs_key_ipv6 *ipv6_mask = mask;

        return
            ((ipv6_mask->ipv6_label & htonl(IPV6_LABEL_MASK))
             == htonl(IPV6_LABEL_MASK))
            && ipv6_mask->ipv6_proto == UINT8_MAX
            && ipv6_mask->ipv6_tclass == UINT8_MAX
            && ipv6_mask->ipv6_hlimit == UINT8_MAX
            && ipv6_mask->ipv6_frag == UINT8_MAX
            && ipv6_mask_is_exact((const struct in6_addr *)ipv6_mask->ipv6_src)
            && ipv6_mask_is_exact((const struct in6_addr *)ipv6_mask->ipv6_dst);
    }
    if (attr == OVS_KEY_ATTR_TUNNEL) {
        return false;
    }

    if (attr == OVS_KEY_ATTR_ARP) {
        /* ARP key has padding, ignore it. */
        BUILD_ASSERT_DECL(sizeof(struct ovs_key_arp) == 24);
        BUILD_ASSERT_DECL(offsetof(struct ovs_key_arp, arp_tha) == 10 + 6);
        size = offsetof(struct ovs_key_arp, arp_tha) + ETH_ADDR_LEN;
        ovs_assert(((uint16_t *)mask)[size/2] == 0);
    }

    return is_all_ones(mask, size);
}

static bool
odp_mask_attr_is_exact(const struct nlattr *ma)
{
	uint16_t attr = nl_attr_type(ma);
    const void *mask;
    size_t size;

    if (attr == OVS_KEY_ATTR_TUNNEL) {
        return false;
    } else {
        mask = nl_attr_get(ma);
        size = nl_attr_get_size(ma);
    }

    return odp_mask_is_exact(attr, mask, size);
}

void
odp_portno_names_set(struct hmap *portno_names, odp_port_t port_no,
                     char *port_name)
{
    struct odp_portno_names *odp_portno_names;

    odp_portno_names = xmalloc(sizeof *odp_portno_names);
    odp_portno_names->port_no = port_no;
    odp_portno_names->name = xstrdup(port_name);
    hmap_insert(portno_names, &odp_portno_names->hmap_node,
                hash_odp_port(port_no));
}

static char *
odp_portno_names_get(const struct hmap *portno_names, odp_port_t port_no)
{
    struct odp_portno_names *odp_portno_names;

    HMAP_FOR_EACH_IN_BUCKET (odp_portno_names, hmap_node,
                             hash_odp_port(port_no), portno_names) {
        if (odp_portno_names->port_no == port_no) {
            return odp_portno_names->name;
        }
    }
    return NULL;
}

void
odp_portno_names_destroy(struct hmap *portno_names)
{
    struct odp_portno_names *odp_portno_names, *odp_portno_names_next;
    HMAP_FOR_EACH_SAFE (odp_portno_names, odp_portno_names_next,
                        hmap_node, portno_names) {
        hmap_remove(portno_names, &odp_portno_names->hmap_node);
        free(odp_portno_names->name);
        free(odp_portno_names);
    }
}

/* Format helpers. */

static void
format_eth(struct ds *ds, const char *name, const struct eth_addr key,
           const struct eth_addr *mask, bool verbose)
{
    bool mask_empty = mask && eth_addr_is_zero(*mask);

    if (verbose || !mask_empty) {
        bool mask_full = !mask || eth_mask_is_exact(*mask);

        if (mask_full) {
            ds_put_format(ds, "%s="ETH_ADDR_FMT",", name, ETH_ADDR_ARGS(key));
        } else {
            ds_put_format(ds, "%s=", name);
            eth_format_masked(key, mask, ds);
            ds_put_char(ds, ',');
        }
    }
}

static void
format_be64(struct ds *ds, const char *name, ovs_be64 key,
            const ovs_be64 *mask, bool verbose)
{
    bool mask_empty = mask && !*mask;

    if (verbose || !mask_empty) {
        bool mask_full = !mask || *mask == OVS_BE64_MAX;

        ds_put_format(ds, "%s=0x%"PRIx64, name, ntohll(key));
        if (!mask_full) { /* Partially masked. */
            ds_put_format(ds, "/%#"PRIx64, ntohll(*mask));
        }
        ds_put_char(ds, ',');
    }
}

static void
format_ipv4(struct ds *ds, const char *name, ovs_be32 key,
            const ovs_be32 *mask, bool verbose)
{
    bool mask_empty = mask && !*mask;

    if (verbose || !mask_empty) {
        bool mask_full = !mask || *mask == OVS_BE32_MAX;

        ds_put_format(ds, "%s="IP_FMT, name, IP_ARGS(key));
        if (!mask_full) { /* Partially masked. */
            ds_put_format(ds, "/"IP_FMT, IP_ARGS(*mask));
        }
        ds_put_char(ds, ',');
    }
}

static void
format_in6_addr(struct ds *ds, const char *name,
                const struct in6_addr *key,
                const struct in6_addr *mask,
                bool verbose)
{
    char buf[INET6_ADDRSTRLEN];
    bool mask_empty = mask && ipv6_mask_is_any(mask);

    if (verbose || !mask_empty) {
        bool mask_full = !mask || ipv6_mask_is_exact(mask);

        inet_ntop(AF_INET6, key, buf, sizeof buf);
        ds_put_format(ds, "%s=%s", name, buf);
        if (!mask_full) { /* Partially masked. */
            inet_ntop(AF_INET6, mask, buf, sizeof buf);
            ds_put_format(ds, "/%s", buf);
        }
        ds_put_char(ds, ',');
    }
}

static void
format_ipv6(struct ds *ds, const char *name, const ovs_be32 key_[4],
            const ovs_be32 (*mask_)[4], bool verbose)
{
    format_in6_addr(ds, name,
                    (const struct in6_addr *)key_,
                    mask_ ? (const struct in6_addr *)*mask_ : NULL,
                    verbose);
}

static void
format_ipv6_label(struct ds *ds, const char *name, ovs_be32 key,
                  const ovs_be32 *mask, bool verbose)
{
    bool mask_empty = mask && !*mask;

    if (verbose || !mask_empty) {
        bool mask_full = !mask
            || (*mask & htonl(IPV6_LABEL_MASK)) == htonl(IPV6_LABEL_MASK);

        ds_put_format(ds, "%s=%#"PRIx32, name, ntohl(key));
        if (!mask_full) { /* Partially masked. */
            ds_put_format(ds, "/%#"PRIx32, ntohl(*mask));
        }
        ds_put_char(ds, ',');
    }
}

static void
format_u8x(struct ds *ds, const char *name, uint8_t key,
           const uint8_t *mask, bool verbose)
{
    bool mask_empty = mask && !*mask;

    if (verbose || !mask_empty) {
        bool mask_full = !mask || *mask == UINT8_MAX;

        ds_put_format(ds, "%s=%#"PRIx8, name, key);
        if (!mask_full) { /* Partially masked. */
            ds_put_format(ds, "/%#"PRIx8, *mask);
        }
        ds_put_char(ds, ',');
    }
}

static void
format_u8u(struct ds *ds, const char *name, uint8_t key,
           const uint8_t *mask, bool verbose)
{
    bool mask_empty = mask && !*mask;

    if (verbose || !mask_empty) {
        bool mask_full = !mask || *mask == UINT8_MAX;

        ds_put_format(ds, "%s=%"PRIu8, name, key);
        if (!mask_full) { /* Partially masked. */
            ds_put_format(ds, "/%#"PRIx8, *mask);
        }
        ds_put_char(ds, ',');
    }
}

static void
format_be16(struct ds *ds, const char *name, ovs_be16 key,
            const ovs_be16 *mask, bool verbose)
{
    bool mask_empty = mask && !*mask;

    if (verbose || !mask_empty) {
        bool mask_full = !mask || *mask == OVS_BE16_MAX;

        ds_put_format(ds, "%s=%"PRIu16, name, ntohs(key));
        if (!mask_full) { /* Partially masked. */
            ds_put_format(ds, "/%#"PRIx16, ntohs(*mask));
        }
        ds_put_char(ds, ',');
    }
}

static void
format_be16x(struct ds *ds, const char *name, ovs_be16 key,
             const ovs_be16 *mask, bool verbose)
{
    bool mask_empty = mask && !*mask;

    if (verbose || !mask_empty) {
        bool mask_full = !mask || *mask == OVS_BE16_MAX;

        ds_put_format(ds, "%s=%#"PRIx16, name, ntohs(key));
        if (!mask_full) { /* Partially masked. */
            ds_put_format(ds, "/%#"PRIx16, ntohs(*mask));
        }
        ds_put_char(ds, ',');
    }
}

static void
format_tun_flags(struct ds *ds, const char *name, uint16_t key,
                 const uint16_t *mask, bool verbose)
{
    bool mask_empty = mask && !*mask;

    if (verbose || !mask_empty) {
        ds_put_cstr(ds, name);
        ds_put_char(ds, '(');
        if (mask) {
            format_flags_masked(ds, NULL, flow_tun_flag_to_string, key,
                                *mask & FLOW_TNL_F_MASK, FLOW_TNL_F_MASK);
        } else { /* Fully masked. */
            format_flags(ds, flow_tun_flag_to_string, key, '|');
        }
        ds_put_cstr(ds, "),");
    }
}

static bool
check_attr_len(struct ds *ds, const struct nlattr *a, const struct nlattr *ma,
               const struct attr_len_tbl tbl[], int max_len, bool need_key)
{
    int expected_len;

    expected_len = odp_key_attr_len(tbl, max_len, nl_attr_type(a));
    if (expected_len != ATTR_LEN_VARIABLE &&
        expected_len != ATTR_LEN_NESTED) {

        bool bad_key_len = nl_attr_get_size(a) != expected_len;
        bool bad_mask_len = ma && nl_attr_get_size(ma) != expected_len;

        if (bad_key_len || bad_mask_len) {
            if (need_key) {
                ds_put_format(ds, "key%u", nl_attr_type(a));
            }
            if (bad_key_len) {
                ds_put_format(ds, "(bad key length %"PRIuSIZE", expected %d)(",
                              nl_attr_get_size(a), expected_len);
            }
            format_generic_odp_key(a, ds);
            if (ma) {
                ds_put_char(ds, '/');
                if (bad_mask_len) {
                    ds_put_format(ds, "(bad mask length %"PRIuSIZE", expected %d)(",
                                  nl_attr_get_size(ma), expected_len);
                }
                format_generic_odp_key(ma, ds);
            }
            ds_put_char(ds, ')');
            return false;
        }
    }

    return true;
}

static void
format_unknown_key(struct ds *ds, const struct nlattr *a,
                   const struct nlattr *ma)
{
    ds_put_format(ds, "key%u(", nl_attr_type(a));
    format_generic_odp_key(a, ds);
    if (ma && !odp_mask_attr_is_exact(ma)) {
        ds_put_char(ds, '/');
        format_generic_odp_key(ma, ds);
    }
    ds_put_cstr(ds, "),");
}

static void
format_odp_tun_vxlan_opt(const struct nlattr *attr,
                         const struct nlattr *mask_attr, struct ds *ds,
                         bool verbose)
{
    unsigned int left;
    const struct nlattr *a;
    struct ofpbuf ofp;

    ofpbuf_init(&ofp, 100);
    NL_NESTED_FOR_EACH(a, left, attr) {
        uint16_t type = nl_attr_type(a);
        const struct nlattr *ma = NULL;

        if (mask_attr) {
            ma = nl_attr_find__(nl_attr_get(mask_attr),
                                nl_attr_get_size(mask_attr), type);
            if (!ma) {
                ma = generate_all_wildcard_mask(ovs_vxlan_ext_attr_lens,
                                                OVS_VXLAN_EXT_MAX,
                                                &ofp, a);
            }
        }

        if (!check_attr_len(ds, a, ma, ovs_vxlan_ext_attr_lens,
                            OVS_VXLAN_EXT_MAX, true)) {
            continue;
        }

        switch (type) {
        case OVS_VXLAN_EXT_GBP: {
            uint32_t key = nl_attr_get_u32(a);
            ovs_be16 id, id_mask;
            uint8_t flags, flags_mask;

            id = htons(key & 0xFFFF);
            flags = (key >> 16) & 0xFF;
            if (ma) {
                uint32_t mask = nl_attr_get_u32(ma);
                id_mask = htons(mask & 0xFFFF);
                flags_mask = (mask >> 16) & 0xFF;
            }

            ds_put_cstr(ds, "gbp(");
            format_be16(ds, "id", id, ma ? &id_mask : NULL, verbose);
            format_u8x(ds, "flags", flags, ma ? &flags_mask : NULL, verbose);
            ds_chomp(ds, ',');
            ds_put_cstr(ds, "),");
            break;
        }

        default:
            format_unknown_key(ds, a, ma);
        }
        ofpbuf_clear(&ofp);
    }

    ds_chomp(ds, ',');
    ofpbuf_uninit(&ofp);
}

#define MASK(PTR, FIELD) PTR ? &PTR->FIELD : NULL

static void
format_geneve_opts(const struct geneve_opt *opt,
                   const struct geneve_opt *mask, int opts_len,
                   struct ds *ds, bool verbose)
{
    while (opts_len > 0) {
        unsigned int len;
        uint8_t data_len, data_len_mask;

        if (opts_len < sizeof *opt) {
            ds_put_format(ds, "opt len %u less than minimum %"PRIuSIZE,
                          opts_len, sizeof *opt);
            return;
        }

        data_len = opt->length * 4;
        if (mask) {
            if (mask->length == 0x1f) {
                data_len_mask = UINT8_MAX;
            } else {
                data_len_mask = mask->length;
            }
        }
        len = sizeof *opt + data_len;
        if (len > opts_len) {
            ds_put_format(ds, "opt len %u greater than remaining %u",
                          len, opts_len);
            return;
        }

        ds_put_char(ds, '{');
        format_be16x(ds, "class", opt->opt_class, MASK(mask, opt_class),
                    verbose);
        format_u8x(ds, "type", opt->type, MASK(mask, type), verbose);
        format_u8u(ds, "len", data_len, mask ? &data_len_mask : NULL, verbose);
        if (data_len &&
            (verbose || !mask || !is_all_zeros(mask + 1, data_len))) {
            ds_put_hex(ds, opt + 1, data_len);
            if (mask && !is_all_ones(mask + 1, data_len)) {
                ds_put_char(ds, '/');
                ds_put_hex(ds, mask + 1, data_len);
            }
        } else {
            ds_chomp(ds, ',');
        }
        ds_put_char(ds, '}');

        opt += len / sizeof(*opt);
        if (mask) {
            mask += len / sizeof(*opt);
        }
        opts_len -= len;
    };
}

static void
format_odp_tun_geneve(const struct nlattr *attr,
                      const struct nlattr *mask_attr, struct ds *ds,
                      bool verbose)
{
    int opts_len = nl_attr_get_size(attr);
    const struct geneve_opt *opt = nl_attr_get(attr);
    const struct geneve_opt *mask = mask_attr ?
                                    nl_attr_get(mask_attr) : NULL;

    if (mask && nl_attr_get_size(attr) != nl_attr_get_size(mask_attr)) {
        ds_put_format(ds, "value len %"PRIuSIZE" different from mask len %"PRIuSIZE,
                      nl_attr_get_size(attr), nl_attr_get_size(mask_attr));
        return;
    }

    format_geneve_opts(opt, mask, opts_len, ds, verbose);
}

static void
format_odp_tun_attr(const struct nlattr *attr, const struct nlattr *mask_attr,
                    struct ds *ds, bool verbose)
{
    unsigned int left;
    const struct nlattr *a;
    uint16_t flags = 0;
    uint16_t mask_flags = 0;
    struct ofpbuf ofp;

    ofpbuf_init(&ofp, 100);
    NL_NESTED_FOR_EACH(a, left, attr) {
        enum ovs_tunnel_key_attr type = nl_attr_type(a);
        const struct nlattr *ma = NULL;

        if (mask_attr) {
            ma = nl_attr_find__(nl_attr_get(mask_attr),
                                nl_attr_get_size(mask_attr), type);
            if (!ma) {
                ma = generate_all_wildcard_mask(ovs_tun_key_attr_lens,
                                                OVS_TUNNEL_KEY_ATTR_MAX,
                                                &ofp, a);
            }
        }

        if (!check_attr_len(ds, a, ma, ovs_tun_key_attr_lens,
                            OVS_TUNNEL_KEY_ATTR_MAX, true)) {
            continue;
        }

        switch (type) {
        case OVS_TUNNEL_KEY_ATTR_ID:
            format_be64(ds, "tun_id", nl_attr_get_be64(a),
                        ma ? nl_attr_get(ma) : NULL, verbose);
	    flags |= FLOW_TNL_F_KEY;
            if (ma) {
                mask_flags |= FLOW_TNL_F_KEY;
            }
            break;
        case OVS_TUNNEL_KEY_ATTR_IPV4_SRC:
            format_ipv4(ds, "src", nl_attr_get_be32(a),
                        ma ? nl_attr_get(ma) : NULL, verbose);
            break;
        case OVS_TUNNEL_KEY_ATTR_IPV4_DST:
            format_ipv4(ds, "dst", nl_attr_get_be32(a),
                        ma ? nl_attr_get(ma) : NULL, verbose);
            break;
        case OVS_TUNNEL_KEY_ATTR_IPV6_SRC: {
            struct in6_addr ipv6_src;
            ipv6_src = nl_attr_get_in6_addr(a);
            format_in6_addr(ds, "ipv6_src", &ipv6_src,
                            ma ? nl_attr_get(ma) : NULL, verbose);
            break;
        }
        case OVS_TUNNEL_KEY_ATTR_IPV6_DST: {
            struct in6_addr ipv6_dst;
            ipv6_dst = nl_attr_get_in6_addr(a);
            format_in6_addr(ds, "ipv6_dst", &ipv6_dst,
                            ma ? nl_attr_get(ma) : NULL, verbose);
            break;
        }
        case OVS_TUNNEL_KEY_ATTR_TOS:
            format_u8x(ds, "tos", nl_attr_get_u8(a),
                       ma ? nl_attr_get(ma) : NULL, verbose);
            break;
        case OVS_TUNNEL_KEY_ATTR_TTL:
            format_u8u(ds, "ttl", nl_attr_get_u8(a),
                       ma ? nl_attr_get(ma) : NULL, verbose);
            break;
        case OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT:
	    flags |= FLOW_TNL_F_DONT_FRAGMENT;
            break;
        case OVS_TUNNEL_KEY_ATTR_CSUM:
	    flags |= FLOW_TNL_F_CSUM;
            break;
        case OVS_TUNNEL_KEY_ATTR_TP_SRC:
            format_be16(ds, "tp_src", nl_attr_get_be16(a),
                        ma ? nl_attr_get(ma) : NULL, verbose);
            break;
        case OVS_TUNNEL_KEY_ATTR_TP_DST:
            format_be16(ds, "tp_dst", nl_attr_get_be16(a),
                        ma ? nl_attr_get(ma) : NULL, verbose);
            break;
        case OVS_TUNNEL_KEY_ATTR_OAM:
	    flags |= FLOW_TNL_F_OAM;
            break;
        case OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS:
            ds_put_cstr(ds, "vxlan(");
            format_odp_tun_vxlan_opt(a, ma, ds, verbose);
            ds_put_cstr(ds, "),");
            break;
        case OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS:
            ds_put_cstr(ds, "geneve(");
            format_odp_tun_geneve(a, ma, ds, verbose);
            ds_put_cstr(ds, "),");
            break;
        case __OVS_TUNNEL_KEY_ATTR_MAX:
        default:
            format_unknown_key(ds, a, ma);
        }
        ofpbuf_clear(&ofp);
    }

    /* Flags can have a valid mask even if the attribute is not set, so
     * we need to collect these separately. */
    if (mask_attr) {
        NL_NESTED_FOR_EACH(a, left, mask_attr) {
            switch (nl_attr_type(a)) {
            case OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT:
                mask_flags |= FLOW_TNL_F_DONT_FRAGMENT;
                break;
            case OVS_TUNNEL_KEY_ATTR_CSUM:
                mask_flags |= FLOW_TNL_F_CSUM;
                break;
            case OVS_TUNNEL_KEY_ATTR_OAM:
                mask_flags |= FLOW_TNL_F_OAM;
                break;
            }
        }
    }

    format_tun_flags(ds, "flags", flags, mask_attr ? &mask_flags : NULL,
                     verbose);
    ds_chomp(ds, ',');
    ofpbuf_uninit(&ofp);
}

static const char *
odp_ct_state_to_string(uint32_t flag)
{
    switch (flag) {
    case OVS_CS_F_REPLY_DIR:
        return "rpl";
    case OVS_CS_F_TRACKED:
        return "trk";
    case OVS_CS_F_NEW:
        return "new";
    case OVS_CS_F_ESTABLISHED:
        return "est";
    case OVS_CS_F_RELATED:
        return "rel";
    case OVS_CS_F_INVALID:
        return "inv";
    default:
        return NULL;
    }
}

static void
format_frag(struct ds *ds, const char *name, uint8_t key,
            const uint8_t *mask, bool verbose)
{
    bool mask_empty = mask && !*mask;

    /* ODP frag is an enumeration field; partial masks are not meaningful. */
    if (verbose || !mask_empty) {
        bool mask_full = !mask || *mask == UINT8_MAX;

        if (!mask_full) { /* Partially masked. */
            ds_put_format(ds, "error: partial mask not supported for frag (%#"
                          PRIx8"),", *mask);
        } else {
            ds_put_format(ds, "%s=%s,", name, ovs_frag_type_to_string(key));
        }
    }
}

static bool
mask_empty(const struct nlattr *ma)
{
    const void *mask;
    size_t n;

    if (!ma) {
        return true;
    }
    mask = nl_attr_get(ma);
    n = nl_attr_get_size(ma);

    return is_all_zeros(mask, n);
}

static void
format_odp_key_attr(const struct nlattr *a, const struct nlattr *ma,
                    const struct hmap *portno_names, struct ds *ds,
                    bool verbose)
{
    uint16_t attr = nl_attr_type(a);
    char namebuf[OVS_KEY_ATTR_BUFSIZE];
    bool is_exact;

    is_exact = ma ? odp_mask_attr_is_exact(ma) : true;

    ds_put_cstr(ds, ovs_key_attr_to_string(attr, namebuf, sizeof namebuf));

    if (!check_attr_len(ds, a, ma, ovs_flow_key_attr_lens,
		OVS_KEY_ATTR_GTPV1_MAX, false)) {
        return;
    }

    ds_put_char(ds, '(');
    switch (attr) {
    case OVS_KEY_ATTR_ENCAP:
        if (ma && nl_attr_get_size(ma) && nl_attr_get_size(a)) {
            odp_flow_format(nl_attr_get(a), nl_attr_get_size(a),
                            nl_attr_get(ma), nl_attr_get_size(ma), NULL, ds,
                            verbose);
        } else if (nl_attr_get_size(a)) {
            odp_flow_format(nl_attr_get(a), nl_attr_get_size(a), NULL, 0, NULL,
                            ds, verbose);
        }
        break;

    case OVS_KEY_ATTR_PRIORITY:
    case OVS_KEY_ATTR_SKB_MARK:
    case OVS_KEY_ATTR_DP_HASH:
    case OVS_KEY_ATTR_RECIRC_ID:
        ds_put_format(ds, "%#"PRIx32, nl_attr_get_u32(a));
        if (!is_exact) {
            ds_put_format(ds, "/%#"PRIx32, nl_attr_get_u32(ma));
        }
        break;

    case OVS_KEY_ATTR_CT_MARK:
        if (verbose || !mask_empty(ma)) {
            ds_put_format(ds, "%#"PRIx32, nl_attr_get_u32(a));
            if (!is_exact) {
                ds_put_format(ds, "/%#"PRIx32, nl_attr_get_u32(ma));
            }
        }
        break;

    case OVS_KEY_ATTR_CT_STATE:
        if (verbose) {
                ds_put_format(ds, "%#"PRIx32, nl_attr_get_u32(a));
                if (!is_exact) {
                    ds_put_format(ds, "/%#"PRIx32,
                                  mask_empty(ma) ? 0 : nl_attr_get_u32(ma));
                }
        } else if (!is_exact) {
            format_flags_masked(ds, NULL, odp_ct_state_to_string,
                                nl_attr_get_u32(a),
                                mask_empty(ma) ? 0 : nl_attr_get_u32(ma),
                                UINT32_MAX);
        } else {
            format_flags(ds, odp_ct_state_to_string, nl_attr_get_u32(a), '|');
        }
        break;

    case OVS_KEY_ATTR_CT_ZONE:
        if (verbose || !mask_empty(ma)) {
            ds_put_format(ds, "%#"PRIx16, nl_attr_get_u16(a));
            if (!is_exact) {
                ds_put_format(ds, "/%#"PRIx16, nl_attr_get_u16(ma));
            }
        }
        break;

    case OVS_KEY_ATTR_CT_LABELS: {
        const ovs_u128 *value = nl_attr_get(a);
        const ovs_u128 *mask = ma ? nl_attr_get(ma) : NULL;

        format_u128(ds, value, mask, verbose);
        break;
    }

    case OVS_KEY_ATTR_TUNNEL:
        format_odp_tun_attr(a, ma, ds, verbose);
        break;

    case OVS_KEY_ATTR_IN_PORT:
        if (portno_names && verbose && is_exact) {
            char *name = odp_portno_names_get(portno_names,
                            u32_to_odp(nl_attr_get_u32(a)));
            if (name) {
                ds_put_format(ds, "%s", name);
            } else {
                ds_put_format(ds, "%"PRIu32, nl_attr_get_u32(a));
            }
        } else {
            ds_put_format(ds, "%"PRIu32, nl_attr_get_u32(a));
            if (!is_exact) {
                ds_put_format(ds, "/%#"PRIx32, nl_attr_get_u32(ma));
            }
        }
        break;

    case OVS_KEY_ATTR_ETHERNET: {
        const struct ovs_key_ethernet *mask = ma ? nl_attr_get(ma) : NULL;
        const struct ovs_key_ethernet *key = nl_attr_get(a);

        format_eth(ds, "src", key->eth_src, MASK(mask, eth_src), verbose);
        format_eth(ds, "dst", key->eth_dst, MASK(mask, eth_dst), verbose);
        ds_chomp(ds, ',');
        break;
    }
    case OVS_KEY_ATTR_VLAN:
        format_vlan_tci(ds, nl_attr_get_be16(a),
                        ma ? nl_attr_get_be16(ma) : OVS_BE16_MAX, verbose);
        break;

    case OVS_KEY_ATTR_MPLS: {
        const struct ovs_key_mpls *mpls_key = nl_attr_get(a);
        const struct ovs_key_mpls *mpls_mask = NULL;
        size_t size = nl_attr_get_size(a);

        if (!size || size % sizeof *mpls_key) {
            ds_put_format(ds, "(bad key length %"PRIuSIZE")", size);
            return;
        }
        if (!is_exact) {
            mpls_mask = nl_attr_get(ma);
            if (size != nl_attr_get_size(ma)) {
                ds_put_format(ds, "(key length %"PRIuSIZE" != "
                              "mask length %"PRIuSIZE")",
                              size, nl_attr_get_size(ma));
                return;
            }
        }
        format_mpls(ds, mpls_key, mpls_mask, size / sizeof *mpls_key);
        break;
    }
    case OVS_KEY_ATTR_ETHERTYPE:
        ds_put_format(ds, "0x%04"PRIx16, ntohs(nl_attr_get_be16(a)));
        if (!is_exact) {
            ds_put_format(ds, "/0x%04"PRIx16, ntohs(nl_attr_get_be16(ma)));
        }
        break;

	case OVS_KEY_ATTR_GTPV1:
	{
		const struct ovs_key_gtpv1 *key = nl_attr_get(a);
		const struct ovs_key_gtpv1 *mask = ma ? nl_attr_get(ma) : NULL;

		ds_put_format(ds, "teid=%u", ntohl(key->teid));
		ds_put_char(ds, ',');
		format_ipv4(ds, "dst", key->ipv4_dst, MASK(mask, ipv4_dst), verbose);
		ds_chomp(ds, ',');
		break;
	}

    case OVS_KEY_ATTR_IPV4: {
        const struct ovs_key_ipv4 *key = nl_attr_get(a);
        const struct ovs_key_ipv4 *mask = ma ? nl_attr_get(ma) : NULL;

        format_ipv4(ds, "src", key->ipv4_src, MASK(mask, ipv4_src), verbose);
        format_ipv4(ds, "dst", key->ipv4_dst, MASK(mask, ipv4_dst), verbose);
        format_u8u(ds, "proto", key->ipv4_proto, MASK(mask, ipv4_proto),
                      verbose);
        format_u8x(ds, "tos", key->ipv4_tos, MASK(mask, ipv4_tos), verbose);
        format_u8u(ds, "ttl", key->ipv4_ttl, MASK(mask, ipv4_ttl), verbose);
        format_frag(ds, "frag", key->ipv4_frag, MASK(mask, ipv4_frag),
                    verbose);
        ds_chomp(ds, ',');
        break;
    }
    case OVS_KEY_ATTR_IPV6: {
        const struct ovs_key_ipv6 *key = nl_attr_get(a);
        const struct ovs_key_ipv6 *mask = ma ? nl_attr_get(ma) : NULL;

        format_ipv6(ds, "src", key->ipv6_src, MASK(mask, ipv6_src), verbose);
        format_ipv6(ds, "dst", key->ipv6_dst, MASK(mask, ipv6_dst), verbose);
        format_ipv6_label(ds, "label", key->ipv6_label, MASK(mask, ipv6_label),
                          verbose);
        format_u8u(ds, "proto", key->ipv6_proto, MASK(mask, ipv6_proto),
                      verbose);
        format_u8x(ds, "tclass", key->ipv6_tclass, MASK(mask, ipv6_tclass),
                      verbose);
        format_u8u(ds, "hlimit", key->ipv6_hlimit, MASK(mask, ipv6_hlimit),
                      verbose);
        format_frag(ds, "frag", key->ipv6_frag, MASK(mask, ipv6_frag),
                    verbose);
        ds_chomp(ds, ',');
        break;
    }
        /* These have the same structure and format. */
    case OVS_KEY_ATTR_TCP:
    case OVS_KEY_ATTR_UDP:
    case OVS_KEY_ATTR_SCTP: {
        const struct ovs_key_tcp *key = nl_attr_get(a);
        const struct ovs_key_tcp *mask = ma ? nl_attr_get(ma) : NULL;

        format_be16(ds, "src", key->tcp_src, MASK(mask, tcp_src), verbose);
        format_be16(ds, "dst", key->tcp_dst, MASK(mask, tcp_dst), verbose);
        ds_chomp(ds, ',');
        break;
    }
    case OVS_KEY_ATTR_TCP_FLAGS:
        if (!is_exact) {
            format_flags_masked(ds, NULL, packet_tcp_flag_to_string,
                                ntohs(nl_attr_get_be16(a)),
                                TCP_FLAGS(nl_attr_get_be16(ma)),
                                TCP_FLAGS(OVS_BE16_MAX));
        } else {
            format_flags(ds, packet_tcp_flag_to_string,
                         ntohs(nl_attr_get_be16(a)), '|');
        }
        break;

    case OVS_KEY_ATTR_ICMP: {
        const struct ovs_key_icmp *key = nl_attr_get(a);
        const struct ovs_key_icmp *mask = ma ? nl_attr_get(ma) : NULL;

        format_u8u(ds, "type", key->icmp_type, MASK(mask, icmp_type), verbose);
        format_u8u(ds, "code", key->icmp_code, MASK(mask, icmp_code), verbose);
        ds_chomp(ds, ',');
        break;
    }
    case OVS_KEY_ATTR_ICMPV6: {
        const struct ovs_key_icmpv6 *key = nl_attr_get(a);
        const struct ovs_key_icmpv6 *mask = ma ? nl_attr_get(ma) : NULL;

        format_u8u(ds, "type", key->icmpv6_type, MASK(mask, icmpv6_type),
                   verbose);
        format_u8u(ds, "code", key->icmpv6_code, MASK(mask, icmpv6_code),
                   verbose);
        ds_chomp(ds, ',');
        break;
    }
    case OVS_KEY_ATTR_ARP: {
        const struct ovs_key_arp *mask = ma ? nl_attr_get(ma) : NULL;
        const struct ovs_key_arp *key = nl_attr_get(a);

        format_ipv4(ds, "sip", key->arp_sip, MASK(mask, arp_sip), verbose);
        format_ipv4(ds, "tip", key->arp_tip, MASK(mask, arp_tip), verbose);
        format_be16(ds, "op", key->arp_op, MASK(mask, arp_op), verbose);
        format_eth(ds, "sha", key->arp_sha, MASK(mask, arp_sha), verbose);
        format_eth(ds, "tha", key->arp_tha, MASK(mask, arp_tha), verbose);
        ds_chomp(ds, ',');
        break;
    }
    case OVS_KEY_ATTR_ND: {
        const struct ovs_key_nd *mask = ma ? nl_attr_get(ma) : NULL;
        const struct ovs_key_nd *key = nl_attr_get(a);

        format_ipv6(ds, "target", key->nd_target, MASK(mask, nd_target),
                    verbose);
        format_eth(ds, "sll", key->nd_sll, MASK(mask, nd_sll), verbose);
        format_eth(ds, "tll", key->nd_tll, MASK(mask, nd_tll), verbose);

        ds_chomp(ds, ',');
        break;
    }
    case OVS_KEY_ATTR_UNSPEC:
    case __OVS_KEY_ATTR_GTPV1_MAX:
    default:
        format_generic_odp_key(a, ds);
        if (!is_exact) {
            ds_put_char(ds, '/');
            format_generic_odp_key(ma, ds);
        }
        break;
    }
    ds_put_char(ds, ')');
}

static struct nlattr *
generate_all_wildcard_mask(const struct attr_len_tbl tbl[], int max,
                           struct ofpbuf *ofp, const struct nlattr *key)
{
    const struct nlattr *a;
    unsigned int left;
    int type = nl_attr_type(key);
    int size = nl_attr_get_size(key);

    if (odp_key_attr_len(tbl, max, type) != ATTR_LEN_NESTED) {
        nl_msg_put_unspec_zero(ofp, type, size);
    } else {
        size_t nested_mask;

        if (tbl[type].next) {
            tbl = tbl[type].next;
            max = tbl[type].next_max;
        }

        nested_mask = nl_msg_start_nested(ofp, type);
        NL_ATTR_FOR_EACH(a, left, key, nl_attr_get_size(key)) {
            generate_all_wildcard_mask(tbl, max, ofp, nl_attr_get(a));
        }
        nl_msg_end_nested(ofp, nested_mask);
    }

    return ofp->base;
}

static void
format_u128(struct ds *ds, const ovs_u128 *key, const ovs_u128 *mask,
            bool verbose)
{
    if (verbose || (mask && !ovs_u128_is_zero(mask))) {
        ovs_be128 value;

        value = hton128(*key);
        ds_put_hex(ds, &value, sizeof value);
        if (mask && !(ovs_u128_is_ones(mask))) {
            value = hton128(*mask);
            ds_put_char(ds, '/');
            ds_put_hex(ds, &value, sizeof value);
        }
    }
}

static int
scan_u128(const char *s_, ovs_u128 *value, ovs_u128 *mask)
{
    char *s = CONST_CAST(char *, s_);
    ovs_be128 be_value;
    ovs_be128 be_mask;

    if (!parse_int_string(s, (uint8_t *)&be_value, sizeof be_value, &s)) {
        *value = ntoh128(be_value);

        if (mask) {
            int n;

            if (ovs_scan(s, "/%n", &n)) {
                int error;

                s += n;
                error = parse_int_string(s, (uint8_t *)&be_mask,
                                         sizeof be_mask, &s);
                if (error) {
                    return error;
                }
                *mask = ntoh128(be_mask);
            } else {
                *mask = OVS_U128_MAX;
            }
        }
        return s - s_;
    }

    return 0;
}

int
odp_ufid_from_string(const char *s_, ovs_u128 *ufid)
{
    const char *s = s_;

    if (ovs_scan(s, "ufid:")) {
        s += 5;

        if (!uuid_from_string_prefix((struct uuid *)ufid, s)) {
            return -EINVAL;
        }
        s += UUID_LEN;

        return s - s_;
    }

    return 0;
}

void
odp_format_ufid(const ovs_u128 *ufid, struct ds *ds)
{
    ds_put_format(ds, "ufid:"UUID_FMT, UUID_ARGS((struct uuid *)ufid));
}

/* Appends to 'ds' a string representation of the 'key_len' bytes of
 * OVS_KEY_ATTR_* attributes in 'key'. If non-null, additionally formats the
 * 'mask_len' bytes of 'mask' which apply to 'key'. If 'portno_names' is
 * non-null and 'verbose' is true, translates odp port number to its name. */
void
odp_flow_format(const struct nlattr *key, size_t key_len,
                const struct nlattr *mask, size_t mask_len,
                const struct hmap *portno_names, struct ds *ds, bool verbose)
{
    if (key_len) {
        const struct nlattr *a;
        unsigned int left;
        bool has_ethtype_key = false;
		bool has_gtpv1_key = false;
        const struct nlattr *ma = NULL;
        struct ofpbuf ofp;
        bool first_field = true;

        ofpbuf_init(&ofp, 100);
        NL_ATTR_FOR_EACH (a, left, key, key_len)
		{
            bool is_nested_attr;
            bool is_wildcard = false;
            int attr_type = nl_attr_type(a);

            if (attr_type == OVS_KEY_ATTR_ETHERTYPE)
                has_ethtype_key = true;

			if (attr_type == OVS_KEY_ATTR_GTPV1)
				has_gtpv1_key = true;

            is_nested_attr = odp_key_attr_len(ovs_flow_key_attr_lens,
                                              OVS_KEY_ATTR_GTPV1_MAX, attr_type) ==
                             ATTR_LEN_NESTED;

            if (mask && mask_len) {
                ma = nl_attr_find__(mask, mask_len, nl_attr_type(a));
                is_wildcard = ma ? odp_mask_attr_is_wildcard(ma) : true;
            }

            if (verbose || !is_wildcard  || is_nested_attr) {
                if (is_wildcard && !ma) {
                    ma = generate_all_wildcard_mask(ovs_flow_key_attr_lens,
													OVS_KEY_ATTR_GTPV1_MAX,
                                                    &ofp, a);
                }
                if (!first_field) {
                    ds_put_char(ds, ',');
                }
                format_odp_key_attr(a, ma, portno_names, ds, verbose);
                first_field = false;
            }
            ofpbuf_clear(&ofp);
        }
        ofpbuf_uninit(&ofp);

        if (left) {
            int i;

            if (left == key_len) {
                ds_put_cstr(ds, "<empty>");
            }
            ds_put_format(ds, ",***%u leftover bytes*** (", left);
            for (i = 0; i < left; i++) {
                ds_put_format(ds, "%02x", ((const uint8_t *) a)[i]);
            }
            ds_put_char(ds, ')');
        }
        if (!has_gtpv1_key && !has_ethtype_key) {
            ma = nl_attr_find__(mask, mask_len, OVS_KEY_ATTR_ETHERTYPE);
            if (ma) {
                ds_put_format(ds, ",eth_type(0/0x%04"PRIx16")",
                              ntohs(nl_attr_get_be16(ma)));
            }
        }
    } else {
        ds_put_cstr(ds, "<empty>");
    }
}

/* Appends to 'ds' a string representation of the 'key_len' bytes of
 * OVS_KEY_ATTR_* attributes in 'key'. */
void
odp_flow_key_format(const struct nlattr *key,
                    size_t key_len, struct ds *ds)
{
    odp_flow_format(key, key_len, NULL, 0, NULL, ds, true);
}

static bool
ovs_frag_type_from_string(const char *s, enum ovs_frag_type *type)
{
    if (!strcasecmp(s, "no")) {
        *type = OVS_FRAG_TYPE_NONE;
    } else if (!strcasecmp(s, "first")) {
        *type = OVS_FRAG_TYPE_FIRST;
    } else if (!strcasecmp(s, "later")) {
        *type = OVS_FRAG_TYPE_LATER;
    } else {
        return false;
    }
    return true;
}

/* Parsing. */

static int
scan_eth(const char *s, struct eth_addr *key, struct eth_addr *mask)
{
    int n;

    if (ovs_scan(s, ETH_ADDR_SCAN_FMT"%n",
                 ETH_ADDR_SCAN_ARGS(*key), &n)) {
        int len = n;

        if (mask) {
            if (ovs_scan(s + len, "/"ETH_ADDR_SCAN_FMT"%n",
                         ETH_ADDR_SCAN_ARGS(*mask), &n)) {
                len += n;
            } else {
                memset(mask, 0xff, sizeof *mask);
            }
        }

        return len;
    }
    return 0;
}

static int
scan_ipv4(const char *s, ovs_be32 *key, ovs_be32 *mask)
{
    int n;

    if (ovs_scan(s, IP_SCAN_FMT"%n", IP_SCAN_ARGS(key), &n)) {
        int len = n;

        if (mask) {
            if (ovs_scan(s + len, "/"IP_SCAN_FMT"%n",
                         IP_SCAN_ARGS(mask), &n)) {
                len += n;
            } else {
                *mask = OVS_BE32_MAX;
            }
        }

        return len;
    }
    return 0;
}

static int
scan_in6_addr(const char *s, struct in6_addr *key, struct in6_addr *mask)
{
    int n;
    char ipv6_s[IPV6_SCAN_LEN + 1];

    if (ovs_scan(s, IPV6_SCAN_FMT"%n", ipv6_s, &n)
        && inet_pton(AF_INET6, ipv6_s, key) == 1) {
        int len = n;

        if (mask) {
            if (ovs_scan(s + len, "/"IPV6_SCAN_FMT"%n", ipv6_s, &n)
                && inet_pton(AF_INET6, ipv6_s, mask) == 1) {
                len += n;
            } else {
                memset(mask, 0xff, sizeof *mask);
            }
        }
        return len;
    }
    return 0;
}

static int
scan_ipv6(const char *s, ovs_be32 (*key)[4], ovs_be32 (*mask)[4])
{
    return scan_in6_addr(s, key ? (struct in6_addr *) *key : NULL,
                         mask ? (struct in6_addr *) *mask : NULL);
}

static int
scan_ipv6_label(const char *s, ovs_be32 *key, ovs_be32 *mask)
{
    int key_, mask_;
    int n;

    if (ovs_scan(s, "%i%n", &key_, &n)
        && (key_ & ~IPV6_LABEL_MASK) == 0) {
        int len = n;

        *key = htonl(key_);
        if (mask) {
            if (ovs_scan(s + len, "/%i%n", &mask_, &n)
                && (mask_ & ~IPV6_LABEL_MASK) == 0) {
                len += n;
                *mask = htonl(mask_);
            } else {
                *mask = htonl(IPV6_LABEL_MASK);
            }
        }
        return len;
    }
    return 0;
}

static int
scan_u8(const char *s, uint8_t *key, uint8_t *mask)
{
    int n;

    if (ovs_scan(s, "%"SCNi8"%n", key, &n)) {
        int len = n;

        if (mask) {
            if (ovs_scan(s + len, "/%"SCNi8"%n", mask, &n)) {
                len += n;
            } else {
                *mask = UINT8_MAX;
            }
        }
        return len;
    }
    return 0;
}

static int
scan_u16(const char *s, uint16_t *key, uint16_t *mask)
{
    int n;

    if (ovs_scan(s, "%"SCNi16"%n", key, &n)) {
        int len = n;

        if (mask) {
            if (ovs_scan(s + len, "/%"SCNi16"%n", mask, &n)) {
                len += n;
            } else {
                *mask = UINT16_MAX;
            }
        }
        return len;
    }
    return 0;
}

static int
scan_u32(const char *s, uint32_t *key, uint32_t *mask)
{
    int n;

    if (ovs_scan(s, "%"SCNi32"%n", key, &n)) {
        int len = n;

        if (mask) {
            if (ovs_scan(s + len, "/%"SCNi32"%n", mask, &n)) {
                len += n;
            } else {
                *mask = UINT32_MAX;
            }
        }
        return len;
    }
    return 0;
}

static int scan_gtp_teid(const char *s, ovs_be32 *key, ovs_be32 *mask)
{
	uint32_t key_;
	int n;

	if (ovs_scan(s, "%"SCNi32"%n", &key_, &n))
	{
		int len = n;
		*key = htonl(key_);

		if (mask)
		{
			*mask = OVS_BE32_MAX;
		}
		
		return len;
	}

	return 0;
}

static int
scan_be16(const char *s, ovs_be16 *key, ovs_be16 *mask)
{
    uint16_t key_, mask_;
    int n;

    if (ovs_scan(s, "%"SCNi16"%n", &key_, &n)) {
        int len = n;
        *key = htons(key_);

        if (mask) {
            if (ovs_scan(s + len, "/%"SCNi16"%n", &mask_, &n)) {
                len += n;
                *mask = htons(mask_);
            } else {
                *mask = OVS_BE16_MAX;
            }
        }

        return len;
    }
    return 0;
}

static int
scan_be64(const char *s, ovs_be64 *key, ovs_be64 *mask)
{
    uint64_t key_, mask_;
    int n;

    if (ovs_scan(s, "%"SCNi64"%n", &key_, &n)) {
        int len = n;

        *key = htonll(key_);
        if (mask) {
            if (ovs_scan(s + len, "/%"SCNi64"%n", &mask_, &n)) {
                len += n;
                *mask = htonll(mask_);
            } else {
                *mask = OVS_BE64_MAX;
            }
        }
        return len;
    }
    return 0;
}

static int
scan_tun_flags(const char *s, uint16_t *key, uint16_t *mask)
{
    uint32_t flags, fmask;
    int n;

    n = parse_odp_flags(s, flow_tun_flag_to_string, &flags,
                        FLOW_TNL_F_MASK, mask ? &fmask : NULL);
    if (n >= 0 && s[n] == ')') {
        *key = flags;
        if (mask) {
            *mask = fmask;
        }
        return n + 1;
    }
    return 0;
}

static int
scan_tcp_flags(const char *s, ovs_be16 *key, ovs_be16 *mask)
{
    uint32_t flags, fmask;
    int n;

    n = parse_odp_flags(s, packet_tcp_flag_to_string, &flags,
                        TCP_FLAGS(OVS_BE16_MAX), mask ? &fmask : NULL);
    if (n >= 0) {
        *key = htons(flags);
        if (mask) {
            *mask = htons(fmask);
        }
        return n;
    }
    return 0;
}

static uint32_t
ovs_to_odp_ct_state(uint8_t state)
{
    uint32_t odp = 0;

    if (state & CS_NEW) {
        odp |= OVS_CS_F_NEW;
    }
    if (state & CS_ESTABLISHED) {
        odp |= OVS_CS_F_ESTABLISHED;
    }
    if (state & CS_RELATED) {
        odp |= OVS_CS_F_RELATED;
    }
    if (state & CS_INVALID) {
        odp |= OVS_CS_F_INVALID;
    }
    if (state & CS_REPLY_DIR) {
        odp |= OVS_CS_F_REPLY_DIR;
    }
    if (state & CS_TRACKED) {
        odp |= OVS_CS_F_TRACKED;
    }

    return odp;
}

static uint8_t
odp_to_ovs_ct_state(uint32_t flags)
{
    uint32_t state = 0;

    if (flags & OVS_CS_F_NEW) {
        state |= CS_NEW;
    }
    if (flags & OVS_CS_F_ESTABLISHED) {
        state |= CS_ESTABLISHED;
    }
    if (flags & OVS_CS_F_RELATED) {
        state |= CS_RELATED;
    }
    if (flags & OVS_CS_F_INVALID) {
        state |= CS_INVALID;
    }
    if (flags & OVS_CS_F_REPLY_DIR) {
        state |= CS_REPLY_DIR;
    }
    if (flags & OVS_CS_F_TRACKED) {
        state |= CS_TRACKED;
    }

    return state;
}

static int
scan_ct_state(const char *s, uint32_t *key, uint32_t *mask)
{
    uint32_t flags, fmask;
    int n;

    n = parse_flags(s, odp_ct_state_to_string, ')', NULL, NULL, &flags,
                    ovs_to_odp_ct_state(CS_SUPPORTED_MASK),
                    mask ? &fmask : NULL);

    if (n >= 0) {
        *key = flags;
        if (mask) {
            *mask = fmask;
        }
        return n;
    }
    return 0;
}

static int
scan_frag(const char *s, uint8_t *key, uint8_t *mask)
{
    int n;
    char frag[8];
    enum ovs_frag_type frag_type;

    if (ovs_scan(s, "%7[a-z]%n", frag, &n)
        && ovs_frag_type_from_string(frag, &frag_type)) {
        int len = n;

        *key = frag_type;
        if (mask) {
            *mask = UINT8_MAX;
        }

        return len;
    }
    return 0;
}

static int
scan_port(const char *s, uint32_t *key, uint32_t *mask,
          const struct simap *port_names)
{
    int n;

    if (ovs_scan(s, "%"SCNi32"%n", key, &n))
	{
        int len = n;	// the nr of chars read so far (1 in case s->"in_port(1),eth(....")
            
        if (mask)
		{
            if (ovs_scan(s + len, "/%"SCNi32"%n", mask, &n)) {
                len += n;
            } else {
                *mask = UINT32_MAX;
            }
        }
        return len;
    } else if (port_names) {
        const struct simap_node *node;
        int len;

        len = strcspn(s, ")");
        node = simap_find_len(port_names, s, len);
        if (node) {
            *key = node->data;

            if (mask) {
                *mask = UINT32_MAX;
            }
            return len;
        }
    }
    return 0;
}

/* Helper for vlan parsing. */
struct ovs_key_vlan__ {
    ovs_be16 tci;
};

static bool
set_be16_bf(ovs_be16 *bf, uint8_t bits, uint8_t offset, uint16_t value)
{
    const uint16_t mask = ((1U << bits) - 1) << offset;

    if (value >> bits) {
        return false;
    }

    *bf = htons((ntohs(*bf) & ~mask) | (value << offset));
    return true;
}

static int
scan_be16_bf(const char *s, ovs_be16 *key, ovs_be16 *mask, uint8_t bits,
             uint8_t offset)
{
    uint16_t key_, mask_;
    int n;

    if (ovs_scan(s, "%"SCNi16"%n", &key_, &n)) {
        int len = n;

        if (set_be16_bf(key, bits, offset, key_)) {
            if (mask) {
                if (ovs_scan(s + len, "/%"SCNi16"%n", &mask_, &n)) {
                    len += n;

                    if (!set_be16_bf(mask, bits, offset, mask_)) {
                        return 0;
                    }
                } else {
                    *mask |= htons(((1U << bits) - 1) << offset);
                }
            }
            return len;
        }
    }
    return 0;
}

static int
scan_vid(const char *s, ovs_be16 *key, ovs_be16 *mask)
{
    return scan_be16_bf(s, key, mask, 12, VLAN_VID_SHIFT);
}

static int
scan_pcp(const char *s, ovs_be16 *key, ovs_be16 *mask)
{
    return scan_be16_bf(s, key, mask, 3, VLAN_PCP_SHIFT);
}

static int
scan_cfi(const char *s, ovs_be16 *key, ovs_be16 *mask)
{
    return scan_be16_bf(s, key, mask, 1, VLAN_CFI_SHIFT);
}

/* For MPLS. */
static bool
set_be32_bf(ovs_be32 *bf, uint8_t bits, uint8_t offset, uint32_t value)
{
    const uint32_t mask = ((1U << bits) - 1) << offset;

    if (value >> bits) {
        return false;
    }

    *bf = htonl((ntohl(*bf) & ~mask) | (value << offset));
    return true;
}

static int
scan_be32_bf(const char *s, ovs_be32 *key, ovs_be32 *mask, uint8_t bits,
             uint8_t offset)
{
    uint32_t key_, mask_;
    int n;

    if (ovs_scan(s, "%"SCNi32"%n", &key_, &n)) {
        int len = n;

        if (set_be32_bf(key, bits, offset, key_)) {
            if (mask) {
                if (ovs_scan(s + len, "/%"SCNi32"%n", &mask_, &n)) {
                    len += n;

                    if (!set_be32_bf(mask, bits, offset, mask_)) {
                        return 0;
                    }
                } else {
                    *mask |= htonl(((1U << bits) - 1) << offset);
                }
            }
            return len;
        }
    }
    return 0;
}

static int
scan_mpls_label(const char *s, ovs_be32 *key, ovs_be32 *mask)
{
    return scan_be32_bf(s, key, mask, 20, MPLS_LABEL_SHIFT);
}

static int
scan_mpls_tc(const char *s, ovs_be32 *key, ovs_be32 *mask)
{
    return scan_be32_bf(s, key, mask, 3, MPLS_TC_SHIFT);
}

static int
scan_mpls_ttl(const char *s, ovs_be32 *key, ovs_be32 *mask)
{
    return scan_be32_bf(s, key, mask, 8, MPLS_TTL_SHIFT);
}

static int
scan_mpls_bos(const char *s, ovs_be32 *key, ovs_be32 *mask)
{
    return scan_be32_bf(s, key, mask, 1, MPLS_BOS_SHIFT);
}

static int
scan_vxlan_gbp(const char *s, uint32_t *key, uint32_t *mask)
{
    const char *s_base = s;
    ovs_be16 id = 0, id_mask = 0;
    uint8_t flags = 0, flags_mask = 0;

    if (!strncmp(s, "id=", 3)) {
        s += 3;
        s += scan_be16(s, &id, mask ? &id_mask : NULL);
    }

    if (s[0] == ',') {
        s++;
    }
    if (!strncmp(s, "flags=", 6)) {
        s += 6;
        s += scan_u8(s, &flags, mask ? &flags_mask : NULL);
    }

    if (!strncmp(s, "))", 2)) {
        s += 2;

        *key = (flags << 16) | ntohs(id);
        if (mask) {
            *mask = (flags_mask << 16) | ntohs(id_mask);
        }

        return s - s_base;
    }

    return 0;
}

static int
scan_geneve(const char *s, struct geneve_scan *key, struct geneve_scan *mask)
{
    const char *s_base = s;
    struct geneve_opt *opt = key->d;
    struct geneve_opt *opt_mask = mask ? mask->d : NULL;
    int len_remain = sizeof key->d;

    while (s[0] == '{' && len_remain >= sizeof *opt) {
        int data_len = 0;

        s++;
        len_remain -= sizeof *opt;

        if (!strncmp(s, "class=", 6)) {
            s += 6;
            s += scan_be16(s, &opt->opt_class,
                           mask ? &opt_mask->opt_class : NULL);
        } else if (mask) {
            memset(&opt_mask->opt_class, 0, sizeof opt_mask->opt_class);
        }

        if (s[0] == ',') {
            s++;
        }
        if (!strncmp(s, "type=", 5)) {
            s += 5;
            s += scan_u8(s, &opt->type, mask ? &opt_mask->type : NULL);
        } else if (mask) {
            memset(&opt_mask->type, 0, sizeof opt_mask->type);
        }

        if (s[0] == ',') {
            s++;
        }
        if (!strncmp(s, "len=", 4)) {
            uint8_t opt_len, opt_len_mask;
            s += 4;
            s += scan_u8(s, &opt_len, mask ? &opt_len_mask : NULL);

            if (opt_len > 124 || opt_len % 4 || opt_len > len_remain) {
                return 0;
            }
            opt->length = opt_len / 4;
            if (mask) {
                opt_mask->length = opt_len_mask;
            }
            data_len = opt_len;
        } else if (mask) {
            memset(&opt_mask->type, 0, sizeof opt_mask->type);
        }

        if (s[0] == ',') {
            s++;
        }
        if (parse_int_string(s, (uint8_t *)(opt + 1), data_len, (char **)&s)) {
            return 0;
        }

        if (mask) {
            if (s[0] == '/') {
                s++;
                if (parse_int_string(s, (uint8_t *)(opt_mask + 1),
                                     data_len, (char **)&s)) {
                    return 0;
                }
            }
            opt_mask->r1 = 0;
            opt_mask->r2 = 0;
            opt_mask->r3 = 0;
        }

        if (s[0] == '}') {
            s++;
            opt += 1 + data_len / 4;
            if (mask) {
                opt_mask += 1 + data_len / 4;
            }
            len_remain -= data_len;
        }
    }

    if (s[0] == ')') {
        int len = sizeof key->d - len_remain;

        s++;
        key->len = len;
        if (mask) {
            mask->len = len;
        }
        return s - s_base;
    }

    return 0;
}

static void
tun_flags_to_attr(struct ofpbuf *a, const void *data_)
{
    const uint16_t *flags = data_;

    if (*flags & FLOW_TNL_F_DONT_FRAGMENT) {
        nl_msg_put_flag(a, OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT);
    }
    if (*flags & FLOW_TNL_F_CSUM) {
        nl_msg_put_flag(a, OVS_TUNNEL_KEY_ATTR_CSUM);
    }
    if (*flags & FLOW_TNL_F_OAM) {
        nl_msg_put_flag(a, OVS_TUNNEL_KEY_ATTR_OAM);
    }
}

static void
vxlan_gbp_to_attr(struct ofpbuf *a, const void *data_)
{
    const uint32_t *gbp = data_;

    if (*gbp) {
        size_t vxlan_opts_ofs;

        vxlan_opts_ofs = nl_msg_start_nested(a, OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS);
        nl_msg_put_u32(a, OVS_VXLAN_EXT_GBP, *gbp);
        nl_msg_end_nested(a, vxlan_opts_ofs);
    }
}

static void
geneve_to_attr(struct ofpbuf *a, const void *data_)
{
    const struct geneve_scan *geneve = data_;

    nl_msg_put_unspec(a, OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS, geneve->d,
                      geneve->len);
}

#define SCAN_PUT_ATTR(BUF, ATTR, DATA, FUNC)                      \
    {                                                             \
        unsigned long call_fn = (unsigned long)FUNC;              \
        if (call_fn) {                                            \
            typedef void (*fn)(struct ofpbuf *, const void *);    \
            fn func = FUNC;                                       \
            func(BUF, &(DATA));                                   \
        } else {                                                  \
            nl_msg_put_unspec(BUF, ATTR, &(DATA), sizeof (DATA)); \
        }                                                         \
    }

#define SCAN_IF(NAME)                           \
    if (strncmp(s, NAME, strlen(NAME)) == 0) {  \
        const char *start = s;                  \
        int len;                                \
                                                \
        s += strlen(NAME)

/* Usually no special initialization is needed. */
#define SCAN_BEGIN(NAME, TYPE)                  \
    SCAN_IF(NAME);                              \
        TYPE skey, smask;                       \
        memset(&skey, 0, sizeof skey);          \
        memset(&smask, 0, sizeof smask);        \
        do {                                    \
            len = 0;

/* Init as fully-masked as mask will not be scanned. */
#define SCAN_BEGIN_FULLY_MASKED(NAME, TYPE)     \
    SCAN_IF(NAME);                              \
        TYPE skey, smask;                       \
        memset(&skey, 0, sizeof skey);          \
        memset(&smask, 0xff, sizeof smask);     \
        do {                                    \
            len = 0;

/* VLAN needs special initialization. */
#define SCAN_BEGIN_INIT(NAME, TYPE, KEY_INIT, MASK_INIT)  \
    SCAN_IF(NAME);                                        \
        TYPE skey = KEY_INIT;                       \
        TYPE smask = MASK_INIT;                     \
        do {                                        \
            len = 0;

/* Scan unnamed entry as 'TYPE' */
#define SCAN_TYPE(TYPE, KEY, MASK)              \
    len = scan_##TYPE(s, KEY, MASK);            \
    if (len == 0) {                             \
        return -EINVAL;                         \
    }                                           \
    s += len

/* Scan named ('NAME') entry 'FIELD' as 'TYPE'. */
#define SCAN_FIELD(NAME, TYPE, FIELD)                                   \
    if (strncmp(s, NAME, strlen(NAME)) == 0) {                          \
        s += strlen(NAME);                                              \
        SCAN_TYPE(TYPE, &skey.FIELD, mask ? &smask.FIELD : NULL);       \
        continue;                                                       \
    }

#define SCAN_FINISH()                           \
        } while (*s++ == ',' && len != 0);      \
        if (s[-1] != ')') {                     \
            return -EINVAL;                     \
        }

#define SCAN_FINISH_SINGLE()                    \
        } while (false);                        \
        if (*s++ != ')') {                      \
            return -EINVAL;                     \
        }

/* Beginning of nested attribute. */
#define SCAN_BEGIN_NESTED(NAME, ATTR)                      \
    SCAN_IF(NAME);                                         \
        size_t key_offset, mask_offset;                    \
        key_offset = nl_msg_start_nested(key, ATTR);       \
        if (mask) {                                        \
            mask_offset = nl_msg_start_nested(mask, ATTR); \
        }                                                  \
        do {                                               \
            len = 0;

#define SCAN_END_NESTED()                               \
        SCAN_FINISH();                                  \
        nl_msg_end_nested(key, key_offset);             \
        if (mask) {                                     \
            nl_msg_end_nested(mask, mask_offset);       \
        }                                               \
        return s - start;                               \
    }

#define SCAN_FIELD_NESTED__(NAME, TYPE, SCAN_AS, ATTR, FUNC)  \
    if (strncmp(s, NAME, strlen(NAME)) == 0) {                \
        TYPE skey, smask;                                     \
        memset(&skey, 0, sizeof skey);                        \
        memset(&smask, 0xff, sizeof smask);                   \
        s += strlen(NAME);                                    \
        SCAN_TYPE(SCAN_AS, &skey, &smask);                    \
        SCAN_PUT(ATTR, FUNC);                                 \
        continue;                                             \
    }

#define SCAN_FIELD_NESTED(NAME, TYPE, SCAN_AS, ATTR)  \
        SCAN_FIELD_NESTED__(NAME, TYPE, SCAN_AS, ATTR, NULL)

#define SCAN_FIELD_NESTED_FUNC(NAME, TYPE, SCAN_AS, FUNC)  \
        SCAN_FIELD_NESTED__(NAME, TYPE, SCAN_AS, 0, FUNC)

#define SCAN_PUT(ATTR, FUNC)                            \
        if (!mask || !is_all_zeros(&smask, sizeof smask)) { \
            SCAN_PUT_ATTR(key, ATTR, skey, FUNC);       \
            if (mask) {                                 \
                SCAN_PUT_ATTR(mask, ATTR, smask, FUNC); \
            }                                           \
        }

#define SCAN_END(ATTR)                                  \
        SCAN_FINISH();                                  \
        SCAN_PUT(ATTR, NULL);                           \
        return s - start;                               \
    }

#define SCAN_END_SINGLE(ATTR)                           \
        SCAN_FINISH_SINGLE();                           \
        SCAN_PUT(ATTR, NULL);                           \
        return s - start;                               \
    }

#define SCAN_SINGLE(NAME, TYPE, SCAN_AS, ATTR)       \
    SCAN_BEGIN(NAME, TYPE) {                         \
        SCAN_TYPE(SCAN_AS, &skey, &smask);           \
    } SCAN_END_SINGLE(ATTR)

#define SCAN_SINGLE_FULLY_MASKED(NAME, TYPE, SCAN_AS, ATTR) \
    SCAN_BEGIN_FULLY_MASKED(NAME, TYPE) {                   \
        SCAN_TYPE(SCAN_AS, &skey, NULL);                    \
    } SCAN_END_SINGLE(ATTR)

/* scan_port needs one extra argument. */
#define SCAN_SINGLE_PORT(NAME, TYPE, ATTR)  \
    SCAN_BEGIN(NAME, TYPE) {                            \
       	len = scan_port(s, &skey, &smask, port_names);  \
		if (len == 0) {                                 \
            return -EINVAL;                             \
        }                                               \
        s += len;                                       \
    } SCAN_END_SINGLE(ATTR)

/* GTPv1 flow key string parser */
static int parse_odp_gtpu_key_mask_attr(const char *s, const struct simap *port_names,
										struct ofpbuf *key, struct ofpbuf *mask)
{
	ovs_u128 ufid;
	int len;

	/* Skip UFID. */
	len = odp_ufid_from_string(s, &ufid);
	if (len)
		return len;

	SCAN_SINGLE_PORT("in_port(", uint32_t, OVS_KEY_ATTR_IN_PORT);
	
	/* matches on G-PDU */
	SCAN_BEGIN("ipv4(", struct ovs_key_ipv4)
	{
		SCAN_FIELD("src=", ipv4, ipv4_src);
		SCAN_FIELD("dst=", ipv4, ipv4_dst);
		SCAN_FIELD("proto=", u8, ipv4_proto);
		SCAN_FIELD("tos=", u8, ipv4_tos);
		SCAN_FIELD("ttl=", u8, ipv4_ttl);
		SCAN_FIELD("frag=", frag, ipv4_frag);
	} SCAN_END(OVS_KEY_ATTR_IPV4);

	SCAN_BEGIN("tcp(", struct ovs_key_tcp) {
		SCAN_FIELD("src=", be16, tcp_src);
		SCAN_FIELD("dst=", be16, tcp_dst);
	} SCAN_END(OVS_KEY_ATTR_TCP);

	SCAN_SINGLE("tcp_flags(", ovs_be16, tcp_flags, OVS_KEY_ATTR_TCP_FLAGS);

	SCAN_BEGIN("udp(", struct ovs_key_udp) {
		SCAN_FIELD("src=", be16, udp_src);
		SCAN_FIELD("dst=", be16, udp_dst);
	} SCAN_END(OVS_KEY_ATTR_UDP);

	/* GTPv1 tunnel matching */
	SCAN_BEGIN("gtp(", struct ovs_key_gtpv1)
	{
		SCAN_FIELD("dst=", ipv4, ipv4_dst);
		SCAN_FIELD("teid=", gtp_teid, teid);
	} SCAN_END(OVS_KEY_ATTR_GTPV1);

	return -EINVAL;
}

static int parse_odp_key_mask_attr(const char *s, const struct simap *port_names,
                        struct ofpbuf *key, struct ofpbuf *mask)
{
    ovs_u128 ufid;
    int len;

    /* Skip UFID. */
    len = odp_ufid_from_string(s, &ufid);
    if (len) {
        return len;
    }

    SCAN_SINGLE("skb_priority(", uint32_t, u32, OVS_KEY_ATTR_PRIORITY);
    SCAN_SINGLE("skb_mark(", uint32_t, u32, OVS_KEY_ATTR_SKB_MARK);
    SCAN_SINGLE_FULLY_MASKED("recirc_id(", uint32_t, u32,
                             OVS_KEY_ATTR_RECIRC_ID);
    SCAN_SINGLE("dp_hash(", uint32_t, u32, OVS_KEY_ATTR_DP_HASH);

    SCAN_SINGLE("ct_state(", uint32_t, ct_state, OVS_KEY_ATTR_CT_STATE);
    SCAN_SINGLE("ct_zone(", uint16_t, u16, OVS_KEY_ATTR_CT_ZONE);
    SCAN_SINGLE("ct_mark(", uint32_t, u32, OVS_KEY_ATTR_CT_MARK);
    SCAN_SINGLE("ct_label(", ovs_u128, u128, OVS_KEY_ATTR_CT_LABELS);

    SCAN_BEGIN_NESTED("tunnel(", OVS_KEY_ATTR_TUNNEL) {
        SCAN_FIELD_NESTED("tun_id=", ovs_be64, be64, OVS_TUNNEL_KEY_ATTR_ID);
        SCAN_FIELD_NESTED("src=", ovs_be32, ipv4, OVS_TUNNEL_KEY_ATTR_IPV4_SRC);
        SCAN_FIELD_NESTED("dst=", ovs_be32, ipv4, OVS_TUNNEL_KEY_ATTR_IPV4_DST);
        SCAN_FIELD_NESTED("ipv6_src=", struct in6_addr, in6_addr, OVS_TUNNEL_KEY_ATTR_IPV6_SRC);
        SCAN_FIELD_NESTED("ipv6_dst=", struct in6_addr, in6_addr, OVS_TUNNEL_KEY_ATTR_IPV6_DST);
        SCAN_FIELD_NESTED("tos=", uint8_t, u8, OVS_TUNNEL_KEY_ATTR_TOS);
        SCAN_FIELD_NESTED("ttl=", uint8_t, u8, OVS_TUNNEL_KEY_ATTR_TTL);
        SCAN_FIELD_NESTED("tp_src=", ovs_be16, be16, OVS_TUNNEL_KEY_ATTR_TP_SRC);
        SCAN_FIELD_NESTED("tp_dst=", ovs_be16, be16, OVS_TUNNEL_KEY_ATTR_TP_DST);
        SCAN_FIELD_NESTED_FUNC("vxlan(gbp(", uint32_t, vxlan_gbp, vxlan_gbp_to_attr);
        SCAN_FIELD_NESTED_FUNC("geneve(", struct geneve_scan, geneve,
                               geneve_to_attr);
        SCAN_FIELD_NESTED_FUNC("flags(", uint16_t, tun_flags, tun_flags_to_attr);
    } SCAN_END_NESTED();

    SCAN_SINGLE_PORT("in_port(", uint32_t, OVS_KEY_ATTR_IN_PORT);

    SCAN_BEGIN("eth(", struct ovs_key_ethernet) {
        SCAN_FIELD("src=", eth, eth_src);
        SCAN_FIELD("dst=", eth, eth_dst);
    } SCAN_END(OVS_KEY_ATTR_ETHERNET);

    SCAN_BEGIN_INIT("vlan(", struct ovs_key_vlan__,
                    { htons(VLAN_CFI) }, { htons(VLAN_CFI) }) {
        SCAN_FIELD("vid=", vid, tci);
        SCAN_FIELD("pcp=", pcp, tci);
        SCAN_FIELD("cfi=", cfi, tci);
    } SCAN_END(OVS_KEY_ATTR_VLAN);

    SCAN_SINGLE("eth_type(", ovs_be16, be16, OVS_KEY_ATTR_ETHERTYPE);

    SCAN_BEGIN("mpls(", struct ovs_key_mpls) {
        SCAN_FIELD("label=", mpls_label, mpls_lse);
        SCAN_FIELD("tc=", mpls_tc, mpls_lse);
        SCAN_FIELD("ttl=", mpls_ttl, mpls_lse);
        SCAN_FIELD("bos=", mpls_bos, mpls_lse);
    } SCAN_END(OVS_KEY_ATTR_MPLS);

    SCAN_BEGIN("ipv4(", struct ovs_key_ipv4) {
        SCAN_FIELD("src=", ipv4, ipv4_src);
        SCAN_FIELD("dst=", ipv4, ipv4_dst);
        SCAN_FIELD("proto=", u8, ipv4_proto);
        SCAN_FIELD("tos=", u8, ipv4_tos);
        SCAN_FIELD("ttl=", u8, ipv4_ttl);
        SCAN_FIELD("frag=", frag, ipv4_frag);
    } SCAN_END(OVS_KEY_ATTR_IPV4);

    SCAN_BEGIN("ipv6(", struct ovs_key_ipv6) {
        SCAN_FIELD("src=", ipv6, ipv6_src);
        SCAN_FIELD("dst=", ipv6, ipv6_dst);
        SCAN_FIELD("label=", ipv6_label, ipv6_label);
        SCAN_FIELD("proto=", u8, ipv6_proto);
        SCAN_FIELD("tclass=", u8, ipv6_tclass);
        SCAN_FIELD("hlimit=", u8, ipv6_hlimit);
        SCAN_FIELD("frag=", frag, ipv6_frag);
    } SCAN_END(OVS_KEY_ATTR_IPV6);

    SCAN_BEGIN("tcp(", struct ovs_key_tcp) {
        SCAN_FIELD("src=", be16, tcp_src);
        SCAN_FIELD("dst=", be16, tcp_dst);
    } SCAN_END(OVS_KEY_ATTR_TCP);

    SCAN_SINGLE("tcp_flags(", ovs_be16, tcp_flags, OVS_KEY_ATTR_TCP_FLAGS);

    SCAN_BEGIN("udp(", struct ovs_key_udp) {
        SCAN_FIELD("src=", be16, udp_src);
        SCAN_FIELD("dst=", be16, udp_dst);
    } SCAN_END(OVS_KEY_ATTR_UDP);

    SCAN_BEGIN("sctp(", struct ovs_key_sctp) {
        SCAN_FIELD("src=", be16, sctp_src);
        SCAN_FIELD("dst=", be16, sctp_dst);
    } SCAN_END(OVS_KEY_ATTR_SCTP);

    SCAN_BEGIN("icmp(", struct ovs_key_icmp) {
        SCAN_FIELD("type=", u8, icmp_type);
        SCAN_FIELD("code=", u8, icmp_code);
    } SCAN_END(OVS_KEY_ATTR_ICMP);

    SCAN_BEGIN("icmpv6(", struct ovs_key_icmpv6) {
        SCAN_FIELD("type=", u8, icmpv6_type);
        SCAN_FIELD("code=", u8, icmpv6_code);
    } SCAN_END(OVS_KEY_ATTR_ICMPV6);

    SCAN_BEGIN("arp(", struct ovs_key_arp) {
        SCAN_FIELD("sip=", ipv4, arp_sip);
        SCAN_FIELD("tip=", ipv4, arp_tip);
        SCAN_FIELD("op=", be16, arp_op);
        SCAN_FIELD("sha=", eth, arp_sha);
        SCAN_FIELD("tha=", eth, arp_tha);
    } SCAN_END(OVS_KEY_ATTR_ARP);

    SCAN_BEGIN("nd(", struct ovs_key_nd) {
        SCAN_FIELD("target=", ipv6, nd_target);
        SCAN_FIELD("sll=", eth, nd_sll);
        SCAN_FIELD("tll=", eth, nd_tll);
    } SCAN_END(OVS_KEY_ATTR_ND);

    /* Encap open-coded. */
    if (!strncmp(s, "encap(", 6)) {
        const char *start = s;
        size_t encap, encap_mask = 0;

        encap = nl_msg_start_nested(key, OVS_KEY_ATTR_ENCAP);
        if (mask) {
            encap_mask = nl_msg_start_nested(mask, OVS_KEY_ATTR_ENCAP);
        }

        s += 6;
        for (;;) {
            int retval;

            s += strspn(s, delimiters);
            if (!*s) {
                return -EINVAL;
            } else if (*s == ')') {
                break;
            }

            retval = parse_odp_key_mask_attr(s, port_names, key, mask);
            if (retval < 0) {
                return retval;
            }
            s += retval;
        }
        s++;

        nl_msg_end_nested(key, encap);
        if (mask) {
            nl_msg_end_nested(mask, encap_mask);
        }

        return s - start;
    }

    return -EINVAL;
}

int odp_gtpu_flow_from_string(const char *s, const struct simap *port_names,
	struct ofpbuf *key, struct ofpbuf *mask)
{
	const size_t old_size = key->size;

	/* Each loop parses one flow key attribute from the flow key string.
	* For ex: if the flow key string is
	* "in_port(1),eth(src=00:11:22:33:44:55,dst=11:22:33:44:55:66),eth_type(0x0800),ipv4(src=192.168.1.2,frag=no)"
	* then the 1st loop parses "in_port", the 2nd loop parses "eth", the 3rd loop parses "eth_type",
	* and the 4th loop parses "ipv4".
	*/
	for (;;)
	{
		int retval;

		s += strspn(s, delimiters);	// skip the immediate delimiter (for example a ",") pointed by "s"
		if (!*s) {
			return 0;
		}

		/* parse a flow key attribute from the flow key string pointed by "s" */
		retval = parse_odp_gtpu_key_mask_attr(s, port_names, key, mask);

		if (retval < 0) {
			key->size = old_size;
			return -retval;
		}

		/* if the inserted flow cmd is "in_port(1),eth(src=...", at the first loop "s"
		* skips the first attribute "in_port(1)" so now "s" points to ",eth(src=..."
		*/
		s += retval;
	}

	return 0;
}

/* Parses the string representation of a datapath flow key, in the
 * format output by odp_flow_key_format().  Returns 0 if successful,
 * otherwise a positive errno value.  On success, the flow key is
 * appended to 'key' as a series of Netlink attributes.  On failure, no
 * data is appended to 'key'.  Either way, 'key''s data might be
 * reallocated.
 *
 * If 'port_names' is nonnull, it points to an simap that maps from a port name
 * to a port number.  (Port names may be used instead of port numbers in
 * in_port.)
 *
 * On success, the attributes appended to 'key' are individually syntactically
 * valid, but they may not be valid as a sequence.  'key' might, for example,
 * have duplicated keys.  odp_flow_key_to_flow() will detect those errors. */
int odp_flow_from_string(const char *s, const struct simap *port_names,
                     struct ofpbuf *key, struct ofpbuf *mask)
{
    const size_t old_size = key->size;
    
	/* Each loop parses one flow key attribute from the flow key string.
	 * For ex: if the flow key string is
	 * "in_port(1),eth(src=00:11:22:33:44:55,dst=11:22:33:44:55:66),eth_type(0x0800),ipv4(src=192.168.1.2,frag=no)"
	 * then the 1st loop parses "in_port", the 2nd loop parses "eth", the 3rd loop parses "eth_type", 
	 * and the 4th loop parses "ipv4".
	 */
	for (;;)
	{
        int retval;

        s += strspn(s, delimiters);	// skip the immediate delimiter (for example a ",") pointed by "s"
        if (!*s) {
            return 0;
        }

		/* parse a flow key attribute from the flow key string pointed by "s" */
		retval = parse_odp_key_mask_attr(s, port_names, key, mask);

        if (retval < 0) {
            key->size = old_size;
            return -retval;
        }
        
		/* if the inserted flow cmd is "in_port(1),eth(src=...", at the first loop "s"
		 * skips the first attribute "in_port(1)" so now "s" points to ",eth(src=..."
		 */
		s += retval;
    }

    return 0;
}

static uint8_t
ovs_to_odp_frag(uint8_t nw_frag, bool is_mask)
{
    if (is_mask) {
        /* Netlink interface 'enum ovs_frag_type' is an 8-bit enumeration type,
         * not a set of flags or bitfields. Hence, if the struct flow nw_frag
         * mask, which is a set of bits, has the FLOW_NW_FRAG_ANY as zero, we
         * must use a zero mask for the netlink frag field, and all ones mask
         * otherwise. */
        return (nw_frag & FLOW_NW_FRAG_ANY) ? UINT8_MAX : 0;
    }
    return !(nw_frag & FLOW_NW_FRAG_ANY) ? OVS_FRAG_TYPE_NONE
        : nw_frag & FLOW_NW_FRAG_LATER ? OVS_FRAG_TYPE_LATER
        : OVS_FRAG_TYPE_FIRST;
}

static void get_ethernet_key(const struct flow *, struct ovs_key_ethernet *);
static void put_ethernet_key(const struct ovs_key_ethernet *, struct flow *);
static void get_ipv4_key(const struct flow *, struct ovs_key_ipv4 *,
                         bool is_mask);
static void put_ipv4_key(const struct ovs_key_ipv4 *, struct flow *,
                         bool is_mask);
static void get_ipv6_key(const struct flow *, struct ovs_key_ipv6 *,
                         bool is_mask);
static void put_ipv6_key(const struct ovs_key_ipv6 *, struct flow *,
                         bool is_mask);
static void get_arp_key(const struct flow *, struct ovs_key_arp *);
static void put_arp_key(const struct ovs_key_arp *, struct flow *);
static void get_nd_key(const struct flow *, struct ovs_key_nd *);
static void put_nd_key(const struct ovs_key_nd *, struct flow *);

/* These share the same layout. */
union ovs_key_tp {
    struct ovs_key_tcp tcp;
    struct ovs_key_udp udp;
    struct ovs_key_sctp sctp;
};

static void get_tp_key(const struct flow *, union ovs_key_tp *);
static void put_tp_key(const union ovs_key_tp *, struct flow *);

static void
odp_flow_key_from_flow__(const struct odp_flow_key_parms *parms,
                         bool export_mask, struct ofpbuf *buf)
{
    struct ovs_key_ethernet *eth_key;
    size_t encap;
    const struct flow *flow = parms->flow;
    const struct flow *data = export_mask ? parms->mask : parms->flow;

    nl_msg_put_u32(buf, OVS_KEY_ATTR_PRIORITY, data->skb_priority);

    if (flow_tnl_dst_is_set(&flow->tunnel) || export_mask) {
        tun_key_to_attr(buf, &data->tunnel, &parms->flow->tunnel,
                        parms->key_buf);
    }

    nl_msg_put_u32(buf, OVS_KEY_ATTR_SKB_MARK, data->pkt_mark);

    if (parms->support.ct_state) {
        nl_msg_put_u32(buf, OVS_KEY_ATTR_CT_STATE,
                       ovs_to_odp_ct_state(data->ct_state));
    }
    if (parms->support.ct_zone) {
        nl_msg_put_u16(buf, OVS_KEY_ATTR_CT_ZONE, data->ct_zone);
    }
    if (parms->support.ct_mark) {
        nl_msg_put_u32(buf, OVS_KEY_ATTR_CT_MARK, data->ct_mark);
    }
    if (parms->support.ct_label) {
        nl_msg_put_unspec(buf, OVS_KEY_ATTR_CT_LABELS, &data->ct_label,
                          sizeof(data->ct_label));
    }
    if (parms->support.recirc) {
        nl_msg_put_u32(buf, OVS_KEY_ATTR_RECIRC_ID, data->recirc_id);
        nl_msg_put_u32(buf, OVS_KEY_ATTR_DP_HASH, data->dp_hash);
    }

    /* Add an ingress port attribute if this is a mask or 'odp_in_port'
     * is not the magical value "ODPP_NONE". */
    if (export_mask || parms->odp_in_port != ODPP_NONE) {
        nl_msg_put_odp_port(buf, OVS_KEY_ATTR_IN_PORT, parms->odp_in_port);
    }

    eth_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_ETHERNET,
                                       sizeof *eth_key);
    get_ethernet_key(data, eth_key);

    if (flow->vlan_tci != htons(0) || flow->dl_type == htons(ETH_TYPE_VLAN)) {
        if (export_mask) {
            nl_msg_put_be16(buf, OVS_KEY_ATTR_ETHERTYPE, OVS_BE16_MAX);
        } else {
            nl_msg_put_be16(buf, OVS_KEY_ATTR_ETHERTYPE, htons(ETH_TYPE_VLAN));
        }
        nl_msg_put_be16(buf, OVS_KEY_ATTR_VLAN, data->vlan_tci);
        encap = nl_msg_start_nested(buf, OVS_KEY_ATTR_ENCAP);
        if (flow->vlan_tci == htons(0)) {
            goto unencap;
        }
    } else {
        encap = 0;
    }

    if (ntohs(flow->dl_type) < ETH_TYPE_MIN) {
        /* For backwards compatibility with kernels that don't support
         * wildcarding, the following convention is used to encode the
         * OVS_KEY_ATTR_ETHERTYPE for key and mask:
         *
         *   key      mask    matches
         * -------- --------  -------
         *  >0x5ff   0xffff   Specified Ethernet II Ethertype.
         *  >0x5ff      0     Any Ethernet II or non-Ethernet II frame.
         *  <none>   0xffff   Any non-Ethernet II frame (except valid
         *                    802.3 SNAP packet with valid eth_type).
         */
        if (export_mask) {
            nl_msg_put_be16(buf, OVS_KEY_ATTR_ETHERTYPE, OVS_BE16_MAX);
        }
        goto unencap;
    }

    nl_msg_put_be16(buf, OVS_KEY_ATTR_ETHERTYPE, data->dl_type);

    if (flow->dl_type == htons(ETH_TYPE_IP)) {
        struct ovs_key_ipv4 *ipv4_key;

        ipv4_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_IPV4,
                                            sizeof *ipv4_key);
        get_ipv4_key(data, ipv4_key, export_mask);
    } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
        struct ovs_key_ipv6 *ipv6_key;

        ipv6_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_IPV6,
                                            sizeof *ipv6_key);
        get_ipv6_key(data, ipv6_key, export_mask);
    } else if (flow->dl_type == htons(ETH_TYPE_ARP) ||
               flow->dl_type == htons(ETH_TYPE_RARP)) {
        struct ovs_key_arp *arp_key;

        arp_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_ARP,
                                           sizeof *arp_key);
        get_arp_key(data, arp_key);
    } else if (eth_type_mpls(flow->dl_type)) {
        struct ovs_key_mpls *mpls_key;
        int i, n;

        n = flow_count_mpls_labels(flow, NULL);
        if (export_mask) {
            n = MIN(n, parms->support.max_mpls_depth);
        }
        mpls_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_MPLS,
                                            n * sizeof *mpls_key);
        for (i = 0; i < n; i++) {
            mpls_key[i].mpls_lse = data->mpls_lse[i];
        }
    }

    if (is_ip_any(flow) && !(flow->nw_frag & FLOW_NW_FRAG_LATER)) {
        if (flow->nw_proto == IPPROTO_TCP) {
            union ovs_key_tp *tcp_key;

            tcp_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_TCP,
                                               sizeof *tcp_key);
            get_tp_key(data, tcp_key);
            if (data->tcp_flags) {
                nl_msg_put_be16(buf, OVS_KEY_ATTR_TCP_FLAGS, data->tcp_flags);
            }
        } else if (flow->nw_proto == IPPROTO_UDP) {
            union ovs_key_tp *udp_key;

            udp_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_UDP,
                                               sizeof *udp_key);
            get_tp_key(data, udp_key);
        } else if (flow->nw_proto == IPPROTO_SCTP) {
            union ovs_key_tp *sctp_key;

            sctp_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_SCTP,
                                               sizeof *sctp_key);
            get_tp_key(data, sctp_key);
        } else if (flow->dl_type == htons(ETH_TYPE_IP)
                && flow->nw_proto == IPPROTO_ICMP) {
            struct ovs_key_icmp *icmp_key;

            icmp_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_ICMP,
                                                sizeof *icmp_key);
            icmp_key->icmp_type = ntohs(data->tp_src);
            icmp_key->icmp_code = ntohs(data->tp_dst);
        } else if (flow->dl_type == htons(ETH_TYPE_IPV6)
                && flow->nw_proto == IPPROTO_ICMPV6) {
            struct ovs_key_icmpv6 *icmpv6_key;

            icmpv6_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_ICMPV6,
                                                  sizeof *icmpv6_key);
            icmpv6_key->icmpv6_type = ntohs(data->tp_src);
            icmpv6_key->icmpv6_code = ntohs(data->tp_dst);

            if (flow->tp_dst == htons(0)
                && (flow->tp_src == htons(ND_NEIGHBOR_SOLICIT)
                    || flow->tp_src == htons(ND_NEIGHBOR_ADVERT))
                /* Even though 'tp_src' and 'tp_dst' are 16 bits wide, ICMP
                 * type and code are 8 bits wide.  Therefore, an exact match
                 * looks like htons(0xff), not htons(0xffff).  See
                 * xlate_wc_finish() for details. */
                && (!export_mask || (data->tp_src == htons(0xff)
                                     && data->tp_dst == htons(0xff)))) {

                struct ovs_key_nd *nd_key;

                nd_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_ND,
                                                    sizeof *nd_key);
                memcpy(nd_key->nd_target, &data->nd_target,
                        sizeof nd_key->nd_target);
                nd_key->nd_sll = data->arp_sha;
                nd_key->nd_tll = data->arp_tha;
            }
        }
    }

unencap:
    if (encap) {
        nl_msg_end_nested(buf, encap);
    }
}

/* Appends a representation of 'flow' as OVS_KEY_ATTR_* attributes to 'buf'.
 *
 * 'buf' must have at least ODPUTIL_FLOW_KEY_BYTES bytes of space, or be
 * capable of being expanded to allow for that much space. */
void
odp_flow_key_from_flow(const struct odp_flow_key_parms *parms,
                       struct ofpbuf *buf)
{
    odp_flow_key_from_flow__(parms, false, buf);
}

/* Appends a representation of 'mask' as OVS_KEY_ATTR_* attributes to
 * 'buf'.
 *
 * 'buf' must have at least ODPUTIL_FLOW_KEY_BYTES bytes of space, or be
 * capable of being expanded to allow for that much space. */
void
odp_flow_key_from_mask(const struct odp_flow_key_parms *parms,
                       struct ofpbuf *buf)
{
    odp_flow_key_from_flow__(parms, true, buf);
}

/* Generate ODP flow key from the given packet metadata */
void
odp_key_from_pkt_metadata(struct ofpbuf *buf, const struct pkt_metadata *md)
{
    nl_msg_put_u32(buf, OVS_KEY_ATTR_PRIORITY, md->skb_priority);

    if (flow_tnl_dst_is_set(&md->tunnel)) {
        tun_key_to_attr(buf, &md->tunnel, &md->tunnel, NULL);
    }

    nl_msg_put_u32(buf, OVS_KEY_ATTR_SKB_MARK, md->pkt_mark);

    if (md->ct_state) {
        nl_msg_put_u32(buf, OVS_KEY_ATTR_CT_STATE,
                       ovs_to_odp_ct_state(md->ct_state));
        if (md->ct_zone) {
            nl_msg_put_u16(buf, OVS_KEY_ATTR_CT_ZONE, md->ct_zone);
        }
        if (md->ct_mark) {
            nl_msg_put_u32(buf, OVS_KEY_ATTR_CT_MARK, md->ct_mark);
        }
        if (!ovs_u128_is_zero(&md->ct_label)) {
            nl_msg_put_unspec(buf, OVS_KEY_ATTR_CT_LABELS, &md->ct_label,
                              sizeof(md->ct_label));
        }
    }

    /* Add an ingress port attribute if 'odp_in_port' is not the magical
     * value "ODPP_NONE". */
    if (md->in_port.odp_port != ODPP_NONE) {
        nl_msg_put_odp_port(buf, OVS_KEY_ATTR_IN_PORT, md->in_port.odp_port);
    }
}

/* Generate packet metadata from the given ODP flow key. */
void
odp_key_to_pkt_metadata(const struct nlattr *key, size_t key_len,
                        struct pkt_metadata *md)
{
    const struct nlattr *nla;
    size_t left;
    uint32_t wanted_attrs = 1u << OVS_KEY_ATTR_PRIORITY |
        1u << OVS_KEY_ATTR_SKB_MARK | 1u << OVS_KEY_ATTR_TUNNEL |
        1u << OVS_KEY_ATTR_IN_PORT;

    pkt_metadata_init(md, ODPP_NONE);

    NL_ATTR_FOR_EACH (nla, left, key, key_len) {
        uint16_t type = nl_attr_type(nla);
        size_t len = nl_attr_get_size(nla);
        int expected_len = odp_key_attr_len(ovs_flow_key_attr_lens,
                                            OVS_KEY_ATTR_MAX, type);

        if (len != expected_len && expected_len >= 0) {
            continue;
        }

        switch (type) {
        case OVS_KEY_ATTR_RECIRC_ID:
            md->recirc_id = nl_attr_get_u32(nla);
            wanted_attrs &= ~(1u << OVS_KEY_ATTR_RECIRC_ID);
            break;
        case OVS_KEY_ATTR_DP_HASH:
            md->dp_hash = nl_attr_get_u32(nla);
            wanted_attrs &= ~(1u << OVS_KEY_ATTR_DP_HASH);
            break;
        case OVS_KEY_ATTR_PRIORITY:
            md->skb_priority = nl_attr_get_u32(nla);
            wanted_attrs &= ~(1u << OVS_KEY_ATTR_PRIORITY);
            break;
        case OVS_KEY_ATTR_SKB_MARK:
            md->pkt_mark = nl_attr_get_u32(nla);
            wanted_attrs &= ~(1u << OVS_KEY_ATTR_SKB_MARK);
            break;
        case OVS_KEY_ATTR_CT_STATE:
            md->ct_state = odp_to_ovs_ct_state(nl_attr_get_u32(nla));
            wanted_attrs &= ~(1u << OVS_KEY_ATTR_CT_STATE);
            break;
        case OVS_KEY_ATTR_CT_ZONE:
            md->ct_zone = nl_attr_get_u16(nla);
            wanted_attrs &= ~(1u << OVS_KEY_ATTR_CT_ZONE);
            break;
        case OVS_KEY_ATTR_CT_MARK:
            md->ct_mark = nl_attr_get_u32(nla);
            wanted_attrs &= ~(1u << OVS_KEY_ATTR_CT_MARK);
            break;
        case OVS_KEY_ATTR_CT_LABELS: {
            const ovs_u128 *cl = nl_attr_get(nla);

            md->ct_label = *cl;
            wanted_attrs &= ~(1u << OVS_KEY_ATTR_CT_LABELS);
            break;
        }
        case OVS_KEY_ATTR_TUNNEL: {
            enum odp_key_fitness res;

            res = odp_tun_key_from_attr(nla, true, &md->tunnel);
            if (res == ODP_FIT_ERROR) {
                memset(&md->tunnel, 0, sizeof md->tunnel);
            } else if (res == ODP_FIT_PERFECT) {
                wanted_attrs &= ~(1u << OVS_KEY_ATTR_TUNNEL);
            }
            break;
        }
        case OVS_KEY_ATTR_IN_PORT:
            md->in_port.odp_port = nl_attr_get_odp_port(nla);
            wanted_attrs &= ~(1u << OVS_KEY_ATTR_IN_PORT);
            break;
        default:
            break;
        }

        if (!wanted_attrs) {
            return; /* Have everything. */
        }
    }
}

uint32_t
odp_flow_key_hash(const struct nlattr *key, size_t key_len)
{
    BUILD_ASSERT_DECL(!(NLA_ALIGNTO % sizeof(uint32_t)));
    return hash_words(ALIGNED_CAST(const uint32_t *, key),
                      key_len / sizeof(uint32_t), 0);
}

static void
log_odp_key_attributes(struct vlog_rate_limit *rl, const char *title,
                       uint64_t attrs, int out_of_range_attr,
                       const struct nlattr *key, size_t key_len)
{
    struct ds s;
    int i;

    if (VLOG_DROP_DBG(rl)) {
        return;
    }

    ds_init(&s);
    for (i = 0; i < 64; i++) {
        if (attrs & (UINT64_C(1) << i)) {
            char namebuf[OVS_KEY_ATTR_BUFSIZE];

            ds_put_format(&s, " %s",
                          ovs_key_attr_to_string(i, namebuf, sizeof namebuf));
        }
    }
    if (out_of_range_attr) {
        ds_put_format(&s, " %d (and possibly others)", out_of_range_attr);
    }

    ds_put_cstr(&s, ": ");
    odp_flow_key_format(key, key_len, &s);

    VLOG_DBG("%s:%s", title, ds_cstr(&s));
    ds_destroy(&s);
}

static uint8_t
odp_to_ovs_frag(uint8_t odp_frag, bool is_mask)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

    if (is_mask) {
        return odp_frag ? FLOW_NW_FRAG_MASK : 0;
    }

    if (odp_frag > OVS_FRAG_TYPE_LATER) {
        VLOG_ERR_RL(&rl, "invalid frag %"PRIu8" in flow key", odp_frag);
        return 0xff; /* Error. */
    }

    return (odp_frag == OVS_FRAG_TYPE_NONE) ? 0
        : (odp_frag == OVS_FRAG_TYPE_FIRST) ? FLOW_NW_FRAG_ANY
        :  FLOW_NW_FRAG_ANY | FLOW_NW_FRAG_LATER;
}

static bool
parse_flow_nlattrs(const struct nlattr *key, size_t key_len,
                   const struct nlattr *attrs[], uint64_t *present_attrsp,
                   int *out_of_range_attrp)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 10);
    const struct nlattr *nla;
    uint64_t present_attrs;
    size_t left;

    BUILD_ASSERT(OVS_KEY_ATTR_MAX < CHAR_BIT * sizeof present_attrs);
    present_attrs = 0;
    *out_of_range_attrp = 0;
    NL_ATTR_FOR_EACH (nla, left, key, key_len) {
        uint16_t type = nl_attr_type(nla);
        size_t len = nl_attr_get_size(nla);
        int expected_len = odp_key_attr_len(ovs_flow_key_attr_lens,
                                            OVS_KEY_ATTR_MAX, type);

        if (len != expected_len && expected_len >= 0) {
            char namebuf[OVS_KEY_ATTR_BUFSIZE];

            VLOG_ERR_RL(&rl, "attribute %s has length %"PRIuSIZE" but should have "
                        "length %d", ovs_key_attr_to_string(type, namebuf,
                                                            sizeof namebuf),
                        len, expected_len);
            return false;
        }

        if (type > OVS_KEY_ATTR_MAX) {
            *out_of_range_attrp = type;
        } else {
            if (present_attrs & (UINT64_C(1) << type)) {
                char namebuf[OVS_KEY_ATTR_BUFSIZE];

                VLOG_ERR_RL(&rl, "duplicate %s attribute in flow key",
                            ovs_key_attr_to_string(type,
                                                   namebuf, sizeof namebuf));
                return false;
            }

            present_attrs |= UINT64_C(1) << type;
            attrs[type] = nla;
        }
    }
    if (left) {
        VLOG_ERR_RL(&rl, "trailing garbage in flow key");
        return false;
    }

    *present_attrsp = present_attrs;
    return true;
}

static enum odp_key_fitness
check_expectations(uint64_t present_attrs, int out_of_range_attr,
                   uint64_t expected_attrs,
                   const struct nlattr *key, size_t key_len)
{
    uint64_t missing_attrs;
    uint64_t extra_attrs;

    missing_attrs = expected_attrs & ~present_attrs;
    if (missing_attrs) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 10);
        log_odp_key_attributes(&rl, "expected but not present",
                               missing_attrs, 0, key, key_len);
        return ODP_FIT_TOO_LITTLE;
    }

    extra_attrs = present_attrs & ~expected_attrs;
    if (extra_attrs || out_of_range_attr) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 10);
        log_odp_key_attributes(&rl, "present but not expected",
                               extra_attrs, out_of_range_attr, key, key_len);
        return ODP_FIT_TOO_MUCH;
    }

    return ODP_FIT_PERFECT;
}

static bool
parse_ethertype(const struct nlattr *attrs[OVS_KEY_ATTR_MAX + 1],
                uint64_t present_attrs, uint64_t *expected_attrs,
                struct flow *flow, const struct flow *src_flow)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    bool is_mask = flow != src_flow;

    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_ETHERTYPE)) {
        flow->dl_type = nl_attr_get_be16(attrs[OVS_KEY_ATTR_ETHERTYPE]);
        if (!is_mask && ntohs(flow->dl_type) < ETH_TYPE_MIN) {
            VLOG_ERR_RL(&rl, "invalid Ethertype %"PRIu16" in flow key",
                        ntohs(flow->dl_type));
            return false;
        }
        if (is_mask && ntohs(src_flow->dl_type) < ETH_TYPE_MIN &&
            flow->dl_type != htons(0xffff)) {
            return false;
        }
        *expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_ETHERTYPE;
    } else {
        if (!is_mask) {
            flow->dl_type = htons(FLOW_DL_TYPE_NONE);
        } else if (ntohs(src_flow->dl_type) < ETH_TYPE_MIN) {
            /* See comments in odp_flow_key_from_flow__(). */
            VLOG_ERR_RL(&rl, "mask expected for non-Ethernet II frame");
            return false;
        }
    }
    return true;
}

static enum odp_key_fitness
parse_l2_5_onward(const struct nlattr *attrs[OVS_KEY_ATTR_MAX + 1],
                  uint64_t present_attrs, int out_of_range_attr,
                  uint64_t expected_attrs, struct flow *flow,
                  const struct nlattr *key, size_t key_len,
                  const struct flow *src_flow)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    bool is_mask = src_flow != flow;
    const void *check_start = NULL;
    size_t check_len = 0;
    enum ovs_key_attr expected_bit = 0xff;

    if (eth_type_mpls(src_flow->dl_type)) {
        if (!is_mask || present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_MPLS)) {
            expected_attrs |= (UINT64_C(1) << OVS_KEY_ATTR_MPLS);
        }
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_MPLS)) {
            size_t size = nl_attr_get_size(attrs[OVS_KEY_ATTR_MPLS]);
            const ovs_be32 *mpls_lse = nl_attr_get(attrs[OVS_KEY_ATTR_MPLS]);
            int n = size / sizeof(ovs_be32);
            int i;

            if (!size || size % sizeof(ovs_be32)) {
                return ODP_FIT_ERROR;
            }
            if (flow->mpls_lse[0] && flow->dl_type != htons(0xffff)) {
                return ODP_FIT_ERROR;
            }

            for (i = 0; i < n && i < FLOW_MAX_MPLS_LABELS; i++) {
                flow->mpls_lse[i] = mpls_lse[i];
            }
            if (n > FLOW_MAX_MPLS_LABELS) {
                return ODP_FIT_TOO_MUCH;
            }

            if (!is_mask) {
                /* BOS may be set only in the innermost label. */
                for (i = 0; i < n - 1; i++) {
                    if (flow->mpls_lse[i] & htonl(MPLS_BOS_MASK)) {
                        return ODP_FIT_ERROR;
                    }
                }

                /* BOS must be set in the innermost label. */
                if (n < FLOW_MAX_MPLS_LABELS
                    && !(flow->mpls_lse[n - 1] & htonl(MPLS_BOS_MASK))) {
                    return ODP_FIT_TOO_LITTLE;
                }
            }
        }

        goto done;
    } else if (src_flow->dl_type == htons(ETH_TYPE_IP)) {
        if (!is_mask) {
            expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_IPV4;
        }
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_IPV4)) {
            const struct ovs_key_ipv4 *ipv4_key;

            ipv4_key = nl_attr_get(attrs[OVS_KEY_ATTR_IPV4]);
            put_ipv4_key(ipv4_key, flow, is_mask);
            if (flow->nw_frag > FLOW_NW_FRAG_MASK) {
                return ODP_FIT_ERROR;
            }
            if (is_mask) {
                check_start = ipv4_key;
                check_len = sizeof *ipv4_key;
                expected_bit = OVS_KEY_ATTR_IPV4;
            }
        }
    } else if (src_flow->dl_type == htons(ETH_TYPE_IPV6)) {
        if (!is_mask) {
            expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_IPV6;
        }
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_IPV6)) {
            const struct ovs_key_ipv6 *ipv6_key;

            ipv6_key = nl_attr_get(attrs[OVS_KEY_ATTR_IPV6]);
            put_ipv6_key(ipv6_key, flow, is_mask);
            if (flow->nw_frag > FLOW_NW_FRAG_MASK) {
                return ODP_FIT_ERROR;
            }
            if (is_mask) {
                check_start = ipv6_key;
                check_len = sizeof *ipv6_key;
                expected_bit = OVS_KEY_ATTR_IPV6;
            }
        }
    } else if (src_flow->dl_type == htons(ETH_TYPE_ARP) ||
               src_flow->dl_type == htons(ETH_TYPE_RARP)) {
        if (!is_mask) {
            expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_ARP;
        }
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_ARP)) {
            const struct ovs_key_arp *arp_key;

            arp_key = nl_attr_get(attrs[OVS_KEY_ATTR_ARP]);
            if (!is_mask && (arp_key->arp_op & htons(0xff00))) {
                VLOG_ERR_RL(&rl, "unsupported ARP opcode %"PRIu16" in flow "
                            "key", ntohs(arp_key->arp_op));
                return ODP_FIT_ERROR;
            }
            put_arp_key(arp_key, flow);
            if (is_mask) {
                check_start = arp_key;
                check_len = sizeof *arp_key;
                expected_bit = OVS_KEY_ATTR_ARP;
            }
        }
    } else {
        goto done;
    }
    if (check_len > 0) { /* Happens only when 'is_mask'. */
        if (!is_all_zeros(check_start, check_len) &&
            flow->dl_type != htons(0xffff)) {
            return ODP_FIT_ERROR;
        } else {
            expected_attrs |= UINT64_C(1) << expected_bit;
        }
    }

    expected_bit = OVS_KEY_ATTR_UNSPEC;
    if (src_flow->nw_proto == IPPROTO_TCP
        && (src_flow->dl_type == htons(ETH_TYPE_IP) ||
            src_flow->dl_type == htons(ETH_TYPE_IPV6))
        && !(src_flow->nw_frag & FLOW_NW_FRAG_LATER)) {
        if (!is_mask) {
            expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_TCP;
        }
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_TCP)) {
            const union ovs_key_tp *tcp_key;

            tcp_key = nl_attr_get(attrs[OVS_KEY_ATTR_TCP]);
            put_tp_key(tcp_key, flow);
            expected_bit = OVS_KEY_ATTR_TCP;
        }
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_TCP_FLAGS)) {
            expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_TCP_FLAGS;
            flow->tcp_flags = nl_attr_get_be16(attrs[OVS_KEY_ATTR_TCP_FLAGS]);
        }
    } else if (src_flow->nw_proto == IPPROTO_UDP
               && (src_flow->dl_type == htons(ETH_TYPE_IP) ||
                   src_flow->dl_type == htons(ETH_TYPE_IPV6))
               && !(src_flow->nw_frag & FLOW_NW_FRAG_LATER)) {
        if (!is_mask) {
            expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_UDP;
        }
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_UDP)) {
            const union ovs_key_tp *udp_key;

            udp_key = nl_attr_get(attrs[OVS_KEY_ATTR_UDP]);
            put_tp_key(udp_key, flow);
            expected_bit = OVS_KEY_ATTR_UDP;
        }
    } else if (src_flow->nw_proto == IPPROTO_SCTP
               && (src_flow->dl_type == htons(ETH_TYPE_IP) ||
                   src_flow->dl_type == htons(ETH_TYPE_IPV6))
               && !(src_flow->nw_frag & FLOW_NW_FRAG_LATER)) {
        if (!is_mask) {
            expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_SCTP;
        }
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_SCTP)) {
            const union ovs_key_tp *sctp_key;

            sctp_key = nl_attr_get(attrs[OVS_KEY_ATTR_SCTP]);
            put_tp_key(sctp_key, flow);
            expected_bit = OVS_KEY_ATTR_SCTP;
        }
    } else if (src_flow->nw_proto == IPPROTO_ICMP
               && src_flow->dl_type == htons(ETH_TYPE_IP)
               && !(src_flow->nw_frag & FLOW_NW_FRAG_LATER)) {
        if (!is_mask) {
            expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_ICMP;
        }
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_ICMP)) {
            const struct ovs_key_icmp *icmp_key;

            icmp_key = nl_attr_get(attrs[OVS_KEY_ATTR_ICMP]);
            flow->tp_src = htons(icmp_key->icmp_type);
            flow->tp_dst = htons(icmp_key->icmp_code);
            expected_bit = OVS_KEY_ATTR_ICMP;
        }
    } else if (src_flow->nw_proto == IPPROTO_ICMPV6
               && src_flow->dl_type == htons(ETH_TYPE_IPV6)
               && !(src_flow->nw_frag & FLOW_NW_FRAG_LATER)) {
        if (!is_mask) {
            expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_ICMPV6;
        }
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_ICMPV6)) {
            const struct ovs_key_icmpv6 *icmpv6_key;

            icmpv6_key = nl_attr_get(attrs[OVS_KEY_ATTR_ICMPV6]);
            flow->tp_src = htons(icmpv6_key->icmpv6_type);
            flow->tp_dst = htons(icmpv6_key->icmpv6_code);
            expected_bit = OVS_KEY_ATTR_ICMPV6;
            if (src_flow->tp_dst == htons(0) &&
                (src_flow->tp_src == htons(ND_NEIGHBOR_SOLICIT) ||
                 src_flow->tp_src == htons(ND_NEIGHBOR_ADVERT))) {
                if (!is_mask) {
                    expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_ND;
                }
                if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_ND)) {
                    const struct ovs_key_nd *nd_key;

                    nd_key = nl_attr_get(attrs[OVS_KEY_ATTR_ND]);
                    memcpy(&flow->nd_target, nd_key->nd_target,
                           sizeof flow->nd_target);
                    flow->arp_sha = nd_key->nd_sll;
                    flow->arp_tha = nd_key->nd_tll;
                    if (is_mask) {
                        /* Even though 'tp_src' and 'tp_dst' are 16 bits wide,
                         * ICMP type and code are 8 bits wide.  Therefore, an
                         * exact match looks like htons(0xff), not
                         * htons(0xffff).  See xlate_wc_finish() for details.
                         * */
                        if (!is_all_zeros(nd_key, sizeof *nd_key) &&
                            (flow->tp_src != htons(0xff) ||
                             flow->tp_dst != htons(0xff))) {
                            return ODP_FIT_ERROR;
                        } else {
                            expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_ND;
                        }
                    }
                }
            }
        }
    }
    if (is_mask && expected_bit != OVS_KEY_ATTR_UNSPEC) {
        if ((flow->tp_src || flow->tp_dst) && flow->nw_proto != 0xff) {
            return ODP_FIT_ERROR;
        } else {
            expected_attrs |= UINT64_C(1) << expected_bit;
        }
    }

done:
    return check_expectations(present_attrs, out_of_range_attr, expected_attrs,
                              key, key_len);
}

/* Parse 802.1Q header then encapsulated L3 attributes. */
static enum odp_key_fitness
parse_8021q_onward(const struct nlattr *attrs[OVS_KEY_ATTR_MAX + 1],
                   uint64_t present_attrs, int out_of_range_attr,
                   uint64_t expected_attrs, struct flow *flow,
                   const struct nlattr *key, size_t key_len,
                   const struct flow *src_flow)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    bool is_mask = src_flow != flow;

    const struct nlattr *encap
        = (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_ENCAP)
           ? attrs[OVS_KEY_ATTR_ENCAP] : NULL);
    enum odp_key_fitness encap_fitness;
    enum odp_key_fitness fitness;

    /* Calculate fitness of outer attributes. */
    if (!is_mask) {
        expected_attrs |= ((UINT64_C(1) << OVS_KEY_ATTR_VLAN) |
                          (UINT64_C(1) << OVS_KEY_ATTR_ENCAP));
    } else {
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_VLAN)) {
            expected_attrs |= (UINT64_C(1) << OVS_KEY_ATTR_VLAN);
        }
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_ENCAP)) {
            expected_attrs |= (UINT64_C(1) << OVS_KEY_ATTR_ENCAP);
        }
    }
    fitness = check_expectations(present_attrs, out_of_range_attr,
                                 expected_attrs, key, key_len);

    /* Set vlan_tci.
     * Remove the TPID from dl_type since it's not the real Ethertype.  */
    flow->dl_type = htons(0);
    flow->vlan_tci = (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_VLAN)
                      ? nl_attr_get_be16(attrs[OVS_KEY_ATTR_VLAN])
                      : htons(0));
    if (!is_mask) {
        if (!(present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_VLAN))) {
            return ODP_FIT_TOO_LITTLE;
        } else if (flow->vlan_tci == htons(0)) {
            /* Corner case for a truncated 802.1Q header. */
            if (fitness == ODP_FIT_PERFECT && nl_attr_get_size(encap)) {
                return ODP_FIT_TOO_MUCH;
            }
            return fitness;
        } else if (!(flow->vlan_tci & htons(VLAN_CFI))) {
            VLOG_ERR_RL(&rl, "OVS_KEY_ATTR_VLAN 0x%04"PRIx16" is nonzero "
                        "but CFI bit is not set", ntohs(flow->vlan_tci));
            return ODP_FIT_ERROR;
        }
    } else {
        if (!(present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_ENCAP))) {
            return fitness;
        }
    }

    /* Now parse the encapsulated attributes. */
    if (!parse_flow_nlattrs(nl_attr_get(encap), nl_attr_get_size(encap),
                            attrs, &present_attrs, &out_of_range_attr)) {
        return ODP_FIT_ERROR;
    }
    expected_attrs = 0;

    if (!parse_ethertype(attrs, present_attrs, &expected_attrs, flow, src_flow)) {
        return ODP_FIT_ERROR;
    }
    encap_fitness = parse_l2_5_onward(attrs, present_attrs, out_of_range_attr,
                                      expected_attrs, flow, key, key_len,
                                      src_flow);

    /* The overall fitness is the worse of the outer and inner attributes. */
    return MAX(fitness, encap_fitness);
}

static enum odp_key_fitness
odp_flow_key_to_flow__(const struct nlattr *key, size_t key_len,
                       const struct nlattr *src_key, size_t src_key_len,
                       struct flow *flow, const struct flow *src_flow,
                       bool udpif)
{
    const struct nlattr *attrs[OVS_KEY_ATTR_MAX + 1];
    uint64_t expected_attrs;
    uint64_t present_attrs;
    int out_of_range_attr;
    bool is_mask = src_flow != flow;

    memset(flow, 0, sizeof *flow);

    /* Parse attributes. */
    if (!parse_flow_nlattrs(key, key_len, attrs, &present_attrs,
                            &out_of_range_attr)) {
        return ODP_FIT_ERROR;
    }
    expected_attrs = 0;

    /* Metadata. */
    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_RECIRC_ID)) {
        flow->recirc_id = nl_attr_get_u32(attrs[OVS_KEY_ATTR_RECIRC_ID]);
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_RECIRC_ID;
    } else if (is_mask) {
        /* Always exact match recirc_id if it is not specified. */
        flow->recirc_id = UINT32_MAX;
    }

    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_DP_HASH)) {
        flow->dp_hash = nl_attr_get_u32(attrs[OVS_KEY_ATTR_DP_HASH]);
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_DP_HASH;
    }
    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_PRIORITY)) {
        flow->skb_priority = nl_attr_get_u32(attrs[OVS_KEY_ATTR_PRIORITY]);
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_PRIORITY;
    }

    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_SKB_MARK)) {
        flow->pkt_mark = nl_attr_get_u32(attrs[OVS_KEY_ATTR_SKB_MARK]);
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_SKB_MARK;
    }

    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_CT_STATE)) {
        uint32_t odp_state = nl_attr_get_u32(attrs[OVS_KEY_ATTR_CT_STATE]);

        flow->ct_state = odp_to_ovs_ct_state(odp_state);
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_CT_STATE;
    }
    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_CT_ZONE)) {
        flow->ct_zone = nl_attr_get_u16(attrs[OVS_KEY_ATTR_CT_ZONE]);
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_CT_ZONE;
    }
    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_CT_MARK)) {
        flow->ct_mark = nl_attr_get_u32(attrs[OVS_KEY_ATTR_CT_MARK]);
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_CT_MARK;
    }
    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_CT_LABELS)) {
        const ovs_u128 *cl = nl_attr_get(attrs[OVS_KEY_ATTR_CT_LABELS]);

        flow->ct_label = *cl;
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_CT_LABELS;
    }

    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_TUNNEL)) {
        enum odp_key_fitness res;

        res = odp_tun_key_from_attr__(attrs[OVS_KEY_ATTR_TUNNEL],
                                      is_mask ? src_key : NULL,
                                      src_key_len, &src_flow->tunnel,
                                      &flow->tunnel, udpif);
        if (res == ODP_FIT_ERROR) {
            return ODP_FIT_ERROR;
        } else if (res == ODP_FIT_PERFECT) {
            expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_TUNNEL;
        }
    }

    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_IN_PORT)) {
        flow->in_port.odp_port
            = nl_attr_get_odp_port(attrs[OVS_KEY_ATTR_IN_PORT]);
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_IN_PORT;
    } else if (!is_mask) {
        flow->in_port.odp_port = ODPP_NONE;
    }

    /* Ethernet header. */
    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_ETHERNET)) {
        const struct ovs_key_ethernet *eth_key;

        eth_key = nl_attr_get(attrs[OVS_KEY_ATTR_ETHERNET]);
        put_ethernet_key(eth_key, flow);
        if (is_mask) {
            expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_ETHERNET;
        }
    }
    if (!is_mask) {
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_ETHERNET;
    }

    /* Get Ethertype or 802.1Q TPID or FLOW_DL_TYPE_NONE. */
    if (!parse_ethertype(attrs, present_attrs, &expected_attrs, flow,
        src_flow)) {
        return ODP_FIT_ERROR;
    }

    if (is_mask
        ? (src_flow->vlan_tci & htons(VLAN_CFI)) != 0
        : src_flow->dl_type == htons(ETH_TYPE_VLAN)) {
        return parse_8021q_onward(attrs, present_attrs, out_of_range_attr,
                                  expected_attrs, flow, key, key_len, src_flow);
    }
    if (is_mask) {
        /* A missing VLAN mask means exact match on vlan_tci 0 (== no VLAN). */
        flow->vlan_tci = htons(0xffff);
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_VLAN)) {
            flow->vlan_tci = nl_attr_get_be16(attrs[OVS_KEY_ATTR_VLAN]);
            expected_attrs |= (UINT64_C(1) << OVS_KEY_ATTR_VLAN);
        }
    }
    return parse_l2_5_onward(attrs, present_attrs, out_of_range_attr,
                             expected_attrs, flow, key, key_len, src_flow);
}

/* Converts the 'key_len' bytes of OVS_KEY_ATTR_* attributes in 'key' to a flow
 * structure in 'flow'.  Returns an ODP_FIT_* value that indicates how well
 * 'key' fits our expectations for what a flow key should contain.
 *
 * The 'in_port' will be the datapath's understanding of the port.  The
 * caller will need to translate with odp_port_to_ofp_port() if the
 * OpenFlow port is needed.
 *
 * This function doesn't take the packet itself as an argument because none of
 * the currently understood OVS_KEY_ATTR_* attributes require it.  Currently,
 * it is always possible to infer which additional attribute(s) should appear
 * by looking at the attributes for lower-level protocols, e.g. if the network
 * protocol in OVS_KEY_ATTR_IPV4 or OVS_KEY_ATTR_IPV6 is IPPROTO_TCP then we
 * know that a OVS_KEY_ATTR_TCP attribute must appear and that otherwise it
 * must be absent. */
enum odp_key_fitness
odp_flow_key_to_flow(const struct nlattr *key, size_t key_len,
                     struct flow *flow)
{
   return odp_flow_key_to_flow__(key, key_len, NULL, 0, flow, flow, false);
}

static enum odp_key_fitness
odp_flow_key_to_mask__(const struct nlattr *mask_key, size_t mask_key_len,
                       const struct nlattr *flow_key, size_t flow_key_len,
                       struct flow_wildcards *mask,
                       const struct flow *src_flow,
                       bool udpif)
{
    if (mask_key_len) {
        return odp_flow_key_to_flow__(mask_key, mask_key_len,
                                      flow_key, flow_key_len,
                                      &mask->masks, src_flow, udpif);

    } else {
        /* A missing mask means that the flow should be exact matched.
         * Generate an appropriate exact wildcard for the flow. */
        flow_wildcards_init_for_packet(mask, src_flow);

        return ODP_FIT_PERFECT;
    }
}
/* Converts the 'mask_key_len' bytes of OVS_KEY_ATTR_* attributes in 'mask_key'
 * to a mask structure in 'mask'.  'flow' must be a previously translated flow
 * corresponding to 'mask' and similarly flow_key/flow_key_len must be the
 * attributes from that flow.  Returns an ODP_FIT_* value that indicates how
 * well 'key' fits our expectations for what a flow key should contain. */
enum odp_key_fitness
odp_flow_key_to_mask(const struct nlattr *mask_key, size_t mask_key_len,
                     const struct nlattr *flow_key, size_t flow_key_len,
                     struct flow_wildcards *mask, const struct flow *flow)
{
    return odp_flow_key_to_mask__(mask_key, mask_key_len,
                                  flow_key, flow_key_len,
                                  mask, flow, false);
}

/* These functions are similar to their non-"_udpif" variants but output a
 * 'flow' that is suitable for fast-path packet processing.
 *
 * Some fields have different representation for flow setup and per-
 * packet processing (i.e. different between ofproto-dpif and userspace
 * datapath). In particular, with the non-"_udpif" functions, struct
 * tun_metadata is in the per-flow format (using 'present.map' and 'opts.u8');
 * with these functions, struct tun_metadata is in the per-packet format
 * (using 'present.len' and 'opts.gnv'). */
enum odp_key_fitness
odp_flow_key_to_flow_udpif(const struct nlattr *key, size_t key_len,
                           struct flow *flow)
{
   return odp_flow_key_to_flow__(key, key_len, NULL, 0, flow, flow, true);
}

enum odp_key_fitness
odp_flow_key_to_mask_udpif(const struct nlattr *mask_key, size_t mask_key_len,
                           const struct nlattr *flow_key, size_t flow_key_len,
                           struct flow_wildcards *mask,
                           const struct flow *flow)
{
    return odp_flow_key_to_mask__(mask_key, mask_key_len,
                                  flow_key, flow_key_len,
                                  mask, flow, true);
}

/* Returns 'fitness' as a string, for use in debug messages. */
const char *
odp_key_fitness_to_string(enum odp_key_fitness fitness)
{
    switch (fitness) {
    case ODP_FIT_PERFECT:
        return "OK";
    case ODP_FIT_TOO_MUCH:
        return "too_much";
    case ODP_FIT_TOO_LITTLE:
        return "too_little";
    case ODP_FIT_ERROR:
        return "error";
    default:
        return "<unknown>";
    }
}

/* Appends an OVS_ACTION_ATTR_USERSPACE action to 'odp_actions' that specifies
 * Netlink PID 'pid'.  If 'userdata' is nonnull, adds a userdata attribute
 * whose contents are the 'userdata_size' bytes at 'userdata' and returns the
 * offset within 'odp_actions' of the start of the cookie.  (If 'userdata' is
 * null, then the return value is not meaningful.) */
size_t
odp_put_userspace_action(uint32_t pid,
                         const void *userdata, size_t userdata_size,
                         odp_port_t tunnel_out_port,
                         bool include_actions,
                         struct ofpbuf *odp_actions)
{
    size_t userdata_ofs;
    size_t offset;

    offset = nl_msg_start_nested(odp_actions, OVS_ACTION_ATTR_USERSPACE);
    nl_msg_put_u32(odp_actions, OVS_USERSPACE_ATTR_PID, pid);
    if (userdata) {
        userdata_ofs = odp_actions->size + NLA_HDRLEN;

        /* The OVS kernel module before OVS 1.11 and the upstream Linux kernel
         * module before Linux 3.10 required the userdata to be exactly 8 bytes
         * long:
         *
         *   - The kernel rejected shorter userdata with -ERANGE.
         *
         *   - The kernel silently dropped userdata beyond the first 8 bytes.
         *
         * Thus, for maximum compatibility, always put at least 8 bytes.  (We
         * separately disable features that required more than 8 bytes.) */
        memcpy(nl_msg_put_unspec_zero(odp_actions, OVS_USERSPACE_ATTR_USERDATA,
                                      MAX(8, userdata_size)),
               userdata, userdata_size);
    } else {
        userdata_ofs = 0;
    }
    if (tunnel_out_port != ODPP_NONE) {
        nl_msg_put_odp_port(odp_actions, OVS_USERSPACE_ATTR_EGRESS_TUN_PORT,
                            tunnel_out_port);
    }
    if (include_actions) {
        nl_msg_put_flag(odp_actions, OVS_USERSPACE_ATTR_ACTIONS);
    }
    nl_msg_end_nested(odp_actions, offset);

    return userdata_ofs;
}

void
odp_put_tunnel_action(const struct flow_tnl *tunnel,
                      struct ofpbuf *odp_actions)
{
    size_t offset = nl_msg_start_nested(odp_actions, OVS_ACTION_ATTR_SET);
    tun_key_to_attr(odp_actions, tunnel, tunnel, NULL);
    nl_msg_end_nested(odp_actions, offset);
}

void
odp_put_tnl_push_action(struct ofpbuf *odp_actions,
                        struct ovs_action_push_tnl *data)
{
    int size = offsetof(struct ovs_action_push_tnl, header);

    size += data->header_len;
    nl_msg_put_unspec(odp_actions, OVS_ACTION_ATTR_TUNNEL_PUSH, data, size);
}


/* The commit_odp_actions() function and its helpers. */

static void
commit_set_action(struct ofpbuf *odp_actions, enum ovs_key_attr key_type,
                  const void *key, size_t key_size)
{
    size_t offset = nl_msg_start_nested(odp_actions, OVS_ACTION_ATTR_SET);
    nl_msg_put_unspec(odp_actions, key_type, key, key_size);
    nl_msg_end_nested(odp_actions, offset);
}

/* Masked set actions have a mask following the data within the netlink
 * attribute.  The unmasked bits in the data will be cleared as the data
 * is copied to the action. */
void
commit_masked_set_action(struct ofpbuf *odp_actions,
                         enum ovs_key_attr key_type,
                         const void *key_, const void *mask_, size_t key_size)
{
    size_t offset = nl_msg_start_nested(odp_actions,
                                        OVS_ACTION_ATTR_SET_MASKED);
    char *data = nl_msg_put_unspec_uninit(odp_actions, key_type, key_size * 2);
    const char *key = key_, *mask = mask_;

    memcpy(data + key_size, mask, key_size);
    /* Clear unmasked bits while copying. */
    while (key_size--) {
        *data++ = *key++ & *mask++;
    }
    nl_msg_end_nested(odp_actions, offset);
}

/* If any of the flow key data that ODP actions can modify are different in
 * 'base->tunnel' and 'flow->tunnel', appends a set_tunnel ODP action to
 * 'odp_actions' that change the flow tunneling information in key from
 * 'base->tunnel' into 'flow->tunnel', and then changes 'base->tunnel' in the
 * same way.  In other words, operates the same as commit_odp_actions(), but
 * only on tunneling information. */
void
commit_odp_tunnel_action(const struct flow *flow, struct flow *base,
                         struct ofpbuf *odp_actions)
{
    /* A valid IPV4_TUNNEL must have non-zero ip_dst; a valid IPv6 tunnel
     * must have non-zero ipv6_dst. */
    if (flow_tnl_dst_is_set(&flow->tunnel)) {
        if (!memcmp(&base->tunnel, &flow->tunnel, sizeof base->tunnel)) {
            return;
        }
        memcpy(&base->tunnel, &flow->tunnel, sizeof base->tunnel);
        odp_put_tunnel_action(&base->tunnel, odp_actions);
    }
}

static bool
commit(enum ovs_key_attr attr, bool use_masked_set,
       const void *key, void *base, void *mask, size_t size,
       struct ofpbuf *odp_actions)
{
    if (memcmp(key, base, size)) {
        bool fully_masked = odp_mask_is_exact(attr, mask, size);

        if (use_masked_set && !fully_masked) {
            commit_masked_set_action(odp_actions, attr, key, mask, size);
        } else {
            if (!fully_masked) {
                memset(mask, 0xff, size);
            }
            commit_set_action(odp_actions, attr, key, size);
        }
        memcpy(base, key, size);
        return true;
    } else {
        /* Mask bits are set when we have either read or set the corresponding
         * values.  Masked bits will be exact-matched, no need to set them
         * if the value did not actually change. */
        return false;
    }
}

static void
get_ethernet_key(const struct flow *flow, struct ovs_key_ethernet *eth)
{
    eth->eth_src = flow->dl_src;
    eth->eth_dst = flow->dl_dst;
}

static void
put_ethernet_key(const struct ovs_key_ethernet *eth, struct flow *flow)
{
    flow->dl_src = eth->eth_src;
    flow->dl_dst = eth->eth_dst;
}

static void
commit_set_ether_addr_action(const struct flow *flow, struct flow *base_flow,
                             struct ofpbuf *odp_actions,
                             struct flow_wildcards *wc,
                             bool use_masked)
{
    struct ovs_key_ethernet key, base, mask;

    get_ethernet_key(flow, &key);
    get_ethernet_key(base_flow, &base);
    get_ethernet_key(&wc->masks, &mask);

    if (commit(OVS_KEY_ATTR_ETHERNET, use_masked,
               &key, &base, &mask, sizeof key, odp_actions)) {
        put_ethernet_key(&base, base_flow);
        put_ethernet_key(&mask, &wc->masks);
    }
}

static void
pop_vlan(struct flow *base,
         struct ofpbuf *odp_actions, struct flow_wildcards *wc)
{
    memset(&wc->masks.vlan_tci, 0xff, sizeof wc->masks.vlan_tci);

    if (base->vlan_tci & htons(VLAN_CFI)) {
        nl_msg_put_flag(odp_actions, OVS_ACTION_ATTR_POP_VLAN);
        base->vlan_tci = 0;
    }
}

static void
commit_vlan_action(ovs_be16 vlan_tci, struct flow *base,
                   struct ofpbuf *odp_actions, struct flow_wildcards *wc)
{
    if (base->vlan_tci == vlan_tci) {
        return;
    }

    pop_vlan(base, odp_actions, wc);
    if (vlan_tci & htons(VLAN_CFI)) {
        struct ovs_action_push_vlan vlan;

        vlan.vlan_tpid = htons(ETH_TYPE_VLAN);
        vlan.vlan_tci = vlan_tci;
        nl_msg_put_unspec(odp_actions, OVS_ACTION_ATTR_PUSH_VLAN,
                          &vlan, sizeof vlan);
    }
    base->vlan_tci = vlan_tci;
}

/* Wildcarding already done at action translation time. */
static void
commit_mpls_action(const struct flow *flow, struct flow *base,
                   struct ofpbuf *odp_actions)
{
    int base_n = flow_count_mpls_labels(base, NULL);
    int flow_n = flow_count_mpls_labels(flow, NULL);
    int common_n = flow_count_common_mpls_labels(flow, flow_n, base, base_n,
                                                 NULL);

    while (base_n > common_n) {
        if (base_n - 1 == common_n && flow_n > common_n) {
            /* If there is only one more LSE in base than there are common
             * between base and flow; and flow has at least one more LSE than
             * is common then the topmost LSE of base may be updated using
             * set */
            struct ovs_key_mpls mpls_key;

            mpls_key.mpls_lse = flow->mpls_lse[flow_n - base_n];
            commit_set_action(odp_actions, OVS_KEY_ATTR_MPLS,
                              &mpls_key, sizeof mpls_key);
            flow_set_mpls_lse(base, 0, mpls_key.mpls_lse);
            common_n++;
        } else {
            /* Otherwise, if there more LSEs in base than are common between
             * base and flow then pop the topmost one. */
            ovs_be16 dl_type;
            bool popped;

            /* If all the LSEs are to be popped and this is not the outermost
             * LSE then use ETH_TYPE_MPLS as the ethertype parameter of the
             * POP_MPLS action instead of flow->dl_type.
             *
             * This is because the POP_MPLS action requires its ethertype
             * argument to be an MPLS ethernet type but in this case
             * flow->dl_type will be a non-MPLS ethernet type.
             *
             * When the final POP_MPLS action occurs it use flow->dl_type and
             * the and the resulting packet will have the desired dl_type. */
            if ((!eth_type_mpls(flow->dl_type)) && base_n > 1) {
                dl_type = htons(ETH_TYPE_MPLS);
            } else {
                dl_type = flow->dl_type;
            }
            nl_msg_put_be16(odp_actions, OVS_ACTION_ATTR_POP_MPLS, dl_type);
            popped = flow_pop_mpls(base, base_n, flow->dl_type, NULL);
            ovs_assert(popped);
            base_n--;
        }
    }

    /* If, after the above popping and setting, there are more LSEs in flow
     * than base then some LSEs need to be pushed. */
    while (base_n < flow_n) {
        struct ovs_action_push_mpls *mpls;

        mpls = nl_msg_put_unspec_zero(odp_actions,
                                      OVS_ACTION_ATTR_PUSH_MPLS,
                                      sizeof *mpls);
        mpls->mpls_ethertype = flow->dl_type;
        mpls->mpls_lse = flow->mpls_lse[flow_n - base_n - 1];
        flow_push_mpls(base, base_n, mpls->mpls_ethertype, NULL);
        flow_set_mpls_lse(base, 0, mpls->mpls_lse);
        base_n++;
    }
}

static void
get_ipv4_key(const struct flow *flow, struct ovs_key_ipv4 *ipv4, bool is_mask)
{
    ipv4->ipv4_src = flow->nw_src;
    ipv4->ipv4_dst = flow->nw_dst;
    ipv4->ipv4_proto = flow->nw_proto;
    ipv4->ipv4_tos = flow->nw_tos;
    ipv4->ipv4_ttl = flow->nw_ttl;
    ipv4->ipv4_frag = ovs_to_odp_frag(flow->nw_frag, is_mask);
}

static void
put_ipv4_key(const struct ovs_key_ipv4 *ipv4, struct flow *flow, bool is_mask)
{
    flow->nw_src = ipv4->ipv4_src;
    flow->nw_dst = ipv4->ipv4_dst;
    flow->nw_proto = ipv4->ipv4_proto;
    flow->nw_tos = ipv4->ipv4_tos;
    flow->nw_ttl = ipv4->ipv4_ttl;
    flow->nw_frag = odp_to_ovs_frag(ipv4->ipv4_frag, is_mask);
}

static void
commit_set_ipv4_action(const struct flow *flow, struct flow *base_flow,
                       struct ofpbuf *odp_actions, struct flow_wildcards *wc,
                       bool use_masked)
{
    struct ovs_key_ipv4 key, mask, base;

    /* Check that nw_proto and nw_frag remain unchanged. */
    ovs_assert(flow->nw_proto == base_flow->nw_proto &&
               flow->nw_frag == base_flow->nw_frag);

    get_ipv4_key(flow, &key, false);
    get_ipv4_key(base_flow, &base, false);
    get_ipv4_key(&wc->masks, &mask, true);
    mask.ipv4_proto = 0;        /* Not writeable. */
    mask.ipv4_frag = 0;         /* Not writable. */

    if (commit(OVS_KEY_ATTR_IPV4, use_masked, &key, &base, &mask, sizeof key,
               odp_actions)) {
        put_ipv4_key(&base, base_flow, false);
        if (mask.ipv4_proto != 0) { /* Mask was changed by commit(). */
            put_ipv4_key(&mask, &wc->masks, true);
        }
   }
}

static void
get_ipv6_key(const struct flow *flow, struct ovs_key_ipv6 *ipv6, bool is_mask)
{
    memcpy(ipv6->ipv6_src, &flow->ipv6_src, sizeof ipv6->ipv6_src);
    memcpy(ipv6->ipv6_dst, &flow->ipv6_dst, sizeof ipv6->ipv6_dst);
    ipv6->ipv6_label = flow->ipv6_label;
    ipv6->ipv6_proto = flow->nw_proto;
    ipv6->ipv6_tclass = flow->nw_tos;
    ipv6->ipv6_hlimit = flow->nw_ttl;
    ipv6->ipv6_frag = ovs_to_odp_frag(flow->nw_frag, is_mask);
}

static void
put_ipv6_key(const struct ovs_key_ipv6 *ipv6, struct flow *flow, bool is_mask)
{
    memcpy(&flow->ipv6_src, ipv6->ipv6_src, sizeof flow->ipv6_src);
    memcpy(&flow->ipv6_dst, ipv6->ipv6_dst, sizeof flow->ipv6_dst);
    flow->ipv6_label = ipv6->ipv6_label;
    flow->nw_proto = ipv6->ipv6_proto;
    flow->nw_tos = ipv6->ipv6_tclass;
    flow->nw_ttl = ipv6->ipv6_hlimit;
    flow->nw_frag = odp_to_ovs_frag(ipv6->ipv6_frag, is_mask);
}

static void
commit_set_ipv6_action(const struct flow *flow, struct flow *base_flow,
                       struct ofpbuf *odp_actions, struct flow_wildcards *wc,
                       bool use_masked)
{
    struct ovs_key_ipv6 key, mask, base;

    /* Check that nw_proto and nw_frag remain unchanged. */
    ovs_assert(flow->nw_proto == base_flow->nw_proto &&
               flow->nw_frag == base_flow->nw_frag);

    get_ipv6_key(flow, &key, false);
    get_ipv6_key(base_flow, &base, false);
    get_ipv6_key(&wc->masks, &mask, true);
    mask.ipv6_proto = 0;        /* Not writeable. */
    mask.ipv6_frag = 0;         /* Not writable. */

    if (commit(OVS_KEY_ATTR_IPV6, use_masked, &key, &base, &mask, sizeof key,
               odp_actions)) {
        put_ipv6_key(&base, base_flow, false);
        if (mask.ipv6_proto != 0) { /* Mask was changed by commit(). */
            put_ipv6_key(&mask, &wc->masks, true);
        }
    }
}

static void
get_arp_key(const struct flow *flow, struct ovs_key_arp *arp)
{
    /* ARP key has padding, clear it. */
    memset(arp, 0, sizeof *arp);

    arp->arp_sip = flow->nw_src;
    arp->arp_tip = flow->nw_dst;
    arp->arp_op = htons(flow->nw_proto);
    arp->arp_sha = flow->arp_sha;
    arp->arp_tha = flow->arp_tha;
}

static void
put_arp_key(const struct ovs_key_arp *arp, struct flow *flow)
{
    flow->nw_src = arp->arp_sip;
    flow->nw_dst = arp->arp_tip;
    flow->nw_proto = ntohs(arp->arp_op);
    flow->arp_sha = arp->arp_sha;
    flow->arp_tha = arp->arp_tha;
}

static enum slow_path_reason
commit_set_arp_action(const struct flow *flow, struct flow *base_flow,
                      struct ofpbuf *odp_actions, struct flow_wildcards *wc)
{
    struct ovs_key_arp key, mask, base;

    get_arp_key(flow, &key);
    get_arp_key(base_flow, &base);
    get_arp_key(&wc->masks, &mask);

    if (commit(OVS_KEY_ATTR_ARP, true, &key, &base, &mask, sizeof key,
               odp_actions)) {
        put_arp_key(&base, base_flow);
        put_arp_key(&mask, &wc->masks);
        return SLOW_ACTION;
    }
    return 0;
}

static void
get_icmp_key(const struct flow *flow, struct ovs_key_icmp *icmp)
{
    /* icmp_type and icmp_code are stored in tp_src and tp_dst, respectively */
    icmp->icmp_type = ntohs(flow->tp_src);
    icmp->icmp_code = ntohs(flow->tp_dst);
}

static void
put_icmp_key(const struct ovs_key_icmp *icmp, struct flow *flow)
{
    /* icmp_type and icmp_code are stored in tp_src and tp_dst, respectively */
    flow->tp_src = htons(icmp->icmp_type);
    flow->tp_dst = htons(icmp->icmp_code);
}

static enum slow_path_reason
commit_set_icmp_action(const struct flow *flow, struct flow *base_flow,
                       struct ofpbuf *odp_actions, struct flow_wildcards *wc)
{
    struct ovs_key_icmp key, mask, base;
    enum ovs_key_attr attr;

    if (is_icmpv4(flow)) {
        attr = OVS_KEY_ATTR_ICMP;
    } else if (is_icmpv6(flow)) {
        attr = OVS_KEY_ATTR_ICMPV6;
    } else {
        return 0;
    }

    get_icmp_key(flow, &key);
    get_icmp_key(base_flow, &base);
    get_icmp_key(&wc->masks, &mask);

    if (commit(attr, false, &key, &base, &mask, sizeof key, odp_actions)) {
        put_icmp_key(&base, base_flow);
        put_icmp_key(&mask, &wc->masks);
        return SLOW_ACTION;
    }
    return 0;
}

static void
get_nd_key(const struct flow *flow, struct ovs_key_nd *nd)
{
    memcpy(nd->nd_target, &flow->nd_target, sizeof flow->nd_target);
    /* nd_sll and nd_tll are stored in arp_sha and arp_tha, respectively */
    nd->nd_sll = flow->arp_sha;
    nd->nd_tll = flow->arp_tha;
}

static void
put_nd_key(const struct ovs_key_nd *nd, struct flow *flow)
{
    memcpy(&flow->nd_target, nd->nd_target, sizeof flow->nd_target);
    /* nd_sll and nd_tll are stored in arp_sha and arp_tha, respectively */
    flow->arp_sha = nd->nd_sll;
    flow->arp_tha = nd->nd_tll;
}

static enum slow_path_reason
commit_set_nd_action(const struct flow *flow, struct flow *base_flow,
                     struct ofpbuf *odp_actions,
                     struct flow_wildcards *wc, bool use_masked)
{
    struct ovs_key_nd key, mask, base;

    get_nd_key(flow, &key);
    get_nd_key(base_flow, &base);
    get_nd_key(&wc->masks, &mask);

    if (commit(OVS_KEY_ATTR_ND, use_masked, &key, &base, &mask, sizeof key,
               odp_actions)) {
        put_nd_key(&base, base_flow);
        put_nd_key(&mask, &wc->masks);
        return SLOW_ACTION;
    }

    return 0;
}

static enum slow_path_reason
commit_set_nw_action(const struct flow *flow, struct flow *base,
                     struct ofpbuf *odp_actions, struct flow_wildcards *wc,
                     bool use_masked)
{
    /* Check if 'flow' really has an L3 header. */
    if (!flow->nw_proto) {
        return 0;
    }

    switch (ntohs(base->dl_type)) {
    case ETH_TYPE_IP:
        commit_set_ipv4_action(flow, base, odp_actions, wc, use_masked);
        break;

    case ETH_TYPE_IPV6:
        commit_set_ipv6_action(flow, base, odp_actions, wc, use_masked);
        return commit_set_nd_action(flow, base, odp_actions, wc, use_masked);

    case ETH_TYPE_ARP:
        return commit_set_arp_action(flow, base, odp_actions, wc);
    }

    return 0;
}

/* TCP, UDP, and SCTP keys have the same layout. */
BUILD_ASSERT_DECL(sizeof(struct ovs_key_tcp) == sizeof(struct ovs_key_udp) &&
                  sizeof(struct ovs_key_tcp) == sizeof(struct ovs_key_sctp));

static void
get_tp_key(const struct flow *flow, union ovs_key_tp *tp)
{
    tp->tcp.tcp_src = flow->tp_src;
    tp->tcp.tcp_dst = flow->tp_dst;
}

static void
put_tp_key(const union ovs_key_tp *tp, struct flow *flow)
{
    flow->tp_src = tp->tcp.tcp_src;
    flow->tp_dst = tp->tcp.tcp_dst;
}

static void
commit_set_port_action(const struct flow *flow, struct flow *base_flow,
                       struct ofpbuf *odp_actions, struct flow_wildcards *wc,
                       bool use_masked)
{
    enum ovs_key_attr key_type;
    union ovs_key_tp key, mask, base;

    /* Check if 'flow' really has an L3 header. */
    if (!flow->nw_proto) {
        return;
    }

    if (!is_ip_any(base_flow)) {
        return;
    }

    if (flow->nw_proto == IPPROTO_TCP) {
        key_type = OVS_KEY_ATTR_TCP;
    } else if (flow->nw_proto == IPPROTO_UDP) {
        key_type = OVS_KEY_ATTR_UDP;
    } else if (flow->nw_proto == IPPROTO_SCTP) {
        key_type = OVS_KEY_ATTR_SCTP;
    } else {
        return;
    }

    get_tp_key(flow, &key);
    get_tp_key(base_flow, &base);
    get_tp_key(&wc->masks, &mask);

    if (commit(key_type, use_masked, &key, &base, &mask, sizeof key,
               odp_actions)) {
        put_tp_key(&base, base_flow);
        put_tp_key(&mask, &wc->masks);
    }
}

static void
commit_set_priority_action(const struct flow *flow, struct flow *base_flow,
                           struct ofpbuf *odp_actions,
                           struct flow_wildcards *wc,
                           bool use_masked)
{
    uint32_t key, mask, base;

    key = flow->skb_priority;
    base = base_flow->skb_priority;
    mask = wc->masks.skb_priority;

    if (commit(OVS_KEY_ATTR_PRIORITY, use_masked, &key, &base, &mask,
               sizeof key, odp_actions)) {
        base_flow->skb_priority = base;
        wc->masks.skb_priority = mask;
    }
}

static void
commit_set_pkt_mark_action(const struct flow *flow, struct flow *base_flow,
                           struct ofpbuf *odp_actions,
                           struct flow_wildcards *wc,
                           bool use_masked)
{
    uint32_t key, mask, base;

    key = flow->pkt_mark;
    base = base_flow->pkt_mark;
    mask = wc->masks.pkt_mark;

    if (commit(OVS_KEY_ATTR_SKB_MARK, use_masked, &key, &base, &mask,
               sizeof key, odp_actions)) {
        base_flow->pkt_mark = base;
        wc->masks.pkt_mark = mask;
    }
}

/* If any of the flow key data that ODP actions can modify are different in
 * 'base' and 'flow', appends ODP actions to 'odp_actions' that change the flow
 * key from 'base' into 'flow', and then changes 'base' the same way.  Does not
 * commit set_tunnel actions.  Users should call commit_odp_tunnel_action()
 * in addition to this function if needed.  Sets fields in 'wc' that are
 * used as part of the action.
 *
 * Returns a reason to force processing the flow's packets into the userspace
 * slow path, if there is one, otherwise 0. */
enum slow_path_reason
commit_odp_actions(const struct flow *flow, struct flow *base,
                   struct ofpbuf *odp_actions, struct flow_wildcards *wc,
                   bool use_masked)
{
    enum slow_path_reason slow1, slow2;

    commit_set_ether_addr_action(flow, base, odp_actions, wc, use_masked);
    slow1 = commit_set_nw_action(flow, base, odp_actions, wc, use_masked);
    commit_set_port_action(flow, base, odp_actions, wc, use_masked);
    slow2 = commit_set_icmp_action(flow, base, odp_actions, wc);
    commit_mpls_action(flow, base, odp_actions);
    commit_vlan_action(flow->vlan_tci, base, odp_actions, wc);
    commit_set_priority_action(flow, base, odp_actions, wc, use_masked);
    commit_set_pkt_mark_action(flow, base, odp_actions, wc, use_masked);

    return slow1 ? slow1 : slow2;
}
