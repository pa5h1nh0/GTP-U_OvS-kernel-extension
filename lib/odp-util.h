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

#ifndef ODP_UTIL_H
#define ODP_UTIL_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "flow.h"
#include "hash.h"
#include "hmap.h"
#include "odp-netlink.h"
#include "openflow/openflow.h"
#include "util.h"

struct ds;
struct nlattr;
struct ofpbuf;
struct simap;
struct pkt_metadata;

#define SLOW_PATH_REASONS                                               \
    /* These reasons are mutually exclusive. */                         \
    SPR(SLOW_CFM,        "cfm",        "Consists of CFM packets")       \
    SPR(SLOW_BFD,        "bfd",        "Consists of BFD packets")       \
    SPR(SLOW_LACP,       "lacp",       "Consists of LACP packets")      \
    SPR(SLOW_STP,        "stp",        "Consists of STP packets")       \
    SPR(SLOW_LLDP,       "lldp",       "Consists of LLDP packets")    \
    SPR(SLOW_CONTROLLER, "controller",                                  \
        "Sends \"packet-in\" messages to the OpenFlow controller")      \
    SPR(SLOW_ACTION,     "action",                                      \
        "Uses action(s) not supported by datapath")

/* Indexes for slow-path reasons.  Client code uses "enum slow_path_reason"
 * values instead of these, these are just a way to construct those. */
enum {
#define SPR(ENUM, STRING, EXPLANATION) ENUM##_INDEX,
    SLOW_PATH_REASONS
#undef SPR
};

/* Reasons why a subfacet might not be fast-pathable.
 *
 * Each reason is a separate bit to allow reasons to be combined. */
enum slow_path_reason {
#define SPR(ENUM, STRING, EXPLANATION) ENUM = 1 << ENUM##_INDEX,
    SLOW_PATH_REASONS
#undef SPR
};

/* Mask of all slow_path_reasons. */
enum {
    SLOW_PATH_REASON_MASK = 0
#define SPR(ENUM, STRING, EXPLANATION) | 1 << ENUM##_INDEX 
    SLOW_PATH_REASONS
#undef SPR
};

const char *slow_path_reason_to_explanation(enum slow_path_reason);

#define ODPP_LOCAL ODP_PORT_C(OVSP_LOCAL)
#define ODPP_NONE  ODP_PORT_C(UINT32_MAX)

void format_odp_actions(struct ds *, const struct nlattr *odp_actions,
                        size_t actions_len);
int odp_actions_from_string(const char *, const struct simap *port_names,
                            struct ofpbuf *odp_actions);
int odp_gtpu_actions_from_string(const char *, const struct simap *port_names,
	struct ofpbuf *odp_actions);

/* A map from odp port number to its name. */
struct odp_portno_names {
    struct hmap_node hmap_node; /* A node in a port number to name hmap. */
    odp_port_t port_no;         /* Port number in the datapath. */
    char *name;                 /* Name associated with the above 'port_no'. */
};

void odp_portno_names_set(struct hmap *portno_names, odp_port_t port_no,
                          char *port_name);
void odp_portno_names_destroy(struct hmap *portno_names);
/* The maximum number of bytes that odp_flow_key_from_flow() appends to a
 * buffer.  This is the upper bound on the length of a nlattr-formatted flow
 * key that ovs-vswitchd fully understands.
 *
 * OVS doesn't insist that ovs-vswitchd and the datapath have exactly the same
 * idea of a flow, so therefore this value isn't necessarily an upper bound on
 * the length of a flow key that the datapath can pass to ovs-vswitchd.
 *
 * The longest nlattr-formatted flow key appended by odp_flow_key_from_flow()
 * would be:
 *
 *                                     struct  pad  nl hdr  total
 *                                     ------  ---  ------  -----
 *  OVS_KEY_ATTR_PRIORITY                4    --     4      8
 *  OVS_KEY_ATTR_TUNNEL                  0    --     4      4
 *  - OVS_TUNNEL_KEY_ATTR_ID             8    --     4     12
 *  - OVS_TUNNEL_KEY_ATTR_IPV4_SRC       4    --     4      8
 *  - OVS_TUNNEL_KEY_ATTR_IPV4_DST       4    --     4      8
 *  - OVS_TUNNEL_KEY_ATTR_IPV6_SRC       16   --     4     20
 *  - OVS_TUNNEL_KEY_ATTR_IPV6_DST       16   --     4     20
 *  - OVS_TUNNEL_KEY_ATTR_TOS            1    3      4      8
 *  - OVS_TUNNEL_KEY_ATTR_TTL            1    3      4      8
 *  - OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT  0    --     4      4
 *  - OVS_TUNNEL_KEY_ATTR_CSUM           0    --     4      4
 *  - OVS_TUNNEL_KEY_ATTR_OAM            0    --     4      4
 *  - OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS    256  --     4      260
 *  - OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS     -    --     -      - (shared with _GENEVE_OPTS)
 *  OVS_KEY_ATTR_IN_PORT                 4    --     4      8
 *  OVS_KEY_ATTR_SKB_MARK                4    --     4      8
 *  OVS_KEY_ATTR_DP_HASH                 4    --     4      8
 *  OVS_KEY_ATTR_RECIRC_ID               4    --     4      8
 *  OVS_KEY_ATTR_CT_STATE                4    --     4      8
 *  OVS_KEY_ATTR_CT_ZONE                 2     2     4      8
 *  OVS_KEY_ATTR_CT_MARK                 4    --     4      8
 *  OVS_KEY_ATTR_CT_LABEL               16    --     4     20
 *  OVS_KEY_ATTR_ETHERNET               12    --     4     16
 *  OVS_KEY_ATTR_ETHERTYPE               2     2     4      8  (outer VLAN ethertype)
 *  OVS_KEY_ATTR_VLAN                    2     2     4      8
 *  OVS_KEY_ATTR_ENCAP                   0    --     4      4  (VLAN encapsulation)
 *  OVS_KEY_ATTR_ETHERTYPE               2     2     4      8  (inner VLAN ethertype)
 *  OVS_KEY_ATTR_IPV6                   40    --     4     44
 *  OVS_KEY_ATTR_ICMPV6                  2     2     4      8
 *  OVS_KEY_ATTR_ND                     28    --     4     32
 *  ----------------------------------------------------------
 *  total                                                 572
 *
 * We include some slack space in case the calculation isn't quite right or we
 * add another field and forget to adjust this value.
 */
#define ODPUTIL_FLOW_KEY_BYTES 640
BUILD_ASSERT_DECL(FLOW_WC_SEQ == 35);

/* A buffer with sufficient size and alignment to hold an nlattr-formatted flow
 * key.  An array of "struct nlattr" might not, in theory, be sufficiently
 * aligned because it only contains 16-bit types. */
struct odputil_keybuf {
    uint32_t keybuf[DIV_ROUND_UP(ODPUTIL_FLOW_KEY_BYTES, 4)];
};

enum odp_key_fitness odp_tun_key_from_attr(const struct nlattr *, bool udpif,
                                           struct flow_tnl *);

int odp_ufid_from_string(const char *s_, ovs_u128 *ufid);
void odp_format_ufid(const ovs_u128 *ufid, struct ds *);
void odp_flow_format(const struct nlattr *key, size_t key_len,
                     const struct nlattr *mask, size_t mask_len,
                     const struct hmap *portno_names, struct ds *,
                     bool verbose);
void odp_flow_key_format(const struct nlattr *, size_t, struct ds *);
int odp_flow_from_string(const char *s,
                         const struct simap *port_names,
                         struct ofpbuf *, struct ofpbuf *);
int odp_gtpu_flow_from_string(const char *s, const struct simap *port_names,
							  struct ofpbuf *, struct ofpbuf *);

/* Indicates support for various fields. This defines how flows will be
 * serialised. */
struct odp_support {
    /* Maximum number of MPLS label stack entries to serialise in a mask. */
    size_t max_mpls_depth;

    /* If this is true, then recirculation fields will always be serialised. */
    bool recirc;

    /* If true, serialise the corresponding OVS_KEY_ATTR_CONN_* field. */
    bool ct_state;
    bool ct_zone;
    bool ct_mark;
    bool ct_label;
};

struct odp_flow_key_parms {
    /* The flow and mask to be serialized. In the case of masks, 'flow'
     * is used as a template to determine how to interpret 'mask'.  For
     * example, the 'dl_type' of 'mask' describes the mask, but it doesn't
     * indicate whether the other fields should be interpreted as ARP, IPv4,
     * IPv6, etc. */
    const struct flow *flow;
    const struct flow *mask;

   /* 'flow->in_port' is ignored (since it is likely to be an OpenFlow port
    * number rather than a datapath port number).  Instead, if 'odp_in_port'
    * is anything other than ODPP_NONE, it is included in 'buf' as the input
    * port. */
    odp_port_t odp_in_port;

    /* Indicates support for various fields. If the datapath supports a field,
     * then it will always be serialised. */
    struct odp_support support;

    /* The netlink formatted version of the flow. It is used in cases where
     * the mask cannot be constructed from the OVS internal representation
     * and needs to see the original form. */
    const struct ofpbuf *key_buf;
};

void odp_flow_key_from_flow(const struct odp_flow_key_parms *, struct ofpbuf *);
void odp_flow_key_from_mask(const struct odp_flow_key_parms *, struct ofpbuf *);

uint32_t odp_flow_key_hash(const struct nlattr *, size_t);

/* Estimated space needed for metadata. */
enum { ODP_KEY_METADATA_SIZE = 9 * 8 };
void odp_key_from_pkt_metadata(struct ofpbuf *, const struct pkt_metadata *);
void odp_key_to_pkt_metadata(const struct nlattr *key, size_t key_len,
                              struct pkt_metadata *md);

/* How well a kernel-provided flow key (a sequence of OVS_KEY_ATTR_*
 * attributes) matches OVS userspace expectations.
 *
 * These values are arranged so that greater values are "more important" than
 * lesser ones.  In particular, a single flow key can fit the descriptions for
 * both ODP_FIT_TOO_LITTLE and ODP_FIT_TOO_MUCH.  Such a key is treated as
 * ODP_FIT_TOO_LITTLE. */
enum odp_key_fitness {
    ODP_FIT_PERFECT,            /* The key had exactly the fields we expect. */
    ODP_FIT_TOO_MUCH,           /* The key had fields we don't understand. */
    ODP_FIT_TOO_LITTLE,         /* The key lacked fields we expected to see. */
    ODP_FIT_ERROR,              /* The key was invalid. */
};
enum odp_key_fitness odp_flow_key_to_flow(const struct nlattr *, size_t,
                                          struct flow *);
enum odp_key_fitness odp_flow_key_to_mask(const struct nlattr *mask_key,
                                          size_t mask_key_len,
                                          const struct nlattr *flow_key,
                                          size_t flow_key_len,
                                          struct flow_wildcards *mask,
                                          const struct flow *flow);

enum odp_key_fitness odp_flow_key_to_flow_udpif(const struct nlattr *, size_t,
                                                struct flow *);
enum odp_key_fitness odp_flow_key_to_mask_udpif(const struct nlattr *mask_key,
                                                size_t mask_key_len,
                                                const struct nlattr *flow_key,
                                                size_t flow_key_len,
                                                struct flow_wildcards *mask,
                                                const struct flow *flow);

const char *odp_key_fitness_to_string(enum odp_key_fitness);

void commit_odp_tunnel_action(const struct flow *, struct flow *base,
                              struct ofpbuf *odp_actions);
void commit_masked_set_action(struct ofpbuf *odp_actions,
                              enum ovs_key_attr key_type, const void *key,
                              const void *mask, size_t key_size);
enum slow_path_reason commit_odp_actions(const struct flow *,
                                         struct flow *base,
                                         struct ofpbuf *odp_actions,
                                         struct flow_wildcards *wc,
                                         bool use_masked);

/* ofproto-dpif interface.
 *
 * The following types and functions are logically part of ofproto-dpif.
 * ofproto-dpif puts values of these types into the flows that it installs in
 * the kernel datapath, though, so ovs-dpctl needs to interpret them so that
 * it can print flows in a more human-readable manner. */

enum user_action_cookie_type {
    USER_ACTION_COOKIE_UNSPEC,
    USER_ACTION_COOKIE_SFLOW,        /* Packet for per-bridge sFlow sampling. */
    USER_ACTION_COOKIE_SLOW_PATH,    /* Userspace must process this flow. */
    USER_ACTION_COOKIE_FLOW_SAMPLE,  /* Packet for per-flow sampling. */
    USER_ACTION_COOKIE_IPFIX,        /* Packet for per-bridge IPFIX sampling. */
};

/* user_action_cookie is passed as argument to OVS_ACTION_ATTR_USERSPACE.
 * Since it is passed to kernel as u64, its size has to be 8 bytes. */
union user_action_cookie {
    uint16_t type;              /* enum user_action_cookie_type. */

    struct {
        uint16_t type;          /* USER_ACTION_COOKIE_SFLOW. */
        ovs_be16 vlan_tci;      /* Destination VLAN TCI. */
        uint32_t output;        /* SFL_FLOW_SAMPLE_TYPE 'output' value. */
    } sflow;

    struct {
        uint16_t type;          /* USER_ACTION_COOKIE_SLOW_PATH. */
        uint16_t unused;
        uint32_t reason;        /* enum slow_path_reason. */
    } slow_path;

    struct {
        uint16_t type;          /* USER_ACTION_COOKIE_FLOW_SAMPLE. */
        uint16_t probability;   /* Sampling probability. */
        uint32_t collector_set_id; /* ID of IPFIX collector set. */
        uint32_t obs_domain_id; /* Observation Domain ID. */
        uint32_t obs_point_id;  /* Observation Point ID. */
    } flow_sample;

    struct {
        uint16_t   type;            /* USER_ACTION_COOKIE_IPFIX. */
        odp_port_t output_odp_port; /* The output odp port. */
    } ipfix;
};
BUILD_ASSERT_DECL(sizeof(union user_action_cookie) == 16);

size_t odp_put_userspace_action(uint32_t pid,
                                const void *userdata, size_t userdata_size,
                                odp_port_t tunnel_out_port,
                                bool include_actions,
                                struct ofpbuf *odp_actions);
void odp_put_tunnel_action(const struct flow_tnl *tunnel,
                           struct ofpbuf *odp_actions);

void odp_put_tnl_push_action(struct ofpbuf *odp_actions,
                             struct ovs_action_push_tnl *data);
#endif /* odp-util.h */
