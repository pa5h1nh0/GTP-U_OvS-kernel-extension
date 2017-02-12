/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
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

#include "dpif-netlink.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <net/if.h>
#include <linux/types.h>
#include <linux/pkt_sched.h>
#include <poll.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bitmap.h"
#include "dpif-provider.h"
#include "dynamic-string.h"
#include "flow.h"
#include "fat-rwlock.h"
#include "netdev.h"
#include "netdev-linux.h"
#include "netdev-vport.h"
#include "netlink-conntrack.h"
#include "netlink-notifier.h"
#include "netlink-socket.h"
#include "netlink.h"
#include "odp-util.h"
#include "ofpbuf.h"
#include "packets.h"
#include "poll-loop.h"
#include "random.h"
#include "shash.h"
#include "sset.h"
#include "timeval.h"
#include "unaligned.h"
#include "util.h"
#include "openvswitch/vlog.h"
#include "openvswitch_gtpu.h"

VLOG_DEFINE_THIS_MODULE(dpif_netlink);
#ifdef _WIN32
enum { WINDOWS = 1 };
#else
enum { WINDOWS = 0 };
#endif
enum { MAX_PORTS = USHRT_MAX };

/* This ethtool flag was introduced in Linux 2.6.24, so it might be
 * missing if we have old headers. */
#define ETH_FLAG_LRO      (1 << 15)    /* LRO is enabled */

struct dpif_netlink_dp {
    /* Generic Netlink header. */
    uint8_t cmd;

    /* struct ovs_header. */
    int dp_ifindex;

    /* Attributes. */
    const char *name;                  /* OVS_DP_ATTR_NAME. */
    const uint32_t *upcall_pid;        /* OVS_DP_ATTR_UPCALL_PID. */
    uint32_t user_features;            /* OVS_DP_ATTR_USER_FEATURES */
    const struct ovs_dp_stats *stats;  /* OVS_DP_ATTR_STATS. */
    const struct ovs_dp_megaflow_stats *megaflow_stats;
                                       /* OVS_DP_ATTR_MEGAFLOW_STATS.*/
};

static void dpif_netlink_dp_init(struct dpif_netlink_dp *);
static int dpif_netlink_dp_from_ofpbuf(struct dpif_netlink_dp *,
                                       const struct ofpbuf *);
static void dpif_netlink_dp_dump_start(struct nl_dump *);
static int dpif_netlink_dp_transact(const struct dpif_netlink_dp *request,
                                    struct dpif_netlink_dp *reply,
                                    struct ofpbuf **bufp);
static int dpif_netlink_dp_get(const struct dpif *,
                               struct dpif_netlink_dp *reply,
                               struct ofpbuf **bufp);

struct dpif_netlink_flow {
    /* Generic Netlink header. */
    uint8_t cmd;

    /* struct ovs_header. */
    unsigned int nlmsg_flags;
    int dp_ifindex;

    /* Attributes.
     *
     * The 'stats' member points to 64-bit data that might only be aligned on
     * 32-bit boundaries, so get_unaligned_u64() should be used to access its
     * values.
     *
     * If 'actions' is nonnull then OVS_FLOW_ATTR_ACTIONS will be included in
     * the Netlink version of the command, even if actions_len is zero. */
    const struct nlattr *key;		/* OVS_FLOW_ATTR_KEY if 'is_gtp' is false, otherwise OVS_FLOW_ATTR_KEY_GTPV1. */
    size_t key_len;
    const struct nlattr *mask;		/* OVS_FLOW_ATTR_MASK if 'is_gtp' is false, otherwise OVS_FLOW_ATTR_MASK_GTPV1. */
    size_t mask_len;
    const struct nlattr *actions;	/* OVS_FLOW_ATTR_ACTIONS if 'is_gtp' is false, otherwise OVS_FLOW_ATTR_ACTIONS_GTPV1. */
    size_t actions_len;
    ovs_u128 ufid;                      /* OVS_FLOW_ATTR_FLOW_ID. */
    bool ufid_present;                  /* Is there a UFID? */
    bool ufid_terse;                    /* Skip serializing key/mask/acts? */
    const struct ovs_flow_stats *stats; /* OVS_FLOW_ATTR_STATS. */
    const uint8_t *tcp_flags;           /* OVS_FLOW_ATTR_TCP_FLAGS. */
    const ovs_32aligned_u64 *used;      /* OVS_FLOW_ATTR_USED. */
    bool clear;                         /* OVS_FLOW_ATTR_CLEAR. */
    bool probe;                         /* OVS_FLOW_ATTR_PROBE. */
	bool is_gtp;						/* Is this a GTPv1 tunnel related flow? */
};

static void dpif_netlink_flow_init(struct dpif_netlink_flow *);
static int dpif_netlink_flow_from_ofpbuf(struct dpif_netlink_flow *,
                                         const struct ofpbuf *);
static void dpif_netlink_flow_to_ofpbuf(const struct dpif_netlink_flow *,
                                        struct ofpbuf *);
static int dpif_netlink_flow_transact(struct dpif_netlink_flow *request,
                                      struct dpif_netlink_flow *reply,
                                      struct ofpbuf **bufp);
static void dpif_netlink_flow_get_stats(const struct dpif_netlink_flow *,
                                        struct dpif_flow_stats *);
static void dpif_netlink_flow_to_dpif_flow(struct dpif *, struct dpif_flow *,
                                           const struct dpif_netlink_flow *);

/* One of the dpif channels between the kernel and userspace. */
struct dpif_channel {
    struct nl_sock *sock;       /* Netlink socket. */
    long long int last_poll;    /* Last time this channel was polled. */
};

#ifdef _WIN32
#define VPORT_SOCK_POOL_SIZE 1
/* On Windows, there is no native support for epoll.  There are equivalent
 * interfaces though, that are not used currently.  For simpicity, a pool of
 * netlink sockets is used.  Each socket is represented by 'struct
 * dpif_windows_vport_sock'.  Since it is a pool, multiple OVS ports may be
 * sharing the same socket.  In the future, we can add a reference count and
 * such fields. */
struct dpif_windows_vport_sock {
    struct nl_sock *nl_sock;    /* netlink socket. */
};
#endif

struct dpif_handler {
    struct dpif_channel *channels;/* Array of channels for each handler. */
    struct epoll_event *epoll_events;
    int epoll_fd;                 /* epoll fd that includes channel socks. */
    int n_events;                 /* Num events returned by epoll_wait(). */
    int event_offset;             /* Offset into 'epoll_events'. */

#ifdef _WIN32
    /* Pool of sockets. */
    struct dpif_windows_vport_sock *vport_sock_pool;
    size_t last_used_pool_idx; /* Index to aid in allocating a
                                  socket in the pool to a port. */
#endif
};

/* Datapath interface for the openvswitch Linux kernel module. */
struct dpif_netlink {
    struct dpif dpif;
    int dp_ifindex;

    /* Upcall messages. */
    struct fat_rwlock upcall_lock;
    struct dpif_handler *handlers;
    uint32_t n_handlers;           /* Num of upcall handlers. */
    int uc_array_size;             /* Size of 'handler->channels' and */
                                   /* 'handler->epoll_events'. */

    /* Change notification. */
    struct nl_sock *port_notifier; /* vport multicast group subscriber. */
    bool refresh_channels;
};

static void report_loss(struct dpif_netlink *, struct dpif_channel *,
                        uint32_t ch_idx, uint32_t handler_id);

static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(9999, 5);

/* Generic Netlink family numbers for OVS.
 *
 * Initialized by dpif_netlink_init(). */
static int ovs_datapath_family;
static int ovs_vport_family;
static int ovs_flow_family;
static int ovs_packet_family;

/* Generic Netlink multicast groups for OVS.
 *
 * Initialized by dpif_netlink_init(). */
static unsigned int ovs_vport_mcgroup;

static int dpif_netlink_init(void);
static int open_dpif(const struct dpif_netlink_dp *, struct dpif **);
static uint32_t dpif_netlink_port_get_pid(const struct dpif *,
                                          odp_port_t port_no, uint32_t hash);
static void dpif_netlink_handler_uninit(struct dpif_handler *handler);
static int dpif_netlink_refresh_channels(struct dpif_netlink *,
                                         uint32_t n_handlers);
static void dpif_netlink_vport_to_ofpbuf(const struct dpif_netlink_vport *,
                                         struct ofpbuf *);
static int dpif_netlink_vport_from_ofpbuf(struct dpif_netlink_vport *,
                                          const struct ofpbuf *);

static struct dpif_netlink *
dpif_netlink_cast(const struct dpif *dpif)
{
    dpif_assert_class(dpif, &dpif_netlink_class);
    return CONTAINER_OF(dpif, struct dpif_netlink, dpif);
}

static int
dpif_netlink_enumerate(struct sset *all_dps,
                       const struct dpif_class *dpif_class OVS_UNUSED)
{
    struct nl_dump dump;
    uint64_t reply_stub[NL_DUMP_BUFSIZE / 8];
    struct ofpbuf msg, buf;
    int error;

    error = dpif_netlink_init();
    if (error) {
        return error;
    }

    ofpbuf_use_stub(&buf, reply_stub, sizeof reply_stub);
    dpif_netlink_dp_dump_start(&dump);
    while (nl_dump_next(&dump, &msg, &buf)) {
        struct dpif_netlink_dp dp;

        if (!dpif_netlink_dp_from_ofpbuf(&dp, &msg)) {
            sset_add(all_dps, dp.name);
        }
    }
    ofpbuf_uninit(&buf);
    return nl_dump_done(&dump);
}

static int
dpif_netlink_open(const struct dpif_class *class OVS_UNUSED, const char *name,
                  bool create, struct dpif **dpifp)
{
    struct dpif_netlink_dp dp_request, dp;
    struct ofpbuf *buf;
    uint32_t upcall_pid;
    int error;

    error = dpif_netlink_init();
    if (error) {
        return error;
    }

    /* Create or look up datapath. */
    dpif_netlink_dp_init(&dp_request);
    if (create) {
        dp_request.cmd = OVS_DP_CMD_NEW;
        upcall_pid = 0;
        dp_request.upcall_pid = &upcall_pid;
    } else {
        /* Use OVS_DP_CMD_SET to report user features */
        dp_request.cmd = OVS_DP_CMD_SET;
    }
    dp_request.name = name;
    dp_request.user_features |= OVS_DP_F_UNALIGNED;
    dp_request.user_features |= OVS_DP_F_VPORT_PIDS;
    error = dpif_netlink_dp_transact(&dp_request, &dp, &buf);
    if (error) {
        return error;
    }

    error = open_dpif(&dp, dpifp);
    ofpbuf_delete(buf);
    return error;
}

static int
open_dpif(const struct dpif_netlink_dp *dp, struct dpif **dpifp)
{
    struct dpif_netlink *dpif;

    dpif = xzalloc(sizeof *dpif);
    dpif->port_notifier = NULL;
    fat_rwlock_init(&dpif->upcall_lock);

    dpif_init(&dpif->dpif, &dpif_netlink_class, dp->name,
              dp->dp_ifindex, dp->dp_ifindex);

    dpif->dp_ifindex = dp->dp_ifindex;
    *dpifp = &dpif->dpif;

    return 0;
}

/* Destroys the netlink sockets pointed by the elements in 'socksp'
 * and frees the 'socksp'.  */
static void
vport_del_socksp__(struct nl_sock **socksp, uint32_t n_socks)
{
    size_t i;

    for (i = 0; i < n_socks; i++) {
        nl_sock_destroy(socksp[i]);
    }

    free(socksp);
}

/* Creates an array of netlink sockets.  Returns an array of the
 * corresponding pointers.  Records the error in 'error'. */
static struct nl_sock **
vport_create_socksp__(uint32_t n_socks, int *error)
{
    struct nl_sock **socksp = xzalloc(n_socks * sizeof *socksp);
    size_t i;

    for (i = 0; i < n_socks; i++) {
        *error = nl_sock_create(NETLINK_GENERIC, &socksp[i]);
        if (*error) {
            goto error;
        }
    }

    return socksp;

error:
    vport_del_socksp__(socksp, n_socks);

    return NULL;
}

#ifdef _WIN32
static void
vport_delete_sock_pool(struct dpif_handler *handler)
    OVS_REQ_WRLOCK(dpif->upcall_lock)
{
    if (handler->vport_sock_pool) {
        uint32_t i;
        struct dpif_windows_vport_sock *sock_pool =
            handler->vport_sock_pool;

        for (i = 0; i < VPORT_SOCK_POOL_SIZE; i++) {
            if (sock_pool[i].nl_sock) {
                nl_sock_unsubscribe_packets(sock_pool[i].nl_sock);
                nl_sock_destroy(sock_pool[i].nl_sock);
                sock_pool[i].nl_sock = NULL;
            }
        }

        free(handler->vport_sock_pool);
        handler->vport_sock_pool = NULL;
    }
}

static int
vport_create_sock_pool(struct dpif_handler *handler)
    OVS_REQ_WRLOCK(dpif->upcall_lock)
{
    struct dpif_windows_vport_sock *sock_pool;
    size_t i;
    int error = 0;

    sock_pool = xzalloc(VPORT_SOCK_POOL_SIZE * sizeof *sock_pool);
    for (i = 0; i < VPORT_SOCK_POOL_SIZE; i++) {
        error = nl_sock_create(NETLINK_GENERIC, &sock_pool[i].nl_sock);
        if (error) {
            goto error;
        }

        /* Enable the netlink socket to receive packets.  This is equivalent to
         * calling nl_sock_join_mcgroup() to receive events. */
        error = nl_sock_subscribe_packets(sock_pool[i].nl_sock);
        if (error) {
           goto error;
        }
    }

    handler->vport_sock_pool = sock_pool;
    handler->last_used_pool_idx = 0;
    return 0;

error:
    vport_delete_sock_pool(handler);
    return error;
}

/* Returns an array pointers to netlink sockets.  The sockets are picked from a
 * pool. Records the error in 'error'. */
static struct nl_sock **
vport_create_socksp_windows(struct dpif_netlink *dpif, int *error)
    OVS_REQ_WRLOCK(dpif->upcall_lock)
{
    uint32_t n_socks = dpif->n_handlers;
    struct nl_sock **socksp;
    size_t i;

    ovs_assert(n_socks <= 1);
    socksp = xzalloc(n_socks * sizeof *socksp);

    /* Pick netlink sockets to use in a round-robin fashion from each
     * handler's pool of sockets. */
    for (i = 0; i < n_socks; i++) {
        struct dpif_handler *handler = &dpif->handlers[i];
        struct dpif_windows_vport_sock *sock_pool = handler->vport_sock_pool;
        size_t index = handler->last_used_pool_idx;

        /* A pool of sockets is allocated when the handler is initialized. */
        if (sock_pool == NULL) {
            free(socksp);
            *error = EINVAL;
            return NULL;
        }

        ovs_assert(index < VPORT_SOCK_POOL_SIZE);
        socksp[i] = sock_pool[index].nl_sock;
        socksp[i] = sock_pool[index].nl_sock;
        ovs_assert(socksp[i]);
        index = (index == VPORT_SOCK_POOL_SIZE - 1) ? 0 : index + 1;
        handler->last_used_pool_idx = index;
    }

    return socksp;
}

static void
vport_del_socksp_windows(struct dpif_netlink *dpif, struct nl_sock **socksp)
{
    free(socksp);
}
#endif /* _WIN32 */

static struct nl_sock **
vport_create_socksp(struct dpif_netlink *dpif, int *error)
{
#ifdef _WIN32
    return vport_create_socksp_windows(dpif, error);
#else
    return vport_create_socksp__(dpif->n_handlers, error);
#endif
}

static void
vport_del_socksp(struct dpif_netlink *dpif, struct nl_sock **socksp)
{
#ifdef _WIN32
    vport_del_socksp_windows(dpif, socksp);
#else
    vport_del_socksp__(socksp, dpif->n_handlers);
#endif
}

/* Given the array of pointers to netlink sockets 'socksp', returns
 * the array of corresponding pids. If the 'socksp' is NULL, returns
 * a single-element array of value 0. */
static uint32_t *
vport_socksp_to_pids(struct nl_sock **socksp, uint32_t n_socks)
{
    uint32_t *pids;

    if (!socksp) {
        pids = xzalloc(sizeof *pids);
    } else {
        size_t i;

        pids = xzalloc(n_socks * sizeof *pids);
        for (i = 0; i < n_socks; i++) {
            pids[i] = nl_sock_pid(socksp[i]);
        }
    }

    return pids;
}

/* Given the port number 'port_idx', extracts the pids of netlink sockets
 * associated to the port and assigns it to 'upcall_pids'. */
static bool
vport_get_pids(struct dpif_netlink *dpif, uint32_t port_idx,
               uint32_t **upcall_pids)
{
    uint32_t *pids;
    size_t i;

    /* Since the nl_sock can only be assigned in either all
     * or none "dpif->handlers" channels, the following check
     * would suffice. */
    if (!dpif->handlers[0].channels[port_idx].sock) {
        return false;
    }
    ovs_assert(!WINDOWS || dpif->n_handlers <= 1);

    pids = xzalloc(dpif->n_handlers * sizeof *pids);

    for (i = 0; i < dpif->n_handlers; i++) {
        pids[i] = nl_sock_pid(dpif->handlers[i].channels[port_idx].sock);
    }

    *upcall_pids = pids;

    return true;
}

static int
vport_add_channels(struct dpif_netlink *dpif, odp_port_t port_no,
                   struct nl_sock **socksp)
{
    struct epoll_event event;
    uint32_t port_idx = odp_to_u32(port_no);
    size_t i, j;
    int error;

    if (dpif->handlers == NULL) {
        return 0;
    }

    /* We assume that the datapath densely chooses port numbers, which can
     * therefore be used as an index into 'channels' and 'epoll_events' of
     * 'dpif->handler'. */
    if (port_idx >= dpif->uc_array_size) {
        uint32_t new_size = port_idx + 1;

        if (new_size > MAX_PORTS) {
            VLOG_WARN_RL(&error_rl, "%s: datapath port %"PRIu32" too big",
                         dpif_name(&dpif->dpif), port_no);
            return EFBIG;
        }

        for (i = 0; i < dpif->n_handlers; i++) {
            struct dpif_handler *handler = &dpif->handlers[i];

            handler->channels = xrealloc(handler->channels,
                                         new_size * sizeof *handler->channels);

            for (j = dpif->uc_array_size; j < new_size; j++) {
                handler->channels[j].sock = NULL;
            }

            handler->epoll_events = xrealloc(handler->epoll_events,
                new_size * sizeof *handler->epoll_events);

        }
        dpif->uc_array_size = new_size;
    }

    memset(&event, 0, sizeof event);
    event.events = EPOLLIN;
    event.data.u32 = port_idx;

    for (i = 0; i < dpif->n_handlers; i++) {
        struct dpif_handler *handler = &dpif->handlers[i];

#ifndef _WIN32
        if (epoll_ctl(handler->epoll_fd, EPOLL_CTL_ADD, nl_sock_fd(socksp[i]),
                      &event) < 0) {
            error = errno;
            goto error;
        }
#endif
        dpif->handlers[i].channels[port_idx].sock = socksp[i];
        dpif->handlers[i].channels[port_idx].last_poll = LLONG_MIN;
    }

    return 0;

error:
    for (j = 0; j < i; j++) {
#ifndef _WIN32
        epoll_ctl(dpif->handlers[j].epoll_fd, EPOLL_CTL_DEL,
                  nl_sock_fd(socksp[j]), NULL);
#endif
        dpif->handlers[j].channels[port_idx].sock = NULL;
    }

    return error;
}

static void
vport_del_channels(struct dpif_netlink *dpif, odp_port_t port_no)
{
    uint32_t port_idx = odp_to_u32(port_no);
    size_t i;

    if (!dpif->handlers || port_idx >= dpif->uc_array_size) {
        return;
    }

    /* Since the sock can only be assigned in either all or none
     * of "dpif->handlers" channels, the following check would
     * suffice. */
    if (!dpif->handlers[0].channels[port_idx].sock) {
        return;
    }

    for (i = 0; i < dpif->n_handlers; i++) {
        struct dpif_handler *handler = &dpif->handlers[i];
#ifndef _WIN32
        epoll_ctl(handler->epoll_fd, EPOLL_CTL_DEL,
                  nl_sock_fd(handler->channels[port_idx].sock), NULL);
        nl_sock_destroy(handler->channels[port_idx].sock);
#endif
        handler->channels[port_idx].sock = NULL;
        handler->event_offset = handler->n_events = 0;
    }
}

static void
destroy_all_channels(struct dpif_netlink *dpif)
    OVS_REQ_WRLOCK(dpif->upcall_lock)
{
    unsigned int i;

    if (!dpif->handlers) {
        return;
    }

    for (i = 0; i < dpif->uc_array_size; i++ ) {
        struct dpif_netlink_vport vport_request;
        uint32_t upcall_pids = 0;

        /* Since the sock can only be assigned in either all or none
         * of "dpif->handlers" channels, the following check would
         * suffice. */
        if (!dpif->handlers[0].channels[i].sock) {
            continue;
        }

        /* Turn off upcalls. */
        dpif_netlink_vport_init(&vport_request);
        vport_request.cmd = OVS_VPORT_CMD_SET;
        vport_request.dp_ifindex = dpif->dp_ifindex;
        vport_request.port_no = u32_to_odp(i);
        vport_request.n_upcall_pids = 1;
        vport_request.upcall_pids = &upcall_pids;
        dpif_netlink_vport_transact(&vport_request, NULL, NULL);

        vport_del_channels(dpif, u32_to_odp(i));
    }

    for (i = 0; i < dpif->n_handlers; i++) {
        struct dpif_handler *handler = &dpif->handlers[i];

        dpif_netlink_handler_uninit(handler);
        free(handler->epoll_events);
        free(handler->channels);
    }

    free(dpif->handlers);
    dpif->handlers = NULL;
    dpif->n_handlers = 0;
    dpif->uc_array_size = 0;
}

static void
dpif_netlink_close(struct dpif *dpif_)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);

    nl_sock_destroy(dpif->port_notifier);

    fat_rwlock_wrlock(&dpif->upcall_lock);
    destroy_all_channels(dpif);
    fat_rwlock_unlock(&dpif->upcall_lock);

    fat_rwlock_destroy(&dpif->upcall_lock);
    free(dpif);
}

static int
dpif_netlink_destroy(struct dpif *dpif_)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    struct dpif_netlink_dp dp;

    dpif_netlink_dp_init(&dp);
    dp.cmd = OVS_DP_CMD_DEL;
    dp.dp_ifindex = dpif->dp_ifindex;
    return dpif_netlink_dp_transact(&dp, NULL, NULL);
}

static bool
dpif_netlink_run(struct dpif *dpif_)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);

    if (dpif->refresh_channels) {
        dpif->refresh_channels = false;
        fat_rwlock_wrlock(&dpif->upcall_lock);
        dpif_netlink_refresh_channels(dpif, dpif->n_handlers);
        fat_rwlock_unlock(&dpif->upcall_lock);
    }
    return false;
}

static int
dpif_netlink_get_stats(const struct dpif *dpif_, struct dpif_dp_stats *stats)
{
    struct dpif_netlink_dp dp;
    struct ofpbuf *buf;
    int error;

    error = dpif_netlink_dp_get(dpif_, &dp, &buf);
    if (!error) {
        memset(stats, 0, sizeof *stats);

        if (dp.stats) {
            stats->n_hit    = get_32aligned_u64(&dp.stats->n_hit);
            stats->n_missed = get_32aligned_u64(&dp.stats->n_missed);
            stats->n_lost   = get_32aligned_u64(&dp.stats->n_lost);
            stats->n_flows  = get_32aligned_u64(&dp.stats->n_flows);
        }

        if (dp.megaflow_stats) {
            stats->n_masks = dp.megaflow_stats->n_masks;
            stats->n_mask_hit = get_32aligned_u64(
                &dp.megaflow_stats->n_mask_hit);
        } else {
            stats->n_masks = UINT32_MAX;
            stats->n_mask_hit = UINT64_MAX;
        }
        ofpbuf_delete(buf);
    }
    return error;
}

static const char *
get_vport_type(const struct dpif_netlink_vport *vport)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

    switch (vport->type) {
    case OVS_VPORT_TYPE_NETDEV: {
        const char *type = netdev_get_type_from_name(vport->name);

        return type ? type : "system";
    }

    case OVS_VPORT_TYPE_INTERNAL:
        return "internal";

    case OVS_VPORT_TYPE_GENEVE:
        return "geneve";

    case OVS_VPORT_TYPE_GRE:
        return "gre";

    case OVS_VPORT_TYPE_VXLAN:
        return "vxlan";

    case OVS_VPORT_TYPE_LISP:
        return "lisp";

    case OVS_VPORT_TYPE_STT:
        return "stt";

    case OVS_VPORT_TYPE_UNSPEC:
    case __OVS_VPORT_TYPE_MAX:
        break;
    }

    VLOG_WARN_RL(&rl, "dp%d: port `%s' has unsupported type %u",
                 vport->dp_ifindex, vport->name, (unsigned int) vport->type);
    return "unknown";
}

static enum ovs_vport_type
netdev_to_ovs_vport_type(const struct netdev *netdev)
{
    const char *type = netdev_get_type(netdev);

    if (!strcmp(type, "tap") || !strcmp(type, "system")) {
        return OVS_VPORT_TYPE_NETDEV;
    } else if (!strcmp(type, "internal")) {
        return OVS_VPORT_TYPE_INTERNAL;
    } else if (strstr(type, "stt")) {
        return OVS_VPORT_TYPE_STT;
    } else if (!strcmp(type, "geneve")) {
        return OVS_VPORT_TYPE_GENEVE;
    } else if (strstr(type, "gre")) {
        return OVS_VPORT_TYPE_GRE;
    } else if (!strcmp(type, "vxlan")) {
        return OVS_VPORT_TYPE_VXLAN;
    } else if (!strcmp(type, "lisp")) {
        return OVS_VPORT_TYPE_LISP;
    } else {
        return OVS_VPORT_TYPE_UNSPEC;
    }
}

static int
dpif_netlink_port_add__(struct dpif_netlink *dpif, struct netdev *netdev,
                        odp_port_t *port_nop)
    OVS_REQ_WRLOCK(dpif->upcall_lock)
{
    const struct netdev_tunnel_config *tnl_cfg;
    char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
    const char *name = netdev_vport_get_dpif_port(netdev,
                                                  namebuf, sizeof namebuf);
    const char *type = netdev_get_type(netdev);
    struct dpif_netlink_vport request, reply;
    struct ofpbuf *buf;
    uint64_t options_stub[64 / 8];
    struct ofpbuf options;
    struct nl_sock **socksp = NULL;
    uint32_t *upcall_pids;
    int error = 0;

    if (dpif->handlers) {
        socksp = vport_create_socksp(dpif, &error);
        if (!socksp) {
            return error;
        }
    }

    dpif_netlink_vport_init(&request);
    request.cmd = OVS_VPORT_CMD_NEW;
    request.dp_ifindex = dpif->dp_ifindex;
    request.type = netdev_to_ovs_vport_type(netdev);
    if (request.type == OVS_VPORT_TYPE_UNSPEC) {
        VLOG_WARN_RL(&error_rl, "%s: cannot create port `%s' because it has "
                     "unsupported type `%s'",
                     dpif_name(&dpif->dpif), name, type);
        vport_del_socksp(dpif, socksp);
        return EINVAL;
    }
    request.name = name;

    if (request.type == OVS_VPORT_TYPE_NETDEV) {
#ifdef _WIN32
        /* XXX : Map appropiate Windows handle */
#else
        netdev_linux_ethtool_set_flag(netdev, ETH_FLAG_LRO, "LRO", false);
#endif
    }

    tnl_cfg = netdev_get_tunnel_config(netdev);
    if (tnl_cfg && (tnl_cfg->dst_port != 0 || tnl_cfg->exts)) {
        ofpbuf_use_stack(&options, options_stub, sizeof options_stub);
        if (tnl_cfg->dst_port) {
            nl_msg_put_u16(&options, OVS_TUNNEL_ATTR_DST_PORT,
                           ntohs(tnl_cfg->dst_port));
        }
        if (tnl_cfg->exts) {
            size_t ext_ofs;
            int i;

            ext_ofs = nl_msg_start_nested(&options, OVS_TUNNEL_ATTR_EXTENSION);
            for (i = 0; i < 32; i++) {
                if (tnl_cfg->exts & (1 << i)) {
                    nl_msg_put_flag(&options, i);
                }
            }
            nl_msg_end_nested(&options, ext_ofs);
        }
        request.options = options.data;
        request.options_len = options.size;
    }

    request.port_no = *port_nop;
    upcall_pids = vport_socksp_to_pids(socksp, dpif->n_handlers);
    request.n_upcall_pids = socksp ? dpif->n_handlers : 1;
    request.upcall_pids = upcall_pids;

    error = dpif_netlink_vport_transact(&request, &reply, &buf);
    if (!error) {
        *port_nop = reply.port_no;
    } else {
        if (error == EBUSY && *port_nop != ODPP_NONE) {
            VLOG_INFO("%s: requested port %"PRIu32" is in use",
                      dpif_name(&dpif->dpif), *port_nop);
        }

        vport_del_socksp(dpif, socksp);
        goto exit;
    }

    if (socksp) {
        error = vport_add_channels(dpif, *port_nop, socksp);
        if (error) {
            VLOG_INFO("%s: could not add channel for port %s",
                      dpif_name(&dpif->dpif), name);

            /* Delete the port. */
            dpif_netlink_vport_init(&request);
            request.cmd = OVS_VPORT_CMD_DEL;
            request.dp_ifindex = dpif->dp_ifindex;
            request.port_no = *port_nop;
            dpif_netlink_vport_transact(&request, NULL, NULL);
            vport_del_socksp(dpif, socksp);
            goto exit;
        }
    }
    free(socksp);

exit:
    ofpbuf_delete(buf);
    free(upcall_pids);

    return error;
}

static int
dpif_netlink_port_add(struct dpif *dpif_, struct netdev *netdev,
                      odp_port_t *port_nop)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    int error;

    fat_rwlock_wrlock(&dpif->upcall_lock);
    error = dpif_netlink_port_add__(dpif, netdev, port_nop);
    fat_rwlock_unlock(&dpif->upcall_lock);

    return error;
}

static int
dpif_netlink_port_del__(struct dpif_netlink *dpif, odp_port_t port_no)
    OVS_REQ_WRLOCK(dpif->upcall_lock)
{
    struct dpif_netlink_vport vport;
    int error;

    dpif_netlink_vport_init(&vport);
    vport.cmd = OVS_VPORT_CMD_DEL;
    vport.dp_ifindex = dpif->dp_ifindex;
    vport.port_no = port_no;
    error = dpif_netlink_vport_transact(&vport, NULL, NULL);

    vport_del_channels(dpif, port_no);

    return error;
}

static int
dpif_netlink_port_del(struct dpif *dpif_, odp_port_t port_no)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    int error;

    fat_rwlock_wrlock(&dpif->upcall_lock);
    error = dpif_netlink_port_del__(dpif, port_no);
    fat_rwlock_unlock(&dpif->upcall_lock);

    return error;
}

static int
dpif_netlink_port_query__(const struct dpif_netlink *dpif, odp_port_t port_no,
                          const char *port_name, struct dpif_port *dpif_port)
{
    struct dpif_netlink_vport request;
    struct dpif_netlink_vport reply;
    struct ofpbuf *buf;
    int error;

    dpif_netlink_vport_init(&request);
    request.cmd = OVS_VPORT_CMD_GET;
    request.dp_ifindex = dpif->dp_ifindex;
    request.port_no = port_no;
    request.name = port_name;

    error = dpif_netlink_vport_transact(&request, &reply, &buf);
    if (!error) {
        if (reply.dp_ifindex != request.dp_ifindex) {
            /* A query by name reported that 'port_name' is in some datapath
             * other than 'dpif', but the caller wants to know about 'dpif'. */
            error = ENODEV;
        } else if (dpif_port) {
            dpif_port->name = xstrdup(reply.name);
            dpif_port->type = xstrdup(get_vport_type(&reply));
            dpif_port->port_no = reply.port_no;
        }
        ofpbuf_delete(buf);
    }
    return error;
}

static int
dpif_netlink_port_query_by_number(const struct dpif *dpif_, odp_port_t port_no,
                                  struct dpif_port *dpif_port)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);

    return dpif_netlink_port_query__(dpif, port_no, NULL, dpif_port);
}

static int
dpif_netlink_port_query_by_name(const struct dpif *dpif_, const char *devname,
                              struct dpif_port *dpif_port)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);

    return dpif_netlink_port_query__(dpif, 0, devname, dpif_port);
}

static uint32_t
dpif_netlink_port_get_pid__(const struct dpif_netlink *dpif,
                            odp_port_t port_no, uint32_t hash)
    OVS_REQ_RDLOCK(dpif->upcall_lock)
{
    uint32_t port_idx = odp_to_u32(port_no);
    uint32_t pid = 0;

    if (dpif->handlers && dpif->uc_array_size > 0) {
        /* The ODPP_NONE "reserved" port number uses the "ovs-system"'s
         * channel, since it is not heavily loaded. */
        uint32_t idx = port_idx >= dpif->uc_array_size ? 0 : port_idx;
        struct dpif_handler *h = &dpif->handlers[hash % dpif->n_handlers];

        /* Needs to check in case the socket pointer is changed in between
         * the holding of upcall_lock.  A known case happens when the main
         * thread deletes the vport while the handler thread is handling
         * the upcall from that port. */
        if (h->channels[idx].sock) {
            pid = nl_sock_pid(h->channels[idx].sock);
        }
    }

    return pid;
}

static uint32_t
dpif_netlink_port_get_pid(const struct dpif *dpif_, odp_port_t port_no,
                          uint32_t hash)
{
    const struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    uint32_t ret;

    fat_rwlock_rdlock(&dpif->upcall_lock);
    ret = dpif_netlink_port_get_pid__(dpif, port_no, hash);
    fat_rwlock_unlock(&dpif->upcall_lock);

    return ret;
}

static int
dpif_netlink_flow_flush(struct dpif *dpif_)
{
    const struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    struct dpif_netlink_flow flow;

    dpif_netlink_flow_init(&flow);
    flow.cmd = OVS_FLOW_CMD_DEL;
    flow.dp_ifindex = dpif->dp_ifindex;
    return dpif_netlink_flow_transact(&flow, NULL, NULL);
}

struct dpif_netlink_port_state {
    struct nl_dump dump;
    struct ofpbuf buf;
};

static void
dpif_netlink_port_dump_start__(const struct dpif_netlink *dpif,
                               struct nl_dump *dump)
{
    struct dpif_netlink_vport request;
    struct ofpbuf *buf;

    dpif_netlink_vport_init(&request);
    request.cmd = OVS_VPORT_CMD_GET;
    request.dp_ifindex = dpif->dp_ifindex;

    buf = ofpbuf_new(1024);
    dpif_netlink_vport_to_ofpbuf(&request, buf);
    nl_dump_start(dump, NETLINK_GENERIC, buf);
    ofpbuf_delete(buf);
}

static int
dpif_netlink_port_dump_start(const struct dpif *dpif_, void **statep)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    struct dpif_netlink_port_state *state;

    *statep = state = xmalloc(sizeof *state);
    dpif_netlink_port_dump_start__(dpif, &state->dump);

    ofpbuf_init(&state->buf, NL_DUMP_BUFSIZE);
    return 0;
}

static int
dpif_netlink_port_dump_next__(const struct dpif_netlink *dpif,
                              struct nl_dump *dump,
                              struct dpif_netlink_vport *vport,
                              struct ofpbuf *buffer)
{
    struct ofpbuf buf;
    int error;

    if (!nl_dump_next(dump, &buf, buffer)) {
        return EOF;
    }

    error = dpif_netlink_vport_from_ofpbuf(vport, &buf);
    if (error) {
        VLOG_WARN_RL(&error_rl, "%s: failed to parse vport record (%s)",
                     dpif_name(&dpif->dpif), ovs_strerror(error));
    }
    return error;
}

static int
dpif_netlink_port_dump_next(const struct dpif *dpif_, void *state_,
                            struct dpif_port *dpif_port)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    struct dpif_netlink_port_state *state = state_;
    struct dpif_netlink_vport vport;
    int error;

    error = dpif_netlink_port_dump_next__(dpif, &state->dump, &vport,
                                          &state->buf);
    if (error) {
        return error;
    }
    dpif_port->name = CONST_CAST(char *, vport.name);
    dpif_port->type = CONST_CAST(char *, get_vport_type(&vport));
    dpif_port->port_no = vport.port_no;
    return 0;
}

static int
dpif_netlink_port_dump_done(const struct dpif *dpif_ OVS_UNUSED, void *state_)
{
    struct dpif_netlink_port_state *state = state_;
    int error = nl_dump_done(&state->dump);

    ofpbuf_uninit(&state->buf);
    free(state);
    return error;
}

static int
dpif_netlink_port_poll(const struct dpif *dpif_, char **devnamep)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);

    /* Lazily create the Netlink socket to listen for notifications. */
    if (!dpif->port_notifier) {
        struct nl_sock *sock;
        int error;

        error = nl_sock_create(NETLINK_GENERIC, &sock);
        if (error) {
            return error;
        }

        error = nl_sock_join_mcgroup(sock, ovs_vport_mcgroup);
        if (error) {
            nl_sock_destroy(sock);
            return error;
        }
        dpif->port_notifier = sock;

        /* We have no idea of the current state so report that everything
         * changed. */
        return ENOBUFS;
    }

    for (;;) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        uint64_t buf_stub[4096 / 8];
        struct ofpbuf buf;
        int error;

        ofpbuf_use_stub(&buf, buf_stub, sizeof buf_stub);
        error = nl_sock_recv(dpif->port_notifier, &buf, false);
        if (!error) {
            struct dpif_netlink_vport vport;

            error = dpif_netlink_vport_from_ofpbuf(&vport, &buf);
            if (!error) {
                if (vport.dp_ifindex == dpif->dp_ifindex
                    && (vport.cmd == OVS_VPORT_CMD_NEW
                        || vport.cmd == OVS_VPORT_CMD_DEL
                        || vport.cmd == OVS_VPORT_CMD_SET)) {
                    VLOG_DBG("port_changed: dpif:%s vport:%s cmd:%"PRIu8,
                             dpif->dpif.full_name, vport.name, vport.cmd);
                    if (vport.cmd == OVS_VPORT_CMD_DEL && dpif->handlers) {
                        dpif->refresh_channels = true;
                    }
                    *devnamep = xstrdup(vport.name);
                    ofpbuf_uninit(&buf);
                    return 0;
                }
            }
        } else if (error != EAGAIN) {
            VLOG_WARN_RL(&rl, "error reading or parsing netlink (%s)",
                         ovs_strerror(error));
            nl_sock_drain(dpif->port_notifier);
            error = ENOBUFS;
        }

        ofpbuf_uninit(&buf);
        if (error) {
            return error;
        }
    }
}

static void
dpif_netlink_port_poll_wait(const struct dpif *dpif_)
{
    const struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);

    if (dpif->port_notifier) {
        nl_sock_wait(dpif->port_notifier, POLLIN);
    } else {
        poll_immediate_wake();
    }
}

static void
dpif_netlink_flow_init_ufid(struct dpif_netlink_flow *request,
                            const ovs_u128 *ufid, bool terse)
{
    if (ufid) {
        request->ufid = *ufid;
        request->ufid_present = true;
    } else {
        request->ufid_present = false;
    }
    request->ufid_terse = terse;
}

static void
dpif_netlink_init_flow_get__(const struct dpif_netlink *dpif,
                             const struct nlattr *key, size_t key_len,
                             const ovs_u128 *ufid, bool terse,
                             struct dpif_netlink_flow *request)
{
    dpif_netlink_flow_init(request);
    request->cmd = OVS_FLOW_CMD_GET;
    request->dp_ifindex = dpif->dp_ifindex;
    request->key = key;
    request->key_len = key_len;
    dpif_netlink_flow_init_ufid(request, ufid, terse);
}

static void
dpif_netlink_init_flow_get(const struct dpif_netlink *dpif,
                           const struct dpif_flow_get *get,
                           struct dpif_netlink_flow *request)
{
    dpif_netlink_init_flow_get__(dpif, get->key, get->key_len, get->ufid,
                                 false, request);
}

static int
dpif_netlink_flow_get__(const struct dpif_netlink *dpif,
                        const struct nlattr *key, size_t key_len,
                        const ovs_u128 *ufid, bool terse,
                        struct dpif_netlink_flow *reply, struct ofpbuf **bufp)
{
    struct dpif_netlink_flow request;

	dpif_netlink_init_flow_get__(dpif, key, key_len, ufid, terse, &request);
	request.is_gtp = reply->is_gtp;
    return dpif_netlink_flow_transact(&request, reply, bufp);
}

static int
dpif_netlink_flow_get(const struct dpif_netlink *dpif,
                      const struct dpif_netlink_flow *flow,
                      struct dpif_netlink_flow *reply, struct ofpbuf **bufp)
{
    return dpif_netlink_flow_get__(dpif, flow->key, flow->key_len,
                                   flow->ufid_present ? &flow->ufid : NULL,
                                   false, reply, bufp);
}

static void
dpif_netlink_init_flow_put(struct dpif_netlink *dpif,
                           const struct dpif_flow_put *put,
                           struct dpif_netlink_flow *request)
{
    static const struct nlattr dummy_action;

    dpif_netlink_flow_init(request);

	if (put->flags & DPIF_FP_CREATE)
		request->cmd = OVS_FLOW_CMD_NEW;
	else if (put->flags & DPIF_FP_CREATE_GTPV1)
		request->cmd = OVS_FLOW_CMD_NEW_GTPV1;
	else
		request->cmd = OVS_FLOW_CMD_SET;

	request->is_gtp = (put->flags & DPIF_FP_CREATE_GTPV1) ? true : false;
    request->dp_ifindex = dpif->dp_ifindex;
    request->key = put->key;
    request->key_len = put->key_len;
    request->mask = put->mask;
    request->mask_len = put->mask_len;
    dpif_netlink_flow_init_ufid(request, put->ufid, false);

    /* Ensure that OVS_FLOW_ATTR_ACTIONS will always be included. */
    request->actions = (put->actions ? put->actions : CONST_CAST(struct nlattr *, &dummy_action));
    request->actions_len = put->actions_len;
    if (put->flags & DPIF_FP_ZERO_STATS) {
        request->clear = true;
    }
    if (put->flags & DPIF_FP_PROBE) {
        request->probe = true;
    }
    request->nlmsg_flags = put->flags & DPIF_FP_MODIFY ? 0 : NLM_F_CREATE;
}

static void
dpif_netlink_init_flow_del__(struct dpif_netlink *dpif,
                             const struct nlattr *key, size_t key_len,
                             const ovs_u128 *ufid, bool terse,
                             struct dpif_netlink_flow *request)
{
    dpif_netlink_flow_init(request);
    request->cmd = OVS_FLOW_CMD_DEL;
    request->dp_ifindex = dpif->dp_ifindex;
    request->key = key;
    request->key_len = key_len;
    dpif_netlink_flow_init_ufid(request, ufid, terse);
}

static void
dpif_netlink_init_flow_del(struct dpif_netlink *dpif,
                           const struct dpif_flow_del *del,
                           struct dpif_netlink_flow *request)
{
    dpif_netlink_init_flow_del__(dpif, del->key, del->key_len,
                                 del->ufid, del->terse, request);
}

struct dpif_netlink_flow_dump {
    struct dpif_flow_dump up;
    struct nl_dump nl_dump;
    atomic_int status;
};

static struct dpif_netlink_flow_dump *
dpif_netlink_flow_dump_cast(struct dpif_flow_dump *dump)
{
    return CONTAINER_OF(dump, struct dpif_netlink_flow_dump, up);
}

static struct dpif_flow_dump *
dpif_netlink_flow_dump_create(const struct dpif *dpif_, bool terse)
{
    const struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    struct dpif_netlink_flow_dump *dump;
    struct dpif_netlink_flow request;
    struct ofpbuf *buf;

    dump = xmalloc(sizeof *dump);
    dpif_flow_dump_init(&dump->up, dpif_);

    dpif_netlink_flow_init(&request);
    request.cmd = OVS_FLOW_CMD_GET;
    request.dp_ifindex = dpif->dp_ifindex;
    request.ufid_present = false;
    request.ufid_terse = terse;

    buf = ofpbuf_new(1024);
    dpif_netlink_flow_to_ofpbuf(&request, buf);
    nl_dump_start(&dump->nl_dump, NETLINK_GENERIC, buf);
    ofpbuf_delete(buf);
    atomic_init(&dump->status, 0);
    dump->up.terse = terse;

    return &dump->up;
}

static int
dpif_netlink_flow_dump_destroy(struct dpif_flow_dump *dump_)
{
    struct dpif_netlink_flow_dump *dump = dpif_netlink_flow_dump_cast(dump_);
    unsigned int nl_status = nl_dump_done(&dump->nl_dump);
    int dump_status;

    /* No other thread has access to 'dump' at this point. */
    atomic_read_relaxed(&dump->status, &dump_status);
    free(dump);
    return dump_status ? dump_status : nl_status;
}

struct dpif_netlink_flow_dump_thread {
    struct dpif_flow_dump_thread up;
    struct dpif_netlink_flow_dump *dump;
    struct dpif_netlink_flow flow;
    struct dpif_flow_stats stats;
    struct ofpbuf nl_flows;     /* Always used to store flows. */
    struct ofpbuf *nl_actions;  /* Used if kernel does not supply actions. */
};

static struct dpif_netlink_flow_dump_thread *
dpif_netlink_flow_dump_thread_cast(struct dpif_flow_dump_thread *thread)
{
    return CONTAINER_OF(thread, struct dpif_netlink_flow_dump_thread, up);
}

static struct dpif_flow_dump_thread *
dpif_netlink_flow_dump_thread_create(struct dpif_flow_dump *dump_)
{
    struct dpif_netlink_flow_dump *dump = dpif_netlink_flow_dump_cast(dump_);
    struct dpif_netlink_flow_dump_thread *thread;

    thread = xmalloc(sizeof *thread);
    dpif_flow_dump_thread_init(&thread->up, &dump->up);
    thread->dump = dump;
    ofpbuf_init(&thread->nl_flows, NL_DUMP_BUFSIZE);
    thread->nl_actions = NULL;

    return &thread->up;
}

static void
dpif_netlink_flow_dump_thread_destroy(struct dpif_flow_dump_thread *thread_)
{
    struct dpif_netlink_flow_dump_thread *thread
        = dpif_netlink_flow_dump_thread_cast(thread_);

    ofpbuf_uninit(&thread->nl_flows);
    ofpbuf_delete(thread->nl_actions);
    free(thread);
}

static void
dpif_netlink_flow_to_dpif_flow(struct dpif *dpif, struct dpif_flow *dpif_flow,
                               const struct dpif_netlink_flow *datapath_flow)
{
    dpif_flow->key = datapath_flow->key;
    dpif_flow->key_len = datapath_flow->key_len;
    dpif_flow->mask = datapath_flow->mask;
    dpif_flow->mask_len = datapath_flow->mask_len;
    dpif_flow->actions = datapath_flow->actions;
    dpif_flow->actions_len = datapath_flow->actions_len;
    dpif_flow->ufid_present = datapath_flow->ufid_present;
    dpif_flow->pmd_id = PMD_ID_NULL;
    if (datapath_flow->ufid_present) {
        dpif_flow->ufid = datapath_flow->ufid;
    } else {
        ovs_assert(datapath_flow->key && datapath_flow->key_len);
        dpif_flow_hash(dpif, datapath_flow->key, datapath_flow->key_len,
                       &dpif_flow->ufid);
    }
    dpif_netlink_flow_get_stats(datapath_flow, &dpif_flow->stats);
	dpif_flow->is_gtp = datapath_flow->is_gtp;
}

static int
dpif_netlink_flow_dump_next(struct dpif_flow_dump_thread *thread_,
                            struct dpif_flow *flows, int max_flows)
{
    struct dpif_netlink_flow_dump_thread *thread
        = dpif_netlink_flow_dump_thread_cast(thread_);
    struct dpif_netlink_flow_dump *dump = thread->dump;
    struct dpif_netlink *dpif = dpif_netlink_cast(thread->up.dpif);
    int n_flows;

    ofpbuf_delete(thread->nl_actions);
    thread->nl_actions = NULL;

    n_flows = 0;
    while (!n_flows || (n_flows < max_flows && thread->nl_flows.size)) {
        struct dpif_netlink_flow datapath_flow;
        struct ofpbuf nl_flow;
        int error;

        /* Try to grab another flow. */
        if (!nl_dump_next(&dump->nl_dump, &nl_flow, &thread->nl_flows)) {
            break;
        }

        /* Convert the flow to our output format. */
        error = dpif_netlink_flow_from_ofpbuf(&datapath_flow, &nl_flow);
        if (error) {
            atomic_store_relaxed(&dump->status, error);
            break;
        }

        if (dump->up.terse || datapath_flow.actions) {
            /* Common case: we don't want actions, or the flow includes
             * actions. */
            dpif_netlink_flow_to_dpif_flow(&dpif->dpif, &flows[n_flows++],
                                           &datapath_flow);
        } else {
            /* Rare case: the flow does not include actions.  Retrieve this
             * individual flow again to get the actions. */
            error = dpif_netlink_flow_get(dpif, &datapath_flow,
                                          &datapath_flow, &thread->nl_actions);
            if (error == ENOENT) {
                VLOG_DBG("dumped flow disappeared on get");
                continue;
            } else if (error) {
                VLOG_WARN("error fetching dumped flow: %s",
                          ovs_strerror(error));
                atomic_store_relaxed(&dump->status, error);
                break;
            }

            /* Save this flow.  Then exit, because we only have one buffer to
             * handle this case. */
            dpif_netlink_flow_to_dpif_flow(&dpif->dpif, &flows[n_flows++],
                                           &datapath_flow);
            break;
        }
    }

    return n_flows;
}

static void
dpif_netlink_encode_execute(int dp_ifindex, const struct dpif_execute *d_exec,
                            struct ofpbuf *buf)
{
    struct ovs_header *k_exec;
    size_t key_ofs;

    ofpbuf_prealloc_tailroom(buf, (64
                                   + dp_packet_size(d_exec->packet)
                                   + ODP_KEY_METADATA_SIZE
                                   + d_exec->actions_len));

    nl_msg_put_genlmsghdr(buf, 0, ovs_packet_family, NLM_F_REQUEST,
                          OVS_PACKET_CMD_EXECUTE, OVS_PACKET_VERSION);

    k_exec = ofpbuf_put_uninit(buf, sizeof *k_exec);
    k_exec->dp_ifindex = dp_ifindex;

    nl_msg_put_unspec(buf, OVS_PACKET_ATTR_PACKET,
                      dp_packet_data(d_exec->packet),
                      dp_packet_size(d_exec->packet));

    key_ofs = nl_msg_start_nested(buf, OVS_PACKET_ATTR_KEY);
    odp_key_from_pkt_metadata(buf, &d_exec->packet->md);
    nl_msg_end_nested(buf, key_ofs);

    nl_msg_put_unspec(buf, OVS_PACKET_ATTR_ACTIONS,
                      d_exec->actions, d_exec->actions_len);
    if (d_exec->probe) {
        nl_msg_put_flag(buf, OVS_PACKET_ATTR_PROBE);
    }
    if (d_exec->mtu) {
        nl_msg_put_u16(buf, OVS_PACKET_ATTR_MRU, d_exec->mtu);
    }
}

/* Executes, against 'dpif', up to the first 'n_ops' operations in 'ops'.
 * Returns the number actually executed (at least 1, if 'n_ops' is
 * positive). */
static size_t
dpif_netlink_operate__(struct dpif_netlink *dpif,
                       struct dpif_op **ops, size_t n_ops)
{
    enum { MAX_OPS = 50 };

    struct op_auxdata
	{
        struct nl_transaction txn;

        struct ofpbuf request;
        uint64_t request_stub[1024 / 8];

        struct ofpbuf reply;
        uint64_t reply_stub[1024 / 8];
    } auxes[MAX_OPS];

    struct nl_transaction *txnsp[MAX_OPS];
    size_t i;

    n_ops = MIN(n_ops, MAX_OPS);
    for (i = 0; i < n_ops; i++)
	{
        struct op_auxdata *aux = &auxes[i];
        struct dpif_op *op = ops[i];
        struct dpif_flow_put *put;
        struct dpif_flow_del *del;
        struct dpif_flow_get *get;
        struct dpif_netlink_flow flow;

        ofpbuf_use_stub(&aux->request, aux->request_stub, sizeof aux->request_stub);
        aux->txn.request = &aux->request;

        ofpbuf_use_stub(&aux->reply, aux->reply_stub, sizeof aux->reply_stub);
        aux->txn.reply = NULL;

        switch (op->type)
		{
        case DPIF_OP_FLOW_PUT:
            put = &op->u.flow_put;
            dpif_netlink_init_flow_put(dpif, put, &flow);
            if (put->stats) {
                flow.nlmsg_flags |= NLM_F_ECHO;
                aux->txn.reply = &aux->reply;
            }
            dpif_netlink_flow_to_ofpbuf(&flow, &aux->request);
            break;

        case DPIF_OP_FLOW_DEL:
            del = &op->u.flow_del;
            dpif_netlink_init_flow_del(dpif, del, &flow);
            if (del->stats) {
                flow.nlmsg_flags |= NLM_F_ECHO;
                aux->txn.reply = &aux->reply;
            }
            dpif_netlink_flow_to_ofpbuf(&flow, &aux->request);
            break;

        case DPIF_OP_EXECUTE:
            /* Can't execute a packet that won't fit in a Netlink attribute. */
            if (OVS_UNLIKELY(nl_attr_oversized(
                                 dp_packet_size(op->u.execute.packet)))) {
                /* Report an error immediately if this is the first operation.
                 * Otherwise the easiest thing to do is to postpone to the next
                 * call (when this will be the first operation). */
                if (i == 0) {
                    VLOG_ERR_RL(&error_rl,
                                "dropping oversized %"PRIu32"-byte packet",
                                dp_packet_size(op->u.execute.packet));
                    op->error = ENOBUFS;
                    return 1;
                }
                n_ops = i;
            } else {
                dpif_netlink_encode_execute(dpif->dp_ifindex, &op->u.execute,
                                            &aux->request);
            }
            break;

        case DPIF_OP_FLOW_GET:
            get = &op->u.flow_get;
            dpif_netlink_init_flow_get(dpif, get, &flow);
            aux->txn.reply = get->buffer;
            dpif_netlink_flow_to_ofpbuf(&flow, &aux->request);
            break;

        default:
            OVS_NOT_REACHED();
        }
    }

    for (i = 0; i < n_ops; i++) {
        txnsp[i] = &auxes[i].txn;
    }
    nl_transact_multiple(NETLINK_GENERIC, txnsp, n_ops);

    for (i = 0; i < n_ops; i++) {
        struct op_auxdata *aux = &auxes[i];
        struct nl_transaction *txn = &auxes[i].txn;
        struct dpif_op *op = ops[i];
        struct dpif_flow_put *put;
        struct dpif_flow_del *del;
        struct dpif_flow_get *get;

        op->error = txn->error;

        switch (op->type) {
        case DPIF_OP_FLOW_PUT:
            put = &op->u.flow_put;
            if (put->stats) {
                if (!op->error) {
                    struct dpif_netlink_flow reply;

                    op->error = dpif_netlink_flow_from_ofpbuf(&reply,
                                                              txn->reply);
                    if (!op->error) {
                        dpif_netlink_flow_get_stats(&reply, put->stats);
                    }
                }
            }
            break;

        case DPIF_OP_FLOW_DEL:
            del = &op->u.flow_del;
            if (del->stats) {
                if (!op->error) {
                    struct dpif_netlink_flow reply;

                    op->error = dpif_netlink_flow_from_ofpbuf(&reply,
                                                              txn->reply);
                    if (!op->error) {
                        dpif_netlink_flow_get_stats(&reply, del->stats);
                    }
                }
            }
            break;

        case DPIF_OP_EXECUTE:
            break;

        case DPIF_OP_FLOW_GET:
            get = &op->u.flow_get;
            if (!op->error) {
                struct dpif_netlink_flow reply;

                op->error = dpif_netlink_flow_from_ofpbuf(&reply, txn->reply);
                if (!op->error) {
                    dpif_netlink_flow_to_dpif_flow(&dpif->dpif, get->flow,
                                                   &reply);
                }
            }
            break;

        default:
            OVS_NOT_REACHED();
        }

        ofpbuf_uninit(&aux->request);
        ofpbuf_uninit(&aux->reply);
    }

    return n_ops;
}

static void
dpif_netlink_operate(struct dpif *dpif_, struct dpif_op **ops, size_t n_ops)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);

    while (n_ops > 0) {
        size_t chunk = dpif_netlink_operate__(dpif, ops, n_ops);
        ops += chunk;
        n_ops -= chunk;
    }
}

#if _WIN32
static void
dpif_netlink_handler_uninit(struct dpif_handler *handler)
{
    vport_delete_sock_pool(handler);
}

static int
dpif_netlink_handler_init(struct dpif_handler *handler)
{
    return vport_create_sock_pool(handler);
}
#else

static int
dpif_netlink_handler_init(struct dpif_handler *handler)
{
    handler->epoll_fd = epoll_create(10);
    return handler->epoll_fd < 0 ? errno : 0;
}

static void
dpif_netlink_handler_uninit(struct dpif_handler *handler)
{
    close(handler->epoll_fd);
}
#endif

/* Synchronizes 'channels' in 'dpif->handlers'  with the set of vports
 * currently in 'dpif' in the kernel, by adding a new set of channels for
 * any kernel vport that lacks one and deleting any channels that have no
 * backing kernel vports. */
static int
dpif_netlink_refresh_channels(struct dpif_netlink *dpif, uint32_t n_handlers)
    OVS_REQ_WRLOCK(dpif->upcall_lock)
{
    unsigned long int *keep_channels;
    struct dpif_netlink_vport vport;
    size_t keep_channels_nbits;
    struct nl_dump dump;
    uint64_t reply_stub[NL_DUMP_BUFSIZE / 8];
    struct ofpbuf buf;
    int retval = 0;
    size_t i;

    ovs_assert(!WINDOWS || n_handlers <= 1);
    ovs_assert(!WINDOWS || dpif->n_handlers <= 1);

    if (dpif->n_handlers != n_handlers) {
        destroy_all_channels(dpif);
        dpif->handlers = xzalloc(n_handlers * sizeof *dpif->handlers);
        for (i = 0; i < n_handlers; i++) {
            int error;
            struct dpif_handler *handler = &dpif->handlers[i];

            error = dpif_netlink_handler_init(handler);
            if (error) {
                size_t j;
                struct dpif_handler *tmp = &dpif->handlers[i];


                for (j = 0; j < i; j++) {
                    dpif_netlink_handler_uninit(tmp);
                }
                free(dpif->handlers);
                dpif->handlers = NULL;

                return error;
            }
        }
        dpif->n_handlers = n_handlers;
    }

    for (i = 0; i < n_handlers; i++) {
        struct dpif_handler *handler = &dpif->handlers[i];

        handler->event_offset = handler->n_events = 0;
    }

    keep_channels_nbits = dpif->uc_array_size;
    keep_channels = bitmap_allocate(keep_channels_nbits);

    ofpbuf_use_stub(&buf, reply_stub, sizeof reply_stub);
    dpif_netlink_port_dump_start__(dpif, &dump);
    while (!dpif_netlink_port_dump_next__(dpif, &dump, &vport, &buf)) {
        uint32_t port_no = odp_to_u32(vport.port_no);
        uint32_t *upcall_pids = NULL;
        int error;

        if (port_no >= dpif->uc_array_size
            || !vport_get_pids(dpif, port_no, &upcall_pids)) {
            struct nl_sock **socksp = vport_create_socksp(dpif, &error);

            if (!socksp) {
                goto error;
            }

            error = vport_add_channels(dpif, vport.port_no, socksp);
            if (error) {
                VLOG_INFO("%s: could not add channels for port %s",
                          dpif_name(&dpif->dpif), vport.name);
                vport_del_socksp(dpif, socksp);
                retval = error;
                goto error;
            }
            upcall_pids = vport_socksp_to_pids(socksp, dpif->n_handlers);
            free(socksp);
        }

        /* Configure the vport to deliver misses to 'sock'. */
        if (vport.upcall_pids[0] == 0
            || vport.n_upcall_pids != dpif->n_handlers
            || memcmp(upcall_pids, vport.upcall_pids, n_handlers * sizeof
                      *upcall_pids)) {
            struct dpif_netlink_vport vport_request;

            dpif_netlink_vport_init(&vport_request);
            vport_request.cmd = OVS_VPORT_CMD_SET;
            vport_request.dp_ifindex = dpif->dp_ifindex;
            vport_request.port_no = vport.port_no;
            vport_request.n_upcall_pids = dpif->n_handlers;
            vport_request.upcall_pids = upcall_pids;
            error = dpif_netlink_vport_transact(&vport_request, NULL, NULL);
            if (error) {
                VLOG_WARN_RL(&error_rl,
                             "%s: failed to set upcall pid on port: %s",
                             dpif_name(&dpif->dpif), ovs_strerror(error));

                if (error != ENODEV && error != ENOENT) {
                    retval = error;
                } else {
                    /* The vport isn't really there, even though the dump says
                     * it is.  Probably we just hit a race after a port
                     * disappeared. */
                }
                goto error;
            }
        }

        if (port_no < keep_channels_nbits) {
            bitmap_set1(keep_channels, port_no);
        }
        free(upcall_pids);
        continue;

    error:
        free(upcall_pids);
        vport_del_channels(dpif, vport.port_no);
    }
    nl_dump_done(&dump);
    ofpbuf_uninit(&buf);

    /* Discard any saved channels that we didn't reuse. */
    for (i = 0; i < keep_channels_nbits; i++) {
        if (!bitmap_is_set(keep_channels, i)) {
            vport_del_channels(dpif, u32_to_odp(i));
        }
    }
    free(keep_channels);

    return retval;
}

static int
dpif_netlink_recv_set__(struct dpif_netlink *dpif, bool enable)
    OVS_REQ_WRLOCK(dpif->upcall_lock)
{
    if ((dpif->handlers != NULL) == enable) {
        return 0;
    } else if (!enable) {
        destroy_all_channels(dpif);
        return 0;
    } else {
        return dpif_netlink_refresh_channels(dpif, 1);
    }
}

static int
dpif_netlink_recv_set(struct dpif *dpif_, bool enable)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    int error;

    fat_rwlock_wrlock(&dpif->upcall_lock);
    error = dpif_netlink_recv_set__(dpif, enable);
    fat_rwlock_unlock(&dpif->upcall_lock);

    return error;
}

static int
dpif_netlink_handlers_set(struct dpif *dpif_, uint32_t n_handlers)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    int error = 0;

#ifdef _WIN32
    /* Multiple upcall handlers will be supported once kernel datapath supports
     * it. */
    if (n_handlers > 1) {
        return error;
    }
#endif

    fat_rwlock_wrlock(&dpif->upcall_lock);
    if (dpif->handlers) {
        error = dpif_netlink_refresh_channels(dpif, n_handlers);
    }
    fat_rwlock_unlock(&dpif->upcall_lock);

    return error;
}

static int
dpif_netlink_queue_to_priority(const struct dpif *dpif OVS_UNUSED,
                             uint32_t queue_id, uint32_t *priority)
{
    if (queue_id < 0xf000) {
        *priority = TC_H_MAKE(1 << 16, queue_id + 1);
        return 0;
    } else {
        return EINVAL;
    }
}

static int
parse_odp_packet(const struct dpif_netlink *dpif, struct ofpbuf *buf,
                 struct dpif_upcall *upcall, int *dp_ifindex)
{
    static const struct nl_policy ovs_packet_policy[] = {
        /* Always present. */
        [OVS_PACKET_ATTR_PACKET] = { .type = NL_A_UNSPEC,
                                     .min_len = ETH_HEADER_LEN },
        [OVS_PACKET_ATTR_KEY] = { .type = NL_A_NESTED },

        /* OVS_PACKET_CMD_ACTION only. */
        [OVS_PACKET_ATTR_USERDATA] = { .type = NL_A_UNSPEC, .optional = true },
        [OVS_PACKET_ATTR_EGRESS_TUN_KEY] = { .type = NL_A_NESTED, .optional = true },
        [OVS_PACKET_ATTR_ACTIONS] = { .type = NL_A_NESTED, .optional = true },
        [OVS_PACKET_ATTR_MRU] = { .type = NL_A_U16, .optional = true }
    };

    struct ovs_header *ovs_header;
    struct nlattr *a[ARRAY_SIZE(ovs_packet_policy)];
    struct nlmsghdr *nlmsg;
    struct genlmsghdr *genl;
    struct ofpbuf b;
    int type;

    ofpbuf_use_const(&b, buf->data, buf->size);

    nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    genl = ofpbuf_try_pull(&b, sizeof *genl);
    ovs_header = ofpbuf_try_pull(&b, sizeof *ovs_header);
    if (!nlmsg || !genl || !ovs_header
        || nlmsg->nlmsg_type != ovs_packet_family
        || !nl_policy_parse(&b, 0, ovs_packet_policy, a,
                            ARRAY_SIZE(ovs_packet_policy))) {
        return EINVAL;
    }

    type = (genl->cmd == OVS_PACKET_CMD_MISS ? DPIF_UC_MISS
            : genl->cmd == OVS_PACKET_CMD_ACTION ? DPIF_UC_ACTION
            : -1);
    if (type < 0) {
        return EINVAL;
    }

    /* (Re)set ALL fields of '*upcall' on successful return. */
    upcall->type = type;
    upcall->key = CONST_CAST(struct nlattr *,
                             nl_attr_get(a[OVS_PACKET_ATTR_KEY]));
    upcall->key_len = nl_attr_get_size(a[OVS_PACKET_ATTR_KEY]);
    dpif_flow_hash(&dpif->dpif, upcall->key, upcall->key_len, &upcall->ufid);
    upcall->userdata = a[OVS_PACKET_ATTR_USERDATA];
    upcall->out_tun_key = a[OVS_PACKET_ATTR_EGRESS_TUN_KEY];
    upcall->actions = a[OVS_PACKET_ATTR_ACTIONS];
    upcall->mru = a[OVS_PACKET_ATTR_MRU];

    /* Allow overwriting the netlink attribute header without reallocating. */
    dp_packet_use_stub(&upcall->packet,
                    CONST_CAST(struct nlattr *,
                               nl_attr_get(a[OVS_PACKET_ATTR_PACKET])) - 1,
                    nl_attr_get_size(a[OVS_PACKET_ATTR_PACKET]) +
                    sizeof(struct nlattr));
    dp_packet_set_data(&upcall->packet,
                    (char *)dp_packet_data(&upcall->packet) + sizeof(struct nlattr));
    dp_packet_set_size(&upcall->packet, nl_attr_get_size(a[OVS_PACKET_ATTR_PACKET]));

    *dp_ifindex = ovs_header->dp_ifindex;

    return 0;
}

#ifdef _WIN32
#define PACKET_RECV_BATCH_SIZE 50
static int
dpif_netlink_recv_windows(struct dpif_netlink *dpif, uint32_t handler_id,
                          struct dpif_upcall *upcall, struct ofpbuf *buf)
    OVS_REQ_RDLOCK(dpif->upcall_lock)
{
    struct dpif_handler *handler;
    int read_tries = 0;
    struct dpif_windows_vport_sock *sock_pool;
    uint32_t i;

    if (!dpif->handlers) {
        return EAGAIN;
    }

    /* Only one handler is supported currently. */
    if (handler_id >= 1) {
        return EAGAIN;
    }

    if (handler_id >= dpif->n_handlers) {
        return EAGAIN;
    }

    handler = &dpif->handlers[handler_id];
    sock_pool = handler->vport_sock_pool;

    for (i = 0; i < VPORT_SOCK_POOL_SIZE; i++) {
        for (;;) {
            int dp_ifindex;
            int error;

            if (++read_tries > PACKET_RECV_BATCH_SIZE) {
                return EAGAIN;
            }

            error = nl_sock_recv(sock_pool[i].nl_sock, buf, false);
            if (error == ENOBUFS) {
                /* ENOBUFS typically means that we've received so many
                 * packets that the buffer overflowed.  Try again
                 * immediately because there's almost certainly a packet
                 * waiting for us. */
                /* XXX: report_loss(dpif, ch, idx, handler_id); */
                continue;
            }

            /* XXX: ch->last_poll = time_msec(); */
            if (error) {
                if (error == EAGAIN) {
                    break;
                }
                return error;
            }

            error = parse_odp_packet(dpif, buf, upcall, &dp_ifindex);
            if (!error && dp_ifindex == dpif->dp_ifindex) {
                return 0;
            } else if (error) {
                return error;
            }
        }
    }

    return EAGAIN;
}
#else
static int
dpif_netlink_recv__(struct dpif_netlink *dpif, uint32_t handler_id,
                    struct dpif_upcall *upcall, struct ofpbuf *buf)
    OVS_REQ_RDLOCK(dpif->upcall_lock)
{
    struct dpif_handler *handler;
    int read_tries = 0;

    if (!dpif->handlers || handler_id >= dpif->n_handlers) {
        return EAGAIN;
    }

    handler = &dpif->handlers[handler_id];
    if (handler->event_offset >= handler->n_events) {
        int retval;

        handler->event_offset = handler->n_events = 0;

        do {
            retval = epoll_wait(handler->epoll_fd, handler->epoll_events,
                                dpif->uc_array_size, 0);
        } while (retval < 0 && errno == EINTR);

        if (retval < 0) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "epoll_wait failed (%s)", ovs_strerror(errno));
        } else if (retval > 0) {
            handler->n_events = retval;
        }
    }

    while (handler->event_offset < handler->n_events) {
        int idx = handler->epoll_events[handler->event_offset].data.u32;
        struct dpif_channel *ch = &dpif->handlers[handler_id].channels[idx];

        handler->event_offset++;

        for (;;) {
            int dp_ifindex;
            int error;

            if (++read_tries > 50) {
                return EAGAIN;
            }

            error = nl_sock_recv(ch->sock, buf, false);
            if (error == ENOBUFS) {
                /* ENOBUFS typically means that we've received so many
                 * packets that the buffer overflowed.  Try again
                 * immediately because there's almost certainly a packet
                 * waiting for us. */
                report_loss(dpif, ch, idx, handler_id);
                continue;
            }

            ch->last_poll = time_msec();
            if (error) {
                if (error == EAGAIN) {
                    break;
                }
                return error;
            }

            error = parse_odp_packet(dpif, buf, upcall, &dp_ifindex);
            if (!error && dp_ifindex == dpif->dp_ifindex) {
                return 0;
            } else if (error) {
                return error;
            }
        }
    }

    return EAGAIN;
}
#endif

static int
dpif_netlink_recv(struct dpif *dpif_, uint32_t handler_id,
                  struct dpif_upcall *upcall, struct ofpbuf *buf)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    int error;

    fat_rwlock_rdlock(&dpif->upcall_lock);
#ifdef _WIN32
    error = dpif_netlink_recv_windows(dpif, handler_id, upcall, buf);
#else
    error = dpif_netlink_recv__(dpif, handler_id, upcall, buf);
#endif
    fat_rwlock_unlock(&dpif->upcall_lock);

    return error;
}

static void
dpif_netlink_recv_wait__(struct dpif_netlink *dpif, uint32_t handler_id)
    OVS_REQ_RDLOCK(dpif->upcall_lock)
{
#ifdef _WIN32
    uint32_t i;
    struct dpif_windows_vport_sock *sock_pool =
        dpif->handlers[handler_id].vport_sock_pool;

    /* Only one handler is supported currently. */
    if (handler_id >= 1) {
        return;
    }

    for (i = 0; i < VPORT_SOCK_POOL_SIZE; i++) {
        nl_sock_wait(sock_pool[i].nl_sock, POLLIN);
    }
#else
    if (dpif->handlers && handler_id < dpif->n_handlers) {
        struct dpif_handler *handler = &dpif->handlers[handler_id];

        poll_fd_wait(handler->epoll_fd, POLLIN);
    }
#endif
}

static void
dpif_netlink_recv_wait(struct dpif *dpif_, uint32_t handler_id)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);

    fat_rwlock_rdlock(&dpif->upcall_lock);
    dpif_netlink_recv_wait__(dpif, handler_id);
    fat_rwlock_unlock(&dpif->upcall_lock);
}

static void
dpif_netlink_recv_purge__(struct dpif_netlink *dpif)
    OVS_REQ_WRLOCK(dpif->upcall_lock)
{
    if (dpif->handlers) {
        size_t i, j;

        for (i = 0; i < dpif->uc_array_size; i++ ) {
            if (!dpif->handlers[0].channels[i].sock) {
                continue;
            }

            for (j = 0; j < dpif->n_handlers; j++) {
                nl_sock_drain(dpif->handlers[j].channels[i].sock);
            }
        }
    }
}

static void
dpif_netlink_recv_purge(struct dpif *dpif_)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);

    fat_rwlock_wrlock(&dpif->upcall_lock);
    dpif_netlink_recv_purge__(dpif);
    fat_rwlock_unlock(&dpif->upcall_lock);
}

static char *
dpif_netlink_get_datapath_version(void)
{
    char *version_str = NULL;

#ifdef __linux__

#define MAX_VERSION_STR_SIZE 80
#define LINUX_DATAPATH_VERSION_FILE  "/sys/module/openvswitch/version"
    FILE *f;

    f = fopen(LINUX_DATAPATH_VERSION_FILE, "r");
    if (f) {
        char *newline;
        char version[MAX_VERSION_STR_SIZE];

        if (fgets(version, MAX_VERSION_STR_SIZE, f)) {
            newline = strchr(version, '\n');
            if (newline) {
                *newline = '\0';
            }
            version_str = xstrdup(version);
        }
        fclose(f);
    }
#endif

    return version_str;
}

#ifdef __linux__
struct dpif_netlink_ct_dump_state {
    struct ct_dpif_dump_state up;
    struct nl_ct_dump_state *nl_ct_dump;
};

static int
dpif_netlink_ct_dump_start(struct dpif *dpif OVS_UNUSED,
                           struct ct_dpif_dump_state **dump_,
                           const uint16_t *zone)
{
    struct dpif_netlink_ct_dump_state *dump;
    int err;

    dump = xzalloc(sizeof *dump);
    err = nl_ct_dump_start(&dump->nl_ct_dump, zone);
    if (err) {
        free(dump);
        return err;
    }

    *dump_ = &dump->up;

    return 0;
}

static int
dpif_netlink_ct_dump_next(struct dpif *dpif OVS_UNUSED,
                          struct ct_dpif_dump_state *dump_,
                          struct ct_dpif_entry *entry)
{
    struct dpif_netlink_ct_dump_state *dump;

    INIT_CONTAINER(dump, dump_, up);

    return nl_ct_dump_next(dump->nl_ct_dump, entry);
}

static int
dpif_netlink_ct_dump_done(struct dpif *dpif OVS_UNUSED,
                          struct ct_dpif_dump_state *dump_)
{
    struct dpif_netlink_ct_dump_state *dump;
    int err;

    INIT_CONTAINER(dump, dump_, up);

    err = nl_ct_dump_done(dump->nl_ct_dump);
    free(dump);
    return err;
}

static int
dpif_netlink_ct_flush(struct dpif *dpif OVS_UNUSED, const uint16_t *zone)
{
    if (zone) {
        return nl_ct_flush_zone(*zone);
    } else {
        return nl_ct_flush();
    }
}
#endif

const struct dpif_class dpif_netlink_class = {
    "system",
    NULL,                       /* init */
    dpif_netlink_enumerate,
    NULL,
    dpif_netlink_open,
    dpif_netlink_close,
    dpif_netlink_destroy,
    dpif_netlink_run,
    NULL,                       /* wait */
    dpif_netlink_get_stats,
    dpif_netlink_port_add,
    dpif_netlink_port_del,
    dpif_netlink_port_query_by_number,
    dpif_netlink_port_query_by_name,
    dpif_netlink_port_get_pid,
    dpif_netlink_port_dump_start,
    dpif_netlink_port_dump_next,
    dpif_netlink_port_dump_done,
    dpif_netlink_port_poll,
    dpif_netlink_port_poll_wait,
    dpif_netlink_flow_flush,
    dpif_netlink_flow_dump_create,
    dpif_netlink_flow_dump_destroy,
    dpif_netlink_flow_dump_thread_create,
    dpif_netlink_flow_dump_thread_destroy,
    dpif_netlink_flow_dump_next,
    dpif_netlink_operate,
    dpif_netlink_recv_set,
    dpif_netlink_handlers_set,
    NULL,                       /* poll_thread_set */
    dpif_netlink_queue_to_priority,
    dpif_netlink_recv,
    dpif_netlink_recv_wait,
    dpif_netlink_recv_purge,
    NULL,                       /* register_dp_purge_cb */
    NULL,                       /* register_upcall_cb */
    NULL,                       /* enable_upcall */
    NULL,                       /* disable_upcall */
    dpif_netlink_get_datapath_version, /* get_datapath_version */
#ifdef __linux__
    dpif_netlink_ct_dump_start,
    dpif_netlink_ct_dump_next,
    dpif_netlink_ct_dump_done,
    dpif_netlink_ct_flush,
#else
    NULL,                       /* ct_dump_start */
    NULL,                       /* ct_dump_next */
    NULL,                       /* ct_dump_done */
    NULL,                       /* ct_flush */
#endif
};

static int
dpif_netlink_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    static int error;

    if (ovsthread_once_start(&once)) {
        error = nl_lookup_genl_family(OVS_DATAPATH_FAMILY,
                                      &ovs_datapath_family);
        if (error) {
            VLOG_ERR("Generic Netlink family '%s' does not exist. "
                     "The Open vSwitch kernel module is probably not loaded.",
                     OVS_DATAPATH_FAMILY);
        }
        if (!error) {
            error = nl_lookup_genl_family(OVS_VPORT_FAMILY, &ovs_vport_family);
        }
        if (!error) {
            error = nl_lookup_genl_family(OVS_FLOW_FAMILY, &ovs_flow_family);
        }
        if (!error) {
            error = nl_lookup_genl_family(OVS_PACKET_FAMILY,
                                          &ovs_packet_family);
        }
        if (!error) {
            error = nl_lookup_genl_mcgroup(OVS_VPORT_FAMILY, OVS_VPORT_MCGROUP,
                                           &ovs_vport_mcgroup);
        }

        ovsthread_once_done(&once);
    }

    return error;
}

bool
dpif_netlink_is_internal_device(const char *name)
{
    struct dpif_netlink_vport reply;
    struct ofpbuf *buf;
    int error;

    error = dpif_netlink_vport_get(name, &reply, &buf);
    if (!error) {
        ofpbuf_delete(buf);
    } else if (error != ENODEV && error != ENOENT) {
        VLOG_WARN_RL(&error_rl, "%s: vport query failed (%s)",
                     name, ovs_strerror(error));
    }

    return reply.type == OVS_VPORT_TYPE_INTERNAL;
}

/* Parses the contents of 'buf', which contains a "struct ovs_header" followed
 * by Netlink attributes, into 'vport'.  Returns 0 if successful, otherwise a
 * positive errno value.
 *
 * 'vport' will contain pointers into 'buf', so the caller should not free
 * 'buf' while 'vport' is still in use. */
static int
dpif_netlink_vport_from_ofpbuf(struct dpif_netlink_vport *vport,
                             const struct ofpbuf *buf)
{
    static const struct nl_policy ovs_vport_policy[] = {
        [OVS_VPORT_ATTR_PORT_NO] = { .type = NL_A_U32 },
        [OVS_VPORT_ATTR_TYPE] = { .type = NL_A_U32 },
        [OVS_VPORT_ATTR_NAME] = { .type = NL_A_STRING, .max_len = IFNAMSIZ },
        [OVS_VPORT_ATTR_UPCALL_PID] = { .type = NL_A_UNSPEC },
        [OVS_VPORT_ATTR_STATS] = { NL_POLICY_FOR(struct ovs_vport_stats),
                                   .optional = true },
        [OVS_VPORT_ATTR_OPTIONS] = { .type = NL_A_NESTED, .optional = true },
    };

    struct nlattr *a[ARRAY_SIZE(ovs_vport_policy)];
    struct ovs_header *ovs_header;
    struct nlmsghdr *nlmsg;
    struct genlmsghdr *genl;
    struct ofpbuf b;

    dpif_netlink_vport_init(vport);

    ofpbuf_use_const(&b, buf->data, buf->size);
    nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    genl = ofpbuf_try_pull(&b, sizeof *genl);
    ovs_header = ofpbuf_try_pull(&b, sizeof *ovs_header);
    if (!nlmsg || !genl || !ovs_header
        || nlmsg->nlmsg_type != ovs_vport_family
        || !nl_policy_parse(&b, 0, ovs_vport_policy, a,
                            ARRAY_SIZE(ovs_vport_policy))) {
        return EINVAL;
    }

    vport->cmd = genl->cmd;
    vport->dp_ifindex = ovs_header->dp_ifindex;
    vport->port_no = nl_attr_get_odp_port(a[OVS_VPORT_ATTR_PORT_NO]);
    vport->type = nl_attr_get_u32(a[OVS_VPORT_ATTR_TYPE]);
    vport->name = nl_attr_get_string(a[OVS_VPORT_ATTR_NAME]);
    if (a[OVS_VPORT_ATTR_UPCALL_PID]) {
        vport->n_upcall_pids = nl_attr_get_size(a[OVS_VPORT_ATTR_UPCALL_PID])
                               / (sizeof *vport->upcall_pids);
        vport->upcall_pids = nl_attr_get(a[OVS_VPORT_ATTR_UPCALL_PID]);

    }
    if (a[OVS_VPORT_ATTR_STATS]) {
        vport->stats = nl_attr_get(a[OVS_VPORT_ATTR_STATS]);
    }
    if (a[OVS_VPORT_ATTR_OPTIONS]) {
        vport->options = nl_attr_get(a[OVS_VPORT_ATTR_OPTIONS]);
        vport->options_len = nl_attr_get_size(a[OVS_VPORT_ATTR_OPTIONS]);
    }
    return 0;
}

/* Appends to 'buf' (which must initially be empty) a "struct ovs_header"
 * followed by Netlink attributes corresponding to 'vport'. */
static void
dpif_netlink_vport_to_ofpbuf(const struct dpif_netlink_vport *vport,
                             struct ofpbuf *buf)
{
    struct ovs_header *ovs_header;

    nl_msg_put_genlmsghdr(buf, 0, ovs_vport_family, NLM_F_REQUEST | NLM_F_ECHO,
                          vport->cmd, OVS_VPORT_VERSION);

    ovs_header = ofpbuf_put_uninit(buf, sizeof *ovs_header);
    ovs_header->dp_ifindex = vport->dp_ifindex;

    if (vport->port_no != ODPP_NONE) {
        nl_msg_put_odp_port(buf, OVS_VPORT_ATTR_PORT_NO, vport->port_no);
    }

    if (vport->type != OVS_VPORT_TYPE_UNSPEC) {
        nl_msg_put_u32(buf, OVS_VPORT_ATTR_TYPE, vport->type);
    }

    if (vport->name) {
        nl_msg_put_string(buf, OVS_VPORT_ATTR_NAME, vport->name);
    }

    if (vport->upcall_pids) {
        nl_msg_put_unspec(buf, OVS_VPORT_ATTR_UPCALL_PID,
                          vport->upcall_pids,
                          vport->n_upcall_pids * sizeof *vport->upcall_pids);
    }

    if (vport->stats) {
        nl_msg_put_unspec(buf, OVS_VPORT_ATTR_STATS,
                          vport->stats, sizeof *vport->stats);
    }

    if (vport->options) {
        nl_msg_put_nested(buf, OVS_VPORT_ATTR_OPTIONS,
                          vport->options, vport->options_len);
    }
}

/* Clears 'vport' to "empty" values. */
void
dpif_netlink_vport_init(struct dpif_netlink_vport *vport)
{
    memset(vport, 0, sizeof *vport);
    vport->port_no = ODPP_NONE;
}

/* Executes 'request' in the kernel datapath.  If the command fails, returns a
 * positive errno value.  Otherwise, if 'reply' and 'bufp' are null, returns 0
 * without doing anything else.  If 'reply' and 'bufp' are nonnull, then the
 * result of the command is expected to be an ovs_vport also, which is decoded
 * and stored in '*reply' and '*bufp'.  The caller must free '*bufp' when the
 * reply is no longer needed ('reply' will contain pointers into '*bufp'). */
int
dpif_netlink_vport_transact(const struct dpif_netlink_vport *request,
                            struct dpif_netlink_vport *reply,
                            struct ofpbuf **bufp)
{
    struct ofpbuf *request_buf;
    int error;

    ovs_assert((reply != NULL) == (bufp != NULL));

    error = dpif_netlink_init();
    if (error) {
        if (reply) {
            *bufp = NULL;
            dpif_netlink_vport_init(reply);
        }
        return error;
    }

    request_buf = ofpbuf_new(1024);
    dpif_netlink_vport_to_ofpbuf(request, request_buf);
    error = nl_transact(NETLINK_GENERIC, request_buf, bufp);
    ofpbuf_delete(request_buf);

    if (reply) {
        if (!error) {
            error = dpif_netlink_vport_from_ofpbuf(reply, *bufp);
        }
        if (error) {
            dpif_netlink_vport_init(reply);
            ofpbuf_delete(*bufp);
            *bufp = NULL;
        }
    }
    return error;
}

/* Obtains information about the kernel vport named 'name' and stores it into
 * '*reply' and '*bufp'.  The caller must free '*bufp' when the reply is no
 * longer needed ('reply' will contain pointers into '*bufp').  */
int
dpif_netlink_vport_get(const char *name, struct dpif_netlink_vport *reply,
                       struct ofpbuf **bufp)
{
    struct dpif_netlink_vport request;

    dpif_netlink_vport_init(&request);
    request.cmd = OVS_VPORT_CMD_GET;
    request.name = name;

    return dpif_netlink_vport_transact(&request, reply, bufp);
}

/* Parses the contents of 'buf', which contains a "struct ovs_header" followed
 * by Netlink attributes, into 'dp'.  Returns 0 if successful, otherwise a
 * positive errno value.
 *
 * 'dp' will contain pointers into 'buf', so the caller should not free 'buf'
 * while 'dp' is still in use. */
static int
dpif_netlink_dp_from_ofpbuf(struct dpif_netlink_dp *dp, const struct ofpbuf *buf)
{
    static const struct nl_policy ovs_datapath_policy[] = {
        [OVS_DP_ATTR_NAME] = { .type = NL_A_STRING, .max_len = IFNAMSIZ },
        [OVS_DP_ATTR_STATS] = { NL_POLICY_FOR(struct ovs_dp_stats),
                                .optional = true },
        [OVS_DP_ATTR_MEGAFLOW_STATS] = {
                        NL_POLICY_FOR(struct ovs_dp_megaflow_stats),
                        .optional = true },
    };

    struct nlattr *a[ARRAY_SIZE(ovs_datapath_policy)];
    struct ovs_header *ovs_header;
    struct nlmsghdr *nlmsg;
    struct genlmsghdr *genl;
    struct ofpbuf b;

    dpif_netlink_dp_init(dp);

    ofpbuf_use_const(&b, buf->data, buf->size);
    nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    genl = ofpbuf_try_pull(&b, sizeof *genl);
    ovs_header = ofpbuf_try_pull(&b, sizeof *ovs_header);
    if (!nlmsg || !genl || !ovs_header
        || nlmsg->nlmsg_type != ovs_datapath_family
        || !nl_policy_parse(&b, 0, ovs_datapath_policy, a,
                            ARRAY_SIZE(ovs_datapath_policy))) {
        return EINVAL;
    }

    dp->cmd = genl->cmd;
    dp->dp_ifindex = ovs_header->dp_ifindex;
    dp->name = nl_attr_get_string(a[OVS_DP_ATTR_NAME]);
    if (a[OVS_DP_ATTR_STATS]) {
        dp->stats = nl_attr_get(a[OVS_DP_ATTR_STATS]);
    }

    if (a[OVS_DP_ATTR_MEGAFLOW_STATS]) {
        dp->megaflow_stats = nl_attr_get(a[OVS_DP_ATTR_MEGAFLOW_STATS]);
    }

    return 0;
}

/* Appends to 'buf' the Generic Netlink message described by 'dp'. */
static void
dpif_netlink_dp_to_ofpbuf(const struct dpif_netlink_dp *dp, struct ofpbuf *buf)
{
    struct ovs_header *ovs_header;

    nl_msg_put_genlmsghdr(buf, 0, ovs_datapath_family,
                          NLM_F_REQUEST | NLM_F_ECHO, dp->cmd,
                          OVS_DATAPATH_VERSION);

    ovs_header = ofpbuf_put_uninit(buf, sizeof *ovs_header);
    ovs_header->dp_ifindex = dp->dp_ifindex;

    if (dp->name) {
        nl_msg_put_string(buf, OVS_DP_ATTR_NAME, dp->name);
    }

    if (dp->upcall_pid) {
        nl_msg_put_u32(buf, OVS_DP_ATTR_UPCALL_PID, *dp->upcall_pid);
    }

    if (dp->user_features) {
        nl_msg_put_u32(buf, OVS_DP_ATTR_USER_FEATURES, dp->user_features);
    }

    /* Skip OVS_DP_ATTR_STATS since we never have a reason to serialize it. */
}

/* Clears 'dp' to "empty" values. */
static void
dpif_netlink_dp_init(struct dpif_netlink_dp *dp)
{
    memset(dp, 0, sizeof *dp);
}

static void
dpif_netlink_dp_dump_start(struct nl_dump *dump)
{
    struct dpif_netlink_dp request;
    struct ofpbuf *buf;

    dpif_netlink_dp_init(&request);
    request.cmd = OVS_DP_CMD_GET;

    buf = ofpbuf_new(1024);
    dpif_netlink_dp_to_ofpbuf(&request, buf);
    nl_dump_start(dump, NETLINK_GENERIC, buf);
    ofpbuf_delete(buf);
}

/* Executes 'request' in the kernel datapath.  If the command fails, returns a
 * positive errno value.  Otherwise, if 'reply' and 'bufp' are null, returns 0
 * without doing anything else.  If 'reply' and 'bufp' are nonnull, then the
 * result of the command is expected to be of the same form, which is decoded
 * and stored in '*reply' and '*bufp'.  The caller must free '*bufp' when the
 * reply is no longer needed ('reply' will contain pointers into '*bufp'). */
static int
dpif_netlink_dp_transact(const struct dpif_netlink_dp *request,
                         struct dpif_netlink_dp *reply, struct ofpbuf **bufp)
{
    struct ofpbuf *request_buf;
    int error;

    ovs_assert((reply != NULL) == (bufp != NULL));

    request_buf = ofpbuf_new(1024);
    dpif_netlink_dp_to_ofpbuf(request, request_buf);
    error = nl_transact(NETLINK_GENERIC, request_buf, bufp);
    ofpbuf_delete(request_buf);

    if (reply) {
        dpif_netlink_dp_init(reply);
        if (!error) {
            error = dpif_netlink_dp_from_ofpbuf(reply, *bufp);
        }
        if (error) {
            ofpbuf_delete(*bufp);
            *bufp = NULL;
        }
    }
    return error;
}

/* Obtains information about 'dpif_' and stores it into '*reply' and '*bufp'.
 * The caller must free '*bufp' when the reply is no longer needed ('reply'
 * will contain pointers into '*bufp').  */
static int
dpif_netlink_dp_get(const struct dpif *dpif_, struct dpif_netlink_dp *reply,
                    struct ofpbuf **bufp)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    struct dpif_netlink_dp request;

    dpif_netlink_dp_init(&request);
    request.cmd = OVS_DP_CMD_GET;
    request.dp_ifindex = dpif->dp_ifindex;

    return dpif_netlink_dp_transact(&request, reply, bufp);
}

/* Parses the contents of 'buf', which contains a "struct ovs_header" followed
 * by Netlink attributes, into 'flow'.  Returns 0 if successful, otherwise a
 * positive errno value.
 *
 * 'flow' will contain pointers into 'buf', so the caller should not free 'buf'
 * while 'flow' is still in use. */
static int
dpif_netlink_flow_from_ofpbuf(struct dpif_netlink_flow *flow,
                              const struct ofpbuf *buf)
{
    static const struct nl_policy ovs_flow_policy[__OVS_FLOW_ATTR_GTPV1_MAX] = {
        [OVS_FLOW_ATTR_KEY] = { .type = NL_A_NESTED, .optional = true },
        [OVS_FLOW_ATTR_MASK] = { .type = NL_A_NESTED, .optional = true },
        [OVS_FLOW_ATTR_ACTIONS] = { .type = NL_A_NESTED, .optional = true },
        [OVS_FLOW_ATTR_STATS] = { NL_POLICY_FOR(struct ovs_flow_stats),
                                  .optional = true },
        [OVS_FLOW_ATTR_TCP_FLAGS] = { .type = NL_A_U8, .optional = true },
        [OVS_FLOW_ATTR_USED] = { .type = NL_A_U64, .optional = true },
        [OVS_FLOW_ATTR_UFID] = { .type = NL_A_UNSPEC, .optional = true,
                                 .min_len = sizeof(ovs_u128) },
		[OVS_FLOW_ATTR_KEY_GTPV1] = { .type = NL_A_NESTED,.optional = true },
		[OVS_FLOW_ATTR_MASK_GTPV1] = { .type = NL_A_NESTED,.optional = true },
		[OVS_FLOW_ATTR_ACTIONS_GTPV1] = { .type = NL_A_NESTED,.optional = true },
        /* The kernel never uses OVS_FLOW_ATTR_CLEAR. */
        /* The kernel never uses OVS_FLOW_ATTR_PROBE. */
        /* The kernel never uses OVS_FLOW_ATTR_UFID_FLAGS. */
    };

    struct nlattr *a[ARRAY_SIZE(ovs_flow_policy)];	// array of __OVS_FLOW_ATTR_GTPV1_MAX ptrs to 'nlattr'
    struct ovs_header *ovs_header;
    struct nlmsghdr *nlmsg;
    struct genlmsghdr *genl;
    struct ofpbuf b;
	int ovs_flow_attr;

    dpif_netlink_flow_init(flow);	// zero out the 'flow'

    ofpbuf_use_const(&b, buf->data, buf->size);
    nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);		// get ptr to 'nlmsghdr'
    genl = ofpbuf_try_pull(&b, sizeof *genl);		// get ptr to 'genlmsghdr'
    ovs_header = ofpbuf_try_pull(&b, sizeof *ovs_header);	// get ptr to genl user specific header, which is 'ovs_header'
    if (!nlmsg || !genl || !ovs_header || nlmsg->nlmsg_type != ovs_flow_family ||
        !nl_policy_parse(&b, 0, ovs_flow_policy, a, ARRAY_SIZE(ovs_flow_policy)))
	/* parse all the 'OVS_FLOW_ATTR_*' attributes from 'buf' and make 'a[OVS_FLOW_ATTR_*]' point at it */
	{
        return EINVAL;
    }

    if (!a[OVS_FLOW_ATTR_KEY] && !a[OVS_FLOW_ATTR_KEY_GTPV1] && !a[OVS_FLOW_ATTR_UFID]) {
        return EINVAL;
    }
	/* Can't mix normal flows with gtp ones! */
	if ((a[OVS_FLOW_ATTR_KEY] || a[OVS_FLOW_ATTR_MASK] || a[OVS_FLOW_ATTR_ACTIONS]) &&
		(a[OVS_FLOW_ATTR_KEY_GTPV1] || a[OVS_FLOW_ATTR_MASK_GTPV1] || a[OVS_FLOW_ATTR_ACTIONS_GTPV1]))
	{
		return EINVAL;
	}
	
	flow->is_gtp = (a[OVS_FLOW_ATTR_KEY_GTPV1] != NULL);
    flow->nlmsg_flags = nlmsg->nlmsg_flags;
    flow->dp_ifindex = ovs_header->dp_ifindex;

	ovs_flow_attr = !flow->is_gtp ? OVS_FLOW_ATTR_KEY : OVS_FLOW_ATTR_KEY_GTPV1;
    if (a[OVS_FLOW_ATTR_KEY] || a[OVS_FLOW_ATTR_KEY_GTPV1])
	{
        flow->key = nl_attr_get(a[ovs_flow_attr]);
        flow->key_len = nl_attr_get_size(a[ovs_flow_attr]);
    }

    if (a[OVS_FLOW_ATTR_UFID])
	{
        const ovs_u128 *ufid;

        ufid = nl_attr_get_unspec(a[OVS_FLOW_ATTR_UFID],
                                  nl_attr_get_size(a[OVS_FLOW_ATTR_UFID]));
        flow->ufid = *ufid;
        flow->ufid_present = true;
    }

	ovs_flow_attr = !flow->is_gtp ? OVS_FLOW_ATTR_MASK : OVS_FLOW_ATTR_MASK_GTPV1;
    if (a[OVS_FLOW_ATTR_MASK] || a[OVS_FLOW_ATTR_MASK_GTPV1])
	{
        flow->mask = nl_attr_get(a[ovs_flow_attr]);
        flow->mask_len = nl_attr_get_size(a[ovs_flow_attr]);
    }

	ovs_flow_attr = !flow->is_gtp ? OVS_FLOW_ATTR_ACTIONS : OVS_FLOW_ATTR_ACTIONS_GTPV1;
    if (a[OVS_FLOW_ATTR_ACTIONS] || a[OVS_FLOW_ATTR_ACTIONS_GTPV1])
	{
        flow->actions = nl_attr_get(a[ovs_flow_attr]);
        flow->actions_len = nl_attr_get_size(a[ovs_flow_attr]);
    }

    if (a[OVS_FLOW_ATTR_STATS]) {
        flow->stats = nl_attr_get(a[OVS_FLOW_ATTR_STATS]);
    }
    if (a[OVS_FLOW_ATTR_TCP_FLAGS]) {
        flow->tcp_flags = nl_attr_get(a[OVS_FLOW_ATTR_TCP_FLAGS]);
    }
    if (a[OVS_FLOW_ATTR_USED]) {
        flow->used = nl_attr_get(a[OVS_FLOW_ATTR_USED]);
    }

    return 0;
}

/* Appends to 'buf' (which must initially be empty) a "struct ovs_header"
 * followed by Netlink attributes corresponding to 'flow'. */
static void
dpif_netlink_flow_to_ofpbuf(const struct dpif_netlink_flow *flow,
                            struct ofpbuf *buf)
{
    struct ovs_header *ovs_header;
	uint16_t type;

    nl_msg_put_genlmsghdr(buf, 0, ovs_flow_family,
                          NLM_F_REQUEST | flow->nlmsg_flags,
                          flow->cmd, OVS_FLOW_VERSION);

    ovs_header = ofpbuf_put_uninit(buf, sizeof *ovs_header);
    ovs_header->dp_ifindex = flow->dp_ifindex;

    if (flow->ufid_present) {
        nl_msg_put_unspec(buf, OVS_FLOW_ATTR_UFID, &flow->ufid,
                          sizeof flow->ufid);
    }
    if (flow->ufid_terse) {
        nl_msg_put_u32(buf, OVS_FLOW_ATTR_UFID_FLAGS,
                       OVS_UFID_F_OMIT_KEY | OVS_UFID_F_OMIT_MASK
                       | OVS_UFID_F_OMIT_ACTIONS);
    }
    if (!flow->ufid_terse || !flow->ufid_present)
	{
        if (flow->key_len)
		{
			type = !flow->is_gtp ? OVS_FLOW_ATTR_KEY : OVS_FLOW_ATTR_KEY_GTPV1;
			nl_msg_put_unspec(buf, type, flow->key, flow->key_len);
        }

        if (flow->mask_len)
		{
			type = !flow->is_gtp ? OVS_FLOW_ATTR_MASK : OVS_FLOW_ATTR_MASK_GTPV1;
			nl_msg_put_unspec(buf, type, flow->mask, flow->mask_len);
        }

        if (flow->actions || flow->actions_len)
		{
			type = !flow->is_gtp ? OVS_FLOW_ATTR_ACTIONS : OVS_FLOW_ATTR_ACTIONS_GTPV1;
			nl_msg_put_unspec(buf, type, flow->actions, flow->actions_len);
        }
    }

    /* We never need to send these to the kernel. */
    ovs_assert(!flow->stats);
    ovs_assert(!flow->tcp_flags);
    ovs_assert(!flow->used);

    if (flow->clear) {
        nl_msg_put_flag(buf, OVS_FLOW_ATTR_CLEAR);
    }
    if (flow->probe) {
        nl_msg_put_flag(buf, OVS_FLOW_ATTR_PROBE);
    }
}

/* Clears 'flow' to "empty" values. */
static void
dpif_netlink_flow_init(struct dpif_netlink_flow *flow)
{
    memset(flow, 0, sizeof *flow);
}

/* Executes 'request' in the kernel datapath.  If the command fails, returns a
 * positive errno value.  Otherwise, if 'reply' and 'bufp' are null, returns 0
 * without doing anything else.  If 'reply' and 'bufp' are nonnull, then the
 * result of the command is expected to be a flow also, which is decoded and
 * stored in '*reply' and '*bufp'.  The caller must free '*bufp' when the reply
 * is no longer needed ('reply' will contain pointers into '*bufp'). */
static int
dpif_netlink_flow_transact(struct dpif_netlink_flow *request,
                           struct dpif_netlink_flow *reply,
                           struct ofpbuf **bufp)
{
    struct ofpbuf *request_buf;
    int error;

    ovs_assert((reply != NULL) == (bufp != NULL));

    if (reply) {
        request->nlmsg_flags |= NLM_F_ECHO;
    }

    request_buf = ofpbuf_new(1024);
    dpif_netlink_flow_to_ofpbuf(request, request_buf);
    error = nl_transact(NETLINK_GENERIC, request_buf, bufp);
    ofpbuf_delete(request_buf);

    if (reply) {
        if (!error) {
            error = dpif_netlink_flow_from_ofpbuf(reply, *bufp);
        }
        if (error) {
            dpif_netlink_flow_init(reply);
            ofpbuf_delete(*bufp);
            *bufp = NULL;
        }
    }
    return error;
}

static void
dpif_netlink_flow_get_stats(const struct dpif_netlink_flow *flow,
                            struct dpif_flow_stats *stats)
{
    if (flow->stats) {
        stats->n_packets = get_32aligned_u64(&flow->stats->n_packets);
        stats->n_bytes = get_32aligned_u64(&flow->stats->n_bytes);
    } else {
        stats->n_packets = 0;
        stats->n_bytes = 0;
    }
    stats->used = flow->used ? get_32aligned_u64(flow->used) : 0;
    stats->tcp_flags = flow->tcp_flags ? *flow->tcp_flags : 0;
}

/* Logs information about a packet that was recently lost in 'ch' (in
 * 'dpif_'). */
static void
report_loss(struct dpif_netlink *dpif, struct dpif_channel *ch, uint32_t ch_idx,
            uint32_t handler_id)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
    struct ds s;

    if (VLOG_DROP_WARN(&rl)) {
        return;
    }

    ds_init(&s);
    if (ch->last_poll != LLONG_MIN) {
        ds_put_format(&s, " (last polled %lld ms ago)",
                      time_msec() - ch->last_poll);
    }

    VLOG_WARN("%s: lost packet on port channel %u of handler %u",
              dpif_name(&dpif->dpif), ch_idx, handler_id);
    ds_destroy(&s);
}
