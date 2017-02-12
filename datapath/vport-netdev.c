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

#include <linux/if_arp.h>
#include <linux/if_bridge.h>
#include <linux/if_vlan.h>
#include <linux/kernel.h>
#include <linux/llc.h>
#include <linux/rtnetlink.h>
#include <linux/skbuff.h>
#include <linux/openvswitch.h>

#include <net/ip_tunnels.h>
#include <net/rtnetlink.h>

#include "datapath.h"
#include "gso.h"
#include "vport.h"
#include "vport-internal_dev.h"
#include "vport-netdev.h"

static struct vport_ops ovs_netdev_vport_ops;

/* Must be called with rcu_read_lock. */
void netdev_port_receive(struct sk_buff *skb, struct ip_tunnel_info *tun_info)
{
	struct vport *vport;

	vport = ovs_netdev_get_vport(skb->dev);
	if (unlikely(!vport))
		goto error;

	if (unlikely(skb_warn_if_lro(skb)))
		goto error;

	/* Make our own copy of the packet.  Otherwise we will mangle the
	 * packet for anyone who came before us (e.g. tcpdump via AF_PACKET).
	 */
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (unlikely(!skb))
		return;

	skb_push(skb, ETH_HLEN);
	ovs_skb_postpush_rcsum(skb, skb->data, ETH_HLEN);
	ovs_vport_receive(vport, skb, tun_info);
	return;
error:
	kfree_skb(skb);
}

#ifndef HAVE_METADATA_DST
#define port_receive(skb)  netdev_port_receive(skb, NULL)
#else
#define port_receive(skb)  netdev_port_receive(skb, skb_tunnel_info(skb))
#endif

#if defined HAVE_RX_HANDLER_PSKB  /* 2.6.39 and above or backports */
/* Called with rcu_read_lock and bottom-halves disabled. */
static rx_handler_result_t netdev_frame_hook(struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;

	if (unlikely(skb->pkt_type == PACKET_LOOPBACK))
		return RX_HANDLER_PASS;

	port_receive(skb);
	return RX_HANDLER_CONSUMED;
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36) || \
      defined HAVE_RHEL_OVS_HOOK
/* Called with rcu_read_lock and bottom-halves disabled. */
static struct sk_buff *netdev_frame_hook(struct sk_buff *skb)
{
	if (unlikely(skb->pkt_type == PACKET_LOOPBACK))
		return skb;

	port_receive(skb);
	return NULL;
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
/*
 * Used as br_handle_frame_hook.  (Cannot run bridge at the same time, even on
 * different set of devices!)
 */
/* Called with rcu_read_lock and bottom-halves disabled. */
static struct sk_buff *netdev_frame_hook(struct net_bridge_port *p,
					 struct sk_buff *skb)
{
	port_receive(skb);
	return NULL;
}
#else
#error
#endif

static struct net_device *get_dpdev(const struct datapath *dp)
{
	struct vport *local;

	local = ovs_vport_ovsl(dp, OVSP_LOCAL);
	BUG_ON(!local);
	return local->dev;
}

struct vport *ovs_netdev_link(struct vport *vport, const char *name)
{
	int err;

	vport->dev = dev_get_by_name(ovs_dp_get_net(vport->dp), name);
	if (!vport->dev) {
		err = -ENODEV;
		goto error_free_vport;
	}

	if (vport->dev->flags & IFF_LOOPBACK ||
	    vport->dev->type != ARPHRD_ETHER ||
	    ovs_is_internal_dev(vport->dev)) {
		err = -EINVAL;
		goto error_put;
	}

	rtnl_lock();
	err = netdev_master_upper_dev_link(vport->dev,
					   get_dpdev(vport->dp));
	if (err)
		goto error_unlock;

	err = netdev_rx_handler_register(vport->dev, netdev_frame_hook,
					 vport);
	if (err)
		goto error_master_upper_dev_unlink;

	dev_disable_lro(vport->dev);
	dev_set_promiscuity(vport->dev, 1);
	vport->dev->priv_flags |= IFF_OVS_DATAPATH;
	rtnl_unlock();

	return vport;

error_master_upper_dev_unlink:
	netdev_upper_dev_unlink(vport->dev, get_dpdev(vport->dp));
error_unlock:
	rtnl_unlock();
error_put:
	dev_put(vport->dev);
error_free_vport:
	ovs_vport_free(vport);
	return ERR_PTR(err);
}
EXPORT_SYMBOL_GPL(ovs_netdev_link);

static struct vport *netdev_create(const struct vport_parms *parms)
{
	struct vport *vport;

	vport = ovs_vport_alloc(0, &ovs_netdev_vport_ops, parms);
	if (IS_ERR(vport))
		return vport;

	return ovs_netdev_link(vport, parms->name);
}

static void vport_netdev_free(struct rcu_head *rcu)
{
	struct vport *vport = container_of(rcu, struct vport, rcu);

	if (vport->dev)
		dev_put(vport->dev);
	ovs_vport_free(vport);
}

void ovs_netdev_detach_dev(struct vport *vport)
{
	ASSERT_RTNL();
	vport->dev->priv_flags &= ~IFF_OVS_DATAPATH;
	netdev_rx_handler_unregister(vport->dev);
	netdev_upper_dev_unlink(vport->dev,
				netdev_master_upper_dev_get(vport->dev));
	dev_set_promiscuity(vport->dev, -1);
}
EXPORT_SYMBOL_GPL(ovs_netdev_detach_dev);

static void netdev_destroy(struct vport *vport)
{
	rtnl_lock();
	if (vport->dev->priv_flags & IFF_OVS_DATAPATH)
		ovs_netdev_detach_dev(vport);
	rtnl_unlock();

	call_rcu(&vport->rcu, vport_netdev_free);
}

void ovs_netdev_tunnel_destroy(struct vport *vport)
{
	rtnl_lock();
	if (vport->dev->priv_flags & IFF_OVS_DATAPATH)
		ovs_netdev_detach_dev(vport);

	/* We can be invoked by both explicit vport deletion and
	 * underlying netdev deregistration; delete the link only
	 * if it's not already shutting down.
	 */

	if (vport->dev->reg_state == NETREG_REGISTERED)
		rtnl_delete_link(vport->dev);

	dev_put(vport->dev);
	vport->dev = NULL;
	rtnl_unlock();

	call_rcu(&vport->rcu, vport_netdev_free);
}
EXPORT_SYMBOL_GPL(ovs_netdev_tunnel_destroy);

/* Returns null if this device is not attached to a datapath. */
struct vport *ovs_netdev_get_vport(struct net_device *dev)
{
#if defined HAVE_NETDEV_RX_HANDLER_REGISTER || \
    defined HAVE_RHEL_OVS_HOOK
#ifdef HAVE_OVS_DATAPATH
	if (likely(dev->priv_flags & IFF_OVS_DATAPATH))
#else
	if (likely(rcu_access_pointer(dev->rx_handler) == netdev_frame_hook))
#endif
#ifdef HAVE_RHEL_OVS_HOOK
		return (struct vport *)rcu_dereference_rtnl(dev->ax25_ptr);
#else
#ifdef HAVE_NET_DEVICE_EXTENDED
		return (struct vport *)
			rcu_dereference_rtnl(netdev_extended(dev)->rx_handler_data);
#else
		return (struct vport *)rcu_dereference_rtnl(dev->rx_handler_data);
#endif
#endif
	else
		return NULL;
#else
	return (struct vport *)rcu_dereference_rtnl(dev->br_port);
#endif
}

static struct vport_ops ovs_netdev_vport_ops = {
	.type		= OVS_VPORT_TYPE_NETDEV,	// the OVS vport type corresponds to a network device (for ex., eth0)
	.create		= netdev_create,
	.destroy	= netdev_destroy,
	.send		= dev_queue_xmit,
};

int __init ovs_netdev_init(void)
{
	return ovs_vport_ops_register(&ovs_netdev_vport_ops);
}

void ovs_netdev_exit(void)
{
	ovs_vport_ops_unregister(&ovs_netdev_vport_ops);
}

#if !defined HAVE_NETDEV_RX_HANDLER_REGISTER && \
    !defined HAVE_RHEL_OVS_HOOK
/*
 * Enforces, mutual exclusion with the Linux bridge module, by declaring and
 * exporting br_should_route_hook.  Because the bridge module also exports the
 * same symbol, the module loader will refuse to load both modules at the same
 * time (e.g. "bridge: exports duplicate symbol br_should_route_hook (owned by
 * openvswitch)").
 *
 * Before Linux 2.6.36, Open vSwitch cannot safely coexist with the Linux
 * bridge module, so openvswitch uses this macro in those versions.  In
 * Linux 2.6.36 and later, Open vSwitch can coexist with the bridge module.
 *
 * The use of "typeof" here avoids the need to track changes in the type of
 * br_should_route_hook over various kernel versions.
 */
typeof(br_should_route_hook) br_should_route_hook;
EXPORT_SYMBOL(br_should_route_hook);
#endif
