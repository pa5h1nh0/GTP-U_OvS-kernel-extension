#ifndef OPENVSWITCH_GTPU_H
#define OPENVSWITCH_GTPU_H

#include <linux/types.h>

enum ovs_flow_gtpv1_cmd
{
	OVS_FLOW_CMD_NEW_GTPV1 = 0xff,			/* used as "cmd" by genlmsghdr to specify a new gtpv1 flow */
};

enum ovs_key_gtpv1_attr
{
	OVS_KEY_ATTR_UNSPEC_GTPV1 = 32,
	OVS_KEY_ATTR_GTPV1,		/* struct ovs_key_gtpv1 */
	__OVS_KEY_ATTR_GTPV1_MAX
};
#define OVS_KEY_ATTR_GTPV1_MAX (__OVS_KEY_ATTR_GTPV1_MAX - 1)

/**
 * enum ovs_action_gtpv1_attr - GTPv1 action types
 *
 * @OVS_ACTION_ATTR_PUSH_GTPV1: Push a new outermost GTPv1 header onto the packet.
 * @OVS_ACTION_ATTR_POP_GTPV1: Pop all the outermost GTPv1 tunnel related headers from the packet.
 */
enum ovs_action_gtpv1_attr
{
	OVS_ACTION_ATTR_UNSPEC_GTPV1 = 32,
	OVS_ACTION_ATTR_PUSH_GTPV1,	/* struct ovs_action_push_gtpv1 */
	OVS_ACTION_ATTR_POP_GTPV1,
	__OVS_ACTION_ATTR_GTPV1_MAX
};
#define OVS_ACTION_ATTR_GTPV1_MAX (__OVS_ACTION_ATTR_GTPV1_MAX - 1)

/**
 * enum ovs_flow_gtpv1_attr - attributes for %OVS_FLOW_ATTR_* GTPv1 tunnel related commands.
 * @OVS_FLOW_ATTR_KEY_GTPV1: Nested GTPv1 tunnel related %OVS_KEY_ATTR_* attributes specifying the flow key.
 * @OVS_FLOW_ATTR_MASK_GTPV1: Nested GTPv1 tunnel related %OVS_KEY_ATTR_* attributes specifying the mask bits
 *							  for wildcarded flow match.
 * @OVS_FLOW_ATTR_ACTIONS_GTPV1: Nested GTPv1 tunnel related %OVS_ACTION_ATTR_* attributes specifying
 *								 the actions to take for packets that match the key.
 */
enum ovs_flow_gtpv1_attr
{
	OVS_FLOW_ATTR_UNSPEC_GTPV1 = 32,
	OVS_FLOW_ATTR_KEY_GTPV1,		/* Sequence of GTPv1 tunnel related OVS_KEY_ATTR_* attributes. */
	OVS_FLOW_ATTR_MASK_GTPV1,		/* Sequence of GTPv1 tunnel related OVS_KEY_ATTR_* attributes. */
	OVS_FLOW_ATTR_ACTIONS_GTPV1,		/* Nested GTPv1 tunnel related OVS_ACTION_ATTR_* attributes. */
	__OVS_FLOW_ATTR_GTPV1_MAX
};
#define OVS_FLOW_ATTR_GTPV1_MAX (__OVS_FLOW_ATTR_GTPV1_MAX - 1)

struct ovs_key_gtpv1
{
	__be32 ipv4_dst;
	__be32 teid;
};

struct ovs_action_push_gtpv1
{
	struct
	{
		__be32 src;
		__be32 dst;
	} ipv4;
	__be32 teid;
};

#endif  /* openvswitch_gtpu.h */