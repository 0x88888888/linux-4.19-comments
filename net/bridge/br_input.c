/*
 *	Handle incoming frames
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/netfilter_bridge.h>
#include <linux/neighbour.h>
#include <net/arp.h>
#include <linux/export.h>
#include <linux/rculist.h>
#include "br_private.h"
#include "br_private_tunnel.h"

/* Hook for brouter */
br_should_route_hook_t __rcu *br_should_route_hook __read_mostly;
EXPORT_SYMBOL(br_should_route_hook);

/*
 * __netif_receive_skb_core()
 *  br_handle_frame()
 *   br_handle_frame_finish()
 *    br_pass_frame_up()
 *     br_netif_receive_skb()
 */
static int
br_netif_receive_skb(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	br_drop_fake_rtable(skb);
	return netif_receive_skb(skb);
}

/*
 * __netif_receive_skb_core()
 *  br_handle_frame()
 *   br_handle_frame_finish()
 *    br_pass_frame_up()
 */
static int br_pass_frame_up(struct sk_buff *skb)
{
	struct net_device *indev, *brdev = BR_INPUT_SKB_CB(skb)->brdev;
	struct net_bridge *br = netdev_priv(brdev);
	struct net_bridge_vlan_group *vg;
	struct pcpu_sw_netstats *brstats = this_cpu_ptr(br->stats);

	u64_stats_update_begin(&brstats->syncp);
	brstats->rx_packets++;
	brstats->rx_bytes += skb->len;
	u64_stats_update_end(&brstats->syncp);

	vg = br_vlan_group_rcu(br);
	/* Bridge is just like any other port.  Make sure the
	 * packet is allowed except in promisc modue when someone
	 * may be running packet capture.
	 */
	if (!(brdev->flags & IFF_PROMISC) &&
	    !br_allowed_egress(vg, skb)) {
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	indev = skb->dev;
	//将skb的设备换成net_bridge	
	skb->dev = brdev;
	skb = br_handle_vlan(br, NULL, vg, skb);
	if (!skb)
		return NET_RX_DROP;
	/* update the multicast stats if the packet is IGMP/MLD */
	br_multicast_count(br, NULL, skb, br_multicast_igmp_type(skb),
			   BR_MCAST_DIR_TX);

	return NF_HOOK(NFPROTO_BRIDGE, NF_BR_LOCAL_IN,
		       dev_net(indev), NULL, skb, indev, NULL,
		       br_netif_receive_skb);
}

/*
 * __netif_receive_skb_core()
 *  br_handle_frame()
 *   br_handle_frame_finish()
 *
 * note: already called with rcu_read_lock 
 *
 * 转发出去
 */
int br_handle_frame_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct net_bridge_port *p = br_port_get_rcu(skb->dev);
	enum br_pkt_type pkt_type = BR_PKT_UNICAST;
	struct net_bridge_fdb_entry *dst = NULL;
	struct net_bridge_mdb_entry *mdst;
	bool local_rcv, mcast_hit = false;
	const unsigned char *dest;
	struct net_bridge *br;
	u16 vid = 0;

	if (!p || p->state == BR_STATE_DISABLED)
		goto drop;

    /*
     * 判断skb是否可以进入net_bridge内,如果没有开启vlan,则所有的skb都可以进入
     * 如果开启了vlan,则根据vlan相应的规则，从桥上转发
     */
	if (!br_allowed_ingress(p->br, nbp_vlan_group_rcu(p), skb, &vid))
		goto out;

	nbp_switchdev_frame_mark(p, skb);

	/* insert into forwarding database after filtering to avoid spoofing */
	br = p->br;

	//学习skb的源地址
	if (p->flags & BR_LEARNING)
		br_fdb_update(br, p, eth_hdr(skb)->h_source, vid, false);

	local_rcv = !!(br->dev->flags & IFF_PROMISC);
	dest = eth_hdr(skb)->h_dest;
	if (is_multicast_ether_addr(dest)) {
		/* by definition the broadcast is also a multicast address */
		if (is_broadcast_ether_addr(dest)) {
			pkt_type = BR_PKT_BROADCAST;
			local_rcv = true;
		} else {
			pkt_type = BR_PKT_MULTICAST;
			if (br_multicast_rcv(br, p, skb, vid))
				goto drop;
		}
	}

    /*
     * 端口状态(和flags不冲突,flags表示可以做的事情,state表示状态)
     */
	if (p->state == BR_STATE_LEARNING)
		goto drop;

	BR_INPUT_SKB_CB(skb)->brdev = br->dev;
	BR_INPUT_SKB_CB(skb)->src_port_isolated = !!(p->flags & BR_ISOLATED);

	if (IS_ENABLED(CONFIG_INET) &&
	    (skb->protocol == htons(ETH_P_ARP) ||
	     skb->protocol == htons(ETH_P_RARP))) {
		br_do_proxy_suppress_arp(skb, br, vid, p);
	} else if (IS_ENABLED(CONFIG_IPV6) &&
		   skb->protocol == htons(ETH_P_IPV6) &&
		   br->neigh_suppress_enabled &&
		   pskb_may_pull(skb, sizeof(struct ipv6hdr) +
				 sizeof(struct nd_msg)) &&
		   ipv6_hdr(skb)->nexthdr == IPPROTO_ICMPV6) {
			struct nd_msg *msg, _msg;

			msg = br_is_nd_neigh_msg(skb, &_msg);
			if (msg)
				br_do_suppress_nd(skb, br, vid, p, msg);
	}

	switch (pkt_type) {
	case BR_PKT_MULTICAST:
		mdst = br_mdb_get(br, skb, vid);
		if ((mdst || BR_INPUT_SKB_CB_MROUTERS_ONLY(skb)) &&
		    br_multicast_querier_exists(br, eth_hdr(skb))) {
			if ((mdst && mdst->host_joined) ||
			    br_multicast_is_router(br)) {
				local_rcv = true;
				br->dev->stats.multicast++;
			}
			mcast_hit = true;
		} else {
			local_rcv = true;
			br->dev->stats.multicast++;
		}
		break;
	case BR_PKT_UNICAST: //根据dest地址找到net_bridge_fdb_entry
		dst = br_fdb_find_rcu(br, dest, vid);
	default:
		break;
	}

	if (dst) {
		unsigned long now = jiffies;

		if (dst->is_local) //传入本地协议栈处理
			return br_pass_frame_up(skb);

		if (now != dst->used)
			dst->used = now;
		br_forward(dst->dst, skb, local_rcv, false);
	} else {
		if (!mcast_hit)
			br_flood(br, skb, pkt_type, local_rcv, false);
		else
			br_multicast_flood(mdst, skb, local_rcv, false);
	}

   //传入本地协议栈处理
	if (local_rcv)
		return br_pass_frame_up(skb);

out:
	return 0;
drop:
	kfree_skb(skb);
	goto out;
}
EXPORT_SYMBOL_GPL(br_handle_frame_finish);

static void __br_handle_local_finish(struct sk_buff *skb)
{
	struct net_bridge_port *p = br_port_get_rcu(skb->dev);
	u16 vid = 0;

	/* check if vlan is allowed, to avoid spoofing */
	if (p->flags & BR_LEARNING && br_should_learn(p, skb, &vid))
		br_fdb_update(p->br, p, eth_hdr(skb)->h_source, vid, false);
}

/*
 * __netif_receive_skb_core()
 *  br_handle_frame()
 *   br_handle_local_finish()
 * 
 * note: already called with rcu_read_lock 
 *
 * 本机数据，本机处理
 */
static int br_handle_local_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct net_bridge_port *p = br_port_get_rcu(skb->dev);

	__br_handle_local_finish(skb);

	BR_INPUT_SKB_CB(skb)->brdev = p->br->dev;
	br_pass_frame_up(skb);
	return 0;
}

/*
 * __netif_receive_skb_core()
 *  br_handle_frame()
 *
 * Return NULL if skb is handled
 * note: already called with rcu_read_lock
 */
rx_handler_result_t br_handle_frame(struct sk_buff **pskb)
{
	struct net_bridge_port *p;
	struct sk_buff *skb = *pskb;
	const unsigned char *dest = eth_hdr(skb)->h_dest;
	br_should_route_hook_t *rhook;

	if (unlikely(skb->pkt_type == PACKET_LOOPBACK))
		return RX_HANDLER_PASS;

    /* 
     * 判断是否是有效的mac地址，不是多播，也不是0x00地址
     */
	if (!is_valid_ether_addr(eth_hdr(skb)->h_source))
		goto drop;

    /*
     * 判断是否是共享的数据包，如果是，就clone之
     */
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		return RX_HANDLER_CONSUMED;

    //得到对应的net_bridge_port
	p = br_port_get_rcu(skb->dev);
	if (p->flags & BR_VLAN_TUNNEL) {
		if (br_handle_ingress_vlan_tunnel(skb, p,
						  nbp_vlan_group_rcu(p)))
			goto drop;
	}


    /*
     * BPDU是网桥之间交换的报文，目标mac地址是 01:80:c0:00:00:00
     */
	if (unlikely(is_link_local_ether_addr(dest))) {
		u16 fwd_mask = p->br->group_fwd_mask_required;

		/*
		 * See IEEE 802.1D Table 7-10 Reserved addresses
		 *
		 * Assignment		 		Value
		 * Bridge Group Address		01-80-C2-00-00-00
		 * (MAC Control) 802.3		01-80-C2-00-00-01
		 * (Link Aggregation) 802.3	01-80-C2-00-00-02
		 * 802.1X PAE address		01-80-C2-00-00-03
		 *
		 * 802.1AB LLDP 		01-80-C2-00-00-0E
		 *
		 * Others reserved for future standardization
		 */
		fwd_mask |= p->group_fwd_mask;
		switch (dest[5]) {
		case 0x00:	/* Bridge Group Address */
			/* If STP is turned off,
			   then must forward to keep loop detection */
			if (p->br->stp_enabled == BR_NO_STP ||
			    fwd_mask & (1u << dest[5])cols */
			fwd_mask |= p->br->group_fwd_mask;
			if (fwd_mask & (1u << dest[5]))
				goto forward; //走转发路径
		}

		/*
		 * 转到本机的数据
		 * Deliver packet to local host only
		 */
		NF_HOOK(NFPROTO_BRIDGE, NF_BR_LOCAL_IN, dev_net(skb->dev),
			NULL, skb, skb->dev, NULL, br_handle_local_finish);
		return RX_HANDLER_CONSUMED;
	}

forward:
	switch (p->state) { //两个case都走转发路径
	case BR_STATE_FORWARDING:
		//ebtable_broute_init()中获取路由的hook点,ebt_broute
		rhook = rcu_dereference(br_should_route_hook);
		if (rhook) { //如果是转发状态，就转发，然后返回
			if ((*rhook)(skb)) {
				*pskb = skb;
				return RX_HANDLER_PASS;
			}
			dest = eth_hdr(skb)->h_dest;
		}
		/* fall through */
	case BR_STATE_LEARNING:
	
		if (ether_addr_equal(p->br->dev->dev_addr, dest)) //与net_bridge的mac地址相等
			skb->pkt_type = PACKET_HOST;

        //将skb送到br_handle_frame_finish去处理
		NF_HOOK(NFPROTO_BRIDGE, NF_BR_PRE_ROUTING,
			dev_net(skb->dev), NULL, skb, skb->dev, NULL,
			br_handle_frame_finish);
		break;
	default:
drop:
		kfree_skb(skb);
	}
	return RX_HANDLE	return RX_HANDLER_CONSUMED;
}
	retur	return RX_HANDLE	return RX	return RX_HANDLE	return RX_HA	re	return RX_HANDLE	retu	return RX_HANDLE	re	return RX_HANDLE	retu			br_handle_frame_finish);
		break;
	default:
drop:
		kfree_skb(skb);
	}
	return RX_HANDL	return RX_HANDLE	return RX_HANDLER_CONSUM			br_handle_frame_finish);
		break;
	default:
drop:
		kfree_skb(skb);
	}
	return RX_HANDLE	return RX_	return RX_HANDLE	return RX_HANDLER_CONSUMED;
}
}
