/*
 * xt_IPSECOUT
 *
 * Steal a packet to netfilter and send it to the fast path via
 * fptun. It is a terminal rule because it returns NF_STOLEN in
 * any case.
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netfilter/x_tables.h>
#include <net/xfrm.h>

#include <xt_IPSECOUT.h>
#include <ifuid.h>

#include "fptun.h"

#ifdef CONFIG_NET_VRF
#define HAVE_VRF_6WIND 1
#endif

#ifdef USE_VRF_NETNS
#include <vrf.h>
#endif

#ifndef CONFIG_MCORE_RFPVI
extern struct net_device *fpn0;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
#define HAVE_XFRM_DST_POL 1
#elif defined(RHEL_MAJOR) && RHEL_MAJOR == 6 && RHEL_MINOR >= 5
#define HAVE_XFRM_DST_POL 1
#endif

#ifdef CONFIG_XFRM
extern int rfpvi_get_blade_info(uint8_t blade_id, struct net_device **pdev, char *mac);

static int xfrm_fptun_output(struct sk_buff *skb, uint8_t cmd)
{
	struct dst_entry *dst = skb_dst(skb);
	__attribute__ ((unused)) struct xfrm_state *x = dst->xfrm;
	__attribute__ ((unused)) struct xfrm_dst *xdst = (struct xfrm_dst *)dst;
	int need_head, prepend;
#ifdef CONFIG_NET_SKBUFF_SKTAG
	struct cmsghdr *cmsg;
	struct msghdr msg = {
		.msg_control = skb->sktag,
		.msg_controllen = sizeof(skb->sktag)
	};
	struct in_taginfo *sktag;
#endif
	struct fpmtaghdr *mtag;
	int tags = 0;
	struct fptunhdr *fptunhdr;
	struct net_device *output_dev = NULL;
	char output_mac[MAX_ADDR_LEN];
	uint32_t ifuid;
	uint32_t vrfid;
	u8 fp_output_blade = x->sel.user;

#ifdef CONFIG_MCORE_IPSEC_SVTI
#if defined(CONFIG_XFRM_SVTI) || defined(CONFIG_XFRM_SVTI_MODULE)
	if (x->props.svti_dev)
		ifuid = netdev2ifuid(x->props.svti_dev);
	else
#elif defined(HAVE_XFRM_DST_POL)
	if (xdst->pols[0]->mark.m == 0xffffffff &&
	    xdst->pols[0]->mark.v != 0)
		ifuid = htonl(xdst->pols[0]->mark.v);
	else
#endif
#endif
		ifuid = netdev2ifuid(dst->dev);

#ifdef CONFIG_MCORE_RFPVI
	if (rfpvi_get_blade_info(fp_output_blade, &output_dev,
				 output_mac) < 0) {
		printk(KERN_ALERT "xt_IPSECOUT %s: unknown output blade %u\n",
		       __FUNCTION__, fp_output_blade);
		goto bad;
	}
#else
	/* Assume local blade (co-localized mode),
	 * ethernet destination 00:00:00:00:00:00
	 */
	output_dev = fpn0;
	memset(output_mac, 0, sizeof(output_mac));
#endif

	/* room to reserve for FPTUN header */
	prepend = FPTUN_HLEN;

#ifdef CONFIG_NET_SKBUFF_SKTAG
	/* room to reserve for mtags */
	cmsg = CMSG_FIRSTHDR(&msg);
	if (CMSG_OK(&msg, cmsg)) {
		int max_ntags = 0xF; /* nb tags is 4-bit field */

		/* if present, skb->mark will need one mtag */
		if (skb->mark)
			max_ntags--;
		tags = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(struct in_taginfo);
		if (tags > max_ntags) {
			printk(KERN_ALERT "xt_IPSECOUT %s: Too many sktags %u\n",
			       __FUNCTION__, tags);
			goto bad;
		}
		prepend += tags * sizeof(struct fpmtaghdr);
	} else
		tags = 0;

	/* mark will be added as a mtag */
	if (skb->mark)
		prepend += sizeof(struct fpmtaghdr);
#endif

	need_head = prepend + output_dev->hard_header_len;

	/* actually reserve enough headroom */
	if (skb_headroom(skb) < need_head || skb_cloned(skb) || skb_shared(skb)) {
		struct sk_buff *new_skb = skb_realloc_headroom(skb, need_head);
		if (!new_skb)
			goto bad;
		if (skb->sk)
			skb_set_owner_w(new_skb, skb->sk);
		dev_kfree_skb(skb);
		skb = new_skb;
	}

#if defined(HAVE_VRF_6WIND)
	vrfid     = xs_xvrfid(x) & 0xFFFF;
#elif defined(USE_VRF_NETNS)
	vrfid     = vrf_lookup_by_net(xs_net(x));
	if (vrfid == VRF_VRFID_UNSPEC) {
		printk(KERN_ERR
		       "xt_IPSECOUT: unable to get VRFID of SA\n");
		goto bad;
	}
#else
	vrfid     = 0;
#endif

	/* append FPTUN header */
	fptunhdr = (struct fptunhdr *)skb_push(skb, prepend);
	memset(fptunhdr, 0, prepend);
	fptunhdr->fptun_cmd       = cmd;
	fptunhdr->fptun_exc_class = 0;
	fptunhdr->fptun_mtags     = tags;
	fptunhdr->fptun_version   = FPTUN_VERSION;
	fptunhdr->fptun_vrfid     = htons(vrfid);
	fptunhdr->fptun_proto     = 0;
	fptunhdr->fptun_blade_id  = fp_output_blade;
	fptunhdr->fptun_ifuid     = ifuid;

	skb->protocol = htons(ETH_P_FPTUN);

	mtag = (struct fpmtaghdr*)(fptunhdr + 1);
#ifdef CONFIG_NET_SKBUFF_SKTAG
	sktag = CMSG_DATA(cmsg);
	while (tags) {
		memcpy(mtag->fpmtag_name, sktag->iti_name, sizeof(mtag->fpmtag_name));
		mtag->fpmtag_data = sktag->iti_tag;

		mtag++;
		sktag++;
		tags--;
	}
	/* add a tag for mark */
	if (skb->mark) {
		strncpy(mtag->fpmtag_name, "nfm", sizeof(mtag->fpmtag_name));
		mtag->fpmtag_data = htonl(skb->mark);
		mtag++;
		fptunhdr->fptun_mtags++;
	}
#endif

	skb->dev = output_dev;

	/* encapsulate message for output on physical interface */
	if (output_dev->header_ops->create &&
	    output_dev->header_ops->create(skb, output_dev, ETH_P_FPTUN,
					   output_mac, NULL, skb->len) < 0)
		goto bad;

	dev_queue_xmit(skb);
	return NETDEV_TX_OK;

bad:
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}
#endif

static unsigned int
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
ipsecout_target(struct sk_buff *skb, const struct xt_action_param *par)
#else
ipsecout_target(struct sk_buff *skb, const struct xt_target_param *par)
#endif
{
#ifdef CONFIG_XFRM
	struct xfrm_state *x = skb_dst(skb)->xfrm;

	if (x == NULL)
		goto err;

	if (x->sel.user == 0)
		goto err;

	if (x->props.family == AF_INET) {
		xfrm_fptun_output(skb, FPTUN_IPV4_IPSEC_SP_OUTPUT_REQ);
		return NF_STOLEN;
	}

	if (x->props.family == AF_INET6) {
		xfrm_fptun_output(skb, FPTUN_IPV6_IPSEC_SP_OUTPUT_REQ);
		return NF_STOLEN;
	}
#endif

err:
	kfree_skb(skb);
	return NF_STOLEN;
}

struct xt_target xt_ipsecout_target[] __read_mostly = {
	{
		.name		= "IPSECOUT",
		.family		= AF_INET,
		.checkentry	= NULL,
		.targetsize	= 0,
		.target		= ipsecout_target,
		.me		= THIS_MODULE,
	},
	{
		.name		= "IPSECOUT",
		.family		= AF_INET6,
		.checkentry	= NULL,
		.targetsize	= 0,
		.target		= ipsecout_target,
		.me		= THIS_MODULE,
	},
};
