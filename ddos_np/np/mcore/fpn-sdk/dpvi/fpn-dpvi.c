/*
 * Copyright(c) 2011  6WIND
 */

#include <fpn.h>

#include "dpvi.h"
#include "fpn-dpvi.h"

#if 0
#define DPVI_ERR(args...) fpn_printf(args)
#define DPVI_DEBUG(args...) fpn_printf(args)
#else
#define DPVI_ERR(args...) do { } while (0)
#define DPVI_DEBUG(args...) do { } while (0)
#endif

static struct fpn_dpvi_ops *fpn_dpvi_ops = NULL;

/* provide a ethernet header definition as it is not provided by fpn-sdk */
#define	DPVI_ETHER_ADDR_LEN		6
struct	dpvi_ether_header {
	uint8_t	ether_dhost[DPVI_ETHER_ADDR_LEN];
	uint8_t	ether_shost[DPVI_ETHER_ADDR_LEN];
	uint16_t	ether_type;
} __attribute__((packed));

/*
 * Must be called to notify linux of status changes.
 */
int fpn_dpvi_send_status(void)
{
	struct dpvi_ether_header *eth;
	struct dpvi_hdr *dpvi_hdr;
	struct mbuf *m;

	m = m_alloc();
	if (m == NULL) {
		DPVI_ERR("cannot allocate mbuf\n");
		return -1;
	}

	/* prepend DPVI hdr */
	dpvi_hdr = (struct dpvi_hdr *)m_prepend(m, DPVI_HLEN);
	if (dpvi_hdr == NULL) {
		DPVI_ERR("cannot prepend dpvi hdr -- DROP\n");
		m_freem(m);
		return -1;
	}
	dpvi_hdr->type = DPVI_TYPE_CTRL_INFO;
	dpvi_hdr->portid = 0;
	dpvi_hdr->cmd = DPVI_CMD_PORT_STATUS;
	dpvi_hdr->reqid = 0;

	/* prepend ether header ; here we use broadcast dst mac, so we
	 * don't need to set fpn0 in promisc mode on linux. */
	eth = (struct dpvi_ether_header *)
		m_prepend(m, sizeof(struct dpvi_ether_header));
	if (eth == NULL) {
		DPVI_ERR("cannot prepend ether hdr -- DROP\n");
		m_freem(m);
		return -1;
	}
	memset(&eth->ether_dhost, 0xff, 6);
	memset(&eth->ether_shost, 0, 6);
	eth->ether_type = htons(ETH_P_DPVI);

	fpn_send_exception(m, m_control_port());
	return 0;
}

/* Process a control dpvi message. If needed, an answer is sent through
 * fpn_send_exception(). The given packet is always freed so there is no return
 * value. */
static void fpn_dpvi_ctrl_recv(struct mbuf *m, uint16_t portid)
{
	struct dpvi_hdr *dpvi_hdr;
	struct dpvi_ether_header *eth;
	char tmp[6];
	unsigned header_len;
	int need_answer = 1;

	DPVI_DEBUG("%s():%d\n", __FUNCTION__, __LINE__);

	if (fpn_dpvi_ops== NULL) {
		DPVI_ERR("fpn_dpvi_ops is not defined\n");
		m_freem(m);
		return;
	}

	eth = mtod(m, struct dpvi_ether_header *);
	dpvi_hdr = (struct dpvi_hdr *)(eth+1);
	dpvi_hdr->type = DPVI_TYPE_CTRL_ANS;

	header_len = DPVI_HLEN + sizeof(struct dpvi_ether_header);

	switch (dpvi_hdr->cmd) {


		case DPVI_CMD_ETHTOOL_GET_DRVINFO: {
			struct dpvi_ethtool_drvinfo *info;

			DPVI_DEBUG("Get ethtool driver info\n");

			header_len += sizeof(struct dpvi_ethtool_drvinfo);
			if (m_headlen(m) < header_len) {
				dpvi_hdr->cmd = DPVI_CMD_ERROR;
				break;
			}

			info = (struct dpvi_ethtool_drvinfo *)(dpvi_hdr+1);

			if (fpn_dpvi_ops->ethtool_get_drvinfo &&
			    fpn_dpvi_ops->ethtool_get_drvinfo(portid, info) < 0)
				dpvi_hdr->cmd = DPVI_CMD_ERROR;

			break;
		}

		case DPVI_CMD_ETHTOOL_GET_SETTINGS: {
			struct dpvi_ethtool_gsettings *settings;

			DPVI_DEBUG("Get ethtool settings info\n");

			header_len += sizeof(struct dpvi_ethtool_gsettings);
			if (m_headlen(m) < header_len) {
				dpvi_hdr->cmd = DPVI_CMD_ERROR;
				break;
			}

			settings = (struct dpvi_ethtool_gsettings *)(dpvi_hdr+1);

			if (fpn_dpvi_ops->ethtool_get_settings &&
			    fpn_dpvi_ops->ethtool_get_settings(portid, settings) < 0)
				dpvi_hdr->cmd = DPVI_CMD_ERROR;
			break;
		}

		case DPVI_CMD_ETHTOOL_GET_SSET_COUNT: {
		      struct dpvi_ethtool_sset_count *sset_count;

		      DPVI_DEBUG("Get ethtool string set count\n");

		      header_len += sizeof(struct dpvi_ethtool_sset_count);
		      if (m_headlen(m) < header_len) {
			      dpvi_hdr->cmd = DPVI_CMD_ERROR;
			      break;
		      }

		      sset_count = (struct dpvi_ethtool_sset_count *)(dpvi_hdr+1);

		      if (fpn_dpvi_ops->ethtool_get_sset_count &&
			  fpn_dpvi_ops->ethtool_get_sset_count(portid, sset_count) < 0)
			      dpvi_hdr->cmd = DPVI_CMD_ERROR;

		      break;
		}

		case DPVI_CMD_ETHTOOL_GET_STRINGS: {
			struct dpvi_ethtool_gstrings *strings;
			static struct dpvi_ethtool_gstrings *strings_data = NULL;
			uint16_t offset_to_copy, size_to_copy;

			DPVI_DEBUG("Get ethtool strings\n");

			header_len += sizeof(struct dpvi_ethtool_gstrings);
			if (m_headlen(m) < header_len) {
				dpvi_hdr->cmd = DPVI_CMD_ERROR;
				break;
			}

			strings = (struct dpvi_ethtool_gstrings *)(dpvi_hdr+1);

			offset_to_copy = ntohs(strings->offset_to_copy);
			size_to_copy = ntohs(strings->size_to_copy);

			/* Copy the 'strings' to 'strings_data' if it is the first message */
			if (!offset_to_copy) {
				if (unlikely(strings_data != NULL))
					DPVI_ERR("The strings_data should be NULL here!\n");

				strings_data = fpn_malloc(ntohl(strings->len) * DPVI_ETHTOOL_GSTRING_LEN * sizeof(uint8_t) +
						sizeof(struct dpvi_ethtool_gstrings), 0);
				if (!strings_data) {
					dpvi_hdr->cmd = DPVI_CMD_ERROR;
					break;
				}
				strings_data->string_sets = strings->string_sets;
				strings_data->len = strings->len;

				if (fpn_dpvi_ops->ethtool_get_strings &&
						fpn_dpvi_ops->ethtool_get_strings(portid, strings_data) < 0) {
					dpvi_hdr->cmd = DPVI_CMD_ERROR;
				}
			}

			if (size_to_copy)
				memcpy(strings->data, strings_data->data + offset_to_copy, size_to_copy);
			else if (offset_to_copy) {
				/* It is the last packet, free 'strings_data' */
				fpn_free(strings_data);
				strings_data = NULL;
			}

			break;
		}

		case DPVI_CMD_ETHTOOL_GET_STATSINFO: {
			struct dpvi_ethtool_statsinfo *info;

			DPVI_DEBUG("Get ethtool stats info\n");

			header_len += sizeof(struct dpvi_ethtool_statsinfo);
			if (m_headlen(m) < header_len) {
				dpvi_hdr->cmd = DPVI_CMD_ERROR;
				break;
			}

			info = (struct dpvi_ethtool_statsinfo *)(dpvi_hdr+1);

			if (fpn_dpvi_ops->ethtool_get_statsinfo &&
			    fpn_dpvi_ops->ethtool_get_statsinfo(portid, info) < 0)
				dpvi_hdr->cmd = DPVI_CMD_ERROR;

			break;
		}

		case DPVI_CMD_ETHTOOL_GET_PAUSEPARAM: {
			struct dpvi_ethtool_pauseparam *pause;

			DPVI_DEBUG("Get ethtool pause info\n");

			header_len += sizeof(struct dpvi_ethtool_pauseparam);
			if (m_headlen(m) < header_len) {
				dpvi_hdr->cmd = DPVI_CMD_ERROR;
				break;
			}

			pause = (struct dpvi_ethtool_pauseparam *)(dpvi_hdr+1);

			if (fpn_dpvi_ops->ethtool_get_pauseparam &&
			    fpn_dpvi_ops->ethtool_get_pauseparam(portid, pause) < 0)
				dpvi_hdr->cmd = DPVI_CMD_ERROR;

			break;
		}

		case DPVI_CMD_ETHTOOL_SET_PAUSEPARAM: {
			struct dpvi_ethtool_pauseparam *pause;

			DPVI_DEBUG("Set ethtool pause info\n");

			header_len += sizeof(struct dpvi_ethtool_pauseparam);
			if (m_headlen(m) < header_len) {
				dpvi_hdr->cmd = DPVI_CMD_ERROR;
				break;
			}

			pause = (struct dpvi_ethtool_pauseparam *)(dpvi_hdr+1);

			if (fpn_dpvi_ops->ethtool_set_pauseparam &&
			    fpn_dpvi_ops->ethtool_set_pauseparam(portid, pause) < 0)
				dpvi_hdr->cmd = DPVI_CMD_ERROR;

			break;
		}

		default: {
			/* not supported */
			dpvi_hdr->cmd = DPVI_CMD_ERROR;
			break;
		}
	}

	if (need_answer == 0) {
		m_freem(m);
		return;
	}

	/* swap mac addresses */
	memcpy(&tmp, &eth->ether_dhost, 6);
	memcpy(&eth->ether_dhost, &eth->ether_shost, 6);
	memcpy(&eth->ether_shost, &tmp, 6);

	fpn_send_exception(m, m_control_port());
}

#if defined(CONFIG_MCORE_ARCH_TILE) || defined(CONFIG_MCORE_ARCH_TILEGX) || defined(CONFIG_MCORE_VFP_FPVI_NDEVHOOK)
/* Called when we receive a dpvi message from linux kernel. Forward it
 * on the physical port. */
static void fpn_dpvi_data_recv(struct mbuf *m, uint16_t portid)
{
	DPVI_DEBUG("%s():%d on port %d\n", __FUNCTION__, __LINE__, portid);
	m_adj(m, DPVI_HLEN + sizeof(struct dpvi_ether_header));
	fpn_send_packet(m, portid);
}
#endif

/*
 * Receive an ethernet packet that can be dpvi. If it is not a dpvi packet,
 * return -1. Else, process packet and return 0 (packet will be freed).
 */
int fpn_dpvi_recv(struct mbuf *m)
{
	struct dpvi_hdr *dpvi_hdr;
	struct dpvi_ether_header *eth;
	uint16_t ether_type;

	/* malformed packet */
	if (m_headlen(m) < (DPVI_HLEN + sizeof(struct dpvi_ether_header)))
		return -1;

	/* check ethertype */
	eth = mtod(m, struct dpvi_ether_header *);
	ether_type = ntohs(eth->ether_type);
	if (ether_type != ETH_P_DPVI)
		return -1;

	dpvi_hdr = (struct dpvi_hdr *)(eth+1);

	/* dispatch data and ctrl messages, other messages are
	 * silently ignored */
#if defined(CONFIG_MCORE_ARCH_TILE) || defined(CONFIG_MCORE_ARCH_TILEGX) || defined(CONFIG_MCORE_VFP_FPVI_NDEVHOOK)
	if (likely(dpvi_hdr->type == DPVI_TYPE_DATA_LINUX2FP))
		fpn_dpvi_data_recv(m, dpvi_hdr->portid);
	else
#endif
	if (dpvi_hdr->type == DPVI_TYPE_CTRL_REQ)
		fpn_dpvi_ctrl_recv(m, dpvi_hdr->portid);
	else
		m_freem(m);

	return 0;
}

static struct mbuf *fpn_dpvi_realloc_headroom(struct mbuf *m, uint size)
{
	struct mbuf *n;
	uint init_headroom;

	/* m_headroom is sufficient, return m */
	if ( (init_headroom = s_headroom(m_first_seg(m))) >= size)
		return m;

	/* not enough headroom, prepend a new segment */
	n = m_alloc();
	if (n == NULL) {
		m_freem(m);
		return NULL;
	}
	if (m_cat(n, m)) {
		m_freem(m);
		m_freem(n);
		return NULL;
	}

	/* still not enough headroom, drop the new mbuf */
	if ( (init_headroom + s_headroom(m_first_seg(n))) < size) {
		m_freem(n);
		return NULL;
	}

	return n;
}

/*
 * Prepend DPVI headers to the packet before sending it to a
 * co-localized control plane. Typically, this function is called by the
 * arch-specific fpn_send_exception(). Return 0 on success, or a
 * negative value on error (in this case, packet is freed).
 * On tilera, when m_prepend fails, a new mbuf is allocated and
 * concatenated with the original mbuf to enlarge packet's headroom.
 */
int fpn_dpvi_prepend(struct mbuf **pm, uint16_t port)
{
	struct dpvi_ether_header *eth;
	struct dpvi_hdr *dpvi_hdr;
	struct mbuf *m = *pm;

	/* ensure enough headroom for the following m_prepend */
	m = fpn_dpvi_realloc_headroom(m,
		 DPVI_HLEN + sizeof(struct dpvi_ether_header));
	if (m == NULL) {
		DPVI_ERR("cannot realloc enough headroom for dpvi hdr -- DROP\n");
		/* m was already freed */
		return -1;
	}
	*pm = m;

	DPVI_DEBUG("%s(m=%p, port=%d)\n", __FUNCTION__, m, port);

	dpvi_hdr = (struct dpvi_hdr *)m_prepend(m, DPVI_HLEN);
	if (dpvi_hdr == NULL) {
		DPVI_ERR("cannot prepend dpvi hdr -- DROP\n");
		m_freem(m);
		return -1;
	}
	dpvi_hdr->type = DPVI_TYPE_DATA_FP2LINUX;
	dpvi_hdr->portid = port;
	dpvi_hdr->cmd = 0;
	dpvi_hdr->reqid = 0;

	/* prepend ether header (use broadcast for dst) */
	eth = (struct dpvi_ether_header *)
		m_prepend(m, sizeof(struct dpvi_ether_header));
	if (eth == NULL) {
		DPVI_ERR("cannot prepend ether hdr -- DROP\n");
		m_freem(m);
		return -1;
	}
	memset(&eth->ether_dhost, 0xff, 6);
	memset(&eth->ether_shost, 0, 6);
	eth->ether_type = htons(ETH_P_DPVI);

	return 0;
}

/*
 * Register DPVI operations, must be called once at initialization.
 */
int fpn_dpvi_register(struct fpn_dpvi_ops *dpvi_ops)
{
	/* set the global variable */
	fpn_dpvi_ops = dpvi_ops;
	return 0;
}
