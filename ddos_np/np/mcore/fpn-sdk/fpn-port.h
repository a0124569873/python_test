/*
 * Copyright(c) 2013 6WIND
 */
#ifndef __FPN_PORT_H__
#define __FPN_PORT_H__

#include "fpn-eth.h"

typedef struct port_mem {
	/* information for one of the SDK ports (physical or virtual) */
	struct fpn_port {
		char portname[16];
		char drivername[32];
		char driverargs[1024];
		uint8_t etheraddr[FPN_ETHER_ADDR_LEN];
		uint16_t portid;

		uint32_t linux_ifindex;

		/* parameters initially in dpvi_ctrl_port_status */
		uint16_t speed;      /* [10, 100, 1000, 10000] */
		uint8_t full_duplex; /* 0: half, 1: full */
		uint8_t link;        /* 1: up, 0: down, 0xFF: uninitialized */

		uint64_t ipackets;   /* Total of successfully received packets. */
		uint64_t opackets;   /* Total of successfully transmitted packets. */
		uint64_t ibytes;     /* Total of successfully received bytes. */
		uint64_t obytes;     /* Total of successfully transmitted bytes. */
		uint64_t ierrors;    /* Total of erroneous received packets. */
		uint64_t oerrors;    /* Total of failed transmitted packets. */

		/* flags for physical ports in the portmask, or VLAN ports */
		uint16_t enabled:1;
		uint16_t initialized:1;
		/* flag for all ports: is the port managed by dpvi ? */
		uint16_t dpvi_managed:1;
		/* flag for physical ports: is a VLAN attached ? */
		uint16_t vlan_enabled:1;
		uint16_t reserved:12;

		uint16_t rx_offload_capa; /* Device RX offload capabilities.*/
#define FPN_OFFLOAD_RX_VLAN_STRIP  0x0001
#define FPN_OFFLOAD_RX_IPv4_CKSUM  0x0002
#define FPN_OFFLOAD_RX_UDP_CKSUM   0x0004
#define FPN_OFFLOAD_RX_TCP_CKSUM   0x0008
#define FPN_OFFLOAD_RX_SW_LRO      0x0010
		uint16_t tx_offload_capa; /* Device TX offload capabilities.*/
#define FPN_OFFLOAD_TX_VLAN_INSERT 0x0001
#define FPN_OFFLOAD_TX_IPv4_CKSUM  0x0002
#define FPN_OFFLOAD_TX_TCP_CKSUM   0x0004
#define FPN_OFFLOAD_TX_UDP_CKSUM   0x0008
#define FPN_OFFLOAD_TX_TCP_TSO     0x0010

		/* max size of sw-coalesced TCP packets, or 0 if LRO disabled */
		uint16_t sw_lro;

		/* force segmentation of TCP packets: 1 to enable */
		uint16_t force_tso_at_mtu;

		/*
		 * Driver capabilities :
		 * We need a tristate information for each method
		 * because some sdk suppose that you configured an external
		 * component (using ioctl()'s on a kernel driver).
		 * fpn_sdk_init will populate the shared mem with those
		 * capabilites when it knows what must be done :
		 * SET_*_NOOP -> the fpn-sdk knows that nothing should be done
		 * SET_*_FPN  -> the fpn-sdk knows that it must do something
		 * Neither SET_*_NOOP, nor SET_*_FPN -> ioctl() done out of
		 * fpn-sdk.
		 */
#define FPN_DRIVER_SET_MTU_NOOP     0x0001
#define FPN_DRIVER_SET_MTU_FPN      0x0002
#define FPN_DRIVER_SET_MAC_NOOP     0x0004
#define FPN_DRIVER_SET_MAC_FPN      0x0008
#define FPN_DRIVER_SET_FLAGS_NOOP   0x0010
#define FPN_DRIVER_SET_FLAGS_FPN    0x0020
		uint16_t driver_capa;
#if !defined(CONFIG_MCORE_L2_INFRA)
	} port[FPN_MAX_PORTS];
#else
		/* for VLAN ports */
		uint16_t vlan_id; /* 0 is used for a non-VLAN port */
		uint16_t pcp;     /* for 32-bit alignment */
		uint16_t attached_port_number;
	} port[FPN_ALL_PORTS];
	/* portid for all potential phys_port/vlan combinations */
	uint16_t portid[FPN_MAX_PORTS][FPN_MAX_VLANID];
#endif
} port_mem_t;

/* pointer to the common shared memory space for the port configuration */
#ifdef __FastPath__
FPN_DECLARE_SHARED(port_mem_t *, fpn_port_shmem);
#else
extern port_mem_t *fpn_port_shmem;
#endif

#ifndef __KERNEL__
#include <inttypes.h>
#include "shmem/fpn-shmem.h"

#ifndef __FastPath__
#define fpn_printf printf
#endif

static inline
void *fpn_port_mmap(void)
{
	port_mem_t *addr;

	/* map fpn_port */
	addr = (port_mem_t *) fpn_shmem_mmap("fpn-port-shared", NULL,
					     sizeof(port_mem_t));
#ifdef __FastPath__
	if (addr == NULL) {
		fpn_printf("cannot map fpn_port size=%"PRIu64" (%"PRIu64"M)\n",
			   (uint64_t)sizeof(port_mem_t),
			   (uint64_t)sizeof(port_mem_t) >> 20);
		return NULL;
	}
#endif

	return addr;
}

static inline
void *fpn_port_init(void)
{
	/* Create fpn-port memory. Ignore error, it may already
	 * exist.
	 */
	fpn_shmem_add("fpn-port-shared", sizeof(port_mem_t));

	return fpn_port_mmap();
}
#endif
#endif /* __FPN_PORT_H__ */
