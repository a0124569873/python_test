/*
 * Copyright (C) 2010 6WIND, All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * DPVI module: Dataplane Proxy Virtual Interface
 *
 * Goal
 * ----
 *
 * When running the Fastpath above the DPDK or Tilera MDE, the linux
 * kernel does not sees the IGB interfaces, because the linux driver is
 * unloaded. This module provides virtual interfaces that work as a proxy to the
 * driver implemented in fastpath.
 *
 * Communication between kernel and fastpath occurs through the fpn0
 * interface. Control and data packets are encapsulated into a DPVI
 * header (see dpvi.h), whose ethertype is ETH_P_DPVI.
 *
 * At loading, the module asks the fastpath the list of ports seen by
 * the fastpath. For each port, a virtual interface is created in
 * linux. All data send to this virtual interface will be sent to FP
 * and transmitted on the real interface. Exceptions coming from the
 * fastpath are received through these virtual interfaces. Also, some
 * control operations are "profyfied" to the fastpath like setting
 * promiscuous mode, getting statistics or link status, setting mac
 * address, and so on.
 *
 * The list of virtual interfaces is available through
 * /proc/sys/dpvi/list_interfaces with its associated port id.
 *
 * The DPVI protocol
 * -----------------
 *
 * The protocol is splitted in several types:
 *
 * - DPVI_TYPE_CTRL_REQ: control request (linux -> FP)
 * - DPVI_TYPE_CTRL_ANS: control answer to a previous request (FP -> linux)
 * - DPVI_TYPE_CTRL_INFO: control status information (FP -> linux)
 * - DPVI_TYPE_DATA_FP2LINUX: data (FP -> linux)
 * - DPVI_TYPE_DATA_LINUX2FP: data (linux -> FP)
 *
 * Request/answer example
 * ~~~~~~~~~~~~~~~~~~~~~~
 *
 * User sets the mac address of a DPVI interface (through a
 * syscall). The dpvi_set_address() is called. It will create a packet
 * containing a dpvi_hdr and a dpvi_ctrl_mac structure. This packet is
 * sent through fpdev, and is received by the fastpath. The FP will
 * ask the driver to change the mac address. During this time, linux
 * is sleeping, waiting for the answer. We can do this because we are
 * called from a process context. The fastpath can answer the same
 * packet on success, or change the cmd field in dpvi_hdr to
 * DPVI_CMD_ERROR on error. The answer packet contains the same req-id
 * than the request, so it can be recognized easily by the
 * caller. Depending on the answer from FP, the dpvi module will
 * update the mac address or not.
 *
 * Atomic Request example (no answer)
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * Some request don't need answer. For instance, when the link goes up
 * on an ethernet interface, the kernel will add the interface to
 * multicast groups. This operation can be done from an atomic
 * context, so we cannot wait/sleep for the FP answer here. Also, we
 * cannot transmit a packet an fpdev from this context. In
 * dpvi_set_rxmode(), we prepare a packet that is queued in
 * ctrl_rxmode_queue. A work is scheduled and this queue will be
 * emptied in dpvi_set_rxmode_task() from a process context. No answer
 * is expected.
 *
 * Control info or data from FP
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * Packet with ethertype = ETH_P_DPVI are sent by FP and received in
 * dpvi_rcv() by linux. The message can contain status info (link,
 * stats), or a data packet (local exception).
 *
 * Data from linux to FP
 * ~~~~~~~~~~~~~~~~~~~~~
 *
 * Linux is allowed to send data to DPVI interfaces. The data is
 * encapsulated in a DPVI header in dpvi_xmit(), then sent on fpdev.
 *
 */

#ifndef _DPVI_H_
#define _DPVI_H_

#define ETH_P_DPVI 0x2008

#define DPVI_TYPE_CTRL_REQ      0
#define DPVI_TYPE_CTRL_ANS      1
#define DPVI_TYPE_CTRL_INFO     2
#define DPVI_TYPE_DATA_FP2LINUX 3
#define DPVI_TYPE_DATA_LINUX2FP 4

#define DPVI_CMD_ERROR       0
#define DPVI_CMD_PORTLIST    4
#define DPVI_CMD_PORT_STATUS 5
#define DPVI_CMD_ETHTOOL_GET_DRVINFO 6
#define DPVI_CMD_ETHTOOL_GET_SETTINGS    7
#define DPVI_CMD_ETHTOOL_GET_SSET_COUNT  8
#define DPVI_CMD_ETHTOOL_GET_STRINGS     9
#define DPVI_CMD_ETHTOOL_GET_STATSINFO  10
#define DPVI_CMD_ETHTOOL_GET_PAUSEPARAM 11
#define DPVI_CMD_ETHTOOL_SET_PAUSEPARAM 12

/* max number of managed ports: less than the max value in uint8_t */
#if defined(CONFIG_MCORE_L2_INFRA)
#define DPVI_MAX_PORTS FPN_ALL_PORTS
#else
#define DPVI_MAX_PORTS FPN_MAX_PORTS
#endif


/*
 * The DPVI header, used between FP and linux communications
 */
struct dpvi_hdr {
	uint8_t  type;
	uint8_t  cmd;
	uint16_t portid;
	uint8_t  reqid;

	/* keep it aligned: we want sizeof(ether) + sizeof(dpvi) to be aligned
	 * on 32 bits */
	uint8_t  reserved1;
};
#define DPVI_HLEN sizeof(struct dpvi_hdr)

/* Structure used when dpvi_hdr->cmd = DPVI_CMD_ETHTOOL_GET_DRVINFO  */
struct dpvi_ethtool_drvinfo {
	char driver[32];
	char bus_info[32];
} __attribute__((packed));

/* Structure used when dpvi_hdr->cmd = DPVI_CMD_ETHTOOL_GET_SETTINGS  */
struct dpvi_ethtool_gsettings {

#define DPVI_ETHTOOL_LINK_SPEED_10    10    /**< 10 megabits/second. */
#define DPVI_ETHTOOL_LINK_SPEED_100   100   /**< 100 megabits/second. */
#define DPVI_ETHTOOL_LINK_SPEED_1000  1000  /**< 1 gigabits/second. */
#define DPVI_ETHTOOL_LINK_SPEED_10000 10000 /**< 10 gigabits/second. */
#define DPVI_ETHTOOL_LINK_SPEED_40000 40000 /**< 10 gigabits/second. */
	uint16_t speed;      /**< ETH_LINK_SPEED_[10, 100, 1000, 10000] */

#define DPVI_ETHTOOL_LINK_HALF_DUPLEX 1     /**< Half-duplex connection. */
#define DPVI_ETHTOOL_LINK_FULL_DUPLEX 2     /**< Full-duplex connection. */
	uint16_t duplex;     /**< ETH_LINK_[HALF_DUPLEX, FULL_DUPLEX] */

#define DPVI_ETHTOOL_SUPPORTED_10baseT_Half      (1 << 0)
#define DPVI_ETHTOOL_SUPPORTED_10baseT_Full      (1 << 1)
#define DPVI_ETHTOOL_SUPPORTED_100baseT_Half     (1 << 2)
#define DPVI_ETHTOOL_SUPPORTED_100baseT_Full     (1 << 3)
#define DPVI_ETHTOOL_SUPPORTED_1000baseT_Full    (1 << 5)
#define DPVI_ETHTOOL_SUPPORTED_Autoneg           (1 << 6)
#define DPVI_ETHTOOL_SUPPORTED_TP                (1 << 7)
#define DPVI_ETHTOOL_SUPPORTED_FIBRE             (1 << 10)
#define DPVI_ETHTOOL_SUPPORTED_10000baseT_Full   (1 << 12)
#define DPVI_ETHTOOL_SUPPORTED_40000baseT_Full   (1 << 21)
	uint32_t supported;

#define DPVI_ETHTOOL_AUTONEG_DISABLE      0x00
#define DPVI_ETHTOOL_AUTONEG_ENABLE       0x01
	uint32_t autoneg;

#define DPVI_ETHTOOL_ADVERTISED_1000baseT_Full   (1 << 5)
#define DPVI_ETHTOOL_ADVERTISED_Autoneg          (1 << 6)
#define DPVI_ETHTOOL_ADVERTISED_TP               (1 << 7)
#define DPVI_ETHTOOL_ADVERTISED_FIBRE            (1 << 10)
#define DPVI_ETHTOOL_ADVERTISED_10000baseT_Full  (1 << 12)
#define DPVI_ETHTOOL_ADVERTISED_40000baseT_Full  (1 << 21)
	uint32_t autoneg_advertised; /* speeds advertised by autonegocation. */

#define DPVI_ETHTOOL_XCVR_INTERNAL        0x00
#define DPVI_ETHTOOL_XCVR_EXTERNAL        0x01
	uint8_t  transceiver;
	uint8_t  status;     /**< 1 -> link up, 0 -> link down */
	uint8_t  phy_addr;

#define DPVI_ETHTOOL_PORT_TP              0x00
#define DPVI_ETHTOOL_PORT_FIBRE           0x03
#define DPVI_ETHTOOL_PORT_DA              0x05
#define DPVI_ETHTOOL_PORT_NONE            0xef
#define DPVI_ETHTOOL_PORT_OTHER           0xff
	uint8_t  port;

} __attribute__((packed));

#define DPVI_ETHTOOL_SS_STATS	1

/* Structure used when dpvi_hdr->cmd = DPVI_CMD_ETHTOOL_GET_SSET_COUNT  */
struct dpvi_ethtool_sset_count {
	uint32_t string_sets;   /* string set id e.c. ETH_SS_TEST, etc */
	uint32_t val;           /* string set count */
} __attribute__((packed));

#define DPVI_ETHTOOL_GSTRING_LEN	32

/* Structure used when dpvi_hdr->cmd = DPVI_CMD_ETHTOOL_GET_STRINGS */
struct dpvi_ethtool_gstrings {
	uint32_t  string_sets;   /* string set id e.c. ETH_SS_TEST, etc */
	uint32_t  len;           /* number of strings in the string set */
	uint16_t  size_to_copy;  /* the size of strings that copied each time */
	uint16_t  offset_to_copy;/* the offset when copy the strings */
	uint8_t   data[0];
} __attribute__((packed));

/* Structure used when dpvi_hdr->cmd = DPVI_CMD_ETHTOOL_GET_STATSINFO  */
struct dpvi_ethtool_statsinfo {
	uint32_t  n_stats;       /* number of different statistics to display */
	uint64_t  data[0];
} __attribute__((packed));

/* Structure used when dpvi_hdr->cmd = DPVI_CMD_ETHTOOL_GET_PAUSEPARAM
 * or dpvi_hdr->cmd = DPVI_CMD_ETHTOOL_SET_PAUSEPARAM */
struct dpvi_ethtool_pauseparam {
	uint32_t  autoneg;
	uint32_t  rx_pause;
	uint32_t  tx_pause;
} __attribute__((packed));

/* Structure passed as argument to dpvi ioctl calls */
struct dpvi_ioctl_arg {
	int dpvi_cpu;
	int efd;
};

#define DPVI_IOCTL _IOW('=', 1, struct dpvi_ioctl_arg)

#endif
