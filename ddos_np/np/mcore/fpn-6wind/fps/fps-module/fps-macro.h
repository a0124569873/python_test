/*
 * Copyright 2012 6WIND, All rights reserved.
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

/* 6WIND_GPL */

#ifndef __FPS_MACRO_H__
#define __FPS_MACRO_H__

#include <net/netns/mib.h>

/*
 * Debugging Macro
 */
#if 0
#define FPS_DEBUG 1
#endif

#ifdef FPS_DEBUG
#define FPS_TRACE(fmt, args...) do { \
		printk(KERN_DEBUG "%s: " fmt "\n", __FUNCTION__, ## args); \
} while (0)
#else
#define FPS_TRACE(x...) (void)0
#endif

/*
 * The set of statistics ADD/COPY macros below have a conversion operation
 * argument to convert into the local CPU byte order statistics counters
 * transmitted in the CPU byte order of the sending remote blade.
 * The conversion operation argument can be "le", "be" or "cpu" with the
 * following semantics, where XX stands for 16, 32 or 64:
 *
 * - "le": little endian to local big endian CPU conversion through the
 *         "__leXX_to_cpu" Linux kernel macros.
 *
 * - "be": big endian to local little endian CPU conversion through the
 *         "(__beXX_to_cpu" Linux kernel macros.
 *
 * - "cpu": no conversion operation through the "__cpuXX_to_cpu" macros below
 *          whose names are compatible with the naming conventions of the
 *          Linux kernel byte ordering macros used above.
 */
#define __cpu16_to_cpu(x) (x)
#define __cpu32_to_cpu(x) (x)
#define __cpu64_to_cpu(x) (x)

/*
 * Macro which converts FP IP statistics counters into the local CPU byte order
 * and copies them to Linux "ip_mib" counters.
 */

/*
 * Note:
 * - IpInReceives: this is total IP packet received, including errors.
 *   To avoid Linux counting packet exception twice, we use IpForwDatagrams,
 *   plus error counters.
 */
#define __CONV_AND_COPY_FP_IP_STATS_TO_IPSTATS_MIB(fp_ips, ips_mib, fp_bo) \
	(ips_mib)->mibs[IPSTATS_MIB_INPKTS] =                              \
		(unsigned long)(__##fp_bo##64_to_cpu((fp_ips)->IpForwDatagrams)) + \
		(unsigned long)(__##fp_bo##32_to_cpu((fp_ips)->IpInHdrErrors))   + \
		(unsigned long)(__##fp_bo##32_to_cpu((fp_ips)->IpInAddrErrors)),   \
	(ips_mib)->mibs[IPSTATS_MIB_INDELIVERS] = (unsigned long)      \
		(__##fp_bo##64_to_cpu((fp_ips)->IpInDelivers)),        \
	(ips_mib)->mibs[IPSTATS_MIB_INHDRERRORS] = (unsigned long)      \
		(__##fp_bo##32_to_cpu((fp_ips)->IpInHdrErrors)),        \
	(ips_mib)->mibs[IPSTATS_MIB_INADDRERRORS] = (unsigned long)     \
		(__##fp_bo##32_to_cpu((fp_ips)->IpInAddrErrors)),       \
	(ips_mib)->mibs[IPSTATS_MIB_OUTFORWDATAGRAMS] = (unsigned long) \
		(__##fp_bo##64_to_cpu((fp_ips)->IpForwDatagrams)),      \
	(ips_mib)->mibs[IPSTATS_MIB_OUTPKTS] = (unsigned long)      \
		(__##fp_bo##64_to_cpu((fp_ips)->IpForwDatagrams)),      \
	(ips_mib)->mibs[IPSTATS_MIB_REASMTIMEOUT] = (unsigned long)     \
		(__##fp_bo##32_to_cpu((fp_ips)->IpReasmTimeout)),       \
	(ips_mib)->mibs[IPSTATS_MIB_REASMREQDS] = (unsigned long)       \
		(__##fp_bo##64_to_cpu((fp_ips)->IpReasmReqds)),         \
	(ips_mib)->mibs[IPSTATS_MIB_REASMOKS] = (unsigned long)         \
		(__##fp_bo##64_to_cpu((fp_ips)->IpReasmOKs)),	        \
	(ips_mib)->mibs[IPSTATS_MIB_REASMFAILS] = (unsigned long)       \
		(__##fp_bo##64_to_cpu((fp_ips)->IpReasmFails)),	        \
	(ips_mib)->mibs[IPSTATS_MIB_FRAGOKS] = (unsigned long)          \
		(__##fp_bo##64_to_cpu((fp_ips)->IpFragOKs)),	        \
	(ips_mib)->mibs[IPSTATS_MIB_FRAGFAILS] = (unsigned long)        \
		(__##fp_bo##64_to_cpu((fp_ips)->IpFragFails)),	        \
	(ips_mib)->mibs[IPSTATS_MIB_FRAGCREATES] = (unsigned long)      \
		(__##fp_bo##64_to_cpu((fp_ips)->IpFragCreates))

#define COPY_FP_IP_STATS_TO_IPSTATS_MIB(fp_ips, ips_mib) \
	__CONV_AND_COPY_FP_IP_STATS_TO_IPSTATS_MIB(fp_ips, ips_mib, cpu)

#define COPY_LE_FP_IP_STATS_TO_IPSTATS_MIB(fp_ips, ips_mib) \
	__CONV_AND_COPY_FP_IP_STATS_TO_IPSTATS_MIB(fp_ips, ips_mib, le)

#define COPY_BE_FP_IP_STATS_TO_IPSTATS_MIB(fp_ips, ips_mib) \
	__CONV_AND_COPY_FP_IP_STATS_TO_IPSTATS_MIB(fp_ips, ips_mib, be)

#define CONV_AND_ADD_FP_IP_STATS_TO_IPSTATS_MIB(fp_ips, ips_mib, fp_bo) \
	(ips_mib)->mibs[IPSTATS_MIB_INPKTS] += (unsigned long)       \
		(unsigned long)(__##fp_bo##64_to_cpu((fp_ips)->IpForwDatagrams)) + \
		(unsigned long)(__##fp_bo##32_to_cpu((fp_ips)->IpInHdrErrors))   + \
		(unsigned long)(__##fp_bo##32_to_cpu((fp_ips)->IpInAddrErrors)),   \
	(ips_mib)->mibs[IPSTATS_MIB_INDELIVERS] += (unsigned long)      \
		(__##fp_bo##64_to_cpu((fp_ips)->IpInDelivers)),        \
	(ips_mib)->mibs[IPSTATS_MIB_INHDRERRORS] += (unsigned long)      \
		(__##fp_bo##32_to_cpu((fp_ips)->IpInHdrErrors)),        \
	(ips_mib)->mibs[IPSTATS_MIB_INADDRERRORS] += (unsigned long)     \
		(__##fp_bo##32_to_cpu((fp_ips)->IpInAddrErrors)),       \
	(ips_mib)->mibs[IPSTATS_MIB_OUTFORWDATAGRAMS] += (unsigned long) \
		(__##fp_bo##64_to_cpu((fp_ips)->IpForwDatagrams)),      \
	(ips_mib)->mibs[IPSTATS_MIB_OUTPKTS] += (unsigned long)      \
		(__##fp_bo##64_to_cpu((fp_ips)->IpForwDatagrams)),      \
	(ips_mib)->mibs[IPSTATS_MIB_REASMTIMEOUT] += (unsigned long)     \
		(__##fp_bo##32_to_cpu((fp_ips)->IpReasmTimeout)),       \
	(ips_mib)->mibs[IPSTATS_MIB_REASMREQDS] += (unsigned long)       \
		(__##fp_bo##64_to_cpu((fp_ips)->IpReasmReqds)),         \
	(ips_mib)->mibs[IPSTATS_MIB_REASMOKS] += (unsigned long)         \
		(__##fp_bo##64_to_cpu((fp_ips)->IpReasmOKs)),	        \
	(ips_mib)->mibs[IPSTATS_MIB_REASMFAILS] += (unsigned long)       \
		(__##fp_bo##64_to_cpu((fp_ips)->IpReasmFails)),	        \
	(ips_mib)->mibs[IPSTATS_MIB_FRAGOKS] += (unsigned long)          \
		(__##fp_bo##64_to_cpu((fp_ips)->IpFragOKs)),	        \
	(ips_mib)->mibs[IPSTATS_MIB_FRAGFAILS] += (unsigned long)        \
		(__##fp_bo##64_to_cpu((fp_ips)->IpFragFails)),	        \
	(ips_mib)->mibs[IPSTATS_MIB_FRAGCREATES] += (unsigned long)      \
		(__##fp_bo##64_to_cpu((fp_ips)->IpFragCreates))

#define ADD_FP_IP_STATS_TO_IPSTATS_MIB(fp_ips, ips_mib) \
	CONV_AND_ADD_FP_IP_STATS_TO_IPSTATS_MIB(fp_ips, ips_mib, cpu)

#define ADD_LE_FP_IP_STATS_TO_IPSTATS_MIB(fp_ips, ips_mib) \
	CONV_AND_ADD_FP_IP_STATS_TO_IPSTATS_MIB(fp_ips, ips_mib, le)

#define ADD_BE_FP_IP_STATS_TO_IPSTATS_MIB(fp_ips, ip_mib) \
	CONV_AND_ADD_FP_IP_STATS_TO_IPSTATS_MIB(fp_ips, ips_mib, be)

/*
 * Macro which converts FP IFNET statistics counters into the local CPU
 * byte order and adds them to Linux "net_device_stats" counters.
 */
#define CONV_AND_ADD_FP_IF_STATS_TO_NET_DEV_STATS(fp_ifs, nds, fp_bo) \
	(nds)->rx_packets      += (unsigned long)		\
		(__##fp_bo##64_to_cpu((fp_ifs)->ifs_ipackets)), \
	(nds)->tx_packets      += (unsigned long)	        \
		(__##fp_bo##64_to_cpu((fp_ifs)->ifs_opackets)), \
	(nds)->rx_bytes        += (unsigned long)	        \
		(__##fp_bo##64_to_cpu((fp_ifs)->ifs_ibytes)),	\
	(nds)->tx_bytes        += (unsigned long)	        \
		(__##fp_bo##64_to_cpu((fp_ifs)->ifs_obytes)),	\
	(nds)->multicast       += (unsigned long)	        \
		(__##fp_bo##32_to_cpu((fp_ifs)->ifs_imcasts)),	\
	(nds)->rx_crc_errors   += (unsigned long)	        \
		(__##fp_bo##32_to_cpu((fp_ifs)->ifs_ierrors)),	\
	(nds)->rx_frame_errors += (unsigned long)	        \
		(__##fp_bo##32_to_cpu((fp_ifs)->ifs_oerrors)),  \
	(nds)->rx_dropped      += (unsigned long)               \
		(__##fp_bo##32_to_cpu((fp_ifs)->ifs_idropped)), \
	(nds)->tx_dropped        += (unsigned long)             \
		(__##fp_bo##32_to_cpu((fp_ifs)->ifs_odropped)), \
	(nds)->rx_fifo_errors       += (unsigned long)          \
		(__##fp_bo##32_to_cpu((fp_ifs)->ifs_ififoerrors)), \
	(nds)->tx_fifo_errors     += (unsigned long)            \
		(__##fp_bo##32_to_cpu((fp_ifs)->ifs_ofifoerrors))

#define ADD_FP_IF_STATS_TO_NET_DEV_STATS(fp_ifs, nds) \
	CONV_AND_ADD_FP_IF_STATS_TO_NET_DEV_STATS(fp_ifs, nds, cpu)

#define ADD_LE_FP_IF_STATS_TO_NET_DEV_STATS(fp_ifs, nds) \
	CONV_AND_ADD_FP_IF_STATS_TO_NET_DEV_STATS(fp_ifs, nds, le)

#define ADD_BE_FP_IF_STATS_TO_NET_DEV_STATS(fp_ifs, nds) \
	CONV_AND_ADD_FP_IF_STATS_TO_NET_DEV_STATS(fp_ifs, nds, be)

#define __CONV_AND_COPY_FP_IF_STATS_TO_NET_DEV_STATS(fp_ifs, nds, fp_bo) \
	(nds)->rx_packets      = (unsigned long)		\
		(__##fp_bo##64_to_cpu((fp_ifs)->ifs_ipackets)), \
	(nds)->tx_packets      = (unsigned long)	        \
		(__##fp_bo##64_to_cpu((fp_ifs)->ifs_opackets)), \
	(nds)->rx_bytes        = (unsigned long)	        \
		(__##fp_bo##64_to_cpu((fp_ifs)->ifs_ibytes)),	\
	(nds)->tx_bytes        = (unsigned long)	        \
		(__##fp_bo##64_to_cpu((fp_ifs)->ifs_obytes)),	\
	(nds)->multicast       = (unsigned long)	        \
		(__##fp_bo##32_to_cpu((fp_ifs)->ifs_imcasts)),	\
	(nds)->rx_errors       = (unsigned long)	        \
		(__##fp_bo##32_to_cpu((fp_ifs)->ifs_ierrors)),  \
	(nds)->tx_errors       = (unsigned long)	        \
		(__##fp_bo##32_to_cpu((fp_ifs)->ifs_oerrors)),	\
	(nds)->rx_dropped      = (unsigned long)               \
		(__##fp_bo##32_to_cpu((fp_ifs)->ifs_idropped)), \
	(nds)->tx_dropped        = (unsigned long)             \
		(__##fp_bo##32_to_cpu((fp_ifs)->ifs_odropped)), \
	(nds)->rx_fifo_errors       = (unsigned long)          \
		(__##fp_bo##32_to_cpu((fp_ifs)->ifs_ififoerrors)), \
	(nds)->tx_fifo_errors     = (unsigned long)            \
		(__##fp_bo##32_to_cpu((fp_ifs)->ifs_ofifoerrors))

#define COPY_FP_IF_STATS_TO_NET_DEV_STATS(fp_ifs, nds) \
	__CONV_AND_COPY_FP_IF_STATS_TO_NET_DEV_STATS(fp_ifs, nds, cpu)

#define COPY_LE_FP_IF_STATS_TO_NET_DEV_STATS(fp_ifs, nds) \
	__CONV_AND_COPY_FP_IF_STATS_TO_NET_DEV_STATS(fp_ifs, nds, le)

#define COPY_BE_FP_IF_STATS_TO_NET_DEV_STATS(fp_ifs, nds) \
	__CONV_AND_COPY_FP_IF_STATS_TO_NET_DEV_STATS(fp_ifs, nds, be)

/*
 * Macro which copy [a subset of] Linux "net_device_stats" counters
 * into FP IFNET statistics counters.
 */
#define	COPY_NET_DEVICE_STATS_TO_FP_IF_STATS(nds, fp_ifs) \
	(fp_ifs)->ifs_ipackets = (uint64_t) ((nds)->rx_packets),\
	(fp_ifs)->ifs_opackets = (uint64_t) ((nds)->tx_packets),\
	(fp_ifs)->ifs_ibytes   = (uint64_t) ((nds)->rx_bytes),	\
	(fp_ifs)->ifs_obytes   = (uint64_t) ((nds)->tx_bytes),	\
	(fp_ifs)->ifs_imcasts  = (uint32_t) ((nds)->multicast),	\
	(fp_ifs)->ifs_ierrors  = (uint32_t) ((nds)->rx_crc_errors),\
	(fp_ifs)->ifs_oerrors  = (uint32_t) ((nds)->rx_frame_errors),\
	(fp_ifs)->ifs_idropped = (uint32_t) ((nds)->rx_dropped),\
	(fp_ifs)->ifs_odropped = (uint32_t) ((nds)->tx_dropped),\
	(fp_ifs)->ifs_ififoerrors = (uint32_t) ((nds)->rx_fifo_errors), \
	(fp_ifs)->ifs_ofifoerrors = (uint32_t) ((nds)->tx_fifo_errors)

/*
 * Macro which converts FP IPsec SA statistics counters into the local CPU
 * byte order and stores them.
 */
#define CONV_AND_COPY_FP_SA_STATS_TO_FPS_SA_STATS(fp_sas, fps_sas, fp_bo) \
	(fps_sas)->stats.integrity_failed =				  \
		(__##fp_bo##64_to_cpu((fp_sas)->sa_auth_errors)) +        \
		(__##fp_bo##64_to_cpu((fp_sas)->sa_decrypt_errors)),      \
	(fps_sas)->curlft.bytes   = __##fp_bo##64_to_cpu((fp_sas)->sa_bytes), \
	(fps_sas)->curlft.packets = __##fp_bo##64_to_cpu((fp_sas)->sa_packets)

#define COPY_FP_SA_STATS_TO_FPS_SA_STATS(fp_sas, fps_sas) \
	CONV_AND_COPY_FP_SA_STATS_TO_FPS_SA_STATS(fp_sas, fps_sas, cpu)

#define COPY_LE_FP_SA_STATS_TO_FPS_SA_STATS(fp_sas, fps_sas) \
	CONV_AND_COPY_FP_SA_STATS_TO_FPS_SA_STATS(fp_sas, fps_sas, le)

#define COPY_BE_FP_SA_STATS_TO_FPS_SA_STATS(fp_sas, fps_sas) \
	CONV_AND_COPY_FP_SA_STATS_TO_FPS_SA_STATS(fp_sas, fps_sas, be)

#define CONV_AND_ADD_FP_SA_STATS_TO_FPS_SA_STATS(fp_sas, fps_sas, fp_bo) \
	(fps_sas)->stats.integrity_failed +=				  \
		(__##fp_bo##64_to_cpu((fp_sas)->sa_auth_errors)) +        \
		(__##fp_bo##64_to_cpu((fp_sas)->sa_decrypt_errors)),      \
	(fps_sas)->curlft.bytes   += __##fp_bo##64_to_cpu((fp_sas)->sa_bytes), \
	(fps_sas)->curlft.packets += __##fp_bo##64_to_cpu((fp_sas)->sa_packets)

#define ADD_FP_SA_STATS_TO_FPS_SA_STATS(fp_sas, fps_sas) \
	CONV_AND_ADD_FP_SA_STATS_TO_FPS_SA_STATS(fp_sas, fps_sas, cpu)

#define ADD_LE_FP_SA_STATS_TO_FPS_SA_STATS(fp_sas, fps_sas) \
	CONV_AND_ADD_FP_SA_STATS_TO_FPS_SA_STATS(fp_sas, fps_sas, le)

#define ADD_BE_FP_SA_STATS_TO_FPS_SA_STATS(fp_sas, fps_sas) \
	CONV_AND_ADD_FP_SA_STATS_TO_FPS_SA_STATS(fp_sas, fps_sas, be)
/*
 * Macro which converts FP IPsec SP statistics counters into the local CPU
 * byte order and stores them.
 */
#define CONV_AND_COPY_FP_SP_STATS_TO_FPS_SP_STATS(fp_sps, fps_sps, fp_bo) \
	(fps_sps)->curlft.bytes   = __##fp_bo##64_to_cpu((fp_sps)->sp_bytes), \
	(fps_sps)->curlft.packets = __##fp_bo##64_to_cpu((fp_sps)->sp_packets)

#define COPY_FP_SP_STATS_TO_FPS_SP_STATS(fp_sps, fps_sps) \
	CONV_AND_COPY_FP_SP_STATS_TO_FPS_SP_STATS(fp_sps, fps_sps, cpu)

#define COPY_LE_FP_SP_STATS_TO_FPS_SP_STATS(fp_sps, fps_sps) \
	CONV_AND_COPY_FP_SP_STATS_TO_FPS_SP_STATS(fp_sps, fps_sps, le)

#define COPY_BE_FP_SP_STATS_TO_FPS_SP_STATS(fp_sps, fps_sps) \
	CONV_AND_COPY_FP_SP_STATS_TO_FPS_SP_STATS(fp_sps, fps_sps, be)

#define CONV_AND_ADD_FP_SP_STATS_TO_FPS_SP_STATS(fp_sps, fps_sps, fp_bo) \
	(fps_sps)->curlft.bytes   += __##fp_bo##64_to_cpu((fp_sps)->sp_bytes), \
	(fps_sps)->curlft.packets += __##fp_bo##64_to_cpu((fp_sps)->sp_packets)

#define ADD_FP_SP_STATS_TO_FPS_SP_STATS(fp_sps, fps_sps) \
	CONV_AND_ADD_FP_SP_STATS_TO_FPS_SP_STATS(fp_sps, fps_sps, cpu)

#define ADD_LE_FP_SP_STATS_TO_FPS_SP_STATS(fp_sps, fps_sps) \
	CONV_AND_ADD_FP_SP_STATS_TO_FPS_SP_STATS(fp_sps, fps_sps, le)

#define ADD_BE_FP_SP_STATS_TO_FPS_SP_STATS(fp_sps, fps_sps) \
	CONV_AND_ADD_FP_SP_STATS_TO_FPS_SP_STATS(fp_sps, fps_sps, be)

#if !defined(USE_VRF_NETNS)
#define fps_vrfid_to_net(v) (&init_net)
#else
struct net *vrf_lookup_by_vrfid(__u32 vrfid);
#define fps_vrfid_to_net(v) vrf_lookup_by_vrfid(v);
#endif

#endif
