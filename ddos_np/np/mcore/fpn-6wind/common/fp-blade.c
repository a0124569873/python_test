/*
 * Copyight 2007 6WIND, All rights reserved.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "fp.h"
#include "net/fp-ethernet.h"

#ifdef CONFIG_MCORE_MULTIBLADE
/*
 * blade management functions
 */
uint32_t fp_add_blade(uint8_t id, uint8_t flag, const uint8_t mac[6])
{
	fp_blade_t *blade;

	if ((id == 0) || (id > FP_BLADEID_MAX))
		return -1;

	blade = &fp_shared->fp_blades[id];
	blade->blade_active = 1;
	memcpy(blade->blade_mac, mac, sizeof(blade->blade_mac));
	return 0;
}

uint32_t fp_delete_blade(uint8_t id, uint8_t flag)
{
	fp_blade_t *blade;

	if ((id == 0) || (id > FP_BLADEID_MAX))
		return -1;

	blade = &fp_shared->fp_blades[id];
	blade->blade_active = 0;
	return 0;
}
#endif /* CONFIG_MCORE_MULTIBLADE */

uint32_t fp_set_blade_id(uint8_t id, __fpn_maybe_unused uint8_t cp_id)
{
	if ((id == 0) || (id > FP_BLADEID_MAX))
		return -1;
#ifdef CONFIG_MCORE_1CP_XFP
	if ((cp_id == 0) || (cp_id > FP_BLADEID_MAX))
		return -1;
#endif

	fp_shared->fp_blade_id = id;
#ifdef CONFIG_MCORE_1CP_XFP
	fp_shared->cp_blade_id = cp_id;
#endif

	return 0;
}

uint32_t fp_set_active_cpid(uint8_t id)
{
	if ((id == 0) || (id > FP_BLADEID_MAX))
		return -1;

	fp_shared->active_cpid = id;

	return 0;
}

/*
 * Set control plane contact information
 * if_port == IF_PORT_COLOC means that CP is co-localized
 * otherwise, CP can be contacted through the specified port
 * and mac address
 */
uint32_t fp_set_cp_info(uint8_t if_port, const uint8_t portmac[6],
		uint32_t mtu, int auto_thresh)
{
	fp_shared->cp_if_port = if_port;
	fp_shared->cp_if_mtu = mtu;
	if (auto_thresh)
		fp_shared->cp_if_fptun_size_thresh = mtu;
	memcpy(fp_shared->cp_if_mac, portmac, 6);

	return 0;
}

#ifdef CONFIG_MCORE_MULTIBLADE
uint32_t fp_set_fpib_ifuid(uint32_t ifuid, int auto_thresh)
{
	fp_shared->fpib_ifuid = ifuid;
	if (auto_thresh) {
		if (fp_shared->fpib_ifuid) {
			fp_ifnet_t *ifp;

			if ((ifp = fp_ifuid2ifnet(ifuid)) == NULL)
				return -1;
			fp_shared->fpib_fptun_size_thresh = ifp->if_mtu;
		} else
			fp_shared->fpib_fptun_size_thresh = 0;
	}

	return 0;
}
#endif
