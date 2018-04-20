/*
 * Copyright(c) 2011  6WIND
 */

struct fpn_dpvi_ops {

	/* int fpn_dpvi_ethtool_get_drvinfo(int portid, struct dpvi_ethtool_drvinfo *)
	 *
	 * fills dpvi_ethtool_drvinfo with driver name
	 * Return 0 on success or -1 on error
	 */
	int (*ethtool_get_drvinfo)(int, struct dpvi_ethtool_drvinfo *);

	/* int fpn_dpvi_ethtool_get_settings(int portid, struct dpvi_ethtool_gsettings *)
	 *
	 * fills dpvi_ethtool_gsettings with network interface link information
	 * Return 0 on success or -1 on error
	 */
	int (*ethtool_get_settings)(int, struct dpvi_ethtool_gsettings *);

	/* int fpn_dpvi_ethtool_get_sset_count(int portid, struct dpvi_ethtool_sset_count *)
	 *
	 * fills dpvi_ethtool_sset_count with number of statistics to display
	 * Return 0 on success or -1 on error
	 */
	int (*ethtool_get_sset_count)(int, struct dpvi_ethtool_sset_count *);

	/* int fpn_dpvi_ethtool_get_strings(int portid, struct dpvi_ethtool_gstrings *)
	 *
	 * fills dpvi_ethtool_gstrings with strings to display with statistics
	 * Return 0 on success or -1 on error
	 */
	int (*ethtool_get_strings)(int, struct dpvi_ethtool_gstrings *);

	/* int fpn_dpvi_ethtool_get_statsinfo(int portid, struct dpvi_ethtool_stastinfo *)
	 *
	 * fills dpvi_ethtool_statsinfo with statistics from driver
	 * Return 0 on success or -1 on error
	 */
	int (*ethtool_get_statsinfo)(int, struct dpvi_ethtool_statsinfo *);

	/* int fpn_dpvi_ethtool_get_pauseparam(int portid, struct dpvi_ethtool_pauseparam *)
	 *
	 * fills dpvi_ethtool_pauseparam with pause parameter from driver
	 * Return 0 on success or -1 on error
	 */
	int (*ethtool_get_pauseparam)(int, struct dpvi_ethtool_pauseparam *);

	/* int fpn_dpvi_ethtool_set_pauseparam(int portid, struct dpvi_ethtool_pauseparam *)
	 *
	 * set pause parameter of a given port
	 * Return 0 on success or -1 on error
	 */
	int (*ethtool_set_pauseparam)(int, struct dpvi_ethtool_pauseparam *);
};

/*
 * Must be called to notify linux of status changes. Return 0
 * on success (packet is sent properly), or -1 on error.
 */
int fpn_dpvi_send_status(void);

/*
 * Receive an ethernet packet that can be dpvi. If it is not a dpvi packet,
 * return -1, so it can continue its way in the stack. Else, process packet and
 * return 0 (packet will be freed).
 */
int fpn_dpvi_recv(struct mbuf *m);

/*
 * Prepend DPVI headers to the packet before sending it to a
 * co-localized control plane. Typically, this function is called by the
 * arch-specific fpn_send_exception(). Return 0 on success, or a
 * negative value on error (in this case, packet is freed).
 */
int fpn_dpvi_prepend(struct mbuf **m, uint16_t port);

/*
 * Register DPVI operations, must be called once at initialization.
 */
int fpn_dpvi_register(struct fpn_dpvi_ops *dpvi_ops);
