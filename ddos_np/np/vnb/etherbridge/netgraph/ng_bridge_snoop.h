/*
 * Copyright 2004-2013 6WIND S.A.
 */

/*
 * Types and macros for handling bitmaps with one bit per port
 */
#define NPBITS  32
#define NPW     1
typedef struct {
    u_int32_t p_bits[NPW];
} port_set;
#define MAX_PORTS   (NPBITS*NPW)  /* 32 */

#define PORT_SET(n, p)   ((p)->p_bits[(n)/NPBITS] |= (1 << ((n) % NPBITS)))
#define PORT_CLR(n, p)   ((p)->p_bits[(n)/NPBITS] &= ~(1 << ((n) % NPBITS)))
#define PORT_ISSET(n, p) ((p)->p_bits[(n)/NPBITS] & (1 << ((n) % NPBITS)))
#define PORT_ZERO(p)     memset(p, 0, sizeof(*(p)))
#define PORT_OR(r, a, b) \
	do {\
		int _x;\
		for (_x=0 ; _x < NPW ; _x++)\
			(r)->p_bits[_x] = (a)->p_bits[_x] | (b)->p_bits[_x];\
	} while (0)
#define NG_BRIDGE_SNOOP_HOOK "snoop"
/*
 * Structure describing a single group. USed as well for echange
 * between netgraph bridge and snooping daemon, as internally  by each.
 */
struct ng_bridge_group {
	u_char      addr[6];    /* ethernet address */
	u_char      stuff[2];
	port_set    oifs;       /* links where to forward */
};

struct ng_bridge_snoop_msg {
	u_int16_t	nbs_cmd;
		/* Control from daemon to node */
#		define    START_MLD_SNOOPING        0x01
#		define    START_IGMP_SNOOPING       0x02
#		define    STOP_MLD_SNOOPING         0x03
#		define    STOP_IGMP_SNOOPING        0x04
#		define    ADD_L2_GROUP              0x05
#		define    DEL_L2_GROUP              0x06
#		define    DEL_ALL_L2_GROUP          0x07
#		define    SET_MLD_ROUTERS           0x08
#		define    SET_IGMP_ROUTERS          0x09
#		define    GET_NUM_PORTS             0x0a
#		define    SET_SPY_PORTS             0x10

		/* Control from node to daemon */
#		define    RECV_NUM_PORTS            0x11
#		define    RECV_ADDED_PORT_INDEX     0x12
#		define    RECV_REMOVED_PORT_INDEX   0x13

		/* Data from node to daemon */
#		define    RECV_IGMP_MSG             0x81
#		define    RECV_MLD_MSG              0x82
#		define    RECV_PIM4_MSG             0x83
#		define    RECV_PIM6_MSG             0x84
#		define    RECV_IPV6_RA_MSG          0x85

	u_int16_t    nbs_port;
	u_int16_t    nbs_len;	/* Length of data following, if any */
};

/* Keep this in sync with the above structure definition */
#define NG_BRIDGE_SNOOP_MSG_TYPE_INFO	{			\
	  { "nbs_cmd",		&ng_parse_uint16_type, 0	},	\
	  { "nbs_port",		&ng_parse_uint16_type, 0	},	\
	  { "nbs_len",		&ng_parse_uint16_type, 0	},	\
	  { NULL, NULL, 0 }						\
}
#define SNOOP_HDR_LEN  sizeof (struct ng_bridge_snoop_msg)

/* The address range used for mcast4 is 01:00:5E:00:00:00 to 01:00:5E:7F:FF:FF */
#define IS_ETH_MCAST4(x) (((x)[0] == 0x01) && ((x)[1] == 0x00) && ((x)[2] == 0x5e) && (((x)[3] & 0x80) == 0x00))
/* The address range used for mcast6 is 33:33:XX:XX:XX:XX */
#define IS_ETH_MCAST6(x) (((x)[0] == 0x33) && ((x)[1] == 0x33))
