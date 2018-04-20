/*
 * Copyright 2007-2013 6WIND S.A.
 */

struct iface;

#define MAX_OSI_LEN 20
struct osi_addr {
	u_int8_t  osi_len;
	u_int8_t  osi_val [MAX_OSI_LEN];
} __attribute__((packed));

#define MAX_MAC_LEN 6
struct mac_addr {
	u_int8_t  mac_len;
	u_int8_t  mac_val [MAX_MAC_LEN];
};


/* ES Announce entry */
struct an_entry {
	LIST_ENTRY(an_entry)  an_link;      /* AN entry linkage               */
	struct osi_addr       an_osi;
	u_int32_t             an_refcount;
};

/* ES entry */
struct es_entry {
	LIST_ENTRY(es_entry)  es_link;      /* ES entry linkage               */
	time_t                es_date;      /* Creation date                  */
	u_int32_t             es_hold;      /* Hold Time                      */
	struct event          es_evt;       /* Timer                          */
	struct iface         *es_ifp;       /* Associated iface               */
	struct osi_addr       es_osi;
	struct mac_addr       es_mac;
};

/* IS Entry */
struct is_entry {
	LIST_ENTRY(is_entry)  is_link;      /* RS entry linkage               */
	time_t                is_date;      /* Creation date                  */
	u_int32_t             is_hold;      /* Hold Time                      */
	struct event          is_evt;       /* Timer                          */
	struct iface         *is_ifp;       /* Associated iface               */
	struct osi_addr       is_osi;
	struct mac_addr       is_mac;
};

/* Redirect entry */
struct rd_entry {
	LIST_ENTRY(rd_entry)  rd_link;      /* RD entry linkage               */
	time_t                rd_date;      /* Creation date                  */
	u_int32_t             rd_hold;      /* Hold Time                      */
	struct event          rd_evt;       /* Timer                          */
	struct iface         *rd_ifp;       /* Associated iface               */
	struct osi_addr       rd_es_osi;
	struct osi_addr       rd_is_osi;
	struct mac_addr       rd_is_mac;
};

#define MAX_PING 4
#define PING_INTERVAL_SEC   0
#define PING_INTERVAL_USEC  250000
#define OSI_PING_DATA  32
#define OSI_PING_SIZE  128
struct ping_entry {
	u_int8_t          pe_packet   [MAX_PING] [OSI_PING_SIZE] ;
	u_int8_t          pe_received [MAX_PING];
	struct osi_addr   pe_dst;
	struct osi_addr   pe_src;
	u_int8_t          pe_sent;
	u_int8_t          pe_tosend;
	struct event      pe_evt;
	struct iface     *pe_ifp;
	int               pe_fd;
	int               pe_len;
};

struct iface {
	LIST_ENTRY(iface)     if_link;       /* I/F linkage                   */
	u_int8_t             *if_name;       /* ifname e.g. fxp0 ...          */
	u_int8_t             *if_ngname;     /* node name e.g. bridge_0: ...  */
	u_int32_t             if_csock;      /* VNB node access               */
	u_int32_t             if_dsock;      /* VNB node access               */
	struct event          if_cs_ev;
	struct event          if_ds_ev;
	struct event          if_es_announce;
	LIST_HEAD(,an_entry)  if_an_head;
	LIST_HEAD(,es_entry)  if_es_head;
	LIST_HEAD(,is_entry)  if_is_head;
	LIST_HEAD(,rd_entry)  if_rd_head;
	struct mac_addr       if_mac;
	struct ping_entry    *if_pe;
};
LIST_HEAD(ifhead, iface);
extern struct ifhead ifnet;

/*
 * Intenal command mngt
 */
#define OSI_ADD        1
#define OSI_DEL        2
#define OSI_CHANGE     3

/*
 * VNB node comms
 */
#define NG_SOCK_HOOK_NAME       "daemon"

/*
 * Protocol Stuff
 */
#define ES_HELLO_INTERVAL    19
#define ES_HOLD_TIME	     60

struct esis_fixed {
	u_char esis_proto_id; /* network layer protocol identifier */
#define NLPI_ESIS       0x82
	u_char esis_hdr_len;  /* length indicator (octets) */
	u_char esis_vers;     /* version/protocol identifier extension */
#define ESIS_VERSION    1
	u_char esis_res1;     /* reserved */
	u_char esis_type;     /* type code technically, type should be &='d 0x1f */
#define ESIS_ESH        0x02    /* End System Hello */
#define ESIS_ISH        0x04    /* Intermediate System Hello */
#define ESIS_RD         0x06    /* Redirect */
#define ESIS_RA         0x01
#define ESIS_AA         0x03
	u_char esis_ht_msb;    /* holding time (seconds) high byte */
	u_char esis_ht_lsb;    /* holding time (seconds) low byte */
	u_char esis_cksum_msb; /* checksum high byte */
	u_char esis_cksum_lsb; /* checksum low byte */
} __attribute__((packed));
#define ESIS_CKSUM_OFF  0x07

struct clnp_fixed {
	u_char cnf_proto_id; /* network layer protocol identifier */
#define NLPI_CLNP       0x81
	u_char cnf_hdr_len;  /* length indicator (octets) */
	u_char cnf_vers;     /* version/protocol identifier extension */
#define CLNP_VERSION    1
	u_char cnf_ttl;       /* TTL */
	u_char cnf_type;     /* type code */
	/* Includes err_ok, more_segs, and seg_ok */
	u_char cnf_seglen_msb; /* pdu segment length (octets) high byte */
	u_char cnf_seglen_lsb; /* pdu segment length (octets) low  byte */
	u_char cnf_cksum_msb;  /* checksum high byte */
	u_char cnf_cksum_lsb;  /* checksum low byte */
} __attribute__((packed));

struct clnp_segment {
	u_short         cng_id; /* data unit identifier */
	u_short         cng_off;/* segment offset */
	u_short         cng_tot_len;    /* total length */
} __attribute__((packed));
#define CNF_TYPE        0x1f
#define CNF_ERR_OK      0x20
#define CNF_MORE_SEGS   0x40
#define CNF_SEG_OK      0x80
#define CLNP_CKSUM_OFF  0x07    /* offset of checksum */

#define CLNP_ERQ 0x1e
#define CLNP_ERP 0x1f

struct eth_llc_hdr {
	u_int8_t       eh_dst[6];
	u_int8_t       eh_src[6];
	u_int16_t      eh_len;
	u_int8_t       eh_dsap;
#define LCC_DSAP_OSI  0xFE
	u_int8_t       eh_ssap;
#define LCC_SSAP_OSI  0xFE
	u_int8_t       eh_ctrl;
#define LLC_OSI_CRTL 0x03
} __attribute__((packed));
#define LLC_SIZE 3

#define NSEL_NON_OSI    0x00
#define NSEL_OSI        0x01


/* config.c */
extern int parse_mac (u_int8_t *, struct mac_addr *);
extern int parse_osi (u_int8_t *, struct osi_addr *);
extern void dump_mac (struct mac_addr *, u_int8_t *, int, int *);
extern void dump_osi (struct osi_addr *, u_int8_t *, int, int *);
extern void dump_hex (int, u_int8_t *, u_int8_t *, u_int8_t *, int, int *);
extern u_int8_t eth_ESIS_ESH [];
extern struct iface *new_iface (char *, char *, int *);
extern struct iface *get_ifp (char *);
extern int add_es_announce (u_int8_t *, u_int8_t *);
extern int remove_es_announce (u_int8_t *, u_int8_t *);
extern int iface_delete (int, char *);
extern void do_config (int, int);
extern void parse (char *);
extern void flush (int, struct iface *, int);
#define SZ_DBUF 512
extern u_int8_t dump_buf1 [];
extern u_int8_t dump_buf2 [];
extern u_int8_t dump_buf3 [];
extern void show (int, struct iface *);
extern int debug;

/* core.c */
extern void es_announce_cb (int, short, void *);
extern void receive_es_hello (struct iface *, struct osi_addr *,
             struct mac_addr *, u_int16_t);
extern void receive_is_hello (struct iface *, struct osi_addr *,
             struct mac_addr *, u_int16_t);
extern void receive_redirect (struct iface *, struct osi_addr *,
                  struct mac_addr *, struct osi_addr *, u_int16_t);
extern int remove_es_hello (struct iface *, struct osi_addr *);
extern int remove_is_hello (struct iface *, struct osi_addr *);
extern int  remove_redirect (struct iface *, struct osi_addr *);
extern void  es_entry_aging (int, short, void *);
extern void  is_entry_aging (int, short, void *);
extern void  rd_entry_aging (int, short, void *);
extern struct an_entry *osi_get_an (struct iface *, struct osi_addr *);
extern struct mac_addr *osi_get_l2 (struct iface *, struct osi_addr *);

/* osi.c */
extern void read_dsock_cb (int, short, void *);
extern void send_es_hello (struct iface *);
extern int skip_cksum;
extern void pinger (int, struct iface *, struct osi_addr *) ;

/* vnb.c */
extern void read_csock_cb (int, short, void *);
extern void notify_es (int, struct es_entry *);
extern void notify_is (int, struct is_entry *);
extern void notify_rd (int, struct rd_entry *);

/* main.c */
extern void display_console(int fd, const char *, ...);
extern void log_msg __P((int, int, char *, ...));
extern int console_acces;
extern int ping_fd;
extern void set_prompt (u_int8_t *);
extern void display_prompt (int);

#ifdef __HARD_CODED_TEST_
extern void do_test_es (struct iface *);
extern void do_test_is (struct iface *);
extern void do_test_rd (struct iface *);
extern void do_test_ping (struct iface *);
extern void do_test_pong (struct iface *);
#endif
