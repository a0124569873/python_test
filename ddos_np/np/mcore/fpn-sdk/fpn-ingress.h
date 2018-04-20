/*
 * Copyright(c) 2007  6WIND
 */
#ifndef __FPN_INGRESS_H__
#define __FPN_INGRESS_H__
/*
 * On systems equipped with ingress queuing points, this API
 * sets the attributes for the ingress queuing points
 * In particular, on the Octeon platform, this API will configure the
 * POW queues
 * Returns
 *   0 if success.
 *   Error if input parameters combination is not supported
 *
 */
int fpn_setIngressFc(
  uint8_t   fc,        /* Forwarding class Id: 0..7 for the Octeon */
  uint8_t   weight,    /* scheduling weight of this fc (0 to 100%) */
  uint64_t  startdrop, /* pass threshold (in % depth) to start random drop */
  uint64_t  depth      /* drop threshold (in % maxbuffers) */
);

/* Update weight on given forwarding class */
int fpn_ingress_update_weight(int queue, int weight);

/*
 * This API sets the mapping from a portId to a
 * forwarding class
 * returns
 *   0 if success.
 */   
/* Flags to instruct setIngressPortQoSMapping how to map to a forwarding class */
#define FPN_USE_FC                  0       /* Use the passed-in fc traffic */
#define FPN_USE_GLBL_DIFFSERV_TABLE 0x20000 /* Use the global diffserv table */
#define FPN_USE_GLBL_PBITS_TABLE    0x10000 /* Use the global Pbits table */
int fpn_setIngressPortToFcMapping(
  uint16_t  portId,    /* 0..35 for the Octeon */
  uint8_t   fc,        /* 0-7 forwarding class (see - fpn_setIngressFc) 
                        * used when FPN_USE_FC is set or when dscp/pbits
                        * mapping does not match
                        */
  uint64_t  flags      /* use the defines above */
); 

/*
 * This API sets the mapping from a combination of DSCP bits to a
 * forwarding class
 * returns
 *   0 if success.
 */
int fpn_setIngressGlobalDSCPMapping(
  uint8_t   DSCP,     /* TOS byte on incoming packet
                       * 0 to 63: valid values
                       * 63..255: invalid
                       */
  uint8_t   fc        /* 0-7 forwarding class (see - fpn_setIngressFc) */
);

/*
 *  This API sets the mapping from a combination of p bits to a
 *  forwarding class
 *  returns
 *    0 if success.
 */
int fpn_setIngressGlobalPbitMapping(
  uint8_t   pbit,      /* pbit (priority bits) values on incoming packet
                        * 0..7:   valid values of TOS
                        * 8..255: invalid
                        */
  uint8_t   fc         /* 0-7 forwarding class (see - fpn_setIngressFc) */
);

/*
 * This API sets the backpressure threshold (in bytes) for an ingress
 * port
 * returns
 *   0 if success.
 */
int fpn_setIngressPortBackpressureThreshold(
  uint16_t portId,    /* 0..35 for Cavium */
  uint64_t threshold  /* backpressure threshold (in buffers) */
);

#if defined(CONFIG_MCORE_ARCH_OCTEON) && defined(CONFIG_MCORE_FPE_MCEE)
#include "octeon/fpn-ingress-octeon.h"
#endif

#endif
