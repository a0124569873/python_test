/*
 * Copyright 2008 6WIND, All rights reserved.
 */
/*-
 * Copyright (c) 2001-2008, by Cisco Systems, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * a) Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * b) Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the distribution.
 *
 * c) Neither the name of Cisco Systems, Inc. nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
/* $KAME: sctp.h,v 1.18 2005/03/06 16:04:16 itojun Exp $         */

#ifndef __NETINET_FP_SCTP_H__
#define __NETINET_FP_SCTP_H__

#define SCTP_PACKED __attribute__((packed))

/*
 * SCTP protocol - RFC2960.
 */
struct fp_sctphdr {
        uint16_t src_port;      /* source port */
        uint16_t dest_port;     /* destination port */
        uint32_t v_tag;         /* verification tag of packet */
        uint32_t checksum;      /* Adler32 C-Sum */
        /* chunks follow... */
} SCTP_PACKED;

/*
 * SCTP Chunks
 */

struct fp_sctpchunkhdr {
        uint8_t chunk_type;     /* chunk type */
        uint8_t chunk_flags;    /* chunk flags */
        uint16_t chunk_length;  /* chunk length */
        /* optional params follow */
} SCTP_PACKED;

/*
 * Main SCTP chunk types we place these here so natd and f/w's in user land
 * can find them.
 */

/************0x00 series ***********/
#define SCTP_DATA               0x00
#define SCTP_INITIATION         0x01
#define SCTP_INITIATION_ACK     0x02
#define SCTP_SELECTIVE_ACK      0x03
#define SCTP_HEARTBEAT_REQUEST  0x04
#define SCTP_HEARTBEAT_ACK      0x05
#define SCTP_ABORT_ASSOCIATION  0x06
#define SCTP_SHUTDOWN           0x07
#define SCTP_SHUTDOWN_ACK       0x08
#define SCTP_OPERATION_ERROR    0x09
#define SCTP_COOKIE_ECHO        0x0a
#define SCTP_COOKIE_ACK         0x0b
#define SCTP_ECN_ECHO           0x0c
#define SCTP_ECN_CWR            0x0d
#define SCTP_SHUTDOWN_COMPLETE  0x0e
/* RFC4895 */
#define SCTP_AUTHENTICATION     0x0f
/* EY nr_sack chunk id*/
#define SCTP_NR_SELECTIVE_ACK 0x10
/************0x40 series ***********/
/************0x80 series ***********/
/* RFC5061 */
#define SCTP_ASCONF_ACK         0x80
/* draft-ietf-stewart-pktdrpsctp */
#define SCTP_PACKET_DROPPED     0x81
/* draft-ietf-stewart-strreset-xxx */
#define SCTP_STREAM_RESET       0x82

/* RFC4820                         */
#define SCTP_PAD_CHUNK          0x84
/************0xc0 series ***********/
/* RFC3758 */
#define SCTP_FORWARD_CUM_TSN    0xc0
/* RFC5061 */
#define SCTP_ASCONF             0xc1

#define SCTP_CID_DATA                 SCTP_DATA               
#define SCTP_CID_INIT                 SCTP_INITIATION         
#define SCTP_CID_INIT_ACK             SCTP_INITIATION_ACK     
#define SCTP_CID_SACK                 SCTP_SELECTIVE_ACK      
#define SCTP_CID_HEARTBEAT            SCTP_HEARTBEAT_REQUEST  
#define SCTP_CID_HEARTBEAT_ACK        SCTP_HEARTBEAT_ACK      
#define SCTP_CID_ABORT                SCTP_ABORT_ASSOCIATION  
#define SCTP_CID_SHUTDOWN             SCTP_SHUTDOWN           
#define SCTP_CID_SHUTDOWN_ACK         SCTP_SHUTDOWN_ACK       
#define SCTP_CID_ERROR                SCTP_OPERATION_ERROR    
#define SCTP_CID_COOKIE_ECHO          SCTP_COOKIE_ECHO        
#define SCTP_CID_COOKIE_ACK           SCTP_COOKIE_ACK         
#define SCTP_CID_ECN_ECNE             SCTP_ECN_ECHO           
#define SCTP_CID_ECN_CWR              SCTP_ECN_CWR            
#define SCTP_CID_SHUTDOWN_COMPLETE    SCTP_SHUTDOWN_COMPLETE  
#define SCTP_CID_FWD_TSN              SCTP_FORWARD_CUM_TSN 
#define SCTP_CID_ASCONF               SCTP_ASCONF 
#define SCTP_CID_ASCONF_ACK           SCTP_ASCONF_ACK         

#undef SCTP_PACKED

#endif /* __NETINET_FP_SCTP_H__ */
