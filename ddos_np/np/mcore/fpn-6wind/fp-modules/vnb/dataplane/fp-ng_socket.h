/*
 * Copyright(c) 2007 6WIND
 */
#ifndef __NG_SOCKET_FP_H__
#define __NG_SOCKET_FP_H__

#define NG_SOCKET_NODE_TYPE     "socket-fp"
#define NGM_SOCKET_COOKIE       851601233

/* Socket messages */
#define NGM_SOCKET_CREATE   1  /* Msg to create socket node */
#define NGM_SOCKET_DELETE   2  /* Msg to delete socket node */

int vnb_ifattach(uint32_t ifuid, uint32_t nodeid);
int vnb_ifdetach(uint32_t ifuid, uint8_t vnb_keep_node);

#endif
