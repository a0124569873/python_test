/*
 * Copyright (c) 2004, 2006 6WIND
 */

/*
 ***************************************************************
 *
 *                CM internals for control link
 *
 * $Id: cm_admin.h,v 1.6 2008-10-27 16:34:54 dichtel Exp $
 ***************************************************************
 */
#ifndef _CM_ADMIN_H_
#define _CM_ADMIN_H_

#define CM_ADMIN_SOCKNAME "/tmp/.cmctl"

#define CMADM_BASE 0x1010

#define CMADM_NEWVALUE (CMADM_BASE+0)

struct admin_msg
{
};

#define ADM_RTA(r) ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct admin_msg))))
#define ADM_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct admin_msg))

/*
 * admin message structure
 *

+------------------------------------+
| Netlink header      (TLV)          |
| struct nlmsghdr                    |
+ +--------------------------------+ +
| | Administration header          | |
| | struct admin_msg               | |
+ +================================+ +
| | Optional attribute  (TLV)      | |
| | struct rtattr                  | |
+ +--------------------------------+ +
|   :        :         :         :   |
+ +--------------------------------+ +
| | Optional attribute  (TLV)      | |
| | struct rtattr                  | |
+ +--------------------------------+ +
+------------------------------------+
+------------------------------------+
| Netlink header      (TLV)          |
| struct nlmsghdr                    |
+ +--------------------------------+ +
| | Administration header          | |
: :                                : :
: :                                : :

 */

enum rtattr_adm_type_t
{
	ADM_DEBUG,
	ADM_LOGFILE,
	ADM_NATPTMODE,
	ADM_SKIP,
	__ADM_MAX
};

#define ADM_MAX (__ADM_MAX - 1)

extern void admin_init (void);

#endif /* _CM_ADMIN_H_ */
