/*
 * Copyright 2007-2012 6WIND S.A.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/signal.h>
#include <linux/types.h> // for 2.4 kernel
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <net/if.h>
#include <event.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <paths.h>
#include <ifaddrs.h>
#include <syslog.h>
#include <err.h>
#include "snoop.h"
#include <arpa/inet.h>
#include "netlink.h"


struct nlsock
{
    int sock;
    int seq;
    struct sockaddr_nl snl;
    char *name;
};

static struct nlsock netlink_socket = { -1, 0, {0}, "netlink-listen" };
static struct event evt_netlink;


struct if_addr *
find_ifaddr (struct eth_if *ifp, struct in_addr *addr,
    u_int8_t mask_len)
{
    struct if_addr *ifa = NULL;

    LIST_FOREACH (ifa, &ifp->if_addr_head, ifa_link) {
        if (ifa->ifa_mask_len == mask_len &&
            ifa->ifa_addr.s_addr == addr->s_addr)
            return ifa;
    }
    return NULL;
}

static void
add_ifaddr (struct eth_if *ifp, struct in_addr *addr,
    u_int8_t mask_len)
{
    struct if_addr *ifa = NULL;

    log_msg (LOG_DEBUG, 0, "add_ifaddr: adding address %s/%d",
             inet_ntoa(*addr), mask_len);

    if (find_ifaddr (ifp, addr, mask_len)) {
        log_msg (LOG_WARNING, 0, "add_ifaddr: duplicated address");
        return;
    }

    ifa = malloc (sizeof(struct if_addr));
    if (!ifa) {
        log_msg (LOG_ERR, errno, "add_ifaddr: allocating memory failed");
        return;
    }
    memset (ifa, 0, sizeof(struct if_addr));

    ifa->ifa_addr = *addr;
    ifa->ifa_mask_len = mask_len;

    LIST_INSERT_HEAD (&ifp->if_addr_head, ifa, ifa_link);
}

static void
del_ifaddr (struct eth_if *ifp, struct in_addr *addr,
    u_int8_t mask_len)
{
    struct if_addr *ifa = NULL;

    log_msg (LOG_DEBUG, 0, "del_ifaddr: deleting address %s/%d",
             inet_ntoa(*addr), mask_len);

    ifa = find_ifaddr (ifp, addr, mask_len);
    if (!ifa) {
        log_msg (LOG_WARNING, 0, "del_ifaddr: address does not exist");
        return;
    }

    LIST_REMOVE (ifa, ifa_link);
    free (ifa);
}

void
clear_ifaddr (struct eth_if *ifp)
{
    struct if_addr *ifa, *p;

    log_msg (LOG_DEBUG, 0, "clear_ifaddr: clearing all the IPv4 addresses");

    for (ifa = LIST_FIRST (&ifp->if_addr_head) ; ifa != NULL ; ) {
        p = ifa;
        ifa = LIST_NEXT (ifa, ifa_link);
        free (p);
    }
    LIST_INIT (&ifp->if_addr_head);
}

struct if_addr6 *
find_ifaddr6 (struct eth_if *ifp, struct in6_addr *addr,
    u_int8_t mask_len)
{
    struct if_addr6 *ifa = NULL;

    LIST_FOREACH (ifa, &ifp->if_addr6_head, ifa_link) {
        if (ifa->ifa_mask_len == mask_len &&
            memcmp(ifa->ifa_addr.s6_addr, addr->s6_addr, IPV6_MAX_BYTELEN) == 0)
            return ifa;
    }
    return NULL;
}

static void
add_ifaddr6 (struct eth_if *ifp, struct in6_addr *addr6,
    u_int8_t mask_len)
{
    struct if_addr6 *ifa = NULL;
    char buf[BUFSIZ];

    log_msg (LOG_DEBUG, 0, "add_ifaddr6: adding address %s/%d",
             inet_ntop(AF_INET6, addr6, buf, BUFSIZ), mask_len);

    if (find_ifaddr6 (ifp, addr6, mask_len)) {
        log_msg (LOG_WARNING, 0, "add_ifaddr6: duplicated address");
        return;
    }

    ifa = malloc (sizeof(struct if_addr6));
    if (!ifa) {
        log_msg (LOG_ERR, errno, "add_ifaddr6: allocating memory failed");
        return;
    }
    memset (ifa, 0, sizeof(struct if_addr6));

    ifa->ifa_addr = *addr6;
    ifa->ifa_mask_len = mask_len;

    LIST_INSERT_HEAD (&ifp->if_addr6_head, ifa, ifa_link);
}

static void
del_ifaddr6 (struct eth_if *ifp, struct in6_addr *addr6,
    u_int8_t mask_len)
{
    struct if_addr6 *ifa = NULL;
    char buf[BUFSIZ];

    log_msg (LOG_DEBUG, 0, "del_ifaddr6: deleting address %s/%d",
             inet_ntop(AF_INET6, addr6, buf, BUFSIZ), mask_len);

    ifa = find_ifaddr6 (ifp, addr6, mask_len);
    if (!ifa) {
        log_msg (LOG_WARNING, 0, "del_ifaddr6: address does not exist");
        return;
    }

    LIST_REMOVE (ifa, ifa_link);
    free (ifa);
}

void
clear_ifaddr6 (struct eth_if *ifp)
{
    struct if_addr6 *ifa, *p;

    log_msg (LOG_DEBUG, 0, "clear_ifaddr6: clearing all the IPv6 addresses");

    for (ifa = LIST_FIRST (&ifp->if_addr6_head) ; ifa != NULL ; ) {
        p = ifa;
        ifa = LIST_NEXT (ifa, ifa_link);
        free (p);
    }
    LIST_INIT (&ifp->if_addr6_head);
}

void
config_ifaddr_from_kernel (struct eth_if *ifp)
{
    short flags;
    int i;
    struct sockaddr_in6 addr6, mask6;
    struct sockaddr_in *addr, *mask;
    u_int8_t mask_len;
    struct ifaddrs *ifap = NULL, *ifa;

    if (getifaddrs(&ifap)) {
        log_msg (LOG_ERR, errno, "config_ifaddr_from_kernel: getifaddrs");
        return;
    }

    log_msg (LOG_DEBUG, 0, "config_ifaddr_from_kernel: interface %s", ifp->if_name);

    /*
     * Loop through all of the interfaces.
     */
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        /*
         * Sanity check
         */
        if (!ifa->ifa_addr)
            continue;

        if (strcmp(ifp->if_name, ifa->ifa_name))
            continue;

        flags = ifa->ifa_flags;

        /*
         * Set the interface state
         */
        if (flags & IFF_UP)
            ifp->if_down = 0;
        else
            ifp->if_down = 1;

        /*
         * This is an IPv4 address
         */
        if (ifa->ifa_addr->sa_family == AF_INET)
        {
            addr = (struct sockaddr_in *) ifa->ifa_addr;
            mask = (struct sockaddr_in *) ifa->ifa_netmask;

            if (mask)
                MASK_TO_MASKLEN (mask->sin_addr.s_addr, mask_len);
            else
                mask_len = IPV4_MAX_BITLEN;

            add_ifaddr (ifp, &addr->sin_addr, mask_len);
        }

        /*
         * This is an IPv6 address. Add it when interface is UP.
         */
        if (ifa->ifa_addr->sa_family == AF_INET6 &&
            flags & IFF_UP)
        {
#ifndef __linux__
            struct in6_ifreq ifr6;
            int ioctl_s;
#endif

            memcpy (&addr6, ifa->ifa_addr, sizeof(struct sockaddr_in6));

            if (ifa->ifa_netmask) {
                memcpy (&mask6, ifa->ifa_netmask, sizeof(struct sockaddr_in6));
                MASK_TO_MASKLEN6 (mask6.sin6_addr, mask_len);
            }
            else
                mask_len = IPV6_MAX_BITLEN;

#ifndef __linux__
            /*
             * Get IPv6 specific flags, and ignore an anycast address.
             * XXX: how about a deprecated, tentative, duplicated or
             * detached address?
             */
            ioctl_s = socket (AF_INET6, SOCK_DGRAM, 0);
            if (ioctl_s < 0) {
                log_msg (LOG_ERR, errno, "config_ifaddr_from_kernel: "
                         "socket SOCK_DGRAM");
                continue;
            }
            strncpy(ifr6.ifr_name, ifa->ifa_name, sizeof(ifr6.ifr_name));
            ifr6.ifr_addr = addr6;
            if (ioctl (ioctl_s, SIOCGIFAFLAG_IN6, &ifr6) < 0) {
                char buf[BUFSIZ];
                log_msg (LOG_ERR, errno, "config_ifaddr_from_kernel: "
                         "ioctl SIOCGIFAFLAG_IN6 for %s/%d",
                         inet_ntop (AF_INET6, addr6, buf, BUFSIZ), mask_len);
                close (ioctl_s);
                continue;
            }
            else {
                if (ifr6.ifr_ifru.ifru_flags6 & IN6_IFF_ANYCAST) {
                    log_msg (LOG_DEBUG, 0, "config_ifaddr_from_kernel: "
                             "%s/%d is an anycast address, ignored",
                             inet_ntop (AF_INET6, addr6, buf, BUFSIZ), mask_len);
                    close (ioctl_s);
                    continue;
                }
            }
            close (ioctl_s);
#endif

#ifdef __KAME__
            if (IN6_IS_ADDR_LINKLOCAL (&addr6.sin6_addr)) {
                /*
                * Hack for KAME kernel.
                * Set sin6_scope_id field of a link local address and clear
                * the index embedded in the address.
                */
                /* clear interface index */
                addr6.sin6_addr.s6_addr[2] = 0;
                addr6.sin6_addr.s6_addr[3] = 0;
            }
#endif

            add_ifaddr6 (ifp, &addr6.sin6_addr, mask_len);
        }
    }

    freeifaddrs (ifap);
}


static void
netlink_parse_rtattr (struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
    while (RTA_OK(rta, len)) {
        if (rta->rta_type <= max)
            tb[rta->rta_type] = rta;
        rta = RTA_NEXT(rta, len);
    }
    if (len)
        log_msg (LOG_WARNING, 0, "NETLINK: Deficit in rtattr %d", len);
}

/* Look up for link status change */
int
netlink_link_change (struct sockaddr_nl *snl, struct nlmsghdr *h)
{
    int len;
    struct ifinfomsg *ifi;
    struct rtattr *tb [IFLA_MAX + 1];
    char *name;
    struct eth_if *ifp = NULL;

    ifi = NLMSG_DATA (h);

    if (!(h->nlmsg_type == RTM_NEWLINK || h->nlmsg_type == RTM_DELLINK)) {
        log_msg (LOG_WARNING, 0, "netlink_link_change: Wrong message %d",
                 h->nlmsg_type);
        return 0;
    }

    len = h->nlmsg_len - NLMSG_LENGTH (sizeof (struct ifinfomsg));
    if (len < 0)
        return -1;

    /* Looking up interface name. */
    memset (tb, 0, sizeof tb);
    netlink_parse_rtattr (tb, IFLA_MAX, IFLA_RTA (ifi), len);
    if (tb[IFLA_IFNAME] == NULL) {
        log_msg (LOG_WARNING, 0, "netlink_link_change: Interface name fetched null");
        return -1;
    }
    else {
        name = ( char *)RTA_DATA(tb[IFLA_IFNAME]);
        log_msg (LOG_INFO, 0, "netlink_link_change: Interface name fetched [%s]", name);
    }

    /* Find whether this interface is a part of SNOOP configuration */
    ifp = get_ifp (name);
    if (!ifp) {
        log_msg (LOG_INFO, 0,
                 "netlink_link_change: Message ignored for an inactive interface %s",
                 name);
        return 0;
    }

    /* RTM_DELLINK message is not used presently */
    if (h->nlmsg_type == RTM_NEWLINK) {

        /* Interface status change. */
        if (ifi->ifi_flags & IFF_UP) {
            log_msg (LOG_INFO, 0, "netlink_link_change: interface is going to up");
            ifp->if_down = 0;
        }
        else {
            log_msg (LOG_INFO, 0, "netlink_link_change: interface is going to down");
            ifp->if_down = 1;
        }

        /* Clear the IPv6 addresses if the message is DOWN.
         * They will be added back when the interface gets UP.
         */
        if (ifp->if_down)
            clear_ifaddr6 (ifp);

        /* Try to start the interface. */
        intend_start_iface (ifp);
    }
    return 0;
}

/* Look up for interface address change */
int
netlink_interface_addr (struct sockaddr_nl *snl, struct nlmsghdr *h)
{
    int len;
    struct ifaddrmsg *ifa;
    struct rtattr *tb[IFA_MAX + 1];
    void *addr; /* in any cases, it is the local address */
    u_char flags = 0;
    struct eth_if *ifp = NULL;

    ifa = NLMSG_DATA (h);

    if (ifa->ifa_family != AF_INET && ifa->ifa_family != AF_INET6 ) {
        log_msg (LOG_WARNING, 0, "netlink_interface_addr: "
                 "Unsupported address family %d",
                 ifa->ifa_family);
        return 0;
    }

    if (h->nlmsg_type != RTM_NEWADDR && h->nlmsg_type != RTM_DELADDR)
    {
        log_msg (LOG_WARNING, 0, "netlink_interface_addr: "
                 "Wrong message type %d",
                 h->nlmsg_type);
        return 0;
    }

    /* Find whether this interface is a part of SNOOP configuration */
    ifp = get_ifp_index (ifa->ifa_index);
    if (!ifp) {
        log_msg (LOG_INFO, 0,
                 "netlink_interface_addr: Message ignored for "
                 "an inactive interface with index %d",
                 ifa->ifa_index);
        return 0;
    }

    /*
    * If the iface is not created yet, ignore the address message
    */
    if (!ifp->if_created) {
        log_msg (LOG_WARNING, 0, "netlink_interface_addr: "
                 "The interface %s is not ready yet",
                 ifp->if_name);
        return 0;
    }

    len = h->nlmsg_len - NLMSG_LENGTH (sizeof (struct ifaddrmsg));
    if (len < 0)
        return -1;

    memset (tb, 0, sizeof tb);
    netlink_parse_rtattr (tb, IFA_MAX, IFA_RTA (ifa), len);

    log_msg (LOG_DEBUG, 0, "netlink_interface_addr: Message(%d) received "
             "for interface %s",
             h->nlmsg_type, ifp->if_name);

    if (tb[IFA_LOCAL] == NULL)
        tb[IFA_LOCAL] = tb[IFA_ADDRESS];
    if (tb[IFA_ADDRESS] == NULL)
        tb[IFA_ADDRESS] = tb[IFA_LOCAL];

    /* local interface address */
    addr = (tb[IFA_LOCAL] ? RTA_DATA(tb[IFA_LOCAL]) : NULL);

    /* addr is primary key, SOL if we don't have one */
    if (addr == NULL)
    {
        log_msg (LOG_WARNING, 0, "netlink_interface_addr: "
                 "Wrong message type %d with null address",
                 h->nlmsg_type);
        return -1;
    }

    /* Register interface address to the interface. */
    if (ifa->ifa_family == AF_INET) {
        if (h->nlmsg_type == RTM_NEWADDR)
            add_ifaddr (ifp, (struct in_addr *) addr, ifa->ifa_prefixlen);
        else
            del_ifaddr (ifp, (struct in_addr *) addr, ifa->ifa_prefixlen);
    }

    if (ifa->ifa_family == AF_INET6) {
        if (h->nlmsg_type == RTM_NEWADDR)
            add_ifaddr6 (ifp, (struct in6_addr *) addr, ifa->ifa_prefixlen);
        else
            del_ifaddr6 (ifp, (struct in6_addr *) addr, ifa->ifa_prefixlen);
    }

    /* Try to start the interface. */
    intend_start_iface (ifp);

    return 0;
}

int
netlink_information_fetch (struct sockaddr_nl *snl, struct nlmsghdr *h)
{
    switch (h->nlmsg_type) {

        case RTM_NEWLINK:
            return  netlink_link_change (snl, h);
        case RTM_DELLINK:
            return  netlink_link_change (snl, h);
        case RTM_NEWADDR:
            return  netlink_interface_addr (snl, h);
        case RTM_DELADDR:
            return  netlink_interface_addr (snl, h);
        default:
            log_msg (LOG_WARNING, 0, "netlink_information_fetch: Unknown netlink nlmsg_type %d",
                     h->nlmsg_type);
            break;
   }
   return 0;
}

static void netlink_cb (int fd, short event, void *arg)
{
    char buf[BUFSIZ];
    int status;
    int error;

    while (1) {
        struct iovec iov = {buf, sizeof buf};
        struct sockaddr_nl snl;
        struct msghdr msg = {(void*)&snl, sizeof snl, &iov, 1, NULL, 0, 0};
        struct nlmsghdr *h;

        status = recvmsg (netlink_socket.sock, &msg, 0);

        if (status < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN)
                break;
            log_msg (LOG_WARNING, 0, "netlink_cb: %s recvmsg overrun", netlink_socket.name);
            continue;
        }

        if (status == 0) {
            log_msg (LOG_DEBUG, 0, "netlink_cb: %s EOF", netlink_socket.name);
            return;
        }

        if (msg.msg_namelen != sizeof snl) {
            log_msg (LOG_ERR, 0, "netlink_cb: %s sender address length error: length %d",
                 netlink_socket.name, msg.msg_namelen);
            return;
        }

        for (h = (struct nlmsghdr *) buf; NLMSG_OK (h, status);
             h = NLMSG_NEXT (h, status)) {
            /* Finish of reading. */
            if (h->nlmsg_type == NLMSG_DONE)
                return;

            /* Error handling. */
            if (h->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = (struct nlmsgerr *) NLMSG_DATA (h);
                /* If the error field is zero, then this is an ACK */
                if (err->error == 0) {
                    /* return if not a multipart message, otherwise continue */
                    if (!(h->nlmsg_flags & NLM_F_MULTI)) {
                        return;
                    }
                    continue;
                }

                if (h->nlmsg_len < NLMSG_LENGTH (sizeof (struct nlmsgerr))) {
                    log_msg (LOG_ERR,0, "netlink_cb: %s error: message truncated",
                             netlink_socket.name);
                    return;
                }
                log_msg (LOG_ERR, 0, "netlink_cb: %s , type=(%u), seq=%u, pid=%d",
                         netlink_socket.name,
                         err->msg.nlmsg_type, err->msg.nlmsg_seq,
                         err->msg.nlmsg_pid);
                return;
            }

            /* OK we got netlink message. */
            log_msg (LOG_INFO, 0, "netlink_cb: %s type=(%u), seq=%u, pid=%d",
                     netlink_socket.name,
                     h->nlmsg_type, h->nlmsg_seq, h->nlmsg_pid);

            /* skip unsolicited messages originating from command socket */

            error = netlink_information_fetch (&snl, h);
            if (error < 0) {
                log_msg (LOG_ERR, 0, "netlink_cb: %s filter function error(%d)",
                         netlink_socket.name, error);
                return;
            }
        }

        /* After error care. */
        if (msg.msg_flags & MSG_TRUNC) {
            log_msg (LOG_ERR, 0, "netlink_cb: %s error: message truncated",
                     netlink_socket.name);
            continue;
        }
        if (status) {
            log_msg (LOG_ERR, 0, "netlink_cb: %s error: data remnant size %d",
                     netlink_socket.name, status);
            return;
        }
    }
    return;
}

void
netlink_init (void)
{
    struct sockaddr_nl snl;
    int sock;
    int namelen;
    int ret;

    sock = socket (AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        log_msg (LOG_ERR, 0, "netlink_init: Can't open %s socket", netlink_socket.name);
        return;
    }

    ret = fcntl (sock, F_SETFL, O_NONBLOCK);
    if (ret < 0) {
        log_msg (LOG_ERR, 0, "netlink_init: Can't set %s socket flags", netlink_socket.name);
        close (sock);
        return;
    }

    memset (&snl, 0, sizeof snl);
    snl.nl_family = AF_NETLINK;
    snl.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;

    /* Bind the socket to the netlink structure for anything. */
    ret = bind (sock, (struct sockaddr *) &snl, sizeof snl);
    if (ret < 0) {
        log_msg (LOG_ERR, 0, "netlink_init: Can't bind %s socket to group 0x%x",
                 netlink_socket.name, snl.nl_groups );
        close (sock);
        return;
    }
    /* multiple netlink sockets will have different nl_pid */
    namelen = sizeof snl;
    ret = getsockname (sock, (struct sockaddr *) &snl, &namelen);
    if (ret < 0 || namelen != sizeof snl) {
        log_msg (LOG_ERR, 0, "netlink_init: Can't get %s socket name", netlink_socket.name);
        close (sock);
        return;
    }

    netlink_socket.snl = snl;
    netlink_socket.sock = sock;

    event_set (&evt_netlink, netlink_socket.sock, EV_READ | EV_PERSIST, netlink_cb, 0);
    event_add (&evt_netlink, NULL);
}


