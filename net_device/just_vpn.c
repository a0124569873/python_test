#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
//#define VPNET_DEBUG
#define BOOL int
#define TRUE 1
#define FALSE 0
static unsigned long domain_aton(const char *s)
{
    unsigned long rv;
    rv = inet_addr(s);
    if (rv == 0xffffffff)
    {
        struct hostent *he;
        he = (struct hostent *)gethostbyname(s);
        if (he)
            return ((struct in_addr *)he->h_addr_list[0])->s_addr;
        else
            return 0xffffffff;
    }
    else
        return rv;
}
static void echo_help(int argc, char *argv[])
{
    printf("Just-VPN for VPN driver test, v0.90/n");
    printf("Usage: %s -s [-p <local_port>]      : Run as server mode/n", argv[0]);
    printf("       %s <host_addr> [host_port]   : Run as client mode/n", argv[0]);
    printf("       %s -h                        : Print this help/n", argv[0]);
    printf("/n");
}
int main(int argc, char *argv[])
{
    char rbuf[1024 * 4];
    const size_t rbuf_sz = sizeof(rbuf);
    int vfd;
    int sfd;
    fd_set rset;
    int rx, tx;
    int ret, i;
    int port = 9000;
    char *host = NULL;
    struct sockaddr_in peer_addr, lsn_addr;
    int peer_addr_len, lsn_addr_len;
    BOOL is_server_mode = FALSE;
    int opt;

    memset(&peer_addr, 0x0, sizeof(peer_addr));
    memset(&lsn_addr, 0x0, sizeof(lsn_addr));
    while ((opt = getopt(argc, argv, "slcp:h-")) != -1)
    {
        switch (opt)
        {
        case 'c':
            is_server_mode = FALSE;
            break;
        case 's':
        case 'l':
            is_server_mode = TRUE;
            break;
        case 'p':
            port = atoi(optarg);
            break;
        case 'h':
        case '-':
            echo_help(argc, argv);
            return 0;
            break;
        case '?':
            echo_help(argc, argv);
            return -1;
            break;
        }
    }

    /* Hostname or dotted-IP of peer host */
    if (optind < argc)
        host = argv[optind++];
    /* Listen port of peer host (UDP) */
    if (optind < argc && !is_server_mode)
        port = atoi(argv[optind++]);
    /* Open device file, while opening the interface is created */
    vfd = open("/dev/vpnet", O_RDWR);
    if (vfd < 0)
    {
        fprintf(stderr, "open() error: %s./n", strerror(errno));
        return -1;
    }
    /* Create data transmission socket */
    sfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sfd < 0)
    {
        fprintf(stderr, "socket() error: %s./n", strerror(errno));
        return -1;
    }
    if (is_server_mode)
    {
        lsn_addr.sin_family = AF_INET;
        lsn_addr.sin_addr.s_addr = htonl(0);
        lsn_addr.sin_port = htons(port);
        ret = bind(sfd, (struct sockaddr *)&lsn_addr, sizeof(lsn_addr));
        if (ret < 0)
        {
            fprintf(stderr, "%s[%d] bind() error: %s./n", __FILE__, __LINE__, strerror(errno));
            return -1;
        }
        printf("Just-VPN, listening on `%s:%d`.../n",
               inet_ntoa(lsn_addr.sin_addr),
               (int)ntohs(lsn_addr.sin_port));
    }
    else
    {
        if (host == NULL)
        {
            fprintf(stderr, "%s[%d] Invalid IP address./n", __FILE__, __LINE__);
            return -1;
        }
        peer_addr.sin_family = AF_INET;
        peer_addr.sin_addr.s_addr = domain_aton(host);
        peer_addr.sin_port = htons(port);
        printf("Just-VPN, connecting with `%s:%d`.../n",
               inet_ntoa(peer_addr.sin_addr),
               (int)ntohs(peer_addr.sin_port));
    }

    /* Forward each frame data packet */
    for (;;)
    {
        FD_ZERO(&rset);
        FD_SET(vfd, &rset);
        FD_SET(sfd, &rset);
        ret = select((sfd > vfd ? sfd : vfd) + 1, &rset, NULL, NULL, NULL);
        if (ret < 0)
            continue;
        else if (ret == 0)
            continue;

        if (FD_ISSET(sfd, &rset))
        {
            /* For the server, we need this to know where the client is; 
               while for the client, this address may changed after  
               received this packet, so risk of attack occurs here.  */
            peer_addr_len = sizeof(peer_addr);
            rx = recvfrom(sfd, rbuf, rbuf_sz, 0,
                          (struct sockaddr *)&peer_addr, &peer_addr_len);
            if (rx > 0)
            {
                tx = write(vfd, rbuf, (size_t)rx);
                //printf("recvfrom()->write(): %d/n", tx);
            }
        }

        if (FD_ISSET(vfd, &rset))
        {
            rx = read(vfd, rbuf, rbuf_sz);
            /* For the server, before the client sends packet to it,  
               we cannot know where to send local frame packets to */
            if (rx > 0 && peer_addr.sin_addr.s_addr != 0 && peer_addr.sin_port != 0)
            {
                tx = sendto(sfd, rbuf, rx, 0,
                            (struct sockaddr *)&peer_addr, sizeof(peer_addr));
                //printf("read()->sendto(): %d/n", tx);
            }
        }
    }

    return 0;
}