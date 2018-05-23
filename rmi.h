#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <linux/in_route.h>
#include <linux/icmpv6.h>
#include <errno.h>

#include <net/if_arp.h>
#include <sys/ioctl.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/ether.h>


/// icmp
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <strings.h>
#include <net/if.h>
///


#define IFLIST_REPLY_BUFFER 8192
#define DEBUG 0

int xlb_parse_route(struct nlmsghdr *nlh, __u8 *src, __u8 *next, int *dev);

#define NLMSG_TAIL(nmsg) \
        ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data,
              int alen);

//static int xlb_iproute_get(char *dst_ip, __u8 *src , __u8 *next, int *dev);
int xlb_iproute_get(char *dst_ip, __u8 *src , __u8 *next, int *dev);

//static int xlb_get_mac(__u8 *host, __u8 *mac, int *dev);
int xlb_get_mac(__u8 *host, __u8 *mac, int *dev);


unsigned short checksum(void *b, int len);
void ping(struct sockaddr_in *addr);
int icmp_send_1pkt(in_addr_t *dst_ip);

