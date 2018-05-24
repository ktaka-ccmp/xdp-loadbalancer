#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <unistd.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <arpa/inet.h>

#define IFLIST_REPLY_BUFFER	8192

typedef struct nl_req_s nl_req_t;  

struct nl_req_s {
  struct nlmsghdr hdr;
  struct rtmsg	r;
  char      buf[1025];
};

void rtnl_print_route(struct nlmsghdr *nlh)
{
    struct  rtmsg *route_entry;
    struct  rtattr *route_attribute; 
    int     route_attribute_len = 0;
    unsigned char    route_netmask = 0;
    unsigned char    route_protocol = 0;
    char    dst_ip[32];
    char    gw_ip[32];
    char    src_ip[32];
    int     via = 0;

    route_entry = (struct rtmsg *) NLMSG_DATA(nlh);

    if (route_entry->rtm_table != RT_TABLE_MAIN)
      return;

    route_netmask = route_entry->rtm_dst_len;
    route_protocol = route_entry->rtm_protocol;
    route_attribute = (struct rtattr *) RTM_RTA(route_entry);
    route_attribute_len = RTM_PAYLOAD(nlh);

    for ( ; RTA_OK(route_attribute, route_attribute_len);		\
	  route_attribute = RTA_NEXT(route_attribute, route_attribute_len))
      {
	printf("hello\n");
        if (route_attribute->rta_type == RTA_DST)
	  {
            inet_ntop(AF_INET, RTA_DATA(route_attribute),		\
		      dst_ip, sizeof(dst_ip));
	  }
        if (route_attribute->rta_type == RTA_GATEWAY)
	  {
            inet_ntop(AF_INET, RTA_DATA(route_attribute),	\
		      gw_ip, sizeof(gw_ip));
	    via = 1;
	  }
        if (route_attribute->rta_type == RTA_PREFSRC)
	  {
            inet_ntop(AF_INET, RTA_DATA(route_attribute),	\
		      src_ip, sizeof(src_ip));
	  }
      }
    printf("route to destination --> %s/%d proto %d and gateway %s\n src=%s, via=%d\n", \
	   dst_ip, route_netmask, route_protocol, gw_ip,src_ip, via);

}

#define NLMSG_TAIL(nmsg) \
        ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data,
              int alen)
{
        int len = RTA_LENGTH(alen);
        struct rtattr *rta;

        if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
                fprintf(stderr,
                        "addattr_l ERROR: message exceeded bound of %d\n",
                        maxlen);
                return -1;
        }
        rta = NLMSG_TAIL(n);
        rta->rta_type = type;
        rta->rta_len = len;
        if (alen)
                memcpy(RTA_DATA(rta), data, alen);
        n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
        return 0;
}

int main(int argc, char **argv)
{
  int fd;
 
  struct msghdr rtnl_msg;    /* generic msghdr struct for use with sendmsg */
  struct iovec io;	     /* IO vector for sendmsg */

  nl_req_t req;              /* structure that describes the rtnetlink packet itself */
  char reply[IFLIST_REPLY_BUFFER]; /* a large buffer to receive lots of link information */

  pid_t pid = getpid();	     /* our process ID to build the correct netlink address */
  int end = 0;		     /* some flag to end loop parsing */

  fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

  memset(&rtnl_msg, 0, sizeof(rtnl_msg));
  memset(&req, 0, sizeof(req));

  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  req.hdr.nlmsg_type = RTM_GETROUTE;
  req.hdr.nlmsg_flags = NLM_F_REQUEST; 
  req.r.rtm_family = AF_INET; 

//  char ipaddr[16];
//  strcpy(ipaddr, argv[1]);
//  strcpy(ipaddr, "10.0.0.22");
  __u8 cp[]={10,1,0,22};
  __u8 *ap;
  int i;

  addattr_l(&req.hdr, sizeof(req), RTA_DST, cp, 4);

  io.iov_base = &req;
  io.iov_len = req.hdr.nlmsg_len;
  rtnl_msg.msg_iov = &io;
  rtnl_msg.msg_iovlen = 1;

  sendmsg(fd, (struct msghdr *) &rtnl_msg, 0);

  /* parse reply */

  {
    int len;
    struct nlmsghdr *msg_ptr;	/* pointer to current message part */
  
    struct msghdr rtnl_reply;	/* generic msghdr structure for use with recvmsg */
    struct iovec io_reply;

    memset(&io_reply, 0, sizeof(io_reply));
    memset(&rtnl_reply, 0, sizeof(rtnl_reply));
      
    io.iov_base = reply;
    io.iov_len = IFLIST_REPLY_BUFFER;
    rtnl_reply.msg_iov = &io;
    rtnl_reply.msg_iovlen = 1;
    
    len = recvmsg(fd, &rtnl_reply, 0); /* read as much data as fits in the receive buffer */
    msg_ptr = (struct nlmsghdr *) reply;
    rtnl_print_route(msg_ptr);
  }
  
  close(fd);

  return 0;
}
