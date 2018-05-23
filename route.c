#include "rmi.h"

int xlb_parse_route(struct nlmsghdr *nlh, __u8 *src, __u8 *next, int *dev)
{
    struct  rtmsg *route_entry;
    struct  rtattr *route_attribute; 
    int     route_attribute_len = 0;
    unsigned char    route_netmask = 0;
    unsigned char    route_protocol = 0;
    char    dst_ip[32];
    char    gw_ip[32];
    char    src_ip[32];
    int i, via = 0;
    __u8 *addr;
    
    route_entry = (struct rtmsg *) NLMSG_DATA(nlh);

    if (route_entry->rtm_table != RT_TABLE_MAIN)
      return 1;

    route_netmask = route_entry->rtm_dst_len;
    route_protocol = route_entry->rtm_protocol;
    route_attribute = (struct rtattr *) RTM_RTA(route_entry);
    route_attribute_len = RTM_PAYLOAD(nlh);

    for ( ; RTA_OK(route_attribute, route_attribute_len);		\
	  route_attribute = RTA_NEXT(route_attribute, route_attribute_len))
      {

        if (route_attribute->rta_type == RTA_DST)
	  {
            if(DEBUG) inet_ntop(AF_INET, RTA_DATA(route_attribute), dst_ip, sizeof(dst_ip));
	    if (via == 0)
	      memcpy(next, RTA_DATA(route_attribute), 4);
	  }

        if (route_attribute->rta_type == RTA_GATEWAY)
	  {
	    if(DEBUG) inet_ntop(AF_INET, RTA_DATA(route_attribute), gw_ip, sizeof(gw_ip));
	    memcpy(next, RTA_DATA(route_attribute), 4);
	    via = 1;
	  }

        if (route_attribute->rta_type == RTA_PREFSRC)
	  {
	    if(DEBUG) inet_ntop(AF_INET, RTA_DATA(route_attribute), src_ip, sizeof(src_ip));
	    memcpy(src, RTA_DATA(route_attribute), 4);
	  }
	
	if (route_attribute->rta_type == RTA_OIF)
	  {
	    memcpy(dev, RTA_DATA(route_attribute), sizeof(int));
	  }
      }

    if(DEBUG) 
      printf("route to destination --> %s/%d proto %d and gateway %s\n src=%s\n", \
	   dst_ip, route_netmask, route_protocol, gw_ip,src_ip);

    return 0;
}

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

//static int xlb_iproute_get(char *dst_ip, __u8 *src , __u8 *next, int *dev)
int xlb_iproute_get(char *dst_ip, __u8 *src , __u8 *next, int *dev)
{
  struct msghdr rtnl_msg;
  struct iovec io;
  int fd;
  __u32 addr;
    
  struct {
    struct nlmsghdr	n;
    struct rtmsg		r;
    char			buf[1024];
  } req;

  memset(&rtnl_msg, 0, sizeof(rtnl_msg));
  memset(&req, 0, sizeof(req));

  req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  req.n.nlmsg_flags = NLM_F_REQUEST;
  req.n.nlmsg_type = RTM_GETROUTE;
  req.r.rtm_family = AF_INET;

  inet_pton(AF_INET, dst_ip , &addr); 

  addattr_l(&req.n, sizeof(req), RTA_DST, &addr, 4);
	
  io.iov_base = &req;
  io.iov_len = req.n.nlmsg_len;
  rtnl_msg.msg_iov = &io;
  rtnl_msg.msg_iovlen = 1;

  fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  sendmsg(fd, (struct msghdr *) &rtnl_msg, 0);

  /* parse reply */

  {
    int len;
    struct nlmsghdr *answer;
    struct msghdr rtnl_reply;
    struct iovec io_reply;
    char reply[IFLIST_REPLY_BUFFER];

    
    memset(&io_reply, 0, sizeof(io_reply));
    memset(&rtnl_reply, 0, sizeof(rtnl_reply));
      
    io.iov_base = reply;
    io.iov_len = IFLIST_REPLY_BUFFER;
    rtnl_reply.msg_iov = &io;
    rtnl_reply.msg_iovlen = 1;
    
    len = recvmsg(fd, &rtnl_reply, 0);
    answer = (struct nlmsghdr *) reply;
    //    rtnl_print_route(msg_ptr);

    xlb_parse_route(answer, src, next, dev);
  }
  
  close(fd);

  return 0;
}

