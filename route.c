#include "rmi.h"

int xlb_parse_route(struct nlmsghdr *nlh, in_addr_t *src_ip, in_addr_t *nh_ip, int *dev)
{
    struct  rtmsg *route_entry;
    struct  rtattr *route_attribute; 
    int     route_attribute_len = 0;
    //    unsigned char route_netmask = 0;
    //    unsigned char route_protocol = 0;
    int  via = 0;
    
    route_entry = (struct rtmsg *) NLMSG_DATA(nlh);

    if (route_entry->rtm_table != RT_TABLE_MAIN)
      return 1;

    //    route_netmask = route_entry->rtm_dst_len;
    //    route_protocol = route_entry->rtm_protocol;
    route_attribute = (struct rtattr *) RTM_RTA(route_entry);
    route_attribute_len = RTM_PAYLOAD(nlh);

    for ( ; RTA_OK(route_attribute, route_attribute_len);		\
	  route_attribute = RTA_NEXT(route_attribute, route_attribute_len))
      {

        if (route_attribute->rta_type == RTA_DST)
	    if (via == 0)
	      memcpy(nh_ip, RTA_DATA(route_attribute), 4);

        if (route_attribute->rta_type == RTA_GATEWAY)
	  {
	    memcpy(nh_ip, RTA_DATA(route_attribute), 4);
	    via = 1;
	  }

        if (route_attribute->rta_type == RTA_PREFSRC)
	    memcpy(src_ip, RTA_DATA(route_attribute), 4);
	
	if (route_attribute->rta_type == RTA_OIF)
	    memcpy(dev, RTA_DATA(route_attribute), sizeof(int));
      }

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

int xlb_iproute_get(in_addr_t *dst_ip, in_addr_t *src_ip , in_addr_t *nh_ip, int *dev)
{
  struct msghdr rtnl_msg;
  struct iovec io;
  int fd;
    
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


  addattr_l(&req.n, sizeof(req), RTA_DST, dst_ip, 4);
	
  io.iov_base = &req;
  io.iov_len = req.n.nlmsg_len;
  rtnl_msg.msg_iov = &io;
  rtnl_msg.msg_iovlen = 1;

  fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  sendmsg(fd, (struct msghdr *) &rtnl_msg, 0);

  /* parse reply */

  {
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
    
    recvmsg(fd, &rtnl_reply, 0);
    answer = (struct nlmsghdr *) reply;

    xlb_parse_route(answer, src_ip, nh_ip, dev);
  }
  
  close(fd);

  return 0;
}

