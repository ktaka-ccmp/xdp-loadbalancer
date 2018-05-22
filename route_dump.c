/* 
   iflist.c : retrieve network interface information thru netlink sockets

   (c) Jean Lorchat @ Internet Initiative Japan - Innovation Institute

   v1.0 : initial version - Feb 19th 2010

   This file was obtained at the following address :
   http://www.iijlab.net/~jean/iflist.c

   Find out more on the blog post :
   http://iijean.blogspot.com/2010/03/howto-get-list-of-network-interfaces-in.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <unistd.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#define IFLIST_REPLY_BUFFER	8192

/* 
   define the message structure : 
     . a netlink message
     . a "general form of address family dependent" message, 
       i.e. how to tell which AF we are interested in
*/

typedef struct nl_req_s nl_req_t;  

struct nl_req_s {
  struct nlmsghdr hdr;
  struct rtmsg	r;
  //struct rtgenmsg gen;
  char      buf[1025];
};

void
rtnl_print_link(struct nlmsghdr *h)
{
  struct ifinfomsg *iface;
  struct rtattr *attribute;
  int len;

  iface = NLMSG_DATA(h);
  len = h->nlmsg_len - NLMSG_LENGTH(sizeof(*iface));

  /* loop over all attributes for the NEWLINK message */
  for (attribute = IFLA_RTA(iface); RTA_OK(attribute, len); attribute = RTA_NEXT(attribute, len))
    {
      switch(attribute->rta_type)
	{
	case IFLA_IFNAME:
	  printf("Interface %d : %s\n", iface->ifi_index, (char *) RTA_DATA(attribute));
	  break;
	default:
	  break;
	}
    }
}

rtnl_print_route(struct nlmsghdr *nlh)
{
    struct  rtmsg *route_entry;  /* This struct represent a route entry \
                                    in the routing table */
    struct  rtattr *route_attribute; /* This struct contain route \
                                            attributes (route type) */
    int     route_attribute_len = 0;
    unsigned char    route_netmask = 0;
    unsigned char    route_protocol = 0;
    char    destination_address[32];
    char    gateway_address[32];

	printf("here we are\n");
	route_entry = (struct rtmsg *) NLMSG_DATA(nlh);

	if (route_entry->rtm_table != RT_TABLE_MAIN)
		return;

	route_netmask = route_entry->rtm_dst_len;
	route_protocol = route_entry->rtm_protocol;
    route_attribute = (struct rtattr *) RTM_RTA(route_entry);
    /* Get the route atttibutes len */
    route_attribute_len = RTM_PAYLOAD(nlh);
    /* Loop through all attributes */
    for ( ; RTA_OK(route_attribute, route_attribute_len); \
        route_attribute = RTA_NEXT(route_attribute, route_attribute_len))
    {
		printf("route attribute type: %d\n", route_attribute->rta_type);
        /* Get the destination address */
        if (route_attribute->rta_type == RTA_DST)
        {
            inet_ntop(AF_INET, RTA_DATA(route_attribute), \
                    destination_address, sizeof(destination_address));
        }
        /* Get the gateway (Next hop) */
        if (route_attribute->rta_type == RTA_GATEWAY)
        {
            inet_ntop(AF_INET, RTA_DATA(route_attribute), \
                    gateway_address, sizeof(gateway_address));
        }
    }
	printf("route to destination --> %s/%d proto %d and gateway %s\n", \
         destination_address, route_netmask, route_protocol, gateway_address);

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

int
main(int argc, char **argv)
{
  int fd;
  struct sockaddr_nl local;  /* our local (user space) side of the communication */
  struct sockaddr_nl kernel; /* the remote (kernel space) side of the communication */
 
  struct msghdr rtnl_msg;    /* generic msghdr struct for use with sendmsg */
  struct iovec io;	     /* IO vector for sendmsg */

  nl_req_t req;              /* structure that describes the rtnetlink packet itself */
  char reply[IFLIST_REPLY_BUFFER]; /* a large buffer to receive lots of link information */

  pid_t pid = getpid();	     /* our process ID to build the correct netlink address */
  int end = 0;		     /* some flag to end loop parsing */

  /* 
     prepare netlink socket for kernel/userland communication 
     we are interested in the ROUTE flavor. 

     There are others like XFRM, but to deal with links, addresses and obviously routes,
     you have to use NETLINK_ROUTE.
     
   */

  fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

  memset(&local, 0, sizeof(local)); /* fill-in local address information */
  local.nl_family = AF_NETLINK;
  local.nl_pid = pid;
  local.nl_groups = 0;
  //local.nl_groups = RTMGRP_IPV4_ROUTE;

  if (bind(fd, (struct sockaddr *) &local, sizeof(local)) < 0)
    {
      perror("cannot bind, are you root ? if yes, check netlink/rtnetlink kernel support");
      return -1;
    }

  /* RTNL socket is ready for use, prepare and send request */

printf("hello0\n");

  memset(&rtnl_msg, 0, sizeof(rtnl_msg));
  memset(&kernel, 0, sizeof(kernel));
  memset(&req, 0, sizeof(req));

  kernel.nl_family = AF_NETLINK; /* fill-in kernel address (destination of our message) */
  kernel.nl_groups = 0;

//  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  req.hdr.nlmsg_type = RTM_GETROUTE;
//  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP; 
  req.hdr.nlmsg_flags = NLM_F_REQUEST; 
  req.hdr.nlmsg_seq = 1;
  req.hdr.nlmsg_pid = pid;
//  req.gen.rtgen_family = AF_INET; 
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
  rtnl_msg.msg_name = &kernel;
  rtnl_msg.msg_namelen = sizeof(kernel);

  sendmsg(fd, (struct msghdr *) &rtnl_msg, 0);

  /* parse reply */

  while (!end)
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
      rtnl_reply.msg_name = &kernel;
      rtnl_reply.msg_namelen = sizeof(kernel);

      len = recvmsg(fd, &rtnl_reply, 0); /* read as much data as fits in the receive buffer */
      if (len)
	{
	  for (msg_ptr = (struct nlmsghdr *) reply; NLMSG_OK(msg_ptr, len); msg_ptr = NLMSG_NEXT(msg_ptr, len))
	    {
	      switch(msg_ptr->nlmsg_type)
		{
		case 3:		/* this is the special meaning NLMSG_DONE message we asked for by using NLM_F_DUMP flag */
		  end++;
		  break;
		case 16:	/* this is a RTM_NEWLINK message, which contains lots of information about a link */
		  rtnl_print_link(msg_ptr);
		  break;
		case 24:
		  rtnl_print_route(msg_ptr);
		  break;
		default:	/* for education only, print any message that would not be DONE or NEWLINK, 
				   which should not happen here */
		  printf("message type %d, length %d\n", msg_ptr->nlmsg_type, msg_ptr->nlmsg_len);
		  break;
		}
	    }
	}
      
    }

  /* clean up and finish properly */

  close(fd);

  return 0;
}
