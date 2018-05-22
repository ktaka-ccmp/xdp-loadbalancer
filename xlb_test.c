/*
 * iproute.c		"ip route".
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 */

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

#include "rt_names.h"
#include "utils.h"
#include "ip_common.h"

#include <net/if_arp.h>
#include <sys/ioctl.h>

#ifndef RTAX_RTTVAR
#define RTAX_RTTVAR RTAX_HOPS
#endif

enum list_action {
	IPROUTE_LIST,
	IPROUTE_FLUSH,
	IPROUTE_SAVE,
};

struct rtnl_handle rth = { .fd = -1 };
int preferred_family = AF_UNSPEC;

static struct
{
	unsigned int tb;
	int cloned;
	int flushed;
	char *flushb;
	int flushp;
	int flushe;
	int protocol, protocolmask;
	int scope, scopemask;
	__u64 typemask;
	int tos, tosmask;
	int iif, iifmask;
	int oif, oifmask;
	int mark, markmask;
	int realm, realmmask;
	__u32 metric, metricmask;
	inet_prefix rprefsrc;
	inet_prefix rvia;
	inet_prefix rdst;
	inet_prefix mdst;
	inet_prefix rsrc;
	inet_prefix msrc;
} filter;

int xlb_parse_route(struct nlmsghdr *n, __u8 *src, __u8 *next, int *dev)
{
	struct rtmsg *r = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr *tb[RTA_MAX+1];
	int host_len;
	__u8 *addr; int i;

	len -= NLMSG_LENGTH(sizeof(*r));
	host_len = af_bit_len(r->rtm_family);
	parse_rtattr(tb, RTA_MAX, RTM_RTA(r), len);

			
	if (tb[RTA_GATEWAY] && filter.rvia.bitlen != host_len) {
	  addr = RTA_DATA(tb[RTA_GATEWAY]);
	  for(i=0 ; i < RTA_PAYLOAD(tb[RTA_GATEWAY]) ; i++ ){ 
	    *next = *addr; addr++ ; next++;
	  }
	} else if (tb[RTA_DST]) {
	  addr = RTA_DATA(tb[RTA_DST]);
	  for(i=0 ; i < RTA_PAYLOAD(tb[RTA_DST]) ; i++ ){ 
	    *next = *addr; addr++ ; next++;
	  }
	}
	
	if (tb[RTA_PREFSRC] && filter.rprefsrc.bitlen != host_len) {
	  addr = RTA_DATA(tb[RTA_PREFSRC]);
	  for(i=0 ; i < RTA_PAYLOAD(tb[RTA_PREFSRC]) ; i++ ){ 
	    *src = *addr; addr++ ; src++;
	  }
	}

	if (tb[RTA_OIF] && filter.oifmask != -1)
	  *dev = rta_getattr_u32(tb[RTA_OIF]);
	  
	return 0;
}

static int xlb_iproute_get(char *dst_ip, __u8 *src , __u8 *next, int *dev)
{
	struct {
		struct nlmsghdr	n;
		struct rtmsg		r;
		char			buf[1024];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
		.n.nlmsg_flags = NLM_F_REQUEST,
		.n.nlmsg_type = RTM_GETROUTE,
		.r.rtm_family = preferred_family,
	};
	struct nlmsghdr *answer;

	inet_prefix addr;

	get_prefix(&addr, dst_ip, req.r.rtm_family);
	if (addr.bytelen)
	  addattr_l(&req.n, sizeof(req),
		    RTA_DST, &addr.data, addr.bytelen);

	if (req.r.rtm_family == AF_UNSPEC)
		req.r.rtm_family = AF_INET;
	
	if (rtnl_open(&rth, 0) < 0) {
	  fprintf(stderr, "Cannot open rtnetlink\n");
	  return EXIT_FAILURE;
	}

	if (rtnl_talk(&rth, &req.n, &answer) < 0)
	  return -2;

	rtnl_close(&rth);

	xlb_parse_route(answer, src, next, dev);
	  
	free(answer);
	return 0;
}

static int xlb_get_mac(__u8 *host, __u8 *mac, int *dev){
  int s;

  struct arpreq req;
  struct sockaddr_in *sin;
  static char buf[256];

  //  char *host = argv[1];

  bzero((caddr_t)&req, sizeof(req));

  sin = (struct sockaddr_in *)&req.arp_pa;
  sin->sin_family = AF_INET; /* Address Family: Internet */
  sin->sin_addr.s_addr = inet_addr(inet_ntop(AF_INET, host, buf, 256));
  //  sin->sin_addr.s_addr = host;

  if((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
    perror("socket() failed.");
    exit(-1);
  } /* Socket is opened.*/

  strcpy(req.arp_dev, "eth0");

  if(ioctl(s, SIOCGARP, (caddr_t)&req) <0){
    if(errno == ENXIO){
      printf("%s - no entry.\n", inet_ntop(AF_INET, host, buf, 256));
      printf("%lu - no entry.\n", *host);
      exit(-1);
    } else {
      perror("SIOCGARP");
      exit(-1);
    }
  }

  int i;
  char *tmp;
  tmp = req.arp_ha.sa_data;
  
  for(i=0 ; i < 6 ; i++ ){ 
    *mac = *tmp;
    mac++; tmp++;
  }

  return(0);
}


int main(int argc, char *argv[])
{
  char ipaddr[16];
  strcpy(ipaddr, argv[1]);
  //  strcpy(ipaddr, "10.0.0.22");

  __u8 src[4], nexthop[4], mac[6];
  int dev=0;
  
  xlb_iproute_get(ipaddr,src,nexthop, &dev);

  xlb_get_mac(nexthop, mac , &dev);

  static char buf[256];
  printf("src: %s \n", inet_ntop(AF_INET, src, buf, 256));
  printf("nexthop: %s \n", inet_ntop(AF_INET, nexthop, buf, 256));
  printf("dev: %d \n", dev);

  char mac_txt[6] = {0};
  ether_ntoa_r((struct ether_addr *)mac, mac_txt);
  printf("mac: %s\n", mac_txt );

}
