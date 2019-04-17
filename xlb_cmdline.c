/*
 * Copyright (c) 2016 Facebook
 * Copyright (c) 2018 Cluster Computing Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#include "rmi.h"
#include "xlb_util.h"

#define STATS_INTERVAL_S 2U

static char ifname_buf[IF_NAMESIZE];
static char *ifname = NULL;

static int ifindex = -1;
static __u32 xdp_flags = 0;

static void usage(const char *cmd)
{
	printf("xlb_cmdline: Xdp Load Balancer command line utility.\n"
	       "The xlb encapsulate incomming packet toward <VIP:PORT> in an IPv4 header and XDP_TX it out.\n"
	       "The workers are selected by a round robin manner.\n\n");
	printf("Usage: %s [...]\n", cmd);
	printf("    -i Interface name(eg. eth0)\n");
	printf("    -A ServiceIP(a.k.a. VIP)\n");
	printf("    -t (for TCP, optional, default)\n");
	printf("    -u (for UDP, optional)\n");
	printf("    -r WorkerIP\n");
	printf("    -v verbose\n");
	printf("    -L list lb table\n");
	printf("    -l list lbcache\n");
	printf("    -h Display this help\n");
}

int main(int argc, char **argv)
{
  const char *optstr = "i:A:D:a:d:r:p:SLlvhut";
  int port = 0;
  struct iptnl_info tnl = {};
  struct vip vip = {};
  int opt;
	
  int fd_service, fd_linklist, fd_worker, fd_svcid;
  
  bool do_list = false;
  bool monitor = false;
	
  enum action action = ACTION_LIST;
	
  tnl.family = AF_UNSPEC;
  vip.protocol = IPPROTO_TCP;


  while ((opt = getopt(argc, argv, optstr)) != -1) {
    unsigned short family;
    unsigned int *v6;

    switch (opt) {
    case 'v':
      verbose = 1;
      break;
    case 'i':
      if (strlen(optarg) >= IF_NAMESIZE) {
	fprintf(stderr, "ERR: Intereface name too long\n");
	goto error;
      }
      ifname = (char *)&ifname_buf;
      strncpy(ifname, optarg, IF_NAMESIZE);
      ifindex = if_nametoindex(ifname);
      if (ifindex == 0) {
	fprintf(stderr,
		"ERR: Interface name unknown err(%d):%s\n",
		errno, strerror(errno));
	goto error;
      }
      break;
    case 'A':
      action = ACTION_ADD_SVC;
      vip.family = parse_ipstr(optarg, vip.daddr.v6);
      if (vip.family == AF_UNSPEC)
	return 1;
      break;
    case 'D':
      action = ACTION_DEL_SVC;
      vip.family = parse_ipstr(optarg, vip.daddr.v6);
      if (vip.family == AF_UNSPEC)
	return 1;
      break;
    case 'a':
      action = ACTION_ADD_REAL;
      vip.family = parse_ipstr(optarg, vip.daddr.v6);
      if (vip.family == AF_UNSPEC)
	return 1;
      break;
    case 'd':
      action = ACTION_DEL_REAL;
      vip.family = parse_ipstr(optarg, vip.daddr.v6);
      if (vip.family == AF_UNSPEC)
	return 1;
      break;
    case 'L':
      do_list = true;
      break;
    case 'l':
      monitor = true;
      break;
    case 'u':
      vip.protocol = IPPROTO_UDP;
      break;
    case 't':
      vip.protocol = IPPROTO_TCP;
      break;
    case 'p':
      if (parse_port(optarg, &port))
	return 1;
      break;
    case 'r':
      v6 = tnl.daddr.v6;

      family = parse_ipstr(optarg, v6);
      if (family == AF_UNSPEC)
	return 1;
      if (tnl.family == AF_UNSPEC) {
	tnl.family = family;
      } else if (tnl.family != family) {
	fprintf(stderr,
		"The IP version of the src and dst addresses used in the IP encapsulation does not match\n");
	return 1;
      }
      break;
    case 'S':
      xdp_flags |= XDP_FLAGS_SKB_MODE;
      break;
    error:
    default:
      usage(argv[0]);
      return 1;
    }
    //		opt_flags[opt] = 0;
  }


  if (ifindex == -1) {
    printf("ERR: required option -i missing");
    usage(argv[0]);
    return EXIT_FAIL_OPTION;
  }

  vip.dport = htons(port);

  if (action == ACTION_ADD_SVC) {
    xlb_add_svc(&vip);
  } else if (action == ACTION_DEL_SVC) {
    xlb_del_svc(&vip);
  } else if (action == ACTION_ADD_REAL) {
    xlb_add_real(&vip, &tnl);
  } else if (action == ACTION_DEL_REAL) {
    xlb_del_real(&vip, &tnl);
  }

  if (DEBUG||verbose||do_list) {
    list_all();
  }

  if (verbose) {
    service_list_all();
    linklist_list_all();
    worker_list_all();
    svcid_list_all();
  }

  if (monitor) {
    list_lbcache();
  }

  return 0;
}
