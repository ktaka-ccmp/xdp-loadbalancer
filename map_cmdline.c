/*
 * Copyright (c) 2016 Facebook
 * Copyright (c) 2018 Cluster Computing Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#include <linux/bpf.h>
#include <linux/if_link.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <unistd.h>
#include <time.h>
#include "bpf_load.h"
#include "libbpf.h"
#include "bpf_util.h"
#include "map_common.h"

#define STATS_INTERVAL_S 2U

#include <net/if.h>

static char ifname_buf[IF_NAMESIZE];
static char *ifname = NULL;

static int ifindex = -1;
static __u64 xdp_flags = 0;

static void usage(const char *cmd)
{
	printf("Usage: %s [...]\n", cmd);
	printf("    -i Interface name\n");
	printf("    -A <vip-service-address> IPv4 or IPv6\n");
	printf("    -h Display this help\n");
}

static int parse_ipstr(const char *ipstr, unsigned int *addr)
{
	if (inet_pton(AF_INET6, ipstr, addr) == 1) {
		return AF_INET6;
	} else if (inet_pton(AF_INET, ipstr, addr) == 1) {
		addr[1] = addr[2] = addr[3] = 0;
		return AF_INET;
	}

	fprintf(stderr, "%s is an invalid IP\n", ipstr);
	return AF_UNSPEC;
}

int open_bpf_map(const char *file)
{
  int fd;

  fd = bpf_obj_get(file);
  if (fd < 0) {
    printf("ERR: Failed to open bpf map file:%s err(%d):%s\n",
	   file, errno, strerror(errno));
    exit(EXIT_FAIL_MAP_FILE);
  }
  return fd;
}

__u64 conv(char ipadr[])
{
  __u64 num=0,val;
  char *tok,*ptr;
  tok=strtok(ipadr,".");
  while( tok != NULL)
    {
      val=strtoul(tok,&ptr,0);
      num=(num << 8) + val;
      //      printf("(val,num)=(%llu,%llu)\n",val,num);
      tok=strtok(NULL,".");
    }
  return(num);
}


static void add_to_map(int fd, struct vip *vip , __u64 *head){
  __u64 key = *head , next, min, ipint;
  char ip_txt[INET_ADDRSTRLEN] = {0};
  
  assert(inet_ntop(vip->family, &vip->daddr.v4, ip_txt, sizeof(ip_txt)));
  ipint = conv(ip_txt);
  //  printf("head = %llu\n", *head);
  //    printf("ipint = %llu\n", ipint);

  //  printf("result = %d\n", bpf_map_lookup_elem(fd, &ipint, &next));
  //  return;

  if ( bpf_map_lookup_elem(fd, &ipint, &next) == 0 ){
    printf("Worker already exists!\n");
    return;
  }
  
  if ( bpf_map_lookup_elem(fd, &key, &next) == -1 ){
    next = key;
    assert(bpf_map_update_elem(fd, &key, &next, BPF_NOEXIST) == 0 );
  }
  
  if ( next == key ){
    assert(bpf_map_update_elem(fd, &key, &ipint, BPF_ANY) == 0 );
    assert(bpf_map_update_elem(fd, &ipint, &key,  BPF_ANY) == 0 );
    return;
    
    //min = ( ipint < key ) ? ipint : key ;
  } else if (key > next){
    min = next;
  } else {
    while (key < next){
      key = next;
      bpf_map_lookup_elem(fd, &key, &next);
    }
    min = next;
  }

  key = min;
  bpf_map_lookup_elem(fd, &key, &next);
  printf("hello3 (key, value) = (%llu,%llu)\n" , key, next);

  if ( ipint < min ){
    assert(bpf_map_update_elem(fd, &ipint, &min, BPF_ANY) == 0 );

    while (next != min){
      key = next;
      bpf_map_lookup_elem(fd, &key, &next);
    }

    printf("hello1 (key, value) = (%llu,%llu)\n" , key, next);
    
    assert(bpf_map_update_elem(fd, &key, &ipint, BPF_ANY) == 0);
    min = ipint;
    return;

  } else {
    if (( key < ipint) && ( ipint < next )){
      assert(bpf_map_update_elem(fd, &key, &ipint, BPF_ANY) == 0);
      assert(bpf_map_update_elem(fd, &ipint, &next, BPF_ANY) == 0);
      return;
      
    } else {
    
      while ( next !=  min ){
	key = next;
	bpf_map_lookup_elem(fd, &key, &next);
	if ((key < ipint) && ( ipint < next )){
	  assert(bpf_map_update_elem(fd, &key, &ipint, BPF_ANY) == 0);
	  assert(bpf_map_update_elem(fd, &ipint, &next, BPF_ANY) == 0);
	printf("hello5 (key, value) = (%llu,%llu)\n" , key, next);
	  return;
	} else if (ipint > next){
	  assert(bpf_map_update_elem(fd, &key, &ipint, BPF_ANY) == 0);
	  assert(bpf_map_update_elem(fd, &ipint, &next, BPF_ANY) == 0);
	printf("hello2 (key, value) = (%llu,%llu)\n" , key, next);
	  return;
	}
      }
    }
  }
}

static void list_map_all(int fd, __u64 *head){

  __u64 key = *head, next_key;
  __u64 next;

  assert(bpf_map_lookup_elem(fd, &key, &next) == 0);

  printf("(key, value) = (%llu,%llu)\n" , key, next);

  while (next != *head){
    key = next;
    assert(bpf_map_lookup_elem(fd, &key, &next) == 0);
    printf("(key, value) = (%llu,%llu)\n" , key, next);
    if (key == next) return;
  }
}

int main(int argc, char **argv)
{
	const char *optstr = "i:A:Lh";
	struct vip vip = {};
	int opt;
	__u64 next, head;
	//	char ip_txt[INET_ADDRSTRLEN] = {0};
	
	int fd_testmap;
	bool do_list = true;
	
        unsigned int action = 0;
	
	vip.family = AF_UNSPEC;

	while ((opt = getopt(argc, argv, optstr)) != -1) {
		unsigned short family;
		unsigned int *v6;

		switch (opt) {
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
		  action |= ACTION_ADD;
		  vip.family = parse_ipstr(optarg, vip.daddr.v6);
		  if (vip.family == AF_UNSPEC)
		    return 1;
		  break;
		case 'L':
		  vip.family = parse_ipstr(optarg, vip.daddr.v6);
		  if (vip.family == AF_UNSPEC)
		    return 1;
		  break;
		error:
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (ifindex == -1) {
	  printf("ERR: required option -i missing");
	  usage(argv[0]);
	  return EXIT_FAIL_OPTION;
	}

	
	fd_testmap = open_bpf_map(file_testmap);

	head = 100;
	//	next = head;
	//	bpf_map_update_elem(fd_testmap, &head, &next, BPF_NOEXIST);

	if (action == ACTION_ADD) {

	  add_to_map(fd_testmap, &vip, &head);

	} else if (action == ACTION_DEL) {
	  ; //	    bpf_map_delete_elem(fd_vip2tnl, &vip);
	}

	if (do_list) {
	  list_map_all(fd_testmap, &head);
	}

	close(fd_testmap);


	return 0;
}
