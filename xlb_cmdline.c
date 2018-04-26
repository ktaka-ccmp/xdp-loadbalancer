/* Copyright (c) 2016 Facebook
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
#include "xlb_common.h"

#define STATS_INTERVAL_S 2U

#include <net/if.h>

static char ifname_buf[IF_NAMESIZE];
static char *ifname = NULL;

static int ifindex = -1;
static __u32 xdp_flags = 0;

static void usage(const char *cmd)
{
	printf("Start a XDP prog which encapsulates incoming packets\n"
	       "in an IPv4/v6 header and XDP_TX it out.  The dst <VIP:PORT>\n"
	       "is used to select packets to encapsulate\n\n");
	printf("Usage: %s [...]\n", cmd);
	printf("    -i Interface name\n");
	printf("    -A <vip-service-address> IPv4 or IPv6\n");
	printf("    -t or -u <vip-service-port> A port range (e.g. 433-444) is also allowed\n");
	printf("    -s <source-ip> Used in the IPTunnel header\n");
	printf("    -d <dest-ip> Used in the IPTunnel header\n");
	printf("    -m <dest-MAC> Used in sending the IP Tunneled pkt\n");
	printf("    -S use skb-mode\n");
	printf("    -v verbose\n");
	printf("    -L list lb table\n");
	printf("    -l list lbcache\n");
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

static int parse_ports(const char *port_str, int *min_port, int *max_port)
{
	char *end;
	long tmp_min_port;
	long tmp_max_port;

	tmp_min_port = strtol(optarg, &end, 10);
	if (tmp_min_port < 1 || tmp_min_port > 65535) {
		fprintf(stderr, "Invalid port(s):%s\n", optarg);
		return 1;
	}

	if (*end == '-') {
		end++;
		tmp_max_port = strtol(end, NULL, 10);
		if (tmp_max_port < 1 || tmp_max_port > 65535) {
			fprintf(stderr, "Invalid port(s):%s\n", optarg);
			return 1;
		}
	} else {
		tmp_max_port = tmp_min_port;
	}

	if (tmp_min_port > tmp_max_port) {
		fprintf(stderr, "Invalid port(s):%s\n", optarg);
		return 1;
	}

	if (tmp_max_port - tmp_min_port + 1 > MAX_IPTNL_ENTRIES) {
		fprintf(stderr, "Port range (%s) is larger than %u\n",
			port_str, MAX_IPTNL_ENTRIES);
		return 1;
	}
	*min_port = tmp_min_port;
	*max_port = tmp_max_port;

	return 0;
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
      //      printf("(val,num)=(%lu,%lu)\n",val,num);
      tok=strtok(NULL,".");
    }
  return(num);
}

static void lnklst_add_to_map(int fd, struct iptnl_info *vip , __u64 *head){
  __u64 key = *head , next, min, max, ipint;
  char ip_txt[INET_ADDRSTRLEN] = {0};

  assert(inet_ntop(vip->family, &vip->daddr.v4, ip_txt, sizeof(ip_txt)));
  ipint = conv(ip_txt);

  if ( bpf_map_lookup_elem(fd, &ipint, &next) == 0 ){
    printf("Worker already exists!\n");
    return;
  }

  if ( bpf_map_lookup_elem(fd, &key, &next) == -1 ){ // 1st entry. Create new.
    next = key;
    assert(bpf_map_update_elem(fd, &key, &next, BPF_NOEXIST) == 0 );

  } else if ( next == key ){ // 2nd entry. Only one entry exists.
    assert(bpf_map_update_elem(fd, &key, &ipint, BPF_ANY) == 0 );
    assert(bpf_map_update_elem(fd, &ipint, &key,  BPF_ANY) == 0 );
    *head = key < ipint ? key : ipint;

  } else {

    // Find minimum
    if (key > next){ // if head is the last entry
      min = next;
      max = key;
    } else {
      while (key < next){
	key = next;
	bpf_map_lookup_elem(fd, &key, &next);
      }
      max = key;
      min = next;
    }

    *head = min;

    if (( ipint < min )||( max < ipint )){ // new entry is the smallest or the largest

      assert(bpf_map_update_elem(fd, &ipint, &min, BPF_ANY) == 0 );
      assert(bpf_map_update_elem(fd, &max, &ipint, BPF_ANY) == 0 ); // update tail

      *head = min < ipint ? min : ipint;

    } else if ( min < ipint < max ){

      key = min;
      bpf_map_lookup_elem(fd, &key, &next);

      while ( next < ipint ){ // find the key where (key < ipint < next)
	key = next;
	bpf_map_lookup_elem(fd, &key, &next);
      }
      assert(bpf_map_update_elem(fd, &key, &ipint, BPF_ANY) == 0);
      assert(bpf_map_update_elem(fd, &ipint, &next, BPF_ANY) == 0);
    }

  }
}

static void vip2tnl_list_all()
{
  int fd;
  struct vip key = {}, next_key;
  struct iptnl_info value;
  char ip_txt[INET_ADDRSTRLEN] = {0};
  char mac_txt[ETHER_ADDR_LEN] = {0};

  fd = open_bpf_map(file_vip2tnl);
  
  while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
    bpf_map_lookup_elem(fd, &next_key, &value);

    assert(inet_ntop(next_key.family, &next_key.daddr.v4, ip_txt, sizeof(ip_txt)));
    printf("{\nVIP: %s\n" , ip_txt);
    printf("%d\n", next_key.protocol );
    printf("%d\n", ntohs(next_key.dport));

    assert(inet_ntop(value.family, &value.saddr.v4, ip_txt, sizeof(ip_txt)));
    printf("src: %s\n", ip_txt );
    assert(inet_ntop(value.family, &value.daddr.v4, ip_txt, sizeof(ip_txt)));
    printf("dst: %s\n", ip_txt );
    assert(ether_ntoa_r(&value.dmac, mac_txt));
    printf("mac: %s\n}\n", mac_txt );
    key = next_key;
  }
  close(fd);
}

static void service_list_all()
{

  struct vip key = {}, next_key;
  __u64 head;
  char ip_txt[INET_ADDRSTRLEN] = {0};

  int fd = open_bpf_map(file_service);
  
  while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
    bpf_map_lookup_elem(fd, &key, &head);
    
    assert(inet_ntop(next_key.family, &next_key.daddr.v4, ip_txt, sizeof(ip_txt)));
    printf("{\nVIP: %s\n" , ip_txt);
    printf("%d\n", next_key.protocol );
    printf("%d\n", ntohs(next_key.dport));
    printf("head = %lu\n}\n", head);

    key = next_key;
  }

  close(fd);
}

static void worker_list_all()
{
  __u64 key = 0, next_key;
  struct iptnl_info value;
  char ip_txt[INET_ADDRSTRLEN] = {0};
  char mac_txt[ETHER_ADDR_LEN] = {0};

  int fd = open_bpf_map(file_worker);
  
  while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
    bpf_map_lookup_elem(fd, &next_key, &value);

    printf("{\nkey: %lu\n" , next_key);

    assert(inet_ntop(value.family, &value.saddr.v4, ip_txt, sizeof(ip_txt)));
    printf("src: %s\n", ip_txt );
    assert(inet_ntop(value.family, &value.daddr.v4, ip_txt, sizeof(ip_txt)));
    printf("dst: %s\n", ip_txt );
    assert(ether_ntoa_r(&value.dmac, mac_txt));
    printf("mac: %s\n}\n", mac_txt );
    key = next_key;
  }

  close(fd);
}

static void linklist_list_all(){

  __u64 key = 0, next_key;
  __u64 value;

  int fd = open_bpf_map(file_linklist);

  while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
    key = next_key;
    bpf_map_lookup_elem(fd, &key, &value);
    printf("(key, value) = (%lu,%Lu)\n" , key, value);
  }
  close(fd);
}

static void linklist_list_all_old( __u64 *head){

  __u64 key = *head, next_key;
  __u64 next;

  int fd = open_bpf_map(file_linklist);

  assert(bpf_map_lookup_elem(fd, &key, &next) == 0);

  printf("(key, value) = (%lu,%lu)\n" , key, next);

  while (next != *head){
    key = next;
    assert(bpf_map_lookup_elem(fd, &key, &next) == 0);
    printf("(key, value) = (%lu,%lu)\n" , key, next);
    if (key == next) return;
  }

  close(fd);
}

static void show_worker( __u64 *key){

  struct iptnl_info value;
  char daddr_txt[INET_ADDRSTRLEN] = {0};
  char saddr_txt[INET_ADDRSTRLEN] = {0};
  char mac_txt[ETHER_ADDR_LEN] = {0};

  int fd = open_bpf_map(file_worker);
  
  bpf_map_lookup_elem(fd, key, &value);
  assert(inet_ntop(value.family, &value.saddr.v4, saddr_txt, sizeof(saddr_txt)));
  assert(inet_ntop(value.family, &value.daddr.v4, daddr_txt, sizeof(daddr_txt)));
  assert(ether_ntoa_r(&value.dmac, mac_txt));

  if (DEBUG) printf("key: %lu\n", *key);
  /*
  printf("    {\n");
  printf("        src: %s\n", saddr_txt );
  printf("        dst: %s (%s)\n", daddr_txt, mac_txt );
  printf("    }\n");
  */

  printf(" src: %s, dst: %s (%s)\n", saddr_txt, daddr_txt, mac_txt );

  close(fd);
}

static void list_worker_from_head( __u64 *head){

  __u64 key = *head;
  __u64 value = NULL;

  int fd = open_bpf_map(file_linklist);

  printf("{\n");
  while (value != *head){
    show_worker(&key);
    assert(bpf_map_lookup_elem(fd, &key, &value) == 0);
    key = value;
  }
  printf("}\n");

  close(fd);
}

static void list_all()
{
  int fd;
  struct vip key = {}, next_key;
  __u64 head;
  char daddr_txt[INET_ADDRSTRLEN] = {0};

  fd = open_bpf_map(file_service);

  while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
    key = next_key;
    bpf_map_lookup_elem(fd, &key, &head);
    
    assert(inet_ntop(key.family, &key.daddr.v4, daddr_txt, sizeof(daddr_txt)));
    printf("service: %s:%d(%d) " , daddr_txt, ntohs(key.dport), key.protocol);

    if (DEBUG) printf(", head = %lu ", head);

    list_worker_from_head(&head);
  }

  close(fd);
}

static void list_lbcache()
{
  int fd;
  struct flow key = {}, next_key;
  __u64 wkid;

  char daddr_txt[INET_ADDRSTRLEN] = {0};
  char saddr_txt[INET_ADDRSTRLEN] = {0};

  fd = open_bpf_map(file_lbcache);
  int fdw = open_bpf_map(file_worker);

  while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {

    key = next_key;
    bpf_map_lookup_elem(fd, &key, &wkid);

    __u32 test_ip = key.vip.daddr.v4;

    inet_ntop(key.vip.family, &key.vip.daddr.v4, daddr_txt, sizeof(daddr_txt));
    inet_ntop(key.sip.family, &key.sip.saddr.v4, saddr_txt, sizeof(saddr_txt));

    printf(" %s:%d -> %s:%d (%d) => "
	   ,saddr_txt,ntohs(key.sip.sport)
	   ,daddr_txt,ntohs(key.vip.dport)
	   ,key.vip.protocol
	   );

    //    show_worker(&wkid);

    struct iptnl_info value;
    char mac_txt[ETHER_ADDR_LEN] = {0};

    bpf_map_lookup_elem(fdw, &wkid, &value);
    //    inet_ntop(value.family, &value.saddr.v4, saddr_txt, sizeof(saddr_txt));
    //    printf("%s ", w_saddr_txt);
    inet_ntop(value.family, &value.daddr.v4, daddr_txt, sizeof(daddr_txt));
    ether_ntoa_r(&value.dmac, mac_txt);
    printf("%s (%s)\n", daddr_txt, mac_txt );

  }

  close(fdw);
  close(fd);
}

int main(int argc, char **argv)
{
  //	unsigned char opt_flags[256] = {};
	const char *optstr = "i:A:D:u:t:s:d:m:T:P:SLlvh";
	int min_port = 0, max_port = 0;
	struct iptnl_info tnl = {};
	struct vip vip = {};
	int opt;
	
	int fd_vip2tnl, fd_service, fd_linklist, fd_worker;
	__u64 head, daddrint;
	char ip_txt[INET_ADDRSTRLEN] = {0};
  
	bool do_list = false;
	bool monitor = false;
	
        unsigned int action = 0;
	
	tnl.family = AF_UNSPEC;
	vip.protocol = IPPROTO_TCP;

	/*
	for (i = 0; i < strlen(optstr); i++)
		if (optstr[i] != 'h' && 'a' <= optstr[i] && optstr[i] <= 'z')
			opt_flags[(unsigned char)optstr[i]] = 1;
	*/

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
		case 'D':
		  action |= ACTION_DEL;
		  vip.family = parse_ipstr(optarg, vip.daddr.v6);
		  if (vip.family == AF_UNSPEC)
		    return 1;
        	  break;
		case 'A':
		  action |= ACTION_ADD;
		  vip.family = parse_ipstr(optarg, vip.daddr.v6);
		  if (vip.family == AF_UNSPEC)
		    return 1;
		  break;
		case 'L':
		  //		  vip.family = parse_ipstr(optarg, vip.daddr.v6);
		  //		  if (vip.family == AF_UNSPEC)
		  //		    return 1;
		  do_list = true;
		  break;
		case 'l':
		  monitor = true;
		  break;
                case 'u':
		  vip.protocol = IPPROTO_UDP;
		case 't':
		  if (parse_ports(optarg, &min_port, &max_port))
		    return 1;
		  break;
		case 's':
		case 'd':
			if (opt == 's')
				v6 = tnl.saddr.v6;
			else
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
		case 'm':
			if (!ether_aton_r(optarg,
					  (struct ether_addr *)tnl.dmac)) {
				fprintf(stderr, "Invalid mac address:%s\n",
					optarg);
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

	/*
	for (i = 0; i < strlen(optstr); i++) {
		if (opt_flags[(unsigned int)optstr[i]]) {
			fprintf(stderr, "Missing argument -%c\n", optstr[i]);
			usage(argv[0]);
			return 1;
		}
	}
	*/

	if (ifindex == -1) {
	  printf("ERR: required option -i missing");
	  usage(argv[0]);
	  return EXIT_FAIL_OPTION;
	}

	fd_vip2tnl = open_bpf_map(file_vip2tnl);
	fd_service = open_bpf_map(file_service);
	fd_linklist = open_bpf_map(file_linklist);
	fd_worker = open_bpf_map(file_worker);

	while (min_port <= max_port) {
	  vip.dport = htons(min_port++);
	  if (action == ACTION_ADD) {
	    if (bpf_map_update_elem(fd_vip2tnl, &vip, &tnl, BPF_ANY)) {
	      perror("bpf_map_update_elem(&vip2tnl)");
	      return 1;
	    }

	    if (bpf_map_lookup_elem(fd_service, &vip, &head) == -1 ){
	      assert(inet_ntop(tnl.family, &tnl.daddr.v4, ip_txt, sizeof(ip_txt)));
	      head = conv(ip_txt);
	    }

	    if (verbose) printf("head old = %lu\n", head);

	    lnklst_add_to_map(fd_linklist, &tnl, &head);
	    bpf_map_update_elem(fd_service, &vip.daddr.v4, &head, BPF_ANY);
	    
	    assert(inet_ntop(tnl.family, &tnl.daddr.v4, ip_txt, sizeof(ip_txt)));
	    daddrint = conv(ip_txt);

	    bpf_map_update_elem(fd_worker, &daddrint, &tnl, BPF_ANY);

	    if (verbose) printf("head new = %lu\n", head);
	    
	  } else if (action == ACTION_DEL) {
	    bpf_map_delete_elem(fd_vip2tnl, &vip);
	  }
	}

	close(fd_vip2tnl);
	close(fd_service);
	close(fd_linklist);
	close(fd_worker);
	
	if (DEBUG||verbose||do_list) {
	  list_all();
	}

	if (verbose) {
	  //	  service_list_all();
	  linklist_list_all();
	  //	  worker_list_all();
	}

	if (monitor) {
	  list_lbcache();
	}

	return 0;
}
