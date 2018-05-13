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

__u64 conv(char ipadr[], __u8 svcid)
{
  __u64 num=svcid, val;
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

static void lnklst_add_to_map(int fd, struct iptnl_info *vip , __u64 *head){
  __u64 key = *head , next, min, max, ipint;
  char ip_txt[INET_ADDRSTRLEN] = {0};

  assert(inet_ntop(vip->family, &vip->daddr.v4, ip_txt, sizeof(ip_txt)));
  ipint = conv(ip_txt, *head>>32);

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

    } else if (( min < ipint ) && ( ipint < max )){

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

static void service_list_all()
{

  struct vip key = {}, next_key;
  __u64 head;
  char ip_txt[INET_ADDRSTRLEN] = {0};

  int fd = open_bpf_map(file_service);
  
  while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
    key = next_key;
    bpf_map_lookup_elem(fd, &key, &head);
    
    assert(inet_ntop(key.family, &key.daddr.v4, ip_txt, sizeof(ip_txt)));
    printf("{\nVIP: %s\n" , ip_txt);
    printf("%d\n", key.protocol );
    printf("%d\n", ntohs(key.dport));
    printf("head = %llu\n}\n", head);
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

    printf("{\nkey: %llu\n" , next_key);

    assert(inet_ntop(value.family, &value.saddr.v4, ip_txt, sizeof(ip_txt)));
    printf("src: %s\n", ip_txt );
    assert(inet_ntop(value.family, &value.daddr.v4, ip_txt, sizeof(ip_txt)));
    printf("dst: %s\n", ip_txt );
    assert(ether_ntoa_r((struct ether_addr *)value.dmac, mac_txt));
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
    printf("(key, value) = (%llu,%llu)\n" , key, value);
  }
  close(fd);
}

static void show_worker( __u64 *key){

  struct iptnl_info value;
  char daddr_txt[INET_ADDRSTRLEN] = {0};
  char saddr_txt[INET_ADDRSTRLEN] = {0};
  char mac_txt[ETHER_ADDR_LEN] = {0};

  int fd = open_bpf_map(file_worker);
  
  if (bpf_map_lookup_elem(fd, key, &value) == -1 ) return;

  assert(inet_ntop(value.family, &value.saddr.v4, saddr_txt, sizeof(saddr_txt)));
  assert(inet_ntop(value.family, &value.daddr.v4, daddr_txt, sizeof(daddr_txt)));
  assert(ether_ntoa_r((struct ether_addr *)value.dmac, mac_txt));

  if (DEBUG) printf("key: %llu\n", *key);

  printf(" src: %s, dst: %s (%s)\n", saddr_txt, daddr_txt, mac_txt );

  close(fd);
}

static void list_worker_from_head( __u64 *head){

  __u64 key = *head;
  __u64 value;

  int fd = open_bpf_map(file_linklist);

  printf("{\n");
  while (value != *head){
    show_worker(&key);
    if (bpf_map_lookup_elem(fd, &key, &value) != 0) break;
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

    if (DEBUG) printf(", head = %llu ", head);

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
    ether_ntoa_r((struct ether_addr *)value.dmac, mac_txt);
    printf("%s (%s)\n", daddr_txt, mac_txt );

  }

  close(fdw);
  close(fd);
}

int main(int argc, char **argv)
{
  //	unsigned char opt_flags[256] = {};
	const char *optstr = "i:A:D:a:d:r:s:m:p:SLlvhut";
	int min_port = 0, max_port = 0;
	struct iptnl_info tnl = {};
	struct vip vip_tmp, vip = {};
	int opt, i, svcid = 0;
	
	int fd_service, fd_linklist, fd_worker, fd_svcid;
	__u64 head, daddrint;
	char ip_txt[INET_ADDRSTRLEN] = {0};
  
	bool do_list = false;
	bool monitor = false;
	
        enum action action = ACTION_LIST;
	
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
		  break;
		case 't':
		  vip.protocol = IPPROTO_TCP;
		  break;
		case 'p':
		  if (parse_ports(optarg, &min_port, &max_port))
		    return 1;
		  break;
		case 's':
		case 'r':
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

	fd_service = open_bpf_map(file_service);
	fd_linklist = open_bpf_map(file_linklist);
	fd_worker = open_bpf_map(file_worker);
	fd_svcid = open_bpf_map(file_svcid);

	while (min_port <= max_port) {
	  vip.dport = htons(min_port++);
	  if (action == ACTION_ADD_SVC) {

	    // Check if the service already exists.
	    // If not, assign svcid and create head(32+8 bit number).
	    if (bpf_map_lookup_elem(fd_service, &vip, &head) == -1 ){
	      for (i = 1; i < MAX_SVC_ENTRIES ; i++)
		if (bpf_map_lookup_elem(fd_svcid, &i, &vip_tmp) == -1 ){
		  svcid = i ;
		  bpf_map_update_elem(fd_svcid, &i, &vip, BPF_NOEXIST);
		  break ;
		}
	      if (svcid == 0) return EXIT_FAIL;

	      strncpy(ip_txt, "0.0.0.0", INET_ADDRSTRLEN);
	      head = conv(ip_txt, svcid);

	      // Create service map entry.
	      bpf_map_update_elem(fd_service, &vip.daddr.v4, &head, BPF_NOEXIST);
	    } else {
	      //Service already exists.
	      return EXIT_FAIL;
	    }

	  } else if (action == ACTION_ADD_REAL) {

	    // Check if the service exists.
	    if (bpf_map_lookup_elem(fd_service, &vip, &head) == -1 ){
	      // Non existent service
	      return EXIT_FAIL;
	    }
	    svcid = head>>32;
	    if (bpf_map_lookup_elem(fd_svcid, &svcid, &vip_tmp) == -1 ){
	      // Non service id ? Something wrong
	      return EXIT_FAIL;
	    }

	    strncpy(ip_txt, "0.0.0.0", INET_ADDRSTRLEN);

	    if (head == conv(ip_txt,svcid)) { 
		assert(inet_ntop(tnl.family, &tnl.daddr.v4, ip_txt, sizeof(ip_txt)));
		head = conv(ip_txt,svcid);
	    }

	    if (verbose) printf("head old = %llu\n", head);

	    // Insert wkrtag into the linked-list.
	    lnklst_add_to_map(fd_linklist, &tnl, &head);

	    // Update service map entry with new head.
	    bpf_map_update_elem(fd_service, &vip.daddr.v4, &head, BPF_ANY);

	    // Create worker map entry.
	    assert(inet_ntop(tnl.family, &tnl.daddr.v4, ip_txt, sizeof(ip_txt)));
	    daddrint = conv(ip_txt, head>>32);

	    bpf_map_update_elem(fd_worker, &daddrint, &tnl, BPF_ANY);

	    if (verbose) printf("head new = %llu\n", head);
	    
	  } else if (action == ACTION_DEL_REAL) {

	    // Check if the service already exists.
	    // Determine svcid 
	    bpf_map_lookup_elem(fd_service, &vip, &head);
	    svcid = head>>32;
	    bpf_map_lookup_elem(fd_svcid, &svcid, &vip_tmp);

	      
	      assert(inet_ntop(tnl.family, &tnl.daddr.v4, ip_txt, sizeof(ip_txt)));
	      head = conv(ip_txt,svcid);

	    
	    // Insert wkrtag into the linked-list.
	    lnklst_add_to_map(fd_linklist, &tnl, &head);
	    // Create service map entry.
	    bpf_map_update_elem(fd_service, &vip.daddr.v4, &head, BPF_ANY);

	    // Create worker map entry.
	    assert(inet_ntop(tnl.family, &tnl.daddr.v4, ip_txt, sizeof(ip_txt)));
	    daddrint = conv(ip_txt, head>>32);

	    bpf_map_update_elem(fd_worker, &daddrint, &tnl, BPF_ANY);

	  }
	}

	close(fd_service);
	close(fd_linklist);
	close(fd_worker);
	close(fd_svcid);
	
	if (DEBUG||verbose||do_list) {
	  list_all();
	}

	if (verbose) {
	  service_list_all();
	  linklist_list_all();
	  worker_list_all();
	}

	if (monitor) {
	  list_lbcache();
	}

	return 0;
}
