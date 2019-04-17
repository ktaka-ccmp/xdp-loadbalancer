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
#include <net/if.h>
#include "xlb_common.h"

int parse_ipstr(const char*, unsigned int*);
int parse_port(const char*, int*);

int open_bpf_map(const char*);

void lnklst_add_to_map(int, struct iptnl_info *, __u64*);
void lnklst_del_from_map(int, struct iptnl_info*, __u64*);

void svcid_list_all();
void service_list_all();
void worker_list_all();
void linklist_list_all();
void show_worker(__u64);
void list_worker_from_head(__u64);
void list_all();
void list_lbcache();

void xlb_add_svc(struct vip*);
void xlb_del_svc(struct vip*);
void xlb_add_real(struct vip*, struct iptnl_info*);
void xlb_del_real(struct vip*, struct iptnl_info*);

struct _service {
  struct vip svc;
  struct iptnl_info wkr[256];
  int wkr_count;
};


