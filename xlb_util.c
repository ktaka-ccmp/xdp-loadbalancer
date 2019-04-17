#include "rmi.h"
#include "xlb_util.h"

int parse_ipstr(const char *ipstr, unsigned int *addr)
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

int parse_port(const char *port_str, int *port)
{
	char *end;
	long tmp_port;

	tmp_port = strtol(port_str, &end, 10);
	if (tmp_port < 1 || tmp_port > 65535) {
		fprintf(stderr, "Invalid port(s):%s\n", port_str);
		return 1;
	}

	*port = tmp_port;
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

__u64 conv(char ipadr[], __u16 svcid)
{
  
  __u64 num=svcid, val;
  char *tok,*ptr;
  char ip_txt[INET_ADDRSTRLEN] = {0};
  
  strncpy(ip_txt, ipadr, INET_ADDRSTRLEN);

  tok=strtok(ip_txt,".");
  while( tok != NULL)
    {
      val=strtoul(tok,&ptr,0);
      num=(num << 8) + val;
      //      printf("(val,num)=(%llu,%llu)\n",val,num);
      tok=strtok(NULL,".");
    }
  return(num);
}

void lnklst_add_to_map(int fd, struct iptnl_info *vip , __u64 *head){
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

void lnklst_del_from_map(int fd, struct iptnl_info *vip , __u64 *head){
  __u64 key = *head , next, min, max, ipint;
  char ip_txt[INET_ADDRSTRLEN] = {0};

  int svcint = *head>>32;
  
  assert(inet_ntop(vip->family, &vip->daddr.v4, ip_txt, sizeof(ip_txt)));
  ipint = conv(ip_txt, svcint);

  if ( bpf_map_lookup_elem(fd, &ipint, &next) != 0 ){
    printf("Worker does not exist!\n");
    return;
  }

  if ( ipint == next ) {// last entry. Delete & update head

    assert(bpf_map_delete_elem(fd, &ipint) == 0 );

    *head = conv("0.0.0.0", svcint);
  
  } else {
    bpf_map_lookup_elem(fd, &key, &next);
    // Find minimum
    if (key > next){ // if head is the last entry
      min = next;
      max = key;
    } else {
      while (key < next){
	key = next;
	bpf_map_lookup_elem(fd, &key, &next);
      }
      min = next;
      max = key;
    }

    *head = min;

    if ( ipint == min ){ // new entry is the smallest or the largest

      bpf_map_lookup_elem(fd, &ipint, &next);

      assert(bpf_map_update_elem(fd, &max, &next, BPF_ANY) == 0 );
      assert(bpf_map_delete_elem(fd, &ipint) == 0 );

      *head = next;

    } else if ( max == ipint ){ // new entry is the smallest or the largest

      key = min;
      bpf_map_lookup_elem(fd, &key, &next);

      while ( next < ipint ){ // find the key where (key < ipint = next = max)
	key = next;
	bpf_map_lookup_elem(fd, &key, &next);
      }
      assert(bpf_map_update_elem(fd, &key, &min, BPF_ANY) == 0);
      assert(bpf_map_delete_elem(fd, &ipint) == 0);

    } else if (( min < ipint ) && ( ipint < max ) ){

      key = min;
      bpf_map_lookup_elem(fd, &key, &next);

      while ( next < ipint ){ // find the key where (key < ipint = next)
	key = next;
	bpf_map_lookup_elem(fd, &key, &next);
      }
      bpf_map_lookup_elem(fd, &ipint, &next); 
      assert(bpf_map_update_elem(fd, &key, &next, BPF_ANY) == 0);
      assert(bpf_map_delete_elem(fd, &ipint) == 0);
    }

  }
}

void svcid_list_all()
{

  __u64 key = 0, next_key;
  __u64 head;

  int fd = open_bpf_map(file_svcid);
  
  while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
    key = next_key;
    bpf_map_lookup_elem(fd, &key, &head);
    
    printf("svcid = %llu\n}\n", key);
    printf("head = %llu\n}\n", head);
  }

  close(fd);
}

void service_list_all()
{

  struct vip key = {}, next_key;
  __u64 head;
  char ip_txt[INET_ADDRSTRLEN] = {0};

  int fd = open_bpf_map(file_service);
  
  printf("Service List: \n");
  while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
    key = next_key;
    bpf_map_lookup_elem(fd, &key, &head);
    
    assert(inet_ntop(key.family, &key.daddr.v4, ip_txt, sizeof(ip_txt)));
    printf("{\nVIP: %s\n" , ip_txt);
    printf("%d\n", key.protocol );
    printf("%d\n", ntohs(key.dport));
    printf("head = %llu\n}\n", head);
  }
  printf("\n");

  close(fd);
}

void worker_list_all()
{
  __u64 key = 0, next_key;
  struct iptnl_info value;
  char ip_txt[INET_ADDRSTRLEN] = {0};
  char mac_txt[] = "00:00:00:00:00:00";

  int fd = open_bpf_map(file_worker);

  while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
    bpf_map_lookup_elem(fd, &next_key, &value);

    printf("{\nkey: %llu\n" , next_key);
    printf("{\nsvcid: %d\n" , next_key>>32);

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

void linklist_list_all(){

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

void show_worker( __u64 key){

  struct iptnl_info value;
  char daddr_txt[INET_ADDRSTRLEN] = {0};
  char saddr_txt[INET_ADDRSTRLEN] = {0};
  char mac_txt[] = "00:00:00:00:00:00";
  
  int fd = open_bpf_map(file_worker);
  
  if (bpf_map_lookup_elem(fd, &key, &value) == -1 ) return;

  assert(inet_ntop(value.family, &value.saddr.v4, saddr_txt, sizeof(saddr_txt)));
  assert(inet_ntop(value.family, &value.daddr.v4, daddr_txt, sizeof(daddr_txt)));
  assert(ether_ntoa_r((struct ether_addr *)value.dmac, mac_txt));
  
  if (DEBUG) printf("key: %llu\n", key);

  //  printf(" dst: %u\n", value.daddr.v4);
  printf(" src: %s, dst: %s (%s)\n", saddr_txt, daddr_txt, mac_txt );

  close(fd);
}

void list_worker_from_head( __u64 head){

  __u64 key = head;
  __u64 value=0;

  int fd = open_bpf_map(file_linklist);

  printf("{\n");
  while (value != head){
    show_worker(key);
    if (bpf_map_lookup_elem(fd, &key, &value) != 0) break;
    key = value;
  }
  printf("}\n");

  close(fd);
}

void list_all()
{
  int fd, flag=0;
  struct vip key = {}, next_key;
  __u64 head;
  char daddr_txt[INET_ADDRSTRLEN] = {0};

  fd = open_bpf_map(file_service);

  while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
    key = next_key;
    bpf_map_lookup_elem(fd, &key, &head);
    
    assert(inet_ntop(key.family, &key.daddr.v4, daddr_txt, sizeof(daddr_txt)));
    printf("service(#%d): %s:%d(%d) " , (__u16)(head>>32), daddr_txt, ntohs(key.dport), key.protocol);

    if (DEBUG) printf(", head = %llu ", head);

    list_worker_from_head(head);
    flag=1;
  }

  if (flag == 0){
    printf("We have no service here.\n");
  }
  
  close(fd);
}

void list_lbcache()
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

    struct iptnl_info value;
    char mac_txt[] = "00:00:00:00:00:00";

    bpf_map_lookup_elem(fdw, &wkid, &value);
    inet_ntop(value.family, &value.daddr.v4, daddr_txt, sizeof(daddr_txt));
    assert(ether_ntoa_r((struct ether_addr *)value.dmac, mac_txt));
    printf("%s (%s)\n", daddr_txt, mac_txt );

  }

  close(fdw);
  close(fd);
}

void xlb_add_svc(struct vip* vip)
{
  int i;
  struct vip vip_tmp;
  char ip_txt[INET_ADDRSTRLEN] = {0};
  __u16 svcid = 0;
  __u64 head;

  //  printf("vip->daddr.v4 = %u \n", &vip->daddr.v4);
  //  assert(inet_ntop(vip->family, &vip->daddr.v4, ip_txt, sizeof(ip_txt)));
  //  printf("Adding service \"%s:%d\".\n", ip_txt, ntohs(vip->dport));

  int fd_service = open_bpf_map(file_service);
  int fd_svcid = open_bpf_map(file_svcid);
 
    // 0. Check if the service already exists.
  if (bpf_map_lookup_elem(fd_service, vip, &head) == 0 ){
    //    assert(inet_ntop((*vip).family, &(*vip).daddr.v4, ip_txt, sizeof(ip_txt)));
    assert(inet_ntop(vip->family, &vip->daddr.v4, ip_txt, sizeof(ip_txt)));
    printf("%s:%d (#%d)\n",ip_txt,ntohs(vip->dport),head>>32);
    return;
  }

  // 1. Assign svcid and create head(32+8 bit number).
  for (i = 1; i < MAX_SVC_ENTRIES ; i++){
    if (bpf_map_lookup_elem(fd_svcid, &i, &vip_tmp) == -1 ){
      svcid = i ;
      bpf_map_update_elem(fd_svcid, &i, vip, BPF_NOEXIST);
      break ;
    }
  }
  if (svcid == 0) return;

  //  printf("Service id %d\n", svcid);
    
  head = conv("0.0.0.0", svcid);
  
  // 2. Add service to the service map.
  //  bpf_map_update_elem(fd_service, &vip->daddr.v4, &head, BPF_NOEXIST);
  bpf_map_update_elem(fd_service, vip, &head, BPF_NOEXIST);

  assert(inet_ntop(vip->family, &vip->daddr.v4, ip_txt, sizeof(ip_txt)));
  printf("+%s:%d (#%d)\n",ip_txt,ntohs(vip->dport),svcid);

  close(fd_service);
  close(fd_svcid);
}

void xlb_del_svc(struct vip* vip)
{
  char ip_txt[INET_ADDRSTRLEN] = {0};
  __u16 svcid = 0;
  __u64 head;

  int fd_service = open_bpf_map(file_service);
  int fd_svcid = open_bpf_map(file_svcid);

  // 0. Check if the service & worker exist.
  if (bpf_map_lookup_elem(fd_service, vip, &head) == -1 ){
    assert(inet_ntop(vip->family, &vip->daddr.v4, ip_txt, sizeof(ip_txt)));
    printf("The service \"%s:%d\" does not exist!\n", ip_txt, ntohs(vip->dport));
    return;
  }
  svcid = head>>32;

  if (head == conv("0.0.0.0", svcid)) { // If there is no worker then remove service
    bpf_map_delete_elem(fd_service, vip);
    bpf_map_delete_elem(fd_svcid, &svcid);

    assert(inet_ntop(vip->family, &vip->daddr.v4, ip_txt, sizeof(ip_txt)));
    printf("-%s:%d (#%d)\n",ip_txt,ntohs(vip->dport),svcid);

  } else {
    printf("\nWorkers still exist for service(#%d)! Delete them first.\n\n",svcid);
    //    do_list=1;
    //	      return EXIT_FAIL;
  }
  close(fd_service);
  close(fd_svcid);
}

void xlb_add_real(struct vip* vip, struct iptnl_info* tnl)
{
  char ip_txt[INET_ADDRSTRLEN] = {0};
  struct vip vip_tmp;
  struct iptnl_info tnl_tmp = {};
  __u16 svcid = 0;
  __u64 head, daddrint;


  in_addr_t nh_ip;
  int dev=0;

  xlb_iproute_get(&tnl->daddr.v4, &tnl->saddr.v4, &nh_ip, &dev);
  xlb_get_mac(&nh_ip, tnl->dmac , &dev);

  if (DEBUG){
    char buf[256];
    char mac_txt[] = "00:00:00:00:00:00";

    printf("src: %s \n", inet_ntop(AF_INET, &tnl->saddr.v4, buf, 256));
    assert(ether_ntoa_r((struct ether_addr *)tnl->dmac, mac_txt));
    printf("nexthop: %s (%s) \n", inet_ntop(AF_INET, &nh_ip, buf, 256), mac_txt);
    //    printf("mac: %s\n", mac_txt );
  }

  int fd_service = open_bpf_map(file_service);
  int fd_linklist = open_bpf_map(file_linklist);
  int fd_worker = open_bpf_map(file_worker);
  int fd_svcid = open_bpf_map(file_svcid);

  // 0. Check if the service & worker exist.
  if (bpf_map_lookup_elem(fd_service, vip, &head) == -1 ){
    assert(inet_ntop(vip->family, &vip->daddr.v4, ip_txt, sizeof(ip_txt)));
    printf("The service \"%s:%d\" does not exist!\n", ip_txt, ntohs(vip->dport));
    return;
  }
  svcid = head>>32;

  if (bpf_map_lookup_elem(fd_svcid, &svcid, &vip_tmp) == -1 ){
    // No svcid in the fd_svcid map? Unlikey but just checking.
    return;
  }

  assert(inet_ntop(tnl->family, &tnl->daddr.v4, ip_txt, sizeof(ip_txt)));
  daddrint = conv(ip_txt, svcid);

  // 1. Check if the head is for "0.0.0.0" i.e. there's no worker yet.
  //    If so, generate new head from worker ip. 

  if (head == conv("0.0.0.0",svcid)) { 
    head = daddrint;
  }

  // 2. Check if the worker already exists for the service.
  if (bpf_map_lookup_elem(fd_worker, &daddrint, &tnl_tmp) == 0 ){
    //    printf("\"%s\" already exists for service(#%d)!\n",ip_txt,svcid);
    printf("  %s (#%d)\n",ip_txt,svcid);
  return;
  }

  if (verbose) printf("head old = %llu\n", head);
	    
  // 3. Insert wkrtag into the linked-list.
  // 4. Add worker.
  // 5. Update service map entry with new head.
  lnklst_add_to_map(fd_linklist, tnl, &head);
  bpf_map_update_elem(fd_worker, &daddrint, tnl, BPF_ANY);
  bpf_map_update_elem(fd_service, &vip->daddr.v4, &head, BPF_ANY);

  //  printf("+   %s added for #%d\n",ip_txt,svcid);
  printf("+  %s (#%d)\n",ip_txt,svcid);
  
  if (verbose) printf("head new = %llu\n", head);

  close(fd_service);
  close(fd_svcid);
  close(fd_linklist);
  close(fd_worker);
}

void xlb_del_real(struct vip* vip, struct iptnl_info* tnl)
{
  char ip_txt[INET_ADDRSTRLEN] = {0};
  struct iptnl_info tnl_tmp = {};
  __u16 svcid = 0;
  __u64 head, daddrint;


  int fd_service = open_bpf_map(file_service);
  int fd_linklist = open_bpf_map(file_linklist);
  int fd_worker = open_bpf_map(file_worker);

  // 0. Check if the service & worker exist.
  if (bpf_map_lookup_elem(fd_service, vip, &head) == -1 ){
    assert(inet_ntop(vip->family, &vip->daddr.v4, ip_txt, sizeof(ip_txt)));
    printf("The service \"%s:%d\" does not exist!\n", ip_txt, ntohs(vip->dport));
    return;
  }
  svcid = head>>32;

  assert(inet_ntop(tnl->family, &tnl->daddr.v4, ip_txt, sizeof(ip_txt)));
  daddrint = conv(ip_txt, svcid);
  if (bpf_map_lookup_elem(fd_worker, &daddrint, &tnl_tmp) == -1 ){
    printf("%s does not exist for service(#%d)!\n",ip_txt,svcid);
    return;
  }


  // 1. Delete wkrtag from the linked-list.
  //	    lnklst_del_from_map(fd_linklist, &tnl, &daddr);
  // 2. Delete worker.
  // 3. Update service map entry with new head.

  lnklst_del_from_map(fd_linklist, tnl, &head);
  bpf_map_delete_elem(fd_worker, &daddrint);
  bpf_map_update_elem(fd_service, &vip->daddr.v4, &head, BPF_ANY);

  //  printf("  %s removed from #%d\n",ip_txt,svcid);
  printf("-  %s (#%d)\n",ip_txt,svcid);

  close(fd_service);
  close(fd_linklist);
  close(fd_worker);
}

