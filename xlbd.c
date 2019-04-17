#include <yaml.h>
#include "xlb_util.h"

char* conf_yaml;


enum state_value {
    EXPECT_NONE,
    EXPECT_MAP,
    EXPECT_IPV4,
    EXPECT_PORT,
};

enum vip_or_rip {
    NONE,
    VIP,
    RIP,
};

struct parser_state {
  int rip_nest_level;
  int vip_nest_level;
  enum state_value state;
  enum vip_or_rip vor;
  char *vip;
  char *rip;
  char *port;
};

int svc_num;

struct _service service[256];

void prune_workers(){
  __u64 key = 0, next_key;
  struct iptnl_info tnl;
  char ip_txt[INET_ADDRSTRLEN] = {0};

  int fd_worker = open_bpf_map(file_worker);

  while (bpf_map_get_next_key(fd_worker, &key, &next_key) == 0) {
    bool doomed_worker = true;
    bpf_map_lookup_elem(fd_worker, &next_key, &tnl);

    if(DEBUG){
      printf("\nsvcid: %d\n" , next_key>>32);
      assert(inet_ntop(tnl.family, &tnl.daddr.v4, ip_txt, sizeof(ip_txt)));
      printf("dst: %s\n", ip_txt );
    }
    
    struct vip vip;
    int svcid = next_key>>32;

    int fd_svcid = open_bpf_map(file_svcid);
    bpf_map_lookup_elem(fd_svcid, &svcid, &vip);
    close(fd_svcid);
    
    for (int k=1 ; k < svc_num+1;k++){
      if ( vip.daddr.v4 ==  service[k].svc.daddr.v4 &&
	   vip.dport == service[k].svc.dport &&
	   vip.protocol == service[k].svc.protocol){

	for (int l=0 ; l < service[k].wkr_count ;l++){
	  if (DEBUG)
	    printf("%d,%d,%d,%d\n",tnl.daddr.v4,service->wkr[l].daddr.v4,l,service->wkr_count);

	  if ( tnl.daddr.v4 ==  service[k].wkr[l].daddr.v4){
 	    doomed_worker = false;
	    break;
	  }
	}

	if (doomed_worker == false)
	  break;
      }
    }
     
    if (doomed_worker==true){
      if (DEBUG){
	assert(inet_ntop(tnl.family, &tnl.daddr.v4, ip_txt, sizeof(ip_txt)));
	printf("Worker %s for #%d is doomed\n", ip_txt, svcid);
      }
      xlb_del_real(&vip,&tnl);
    }
    
    key = next_key;
  }

  close(fd_worker);
}
  
void prune_services()
{
  struct vip key = {}, next_key;
  __u64 head,value;
  
  int fd_service = open_bpf_map(file_service);

  while (bpf_map_get_next_key(fd_service, &key, &next_key) == 0) {
    key = next_key;
    bpf_map_lookup_elem(fd_service, &key, &head);
    
    bool doomed_service = true;
    if (DEBUG)
      printf("%d, %d, %d\n",key.daddr.v4, key.dport, key.protocol);
    
    for (int k=1 ; k < svc_num+1;k++){
      if (DEBUG)
	printf("....-> %d, %d, %d\n",service[k].svc.daddr.v4, service[k].svc.dport, service[k].svc.protocol);

      if ( key.daddr.v4 ==  service[k].svc.daddr.v4 &&
	   key.dport == service[k].svc.dport &&
	   key.protocol == service[k].svc.protocol){
	doomed_service = false;
      }
    }

    if (doomed_service){
      if (DEBUG){
	char ip_txt[INET_ADDRSTRLEN] = {0};
	assert(inet_ntop(key.family, &key.daddr.v4, ip_txt, sizeof(ip_txt)));
	printf("Service %s:%d(%d) is doomed\n", ip_txt, ntohs(key.dport), key.protocol);
      }
      xlb_del_svc(&key);
    }
  }

  close(fd_service);
}

int reflect_yaml()
{
  for (int k=1 ; k < svc_num+1;k++){
    xlb_add_svc(&service[k].svc);
    for (int l=0 ; l < service[k].wkr_count ;l++){
	xlb_add_real(&service[k].svc, &service[k].wkr[l]);
    }
  }

  printf("\n");
  
  prune_workers();
  prune_services();

  printf("\n");

  return 0;
}

int parse_yaml()
{
  struct _rs {
    char *ipv4;
  };

  struct _vs {
    int num_rs;
    char *ipv4;
    char *port;
    struct _rs rs[256];
  };

  FILE *fh;
  yaml_parser_t parser;
  yaml_event_t  event;
  int nest_level = 0 ;
  struct parser_state state = {.state=EXPECT_NONE};

  struct _vs *vs = malloc(sizeof(struct _vs)*256); 
  int j=0,i=0;
  
  fh = fopen(conf_yaml, "rb");
  if(fh == NULL)
    printf("Failed to open \"%s\"\n", conf_yaml);
  assert(fh);
  
  if(!yaml_parser_initialize(&parser))
    fputs("Failed to initialize parser!\n", stderr);
  if(fh == NULL)
    fputs("Failed to open file!\n", stderr);

  yaml_parser_set_input_file(&parser, fh);

  do {
    if (!yaml_parser_parse(&parser, &event)) {
      printf("Parser error %d\n", parser.error);
      exit(EXIT_FAILURE);
    }

    switch(event.type)
      {
      case YAML_MAPPING_START_EVENT:
	nest_level++;
	break;
      case YAML_MAPPING_END_EVENT:
	nest_level--;
	if ( state.rip_nest_level == nest_level) {
	  //	  printf("(VIP,PORT,RIP) = (%s,%s,%s)\n", state.vip, state.port, state.rip);
	  vs[i].rs[j].ipv4 = strdup(state.rip);
	  j++;
	  vs[i].num_rs=j;
	}
	break;
      case YAML_SCALAR_EVENT:

	if (strcmp(event.data.scalar.value, "virtual_server") == 0) {
	  state.state = EXPECT_MAP;
	  state.vor = VIP;
	  i++;vs[i].num_rs=0;
	  //	  vs[i].num_rs=0;i++;
	  state.vip_nest_level = nest_level;
	} else if (strcmp((char*)event.data.scalar.value, "real_servers") == 0 ||
		   strcmp((char*)event.data.scalar.value, "real_servers") == 0) {
	  //	  printf("(VIP,PORT) = (%s,%s)\n", state.vip, state.port);
	  vs[i].ipv4 = strdup(state.vip);
	  vs[i].port = strdup(state.port);
	  j=0;
	  state.state = EXPECT_MAP;
	  state.vor = RIP;
	  state.rip_nest_level = nest_level;
	} else if (strcmp((char*)event.data.scalar.value, "ipv4") == 0 ){
	  state.state = EXPECT_IPV4;
	} else if (strcmp(event.data.scalar.value, "port") == 0 ){
	  state.state = EXPECT_PORT;
	} else { // parse values

	  if (state.vor == VIP && state.state == EXPECT_IPV4 ){
	    state.vip = strdup(event.data.scalar.value);
	  } else if (state.vor == VIP && state.state == EXPECT_PORT){
	    state.port = strdup(event.data.scalar.value);
	  } else if (state.vor == RIP && state.state == EXPECT_IPV4){
	    state.rip = strdup(event.data.scalar.value);
	  }
	  
	  state.state = EXPECT_NONE;
	}
	break;

      case YAML_NO_EVENT:
      case YAML_STREAM_START_EVENT:
      case YAML_STREAM_END_EVENT:
      case YAML_DOCUMENT_START_EVENT:
      case YAML_DOCUMENT_END_EVENT:
      case YAML_SEQUENCE_START_EVENT:
      case YAML_SEQUENCE_END_EVENT:
      case YAML_ALIAS_EVENT:
	break;
      default:
	break;
      }
    if(event.type != YAML_STREAM_END_EVENT)
      yaml_event_delete(&event);
  } while(event.type != YAML_STREAM_END_EVENT);

  yaml_event_delete(&event);
  yaml_parser_delete(&parser);
  fclose(fh);

  svc_num=i;

  /*
  for (int k=1 ; k < i+1;k++){
    printf("%s:%s\n",vs[k].ipv4,vs[k].port);
    for (int l=0 ; l < vs[k].num_rs ;l++){
      printf("  %s\n",vs[k].rs[l].ipv4);
    }
  }
  printf("\n");
  */

  for (int k=1 ; k < svc_num+1;k++){

    service[k].svc.protocol = IPPROTO_TCP;
    service[k].svc.family= parse_ipstr(vs[k].ipv4, &service[k].svc.daddr.v6);

    int port=0;
    parse_port(vs[k].port, &port);
    service[k].svc.dport=htons(port);

    for (int l=0 ; l < vs[k].num_rs ;l++){
      service[k].wkr[l].family=parse_ipstr(vs[k].rs[l].ipv4, &service[k].wkr[l].daddr.v6);
    }
    service[k].wkr_count = vs[k].num_rs;
  }

  free(vs);
  return 0;
}

void sig_reader(int signal){
  printf("recved signal = %d\n",signal);
  parse_yaml();
  reflect_yaml();
}

int main(int argc, const char *argv[])
{
  struct sigaction sa;
  if (argc != 2){
    printf("argc = %d\n", argc);
    printf("argc must be 2\n");
    exit(1);
  }
  conf_yaml = strdup(argv[1]);
  parse_yaml();
  reflect_yaml();
  
  printf("\nMy pid is: %d\n\n", getpid());
  sa.sa_handler = &sig_reader;
  sa.sa_flags = SA_RESTART;
  sigfillset(&sa.sa_mask);

  sigaction (SIGUSR1, &sa, NULL);
  sigaction (SIGHUP, &sa, NULL);


  while(1) {
    sleep(1);
  }

}
