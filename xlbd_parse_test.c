#include <stdio.h>
#include <yaml.h>
#include <assert.h>

#include <unistd.h>
#include <signal.h>
#include <string.h>

char* conf_yaml;

struct _rs {
  char *ipv4;
};

struct _vs {
  int num_rs;
  char *nic;
  char *ipv4;
  char *port;
  struct _rs rs[256];
};

struct _vs vs[256];

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

  /***************************************************/
  /* [Start Mapping]				     */
  /*   [Start Mapping]				     */
  /*   (VIP,PORT) = (10.1.1.1,80)		     */
  /*     [Start Mapping]			     */
  /*     (VIP,PORT,RIP) = (10.1.1.1,80,172.16.51.2)  */
  /*     [End Mapping]				     */
  /*     [Start Mapping]			     */
  /*     (VIP,PORT,RIP) = (10.1.1.1,80,172.16.57.2)  */
  /*     [End Mapping]				     */
  /*   [End Mapping]				     */
  /* [End Mapping]				     */
  /* 						     */
  /* [Start Mapping]				     */
  /*   [Start Mapping]				     */
  /*   (VIP,PORT) = (10.1.1.2,80)		     */
  /*     [Start Mapping]			     */
  /*     (VIP,PORT,RIP) = (10.1.1.2,80,172.16.51.2)  */
  /*     [End Mapping]				     */
  /*   [End Mapping]				     */
  /* [End Mapping]				     */
  /* 						     */
  /* [Start Mapping]				     */
  /*   [Start Mapping]				     */
  /*   (VIP,PORT) = (10.0.0.1,81)		     */
  /*     [Start Mapping]			     */
  /*     (VIP,PORT,RIP) = (10.0.0.1,81,172.16.51.2)  */
  /*     [End Mapping]				     */
  /*     [Start Mapping]			     */
  /*     (VIP,PORT,RIP) = (10.0.0.1,81,192.168.51.2) */
  /*     [End Mapping]				     */
  /*   [End Mapping]				     */
  /* [End Mapping]				     */
  /***************************************************/


int parse_yaml()
{
  FILE *fh;
  yaml_parser_t parser;
  yaml_event_t  event;
  int nest_level = 0 ;
  struct parser_state state = {.state=EXPECT_NONE};

  //  struct _vs *vs = malloc(sizeof(struct _vs)*256); 
  int j,i=0;
  
  fh = fopen(conf_yaml, "rb");
  if(fh == NULL)
    printf("Failed to open \"%s\"\n", conf_yaml);
  assert(fh);
  
  if(!yaml_parser_initialize(&parser))
    fputs("Failed to initialize parser!\n", stderr);

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
	  state.vip_nest_level = nest_level;
	} else if (strcmp((char*)event.data.scalar.value, "real_server") == 0 ||
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

  for (int k=1 ; k < i+1;k++){
    printf("%s:%s\n",vs[k].ipv4,vs[k].port);
    for (int l=0 ; l < vs[k].num_rs ;l++){
      printf("  %s\n",vs[k].rs[l].ipv4);
    }
  }
  fclose(fh);
  //  free(vs);
  return 0;
}

void sig_reader(int signal){
  printf("\nrecved signal = %d\n",signal);
  parse_yaml();
}

int main(int argc, const char *argv[])
{
  struct sigaction sa;
  //  struct _vs *vs = malloc(sizeof(struct _vs)*256); 

  if (argc != 2){
    printf("argc = %d\n", argc);
    printf("argc must be 2\n");
    exit(1);
  }
  conf_yaml = strdup(argv[1]);
  parse_yaml();
  
  printf("\nMy pid is: %d\n\n", getpid());
  sa.sa_handler = &sig_reader;
  sa.sa_flags = SA_RESTART;
  sigfillset(&sa.sa_mask);

  sigaction (SIGUSR1, &sa, NULL);
  sigaction (SIGHUP, &sa, NULL);

  while(1) {
    sleep(1);
  }

  //  free(vs);
}
