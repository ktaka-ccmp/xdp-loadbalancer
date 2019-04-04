#include <stdio.h>
#include <yaml.h>
#include <assert.h>

#include <unistd.h>
#include <signal.h>
#include <string.h>

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

  char *ifname;

  
  char *key;
  char *value;
  //    struct _vs vs;
  char *event_name;
  char *state_name;
  char *scalar ;
};

//int main(int argc, const char *argv[])
int parse_yaml()
{
  FILE *fh;
  yaml_parser_t parser;
  yaml_event_t  event;   /* New variable */
  int nest_level = 0 ;
  struct parser_state state = {.state=EXPECT_NONE};

  fh = fopen(conf_yaml, "rb");
  if(fh == NULL)
    printf("Failed to open \"%s\"\n", conf_yaml);
  assert(fh);
  
  /* Initialize parser */
  if(!yaml_parser_initialize(&parser))
    fputs("Failed to initialize parser!\n", stderr);
  if(fh == NULL)
    fputs("Failed to open file!\n", stderr);

  /* Set input file */
  yaml_parser_set_input_file(&parser, fh);

  /* START new code */
  do {
    if (!yaml_parser_parse(&parser, &event)) {
      printf("Parser error %d\n", parser.error);
      exit(EXIT_FAILURE);
    }

    //      printf("indent=%d\n", parser.indent);
    switch(event.type)
      {
      case YAML_NO_EVENT:
	//	puts("No event!");
	break;
      case YAML_STREAM_START_EVENT:
	//	printf("%*s",  nest_level, "");
	//	puts("STREAM START");
	break;
      case YAML_STREAM_END_EVENT:
	//	printf("%*s",  nest_level, "");
	//	puts("STREAM END");
	break;
      case YAML_DOCUMENT_START_EVENT:
	//	printf("%*s",  nest_level, "");
	//	puts("<b>Start Document</b>");
	break;
      case YAML_DOCUMENT_END_EVENT:
	//	printf("%*s",  nest_level, "");
	//	puts("<b>End Document</b>");
	break;
      case YAML_SEQUENCE_START_EVENT:
	//	printf("%*s",  nest_level, "");
	//	puts("<b>Start Sequence</b>");
	break;
      case YAML_SEQUENCE_END_EVENT:
	//	printf("%*s",  nest_level, "");
	//	puts("<b>End Sequence</b>");
	break;
      case YAML_MAPPING_START_EVENT:
	nest_level++;
	//	printf("%*s",  nest_level, "");
	//	puts("<b>Start Mapping</b>");
	break;
      case YAML_MAPPING_END_EVENT:
	//	printf("%*s",  nest_level, "");
	//	puts("<b>End Mapping</b>");
	nest_level--;
	if ( state.rip_nest_level == nest_level) {
	  printf("(VIP,PORT,RIP) = (%s,%s,%s)\n", state.vip, state.port, state.rip);
	}
	break;
	/* Data */
      case YAML_ALIAS_EVENT:
	//	printf("%*s",  nest_level, "");
	//	printf("Got alias (anchor %s)\n", event.data.alias.anchor);
	break;
      case YAML_SCALAR_EVENT:
	//	printf("%*s",  nest_level, "");
	/*
	  if (state.state == EXPECT_MAP){
	  printf("There's something wrong\n");
	  break;
	}
	*/
	
	if (strcmp(event.data.scalar.value, "virtual_server") == 0) {
	  //	  printf("%s\n", event.data.scalar.value);
	  state.state = EXPECT_MAP;
	  state.vor = VIP;
	  state.vip_nest_level = nest_level;
	} else if (strcmp((char*)event.data.scalar.value, "real_servers") == 0 ||
		   strcmp((char*)event.data.scalar.value, "real_servers") == 0) {
	  //	  printf("%s\n", event.data.scalar.value);
	  printf("(VIP,PORT) = (%s,%s)\n", state.vip, state.port);
	  state.state = EXPECT_MAP;
	  state.vor = RIP;
	  state.rip_nest_level = nest_level;
	} else if (strcmp((char*)event.data.scalar.value, "ipv4") == 0 ){
	  //	  printf("Got ipv4(value %s)\n", event.data.scalar.value);
	  state.key = strdup(event.data.scalar.value);
	  state.state = EXPECT_IPV4;
	} else if (strcmp(event.data.scalar.value, "port") == 0 ){
	  //	  printf("Got port (value %s)\n", event.data.scalar.value);
	  state.key = strdup(event.data.scalar.value);
	  state.state = EXPECT_PORT;
	} else {
	  //	  printf("Got values (value %s)\n", event.data.scalar.value);
	  state.value = strdup(event.data.scalar.value);
	  //	  printf("(%s,%s)\n", state.key, state.value);

	  if (state.vor == VIP && state.state == EXPECT_IPV4 ){
	    state.vip = strdup(event.data.scalar.value);
	  } else if (state.vor == VIP && state.state == EXPECT_PORT){
	    state.port = strdup(event.data.scalar.value);
	  } else if (state.vor == RIP && state.state == EXPECT_IPV4){
	    state.rip = strdup(event.data.scalar.value);
	  }
	  
	  state.key = strdup("");
	  state.value = strdup("");
	  state.state = EXPECT_NONE;
	}
	break;
      }
    if(event.type != YAML_STREAM_END_EVENT)
      yaml_event_delete(&event);
  } while(event.type != YAML_STREAM_END_EVENT);
  yaml_event_delete(&event);

  yaml_parser_delete(&parser);
  fclose(fh);
  return 0;
}

void sig_reader(int signal){
  printf("recved signal = %d\n",signal);
  parse_yaml();
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
  
  printf("My pid is: %d\n", getpid());
  sa.sa_handler = &sig_reader;
  sa.sa_flags = SA_RESTART;
  sigfillset(&sa.sa_mask);

  sigaction (SIGUSR1, &sa, NULL);
  sigaction (SIGHUP, &sa, NULL);


  while(1) {
    sleep(1);
  }

}

