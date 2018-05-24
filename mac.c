#include "rmi.h"

int xlb_get_mac(in_addr_t *host, char *mac, int *dev){

  int s;

  struct arpreq req;
  struct sockaddr_in *sin;
  static char buf[256];

  bzero((caddr_t)&req, sizeof(req));

  sin = (struct sockaddr_in *)&req.arp_pa;
  sin->sin_family = AF_INET; 
  sin->sin_addr.s_addr = *host;

  if((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
    perror("socket() failed.");
    exit(-1);
  }

  if_indextoname(*dev, req.arp_dev);
  if (DEBUG) printf("ifname= %s\n", req.arp_dev);
  
  if(ioctl(s, SIOCGARP, (caddr_t)&req) <0){
    if(errno == ENXIO){
  
      icmp_send_1pkt(&sin->sin_addr.s_addr);
      usleep(100000);
      
      if(ioctl(s, SIOCGARP, (caddr_t)&req) <0){
	if(errno == ENXIO){
	  printf("%s - no entry.\n", inet_ntop(AF_INET, host, buf, 256));
	  //	  printf("%lu - no entry.\n", *host);
	  exit(-1);
	} else {
	  perror("SIOCGARP");
	  exit(-1);
	}
      }

    } else {
      perror("SIOCGARP");
      exit(-1);
    }
  }
      
  if(!(req.arp_flags & ATF_COM)){
    printf("incomplete\n");
    exit(-1);
  }

  memcpy(mac, req.arp_ha.sa_data, 6);
  
  return(0);
}

