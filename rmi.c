#include "rmi.h"

int main(int argc, char *argv[])
{
  char ipaddr[16];
  strcpy(ipaddr, argv[1]);

  __u8 src[4], nexthop[4], mac[6];
  int dev=0;
  
  xlb_iproute_get(ipaddr,src,nexthop, &dev);

  xlb_get_mac(nexthop, mac , &dev);

  static char buf[256];
  printf("src: %s \n", inet_ntop(AF_INET, src, buf, 256));
  printf("nexthop: %s \n", inet_ntop(AF_INET, nexthop, buf, 256));
  printf("dev: %d \n", dev);

  char mac_txt[6] = {0};
  ether_ntoa_r((struct ether_addr *)mac, mac_txt);
  printf("mac: %s\n", mac_txt );

}
