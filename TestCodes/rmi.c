#include "rmi.h"

int main(int argc, char *argv[])
{
  char ipaddr[16];
  strcpy(ipaddr, argv[1]);

  char mac[6];
  int dev=0;

  //  struct in_addr src_ip, nh_ip, dst_ip;
  in_addr_t src_ip, nh_ip, dst_ip;

  inet_pton(AF_INET, argv[1], &dst_ip);
  xlb_iproute_get(&dst_ip,&src_ip,&nh_ip, &dev);

  static char buf[256];
  printf("src: %s \n", inet_ntop(AF_INET, &src_ip, buf, 256));
  printf("nexthop: %s \n", inet_ntop(AF_INET, &nh_ip, buf, 256));
  printf("dev: %d \n", dev);

  xlb_get_mac(&nh_ip, mac , &dev);

  char mac_txt[6] = {0};
  ether_ntoa_r((struct ether_addr *)mac, mac_txt);
  printf("mac: %s\n", mac_txt );

}
