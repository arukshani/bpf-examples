#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

int getMACAddress(int iNetType, unsigned char chMAC[6]) {

  char *ifname=NULL;
 
  if (!iNetType) {
    ifname="enp65s0f0np0"; /* Ethernet */
  } else {
    ifname="veth1"; /* veth */
  }

  struct ifreq s;
  int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

  strcpy(s.ifr_name, ifname);
  if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
    memcpy(chMAC, s.ifr_hwaddr.sa_data, 6);
    close(fd);
    int i;
    for (i = 0; i < 6; ++i)
      printf(" %02x", (unsigned char) s.ifr_addr.sa_data[i]);
    puts("\n");
    return 0;
  }
  return 1;
}