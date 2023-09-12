#define _GNU_SOURCE     /* To get defns of NI_MAXSERV and NI_MAXHOST */
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_link.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>

// #include <pci/pci.h>

/* PCI IDs are contained in /sys filesystem. */
// unsigned long read_sysfs_uint(const char* ifa_name, const char* info) {
//     char path[PATH_MAX];
//     char buf[12];
//     int fd;

//     snprintf(path, PATH_MAX, "/sys/class/net/%s/device/%s", ifa_name, info);

//     fd = open(path, O_RDONLY);
//     if(fd == -1)
//         return 0;

//     if(read(fd, buf, 12) == -1) {
//         close(fd);
//         return 0;
//     }

//     close(fd);
//     return strtoul(buf, NULL, 16);
// }

/* Try to get PCI IDs and get PCI device name for it.
   XXX: doesn't check for subsystem's numbers */
// void print_pci_ids(const char* ifa_name) {
//     int vendor = (int) read_sysfs_uint(ifa_name, "vendor");
//     int device = (int) read_sysfs_uint(ifa_name, "device");
//     int subsystem_vendor = (int) read_sysfs_uint(ifa_name, "subsystem_vendor");
//     int subsystem_device = (int) read_sysfs_uint(ifa_name, "subsystem_device");

//     struct pci_access *pacc = pci_alloc();
//     char namebuf[256];

//     printf("PCI IDs: %x %x %x %x\n", vendor, device, subsystem_device, subsystem_vendor);

//     pci_init(pacc);

//     if(pci_lookup_name(pacc, namebuf, 256, 
//                     PCI_LOOKUP_VENDOR | PCI_LOOKUP_DEVICE,
//                     vendor, device)) {
//         printf("PCI Name: %s\n", namebuf);
//     }

//     pci_cleanup(pacc);
// }

// int main(int argc, char *argv[])
// {
//     struct ifaddrs *ifaddr, *ifa;
//     struct in_addr* ifa_inaddr;
//     struct in_addr addr;
//     int family, s, n;

//     if(argc != 2) {
//         fprintf(stderr, "Usage: getifaddr <IP>\n");
//         return EXIT_FAILURE;
//     }

//     if (inet_aton(argv[1], &addr) == 0) {
//         perror("inet_aton");
//         return EXIT_FAILURE;
//     }

//     if (getifaddrs(&ifaddr) == -1) {
//         perror("getifaddrs");
//         return EXIT_FAILURE;
//     }

//     /* Walk through linked list, maintaining head pointer so we
//         can free list later */

//     for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
//         if (ifa->ifa_addr == NULL)
//             continue;

//         /* We seek only for IPv4 addresses */
//         if(ifa->ifa_addr->sa_family != AF_INET)
//             continue;

//         ifa_inaddr = &(((struct sockaddr_in*) ifa->ifa_addr)->sin_addr);
//         if(memcmp(ifa_inaddr, &addr, sizeof(struct in_addr)) == 0) {
//             printf("Interface: %s\n", ifa->ifa_name);
//             print_pci_ids(ifa->ifa_name);
//         }
//     }

//     freeifaddrs(ifaddr);
//     return EXIT_SUCCESS;
// }