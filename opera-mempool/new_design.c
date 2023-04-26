
#define _GNU_SOURCE
#include <stdbool.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <netinet/ether.h>
#include <net/if.h>

#include <linux/err.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>

#include <xdp/libxdp.h>
#include <xdp/xsk.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <bpf/bpf_endian.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <math.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include <linux/ptp_clock.h>
#include "util.h"
#include "xdp_stuff.h"
#include "clock_stuff.h"
#include "routing_stuff.h"
#include "data_structures.h"
#include "mempool_stuff.h"


int main(int argc, char **argv)
{
    int i;

    memcpy(&bpool_params, &bpool_params_default,
	       sizeof(struct bpool_params));
    memcpy(&umem_cfg, &umem_cfg_default,
	       sizeof(struct xsk_umem_config));
    for (i = 0; i < MAX_PORTS; i++)
		memcpy(&port_params[i], &port_params_default,
		       sizeof(struct port_params));

    load_xdp_program();

    n_ports = 2; //0 and 1 (veth and nic)
    port_params[0].iface = "veth1";
	port_params[0].iface_queue = 0;
    port_params[1].iface = "enp65s0f0np0";
	port_params[1].iface_queue = 0;

    n_threads = 4;

    /* Buffer pool initialization. */
	bp = bpool_init(&bpool_params, &umem_cfg);
	if (!bp) {
		printf("Buffer pool initialization failed.\n");
		return -1;
	}
	printf("Buffer pool created successfully.\n");
	printf("================================\n");

    /* Ports initialization. */
	for (i = 0; i < MAX_PORTS; i++)
		port_params[i].bp = bp;

    for (i = 0; i < n_ports; i++) {
		ports[i] = port_init(&port_params[i]);
		if (!ports[i]) {
			printf("Port %d initialization failed.\n", i);
			return -1;
		}
        print_port(i);
        enter_xsks_into_map(i);
    }

    printf("All ports created successfully.\n");

	clkid = get_nic_clock_id();
	
	getMACAddress(0, out_eth_src); //source mac
	arr = (struct HashNode**)malloc(sizeof(struct HashNode*) * capacity);
	// Assign NULL initially
	for (int i = 0; i < capacity; i++)
		arr[i] = NULL;
	u32 dest2 = htonl(0xc0a80102);  //192.168.1.2
    insert(dest2, 1); //dest,index for dest ip
	A = newRouteMatrix(1, 2);
    setRouteElement(A, 1, 1, 1); //ip, topo, port
    setRouteElement(A, 1, 2, 1); //ip, topo, port
    B = newMacMatrix(1, 2);
	unsigned char mac2[ETH_ALEN+1] = { 0x0c, 0x42, 0xa1, 0xdd, 0x5a, 0x45}; //0c:42:a1:dd:5a:45
    struct mac_addr dest_mac2;
    __builtin_memcpy(dest_mac2.bytes, mac2, sizeof(mac2));
    setMacElement(B, 1, 1, dest_mac2); //port, topo, mac
    setMacElement(B, 1, 2, dest_mac2); //port, topo, mac

	n_threads = 4;
	thread_data[0].cpu_core_id = 0; //cat /proc/cpuinfo | grep 'core id' //veth rx
	thread_data[1].cpu_core_id = 1; //cat /proc/cpuinfo | grep 'core id' //nic rx
    thread_data[2].cpu_core_id = 2; //cat /proc/cpuinfo | grep 'core id' //veth tx
	thread_data[3].cpu_core_id = 3; //cat /proc/cpuinfo | grep 'core id' //nic tx

	struct thread_data *t_rx_veth = &thread_data[0];
	struct thread_data *t_rx_nic = &thread_data[1];
    struct thread_data *t_tx_veth = &thread_data[2];
	struct thread_data *t_tx_nic = &thread_data[3];

	t_rx_veth->ports_rx = ports[0]; //veth1 rx
	t_rx_nic->ports_rx = ports[1]; //nic q0 rx
	t_tx_veth->ports_tx = ports[0]; //veth tx
	t_tx_nic->ports_tx = ports[1]; //nic tx

    bpool_free(bp);

    remove_xdp_program();

    return 0;
}