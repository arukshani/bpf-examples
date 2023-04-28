
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
#include "pkt_process.h"

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
	u32 dest2 = htonl(0xc0a80101);  //192.168.1.1
    insert(dest2, 1); //dest,index for dest ip
	A = newRouteMatrix(1, 2);
    setRouteElement(A, 1, 1, 1); //ip, topo, port
    setRouteElement(A, 1, 2, 1); //ip, topo, port
    B = newMacMatrix(1, 2);
	unsigned char mac2[ETH_ALEN+1] = { 0x0c, 0x42, 0xa1, 0xdd, 0x58, 0x78}; //0c:42:a1:dd:58:78
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

	//+++FIFO QUEUE+++++
	struct spsc_queue* rb_forward = NULL;
	rb_forward = spsc_queue_init(rb_forward, 2048, &memtype_heap);

    struct spsc_queue* rb_backward = NULL;
	rb_backward = spsc_queue_init(rb_backward, 2048, &memtype_heap);

	t_rx_veth->rb = rb_forward;
	t_tx_nic->rb = rb_forward;
	t_rx_nic->rb = rb_backward;
	t_tx_veth->rb = rb_backward;

	int status_veth_rx = pthread_create(&threads[0],
				NULL,
				thread_func_rx,
				&thread_data[0]);
	if (status_veth_rx) {
		printf("Thread1 %d creation failed.\n", i);
		return -1;
	}

	int status_nic_rx = pthread_create(&threads[1],
				NULL,
				thread_func_rx,
				&thread_data[1]);
	if (status_nic_rx) {
		printf("Thread2 %d creation failed.\n", i);
		return -1;
	}

	int status_veth_tx = pthread_create(&threads[2],
				NULL,
				thread_func_tx,
				&thread_data[2]);
	if (status_veth_tx) {
		printf("Thread3 %d creation failed.\n", i);
		return -1;
	}

	int status_nic_tx = pthread_create(&threads[3],
				NULL,
				thread_func_tx,
				&thread_data[3]);
	if (status_nic_tx) {
		printf("Thread4 %d creation failed.\n", i);
		return -1;
	}

	printf("All threads created successfully.\n");

	n_cleanup_threads = 2;
	thread_cleanup[0].cpu_core_id = 4; 
	thread_cleanup[1].cpu_core_id = 5; 
	struct thread_cleanup *t_fq_veth = &thread_cleanup[0];
	struct thread_cleanup *t_fq_nic = &thread_cleanup[1];
	t_fq_veth->port_veth = ports[0]; //veth1 
	t_fq_veth->port_nic = ports[1]; //nic 
	t_fq_nic->port_veth = ports[0]; //veth1
	t_fq_nic->port_nic = ports[1]; //nic 
	// if (t_fq_veth->port_veth == NULL) {
	// 	printf("veth port is NULL \n");
	// }
	int status_veth_fq = pthread_create(&cleanup_threads[0],
				NULL,
				thread_func_fq_veth,
				&thread_cleanup[0]);
	if (status_veth_fq) {
		printf("Thread1 %d creation failed.\n", i);
		return -1;
	}
	int status_nic_fq = pthread_create(&cleanup_threads[1],
				NULL,
				thread_func_fq_nic,
				&thread_cleanup[1]);
	if (status_nic_fq) {
		printf("Thread1 %d creation failed.\n", i);
		return -1;
	}

	printf("All cleanup threads created successfully.\n");

	/* Print statistics. */
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGABRT, signal_handler);

	time_t secs = 60; // 2 minutes (can be retrieved from user's input)

	time_t startTime = time(NULL);
	while (time(NULL) - startTime < secs)
	{
		read_time();
	}

	for (i = 0; i < n_threads; i++)
		thread_data[i].quit = 1;

	for (i = 0; i < n_threads; i++)
		pthread_join(threads[i], NULL);

	for (i = 0; i < n_cleanup_threads; i++)
		thread_cleanup[i].quit = 1;

	for (i = 0; i < n_cleanup_threads; i++)
		pthread_join(cleanup_threads[i], NULL);

	for (i = 0; i < n_ports; i++)
		port_free(ports[i]);

    bpool_free(bp);

    remove_xdp_program();

	deleteRouteMatrix(A);
    deleteMacMatrix(B);
    free(arr);
    free(dummy);
	int ret1 = spsc_queue_destroy(rb_forward);
	if (ret1)
		printf("Failed to destroy queue: %d\n", ret1);

    int ret2 = spsc_queue_destroy(rb_backward);
	if (ret2)
		printf("Failed to destroy queue: %d\n", ret2);

    return 0;
}