
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

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>
// #include <rte_malloc.h>
// #include <rte_ring.h>
// #include <rte_ring_elem.h>
// #include <inttypes.h>
// #include <sys/types.h>
// #include <rte_common.h>
// #include <rte_memory.h>
// #include <rte_launch.h>
// #include <rte_eal.h>
// #include <rte_per_lcore.h>
// #include <rte_lcore.h>
// #include <rte_debug.h>
// #include <rte_branch_prediction.h>
// #include <rte_ring.h>
// #include <rte_log.h>
// #include <rte_mempool.h>
// #include <rte_errno.h>

#include "util.h"
#include "xdp_stuff.h"
#include "clock_stuff.h"
#include "routing_stuff.h"
#include "data_structures.h"
#include "mempool_stuff.h"
#include "pkt_process.h"

int main(int argc, char **argv)
{
	// int ret;
	// // unsigned lcore_id;

	// int ret = rte_eal_init(argc, argv);
	// if (ret < 0)
	// 	rte_exit(EXIT_FAILURE, "Cannot init EAL\n");

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

    // n_threads = 4;

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
		printf("==================Initialize Port=================\n");
		ports[i] = port_init(&port_params[i]);
		if (!ports[i]) {
			printf("Port %d initialization failed.\n", i);
			return -1;
		}
        print_port(i);
        // enter_xsks_into_map(i);
    }

	//for two veth sockets
	workers[0] = worker_init(&port_params[0], ports[0]);
	enter_xsks_into_map(0, 0, 0);
	workers[1] = worker_init(&port_params[0], ports[0]);
	enter_xsks_into_map(1, 0, 1);

	//For nic socket
	workers[2] = worker_init(&port_params[1], ports[1]);
	enter_xsks_into_map(0, 1, 0);

	//Initialize fill queue
	for (i = 0; i < n_ports; i++) {
		init_fq(port_params[i].bp->umem_cfg.fill_size, ports[i]);
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
	unsigned char mac2[ETH_ALEN+1] = { 0x0c, 0x42, 0xa1, 0xdd, 0x59, 0x1c}; //0c:42:a1:dd:59:1c
    struct mac_addr dest_mac2;
    __builtin_memcpy(dest_mac2.bytes, mac2, sizeof(mac2));
    setMacElement(B, 1, 1, dest_mac2); //port, topo, mac
    setMacElement(B, 1, 2, dest_mac2); //port, topo, mac

	n_threads = 6;

	for(int k=0; k <n_threads; k++ ) {
		thread_data[k].cpu_core_id = k;
	}

	// 2 veth rx and 1 nic rx; 
	int n_rx_threads = 3;
	int n_tx_threads = 3;

	struct mpmc_queue queue_f;
	struct mpmc_queue queue_b;
	mpmc_queue_init(&queue_f, 2048*2, &memtype_heap);
    mpmc_queue_init(&queue_b, 2048*2, &memtype_heap);
	rb_forward = &queue_f;
	rb_backward = &queue_b;

	// printf("Test1 \n");

	// w0=veth,w1=veth,w3=nic

	//t0=veth rx, t1=veth rx, t2=nic rx
	for (int m=0; m <3; m++ ) {
		struct thread_data *t = &thread_data[m];
		t->worker_rx = workers[m];
		if (m==0 || m==1) {
			t->rb = rb_forward;
		} else if (m==2) {
			t->rb = rb_backward;
		}
	}

	// printf("Test2 \n");

	//t3=veth tx, t4=veth tx, t5=nic tx
	for (int m=3; m <6; m++ ) {
		struct thread_data *t = &thread_data[m];
		int w = m-3;
		t->worker_tx = workers[w];
		if (m==3 || m==4) {
			// printf("tx m is 3 or 4 rb_backward \n");
			t->rb = rb_backward;
		} else if (m==5) {
			// printf("tx m is 5 rb_forward \n");
			t->rb = rb_forward;
		}
	}

	// printf("Test3 \n");

	for (int m=0; m <3; m++ ) {
		int status_rx = pthread_create(&threads[m],
				NULL,
				thread_func_rx,
				&thread_data[m]);
		if (status_rx) {
			printf("Thread1 %d creation failed.\n", m);
			return -1;
		}
	}

	// printf("Test4 \n");

	for (int m=3; m <6; m++ ) {
		int status_tx = pthread_create(&threads[m],
				NULL,
				thread_func_tx,
				&thread_data[m]);
		if (status_tx) {
			printf("Thread1 %d creation failed.\n", m);
			return -1;
		}
	}

	printf("All threads created successfully.\n");

	n_cleanup_threads = 2;
	thread_cleanup[0].cpu_core_id = 11; 
	thread_cleanup[1].cpu_core_id = 12; 
	struct thread_cleanup *t_fq_veth = &thread_cleanup[0];
	struct thread_cleanup *t_fq_nic = &thread_cleanup[1];
	t_fq_veth->port_veth = ports[0]; //veth1 
	t_fq_veth->port_nic = ports[1]; //nic 
	t_fq_nic->port_veth = ports[0]; //veth1
	t_fq_nic->port_nic = ports[1]; //nic 
	
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

	// for (i = 0; i < n_ports; i++)
	// 	port_free(ports[i]);

	for (i = 0; i < 3; i++)
		worker_port_free(workers[i]);

    bpool_free(bp);

    remove_xdp_program();

	deleteRouteMatrix(A);
    deleteMacMatrix(B);
    free(arr);
    free(dummy);
	int ret1 = mpmc_queue_destroy(rb_forward);
	if (ret1)
		printf("Failed to destroy queue: %d", ret1);
	int ret2 = mpmc_queue_destroy(rb_backward);
	if (ret2)
		printf("Failed to destroy queue: %d", ret2);

    return 0;
}