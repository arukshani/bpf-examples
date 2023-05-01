/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>

#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_ring_elem.h>
#include <inttypes.h>
#include <sys/types.h>
#include <rte_common.h>
#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_branch_prediction.h>
#include <rte_ring.h>
#include <rte_log.h>
#include <rte_mempool.h>

// #include <linux/err.h>
// #include <linux/if_link.h>
// #include <linux/if_xdp.h>

// #include <xdp/libxdp.h>
// #include <xdp/xsk.h>
// #include <bpf/bpf.h>
// #include <bpf/libbpf.h>
// #include <linux/if_ether.h>
// #include <linux/ip.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <arpa/inet.h>
// #include <linux/ip.h>
// #include <linux/icmp.h>
// #include <bpf/bpf_endian.h>
#include <time.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <rte_errno.h>

typedef __u64 u64;
typedef __u32 u32;

struct burst_rx {
	__u64 addr;
	__u32 len;
}__attribute__((packed));

struct burst_tx {
	__u64 addr;
	__u32 len;
}__attribute__((packed));

struct thread_data {
	u32 cpu_core_id;
	struct rte_ring *rb;
	int quit;
};

#ifndef MAX_THREADS
#define MAX_THREADS 2
#endif

static struct thread_data thread_data[MAX_THREADS];
static pthread_t threads[MAX_THREADS];
static int n_threads;
cpu_set_t cpuset;
// cpu_set_t cpu_cores;
// cpu_set_t *cpusetp;

static unsigned int ring_size = 2048;

static void *
thread_func_pop(void *arg)
{
	
	struct thread_data *t = arg;
	// cpu_set_t cpu_cores;
	// CPU_ZERO(&cpu_cores);
	// CPU_SET(t->cpu_core_id, &cpu_cores);
	// pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu_cores);
	// pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
	struct rte_ring *q = t->rb;
	
    while (!t->quit) {
		if (unlikely(!rte_ring_empty(q))) {
			struct burst_tx *btx;
			void *ptr;
			// int status = rte_ring_sc_dequeue(msgq_req, (void **)&req);
			// while (rte_ring_sc_dequeue(q, &ptr) == 0) {
			while (rte_ring_sc_dequeue(q, (void **)&btx) == 0) {
				// uintptr_t addr = (uintptr_t)ptr;
				// struct burst_tx *btx = (struct burst_tx*)ptr;
				// struct burst_tx *btx = (struct burst_tx *)addr;
				printf("other thread addr %lld \n", btx->addr);
			}
		}
    }
    return NULL;
}

static void *
thread_func_push(void *arg)
{
	
	struct thread_data *t = arg;
	
	// CPU_SET(t->cpu_core_id, &cpu_cores);
	// pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu_cores);
	// pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
	struct rte_ring *q = t->rb;
	int j =0;
    while (!t->quit) {
        
		
        for (size_t i = 0; i != 5; i += 1) {
			if (j == 5) {
                break;
            }
			j++;
            // struct burst_tx btx;
			// btx.addr = 25000 + i;
			// btx.len = 100;
            // rte_ring_sp_enqueue(q, (void *) &btx);
			// printf("RX pushed adrr %lld \n", btx.addr);

			// void *ptr;
			// while (rte_ring_sc_dequeue(q, &ptr) == 0) {
			// 	uintptr_t addr = (uintptr_t)ptr;
			// 	// struct burst_tx *btx = (struct burst_tx*)ptr;
			// 	struct burst_tx *btx = (struct burst_tx *)addr;
			// 	printf("POP addr %lld \n", btx->addr);
			// }

			struct burst_tx *btx = calloc(1, sizeof(struct burst_tx));
			// struct burst_tx btx;
			btx->addr = 25000 + j;
			btx->len = 100;
            int status = rte_ring_sp_enqueue(q, btx);
			printf("RX pushed adrr %lld \n", btx->addr);

			// if (unlikely(!rte_ring_empty(q))) {
			// 	struct burst_tx *btx;
			// 	while (rte_ring_sc_dequeue(q, (void **)&btx) == 0) {
			// 		printf("other thread addr %lld \n", btx->addr);
			// 	}
			// }

		}

		// printf( "J %d \n", j);

		// if (j == 5) {
		// 	// if (unlikely(!rte_ring_empty(q))) {
		// 	// 	struct burst_tx *btx = calloc(1, sizeof(struct burst_tx));
		// 	// 	while (rte_ring_sc_dequeue(q, (void **)&btx) == 0) {
		// 	// 		printf("same thread POP %lld \n", btx->addr);
		// 	// 	}
		// 	// }
		// 	void *a1 = NULL;
		// 	struct burst_tx *dq1;
		// 	if (rte_ring_sc_dequeue(q, &a1) == 0) {
		// 		uintptr_t addr = (uintptr_t)a1;
		// 		dq1 = (struct burst_tx *)(addr);
		// 		printf("same thread addr %lld \n", dq1->addr);
		// 		a1 = NULL;
		// 	}
		// }
            
    }
    return NULL;
}

struct rte_ring *test_ring;


int
main(int argc, char **argv)
{
	printf("Hello \n");

	int ret;
	// unsigned lcore_id;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Cannot init EAL\n");
	
	test_ring = rte_ring_create("R0", ring_size, SOCKET_ID_ANY,
				  RING_F_SP_ENQ | RING_F_SC_DEQ);

	if (test_ring == NULL)
			rte_exit(EXIT_FAILURE, "Could not create ring :%s\n",
				 rte_strerror(rte_errno));

	struct burst_tx btx1;
	btx1.addr = 89;
	btx1.len = 100;
	rte_ring_sp_enqueue(test_ring, (void *) &btx1);
	struct burst_tx btx2;
	btx2.addr = 90;
	btx2.len = 100;
	rte_ring_sp_enqueue(test_ring, (void *) &btx2);

	void *a1 = NULL;
	struct burst_tx *dq1;
	if (rte_ring_sc_dequeue(test_ring, &a1) == 0) {
		uintptr_t addr = (uintptr_t)a1;
		dq1 = (struct burst_tx *)(addr);
		printf("other thread addr %lld \n", dq1->addr);
		a1 = NULL;
	}

	void *a2 = NULL;
	struct burst_tx *dq2;
	if (rte_ring_sc_dequeue(test_ring, &a2) == 0) {
		uintptr_t addr = (uintptr_t)a2;
		dq2 = (struct burst_tx *)(addr);
		printf("other thread addr %lld \n", dq2->addr);
		a2 = NULL;
	}


	// printf("RX pushed adrr %lld \n", btx.addr);
	// CPU_ZERO(&cpu_cores);

	// cpuset = CPU_ALLOC(2);
	// size_t size;
	// size = CPU_ALLOC_SIZE(2);
    // CPU_ZERO_S(size, &cpuset);

	// CPU_SET(0, &cpuset);
	// CPU_SET(1, &cpuset);

	n_threads = 2;
	thread_data[0].cpu_core_id = 0; 
	thread_data[1].cpu_core_id = 1; 

    struct thread_data *t1 = &thread_data[0];
	struct thread_data *t2 = &thread_data[1];

	// CPU_SET_S(0, size, &cpuset);
	// CPU_SET_S(1, size, &cpuset);

	// printf("CPU_COUNT() of set:    %d\n", CPU_COUNT_S(size, &cpuset));

	// threads[0] = pthread_self();
	// threads[1] = pthread_self();

	// CPU_SET(t1->cpu_core_id, &cpu_cores);
	// CPU_SET(t2->cpu_core_id, &cpu_cores);
	// pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
	// pthread_setaffinity_np(threads[0], sizeof(cpu_set_t), &cpuset);
	// pthread_setaffinity_np(threads[1], sizeof(cpu_set_t), &cpuset);

    t1->rb = test_ring;
	t2->rb = test_ring;

	int status1 = pthread_create(&threads[0],
				NULL,
				thread_func_push,
				&thread_data[0]);
	if (status1) {
		printf("Thread1 creation failed.\n");
		return -1;
	}

	int status2 = pthread_create(&threads[1],
				NULL,
				thread_func_pop,
				&thread_data[1]);
	if (status2) {
		printf("Thread2 creation failed.\n");
		return -1;
	}

	sleep(1);

	// if (unlikely(!rte_ring_empty(test_ring))) {
	// 		struct burst_tx *btx;
	// 		while (rte_ring_sc_dequeue(test_ring, (void **)&btx) == 0) {
	// 			printf("other thread addr %lld \n", btx->addr);
	// 		}
	// 	}
	
	// if (unlikely(!rte_ring_empty(test_ring))) {
			// struct burst_tx *btx;
			// void *slot_id = NULL;
			// while (rte_ring_sc_dequeue(test_ring, &slot_id) == 0) {
			// 	uintptr_t addr = (uintptr_t)slot_id;
			// 	btx = (struct burst_tx *)(addr);
			// 	printf("other thread addr %lld \n", btx->addr);
			// 	slot_id = NULL;
			// }
		// }

    int i;

    for (i = 0; i < n_threads; i++)
		thread_data[i].quit = 1;

	for (i = 0; i < n_threads; i++)
		pthread_join(threads[i], NULL);


	rte_ring_free(test_ring);
	rte_eal_cleanup();
	CPU_FREE(&cpuset);

	return 0;
}
