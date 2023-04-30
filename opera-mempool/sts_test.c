/**
 * Ring buffer is a fixed-size queue, implemented as a table of
 * pointers. Head and tail pointers are modified atomically, allowing
 * concurrent access to it. It has the following features:
 * - FIFO (First In First Out)
 * - Maximum size is fixed; the pointers are stored in a table.
 * - Lockless implementation.
 *
 * The ring buffer implementation is not preemptable.
 */
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

#include "sts_queue/sts_queue.h"

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
	// ringbuf_t *rb;
    StsHeader *rb;
	int quit;
};

#ifndef MAX_THREADS
#define MAX_THREADS 2
#endif

static struct thread_data thread_data[MAX_THREADS];
static pthread_t threads[MAX_THREADS];
static int n_threads;

#include <assert.h>

static void *
thread_func_pop(void *arg)
{
	
	struct thread_data *t = arg;
	cpu_set_t cpu_cores;
	

	CPU_ZERO(&cpu_cores);
	CPU_SET(t->cpu_core_id, &cpu_cores);
	pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu_cores);
	StsHeader *q = t->rb;
	
    while (!t->quit) {
        // u32 i;
        // for (int i = 0; !ringbuf_is_empty(q); i++) {
        //     void *obj;
		// 	struct burst_tx btx_test;
		// 	ringbuf_sc_dequeue(q, &obj);
		// 	struct burst_tx *btx = (struct burst_tx*)obj;
		// 	printf("POP addr %lld \n", btx->addr);
        // }

        // while (mpmc_queue_available(q)) {
        //     void *ptr;
        //     if (mpmc_queue_pull(q, &ptr)) {
        //         struct burst_tx *btx = (struct burst_tx*)ptr;
		// 	    printf("POP addr %lld \n", btx->addr);
        //     }
        // }
        void *ptr;
        while ( (ptr = StsQueue.pop(q)) != NULL) {
            struct burst_tx *btx = (struct burst_tx*)ptr;
	        printf("POP addr %lld \n", btx->addr);
        }
    }
    return NULL;
}

static void *
thread_func_push(void *arg)
{
	
	struct thread_data *t = arg;
	cpu_set_t cpu_cores;
	

	CPU_ZERO(&cpu_cores);
	CPU_SET(t->cpu_core_id, &cpu_cores);
	pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu_cores);
	StsHeader *q = t->rb;
	int j=0;
    while (!t->quit) {
        // u32 i;
        // for (int i = 0; !ringbuf_is_full(q); i++) {
        //     struct burst_tx btx;
		// 	btx.addr = 25000 + i;
		// 	btx.len = 100;
        //     printf("RX pushed adrr %lld \n", btx.addr);
        //     ringbuf_sp_enqueue(q, (void *) &btx);
        // }

        for (size_t i = 0; i != 5; i += 1) {
            
            if (j == 5) {
                break;
            }
            struct burst_tx btx;
			btx.addr = 25000 + i;
			btx.len = 100;
            printf("RX pushed adrr %lld \n", btx.addr);
            StsQueue.push(q, (void *) &btx);
            j++;
            // mpmc_queue_push(q, (void *) &btx);
			// void *ptr = (void *) i;
			// while (!mpmc_queue_push(q, (void *) &btx))
			// 	thrd_yield(); // queue full, let other threads proceed
		}
            
    }
    return NULL;
}

size_t const queue_size = 1 << 20;

int main(void)
{
    // ringbuf_t *rb = ringbuf_create((1 << 6));
    // ringbuf_t *rb = ringbuf_create(16);
    // if (!rb) {
    //     printf("Fail to create ring buffer.\n");
    //     return -1;
    // }

    // struct mpmc_queue *queue;
    // struct mpmc_queue queue_i;
    // mpmc_queue_init(&queue_i, queue_size, &memtype_heap);
    // queue = &queue_i;

    StsHeader *queue = StsQueue.create();

    n_threads = 2;
	thread_data[0].cpu_core_id = 0; 
	thread_data[1].cpu_core_id = 0; 

    struct thread_data *t1 = &thread_data[0];
	struct thread_data *t2 = &thread_data[1];

    t1->rb = queue;
	t2->rb = queue;

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

    // for (int i = 0; !ringbuf_is_full(r); i++)
    //     ringbuf_sp_enqueue(r, *(void **) &i);

    // for (int i = 0; !ringbuf_is_empty(r); i++) {
    //     void *obj;
    //     ringbuf_sc_dequeue(r, &obj);
    //     assert(i == *(int *) &obj);
    // }

    sleep(1);

    int i;

    for (i = 0; i < n_threads; i++)
		thread_data[i].quit = 1;

	for (i = 0; i < n_threads; i++)
		pthread_join(threads[i], NULL);

    // int ret = mpmc_queue_destroy(queue);
	// if (ret)
	// 	printf("Failed to destroy queue: %d", ret);

    StsQueue.destroy(queue);

    // ringbuf_free(rb);
    return 0;
}