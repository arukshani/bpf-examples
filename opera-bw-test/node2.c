// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2020 - 2022 Intel Corporation. */

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


// #include "../common/common_params.h"
// #include "../common/common_user_bpf_xdp.h"
// #include "../common/common_libbpf.h"
///++++++++++

// // SPDX-License-Identifier: GPL-2.0
// /* Copyright(c) 2020 - 2022 Intel Corporation. */

// // #define _GNU_SOURCE
// #include <poll.h>
// #include <pthread.h>
// #include <signal.h>
// #include <sched.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <sys/mman.h>
// #include <sys/resource.h>
// #include <sys/socket.h>
// #include <sys/types.h>
// #include <time.h>
// #include <unistd.h>
// #include <getopt.h>
// #include <netinet/ether.h>
// #include <net/if.h>

// // // #include <linux/err.h>
// #include <linux/if_link.h>
// #include <linux/if_xdp.h>

// #include <bpf/bpf.h>
// #include <xdp/xsk.h>
// // #include <xdp/libxdp.h>
// // #include <bpf/bpf.h>
// // #include <bpf/xsk.h>

// /* SPDX-License-Identifier: GPL-2.0 */

// #include <assert.h>
// #include <errno.h>
// #include <getopt.h>
// #include <locale.h>
// #include <poll.h>
// #include <pthread.h>
// #include <signal.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <time.h>
// #include <unistd.h>

// #include <sys/resource.h>

// // #include <bpf/bpf.h>
// // #include <bpf/xsk.h>

// // #include "../common/common_params.h"
// // #include "../common/common_user_bpf_xdp.h"
// // #include "../common/common_libbpf.h"
// // #include "../lib/xdp-tools/headers/xdp/libxdp.h"

#include <linux/ptp_clock.h>
#define DEVICE "/dev/ptp3"

#ifndef CLOCK_INVALID
#define CLOCK_INVALID -1
#endif

#define CLOCKFD 3
#define FD_TO_CLOCKID(fd)	((clockid_t) ((((unsigned int) ~fd) << 3) | CLOCKFD))
#define CLOCKID_TO_FD(clk)	((unsigned int) ~((clk) >> 3))

#define STRERR_BUFSIZE          1024
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8  u8;


struct bpool_params {
	u32 n_buffers;
	u32 buffer_size;
	int mmap_flags;

	u32 n_users_max;
	u32 n_buffers_per_slab;
};

/*
 * Port
 *
 * Each of the forwarding ports sits on top of an AF_XDP socket. In order for
 * packet forwarding to happen with no packet buffer copy, all the sockets need
 * to share the same UMEM area, which is used as the buffer pool memory.
 */
#ifndef MAX_BURST_RX
#define MAX_BURST_RX 1
#endif

#ifndef MAX_BURST_TX
#define MAX_BURST_TX 64
#endif

struct burst_rx {
	u64 addr[MAX_BURST_RX];
	u32 len[MAX_BURST_RX];
};

struct burst_tx {
	u64 addr[MAX_BURST_TX];
	u32 len[MAX_BURST_TX];
	u32 n_pkts;
};

struct port_params {
	struct xsk_socket_config xsk_cfg;
	struct bpool *bp;
	const char *iface;
	u32 iface_queue;
};

struct port {
	struct port_params params;

	struct bcache *bc;

	struct xsk_ring_cons rxq;
	struct xsk_ring_prod txq;
	struct xsk_ring_prod umem_fq;
	struct xsk_ring_cons umem_cq;
	struct xsk_socket *xsk;
	int umem_fq_initialized;

	u64 n_pkts_rx;
	u64 n_pkts_tx;
};

struct bpool {
	struct bpool_params params;
	pthread_mutex_t lock;
	void *addr;

	u64 **slabs;
	u64 **slabs_reserved;
	u64 *buffers;
	u64 *buffers_reserved;

	u64 n_slabs;
	u64 n_slabs_reserved;
	u64 n_buffers;

	u64 n_slabs_available;
	u64 n_slabs_reserved_available;

	struct xsk_umem_config umem_cfg;
	struct xsk_ring_prod umem_fq;
	struct xsk_ring_cons umem_cq;
	struct xsk_umem *umem;
};

/*
 * Process
 */
static const struct bpool_params bpool_params_default = {
	.n_buffers = 64 * 1024,
	.buffer_size = XSK_UMEM__DEFAULT_FRAME_SIZE,
	.mmap_flags = 0,

	.n_users_max = 16,
	.n_buffers_per_slab = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2
};

static const struct xsk_umem_config umem_cfg_default = {
	.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
	.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
	.frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE,
	.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
	.flags = 0,
};

static const struct port_params port_params_default = {
	.xsk_cfg = {
		.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
		.xdp_flags = XDP_FLAGS_DRV_MODE,
		.bind_flags = XDP_USE_NEED_WAKEUP,
	},

	.bp = NULL,
	.iface = NULL,
	.iface_queue = 0,
};


#ifndef MAX_PORTS
#define MAX_PORTS 64
#endif

#ifndef MAX_THREADS
#define MAX_THREADS 64
#endif

static struct bpool_params bpool_params;
static struct xsk_umem_config umem_cfg;
static struct bpool *bp;

static struct port_params port_params[MAX_PORTS];
static struct port *ports[MAX_PORTS];
static int n_ports;

/*
 * Thread
 *
 * Packet forwarding threads.
 */
#ifndef MAX_PORTS_PER_THREAD
#define MAX_PORTS_PER_THREAD 16
#endif



struct thread_data {
	struct port *ports_rx[MAX_PORTS_PER_THREAD];
	struct port *ports_tx[MAX_PORTS_PER_THREAD];
	u32 n_ports_rx;
	struct burst_rx burst_rx;
	struct burst_tx burst_tx[MAX_PORTS_PER_THREAD];
	u32 cpu_core_id;
	int quit;
};

static pthread_t threads[MAX_THREADS];
static struct thread_data thread_data[MAX_THREADS];
static int n_threads;

struct bcache {
	struct bpool *bp;

	u64 *slab_cons;
	u64 *slab_prod;

	u64 n_buffers_cons;
	u64 n_buffers_prod;
};

static void
bcache_free(struct bcache *bc)
{
	struct bpool *bp;

	if (!bc)
		return;

	/* In order to keep this example simple, the case of freeing any
	 * existing buffers from the cache back to the pool is ignored.
	 */

	bp = bc->bp;
	pthread_mutex_lock(&bp->lock);
	bp->slabs_reserved[bp->n_slabs_reserved_available] = bc->slab_prod;
	bp->slabs_reserved[bp->n_slabs_reserved_available + 1] = bc->slab_cons;
	bp->n_slabs_reserved_available += 2;
	pthread_mutex_unlock(&bp->lock);

	free(bc);
}

static void
port_free(struct port *p)
{
	if (!p)
		return;

	/* To keep this example simple, the code to free the buffers from the
	 * socket's receive and transmit queues, as well as from the UMEM fill
	 * and completion queues, is not included.
	 */

	if (p->xsk)
		xsk_socket__delete(p->xsk);

	bcache_free(p->bc);

	free(p);
}

/* To work correctly, the implementation requires that the *n_buffers* input
 * argument is never greater than the buffer pool's *n_buffers_per_slab*. This
 * is typically the case, with one exception taking place when large number of
 * buffers are allocated at init time (e.g. for the UMEM fill queue setup).
 */
static inline u32
bcache_cons_check(struct bcache *bc, u32 n_buffers)
{
	struct bpool *bp = bc->bp;
	u64 n_buffers_per_slab = bp->params.n_buffers_per_slab;
	u64 n_buffers_cons = bc->n_buffers_cons;
	u64 n_slabs_available;
	u64 *slab_full;

	/*
	 * Consumer slab is not empty: Use what's available locally. Do not
	 * look for more buffers from the pool when the ask can only be
	 * partially satisfied.
	 */
	
	if (n_buffers_cons) {
		// printf("bc->n_buffers_cons %lld not empty \n", n_buffers_cons);
		return (n_buffers_cons < n_buffers) ?
			n_buffers_cons :
			n_buffers;
	}
		

	/*
	 * Consumer slab is empty: look to trade the current consumer slab
	 * (full) for a full slab from the pool, if any is available.
	 */
	pthread_mutex_lock(&bp->lock);
	n_slabs_available = bp->n_slabs_available;
	// printf("n_buffers_cons %lld \n", n_buffers_cons);
	if (!n_slabs_available) {
		pthread_mutex_unlock(&bp->lock);
		return 0;
	}

	n_slabs_available--;
	slab_full = bp->slabs[n_slabs_available];
	bp->slabs[n_slabs_available] = bc->slab_cons;
	bp->n_slabs_available = n_slabs_available;
	pthread_mutex_unlock(&bp->lock);

	// printf("after n_slabs_available--  %lld \n", bp->n_slabs_available);

	bc->slab_cons = slab_full;
	bc->n_buffers_cons = n_buffers_per_slab;
	return n_buffers;
}

static u32
bcache_slab_size(struct bcache *bc)
{
	struct bpool *bp = bc->bp;

	return bp->params.n_buffers_per_slab;
}

static struct bcache *
bcache_init(struct bpool *bp)
{
	struct bcache *bc;

	bc = calloc(1, sizeof(struct bcache));
	if (!bc)
		return NULL;

	bc->bp = bp;
	bc->n_buffers_cons = 0;
	bc->n_buffers_prod = 0;

	pthread_mutex_lock(&bp->lock);
	if (bp->n_slabs_reserved_available == 0) {
		pthread_mutex_unlock(&bp->lock);
		free(bc);
		return NULL;
	}

	bc->slab_cons = bp->slabs_reserved[bp->n_slabs_reserved_available - 1];
	bc->slab_prod = bp->slabs_reserved[bp->n_slabs_reserved_available - 2];
	bp->n_slabs_reserved_available -= 2;
	pthread_mutex_unlock(&bp->lock);

	return bc;
}

static inline u64
bcache_cons(struct bcache *bc)
{
	u64 n_buffers_cons = bc->n_buffers_cons - 1;
	u64 buffer;

	buffer = bc->slab_cons[n_buffers_cons];
	bc->n_buffers_cons = n_buffers_cons;
	// printf("bc->n_buffers_cons %lld \n", n_buffers_cons);
	return buffer;
}

static inline void
bcache_prod(struct bcache *bc, u64 buffer)
{
	struct bpool *bp = bc->bp;
	u64 n_buffers_per_slab = bp->params.n_buffers_per_slab;
	u64 n_buffers_prod = bc->n_buffers_prod;
	u64 n_slabs_available;
	u64 *slab_empty;

	/*
	 * Producer slab is not yet full: store the current buffer to it.
	 */
	if (n_buffers_prod < n_buffers_per_slab) {
		// printf("prod slab is NOT full; %ld n_slabs_available %d n_buffers_prod \n", bp->n_slabs_available, n_buffers_prod);
		bc->slab_prod[n_buffers_prod] = buffer;
		bc->n_buffers_prod = n_buffers_prod + 1;
		return;
	}

	// printf("prod slab FULL bp->n_slabs_available %lld \n", bp->n_slabs_available);

	/*
	 * Producer slab is full: trade the cache's current producer slab
	 * (full) for an empty slab from the pool, then store the current
	 * buffer to the new producer slab. As one full slab exists in the
	 * cache, it is guaranteed that there is at least one empty slab
	 * available in the pool.
	 */
	pthread_mutex_lock(&bp->lock);
	n_slabs_available = bp->n_slabs_available;
	slab_empty = bp->slabs[n_slabs_available];
	bp->slabs[n_slabs_available] = bc->slab_prod;
	bp->n_slabs_available = n_slabs_available + 1;
	pthread_mutex_unlock(&bp->lock);

	slab_empty[0] = buffer;
	bc->slab_prod = slab_empty;
	bc->n_buffers_prod = 1;

	// printf("AFTER prod slab FULL bp->n_slabs_available %lld \n", bp->n_slabs_available);
}

static void apply_setsockopt(struct xsk_socket *xsk)
{
	int sock_opt;

	// if (!opt_busy_poll)
	// 	return;

	sock_opt = 1;
	if (setsockopt(xsk_socket__fd(xsk), SOL_SOCKET, SO_PREFER_BUSY_POLL,
		       (void *)&sock_opt, sizeof(sock_opt)) < 0)
		printf("Error!!!");

	sock_opt = 20;
	if (setsockopt(xsk_socket__fd(xsk), SOL_SOCKET, SO_BUSY_POLL,
		       (void *)&sock_opt, sizeof(sock_opt)) < 0)
		printf("Error!!!");

	sock_opt = 1;
	if (setsockopt(xsk_socket__fd(xsk), SOL_SOCKET, SO_BUSY_POLL_BUDGET,
		       (void *)&sock_opt, sizeof(sock_opt)) < 0)
		printf("Error!!!");
}


static struct port *
port_init(struct port_params *params)
{
	struct port *p;
	u32 umem_fq_size, pos = 0;
	int status, i;

	/* Memory allocation and initialization. */
	p = calloc(sizeof(struct port), 1);
	if (!p)
		return NULL;

	memcpy(&p->params, params, sizeof(p->params));
	umem_fq_size = params->bp->umem_cfg.fill_size;

	/* bcache. */
	p->bc = bcache_init(params->bp);
	if (!p->bc ||
	    (bcache_slab_size(p->bc) < umem_fq_size) ||
	    (bcache_cons_check(p->bc, umem_fq_size) < umem_fq_size)) {
		port_free(p);
		return NULL;
	}

	// printf("hello++++++++ %d \n", params->iface_queue);
	// printf("hello++++++++ %s \n", params->iface);

	// if (IS_ERR_OR_NULL(&p->rxq)) {
	// 	printf("NULL \n");
	// }

	/* xsk socket. */
	status = xsk_socket__create_shared(&p->xsk,
					   params->iface,
					   params->iface_queue,
					   params->bp->umem,
					   &p->rxq,
					   &p->txq,
					   &p->umem_fq,
					   &p->umem_cq,
					   &params->xsk_cfg);
	apply_setsockopt(p->xsk);

	// printf("xsk_socket__create_shared returns %d\n", status) ;

	// status = xsk_socket__create(&p->xsk,
	// 				   params->iface,
	// 				   params->iface_queue,
	// 				   params->bp->umem,
	// 				   &p->rxq,
	// 				   &p->txq,
	// 				   &p->umem_fq,
	// 				   &p->umem_cq,
	// 				   &params->xsk_cfg);
	if (status) {
		printf("ERROR in xsk_socket__create_shared \n");
		port_free(p);
		return NULL;
	}
	

	/* umem fq. */
	xsk_ring_prod__reserve(&p->umem_fq, umem_fq_size, &pos);

	for (i = 0; i < umem_fq_size; i++)
		*xsk_ring_prod__fill_addr(&p->umem_fq, pos + i) =
			bcache_cons(p->bc);

	// printf("b4 %d, \n", p->bc->n_buffers_cons);
	xsk_ring_prod__submit(&p->umem_fq, umem_fq_size);
	// printf("af %d, \n", p->bc->n_buffers_cons);
	p->umem_fq_initialized = 1;

	return p;
}

static struct bpool *
bpool_init(struct bpool_params *params,
	   struct xsk_umem_config *umem_cfg)
{
    printf("Hello \n");
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	u64 n_slabs, n_slabs_reserved, n_buffers, n_buffers_reserved;
	u64 slabs_size, slabs_reserved_size;
	u64 buffers_size, buffers_reserved_size;
	u64 total_size, i;
	struct bpool *bp;
	u8 *p;
	int status;

	/* mmap prep. */
	if (setrlimit(RLIMIT_MEMLOCK, &r))
		return NULL;

	/* bpool internals dimensioning. */
	n_slabs = (params->n_buffers + params->n_buffers_per_slab - 1) /
		params->n_buffers_per_slab;
	n_slabs_reserved = params->n_users_max * 2;
	n_buffers = n_slabs * params->n_buffers_per_slab;
	n_buffers_reserved = n_slabs_reserved * params->n_buffers_per_slab;

	slabs_size = n_slabs * sizeof(u64 *);
	slabs_reserved_size = n_slabs_reserved * sizeof(u64 *);
	buffers_size = n_buffers * sizeof(u64);
	buffers_reserved_size = n_buffers_reserved * sizeof(u64);

	total_size = sizeof(struct bpool) +
		slabs_size + slabs_reserved_size +
		buffers_size + buffers_reserved_size;

    printf("n_slabs %lld \n", n_slabs);
    printf("n_slabs_reserved %lld \n", n_slabs_reserved);
    printf("n_buffers %lld \n", n_buffers);
    printf("n_buffers_reserved %lld \n", n_buffers_reserved);
    printf("slabs_size %lld \n", slabs_size);
    printf("slabs_reserved_size %lld \n", slabs_reserved_size);
    printf("buffers_size %lld \n", buffers_size);
    printf("buffers_reserved_size %lld \n", buffers_reserved_size);
    printf("total_size %lld \n", total_size);

	/* bpool memory allocation. */
	p = calloc(total_size, sizeof(u8)); //store the address of the bool memory block
	if (!p)
		return NULL;

	printf("============= \n");
	printf("bp->slabs p[] %ld \n", sizeof(struct bpool));
	printf("bp->slabs_reserved p[] %lld \n", sizeof(struct bpool) + slabs_size);
	printf("bp->buffers  p[] %lld \n", sizeof(struct bpool) + slabs_size + slabs_reserved_size);
	printf("bp->buffers_reserved  p[] %lld \n", sizeof(struct bpool) + slabs_size + slabs_reserved_size + buffers_size);
	printf("============= \n");

	/* bpool memory initialization. */
	bp = (struct bpool *)p; //address of bpool
	memcpy(&bp->params, params, sizeof(*params));
	bp->params.n_buffers = n_buffers;

	bp->slabs = (u64 **)&p[sizeof(struct bpool)];
	bp->slabs_reserved = (u64 **)&p[sizeof(struct bpool) +
		slabs_size];
	bp->buffers = (u64 *)&p[sizeof(struct bpool) +
		slabs_size + slabs_reserved_size];
	bp->buffers_reserved = (u64 *)&p[sizeof(struct bpool) +
		slabs_size + slabs_reserved_size + buffers_size];

	bp->n_slabs = n_slabs;
	bp->n_slabs_reserved = n_slabs_reserved;
	bp->n_buffers = n_buffers;

	for (i = 0; i < n_slabs; i++)
		bp->slabs[i] = &bp->buffers[i * params->n_buffers_per_slab];
	bp->n_slabs_available = n_slabs;

	for (i = 0; i < n_slabs_reserved; i++)
		bp->slabs_reserved[i] = &bp->buffers_reserved[i *
			params->n_buffers_per_slab];
	bp->n_slabs_reserved_available = n_slabs_reserved;

	for (i = 0; i < n_buffers; i++)
		bp->buffers[i] = i * params->buffer_size;

	/* lock. */
	status = pthread_mutex_init(&bp->lock, NULL);
	if (status) {
		free(p);
		return NULL;
	}

	/* mmap. */
	bp->addr = mmap(NULL,
			n_buffers * params->buffer_size,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | params->mmap_flags,
			-1,
			0);
	if (bp->addr == MAP_FAILED) {
		pthread_mutex_destroy(&bp->lock);
		free(p);
		return NULL;
	}

	/* umem. */
	status = xsk_umem__create(&bp->umem,
				  bp->addr,
				  bp->params.n_buffers * bp->params.buffer_size,
				  &bp->umem_fq,
				  &bp->umem_cq,
				  umem_cfg);
	if (status) {
		munmap(bp->addr, bp->params.n_buffers * bp->params.buffer_size);
		pthread_mutex_destroy(&bp->lock);
		free(p);
		return NULL;
	}
	memcpy(&bp->umem_cfg, umem_cfg, sizeof(*umem_cfg));

    printf("bp->params.n_buffers %d \n", bp->params.n_buffers);
    printf("bp->params.buffer_size %d \n", bp->params.buffer_size);
    printf("total_size umem %d \n", bp->params.n_buffers * bp->params.buffer_size);
    printf("bp->n_slabs %lld \n", bp->n_slabs);
    printf("bp->n_buffers %lld \n", bp->n_buffers);
    printf("params->n_buffers_per_slab %d \n", params->n_buffers_per_slab);
    printf("bp->n_slabs_reserved %lld \n", bp->n_slabs_reserved);

	return bp;
}

static void
bpool_free(struct bpool *bp)
{
	if (!bp)
		return;

	xsk_umem__delete(bp->umem);
	munmap(bp->addr, bp->params.n_buffers * bp->params.buffer_size);
	pthread_mutex_destroy(&bp->lock);
	free(bp);
}

static void
print_port(u32 port_id)
{
	struct port *port = ports[port_id];

	printf("Port %u: interface = %s, queue = %u\n",
	       port_id, port->params.iface, port->params.iface_queue);
}

static void
print_thread(u32 thread_id)
{
	struct thread_data *t = &thread_data[thread_id];
	u32 i;

	printf("Thread %u (CPU core %u): ",
	       thread_id, t->cpu_core_id);

	for (i = 0; i < t->n_ports_rx; i++) {
		struct port *port_rx = t->ports_rx[i];
		struct port *port_tx = t->ports_tx[i];

		printf("(%s, %u) -> (%s, %u), ",
		       port_rx->params.iface,
		       port_rx->params.iface_queue,
		       port_tx->params.iface,
		       port_tx->params.iface_queue);
	}

	printf("\n");
}

static void remove_xdp_program(void)
{
	struct xdp_multiprog *mp;
	int i, err;

	for (i = 0 ; i < n_ports; i++) {
	        mp = xdp_multiprog__get_from_ifindex(if_nametoindex(port_params[i].iface));
	        if (IS_ERR_OR_NULL(mp)) {
	        	printf("No XDP program loaded on %s\n", port_params[i].iface);
	        	continue;
	        }

                err = xdp_multiprog__detach(mp);
                if (err)
                        printf("Unable to detach XDP program: %s\n", strerror(-err));
	}
}

static struct xdp_program *xdp_prog[2];
// static enum xdp_attach_mode opt_attach_mode = XDP_MODE_NATIVE;

static int lookup_bpf_map(int prog_fd)
{
	__u32 i, *map_ids, num_maps, prog_len = sizeof(struct bpf_prog_info);
	__u32 map_len = sizeof(struct bpf_map_info);
	struct bpf_prog_info prog_info = {};
	int fd, err, xsks_map_fd = -ENOENT;
	struct bpf_map_info map_info;

	err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &prog_len);
	if (err)
		return err;

	num_maps = prog_info.nr_map_ids;

	map_ids = calloc(prog_info.nr_map_ids, sizeof(*map_ids));
	if (!map_ids)
		return -ENOMEM;

	memset(&prog_info, 0, prog_len);
	prog_info.nr_map_ids = num_maps;
	prog_info.map_ids = (__u64)(unsigned long)map_ids;

	err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &prog_len);
	if (err) {
		free(map_ids);
		return err;
	}

	for (i = 0; i < prog_info.nr_map_ids; i++) {
		fd = bpf_map_get_fd_by_id(map_ids[i]);
		if (fd < 0)
			continue;

		memset(&map_info, 0, map_len);
		err = bpf_obj_get_info_by_fd(fd, &map_info, &map_len);
		if (err) {
			close(fd);
			continue;
		}

		if (!strncmp(map_info.name, "xsks_map", sizeof(map_info.name)) &&
		    map_info.key_size == 4 && map_info.value_size == 4) {
			xsks_map_fd = fd;
			break;
		}

		close(fd);
	}

	free(map_ids);
	return xsks_map_fd;
}


static void enter_xsks_into_map(u32 index)
{
	int i, xsks_map;

	xsks_map = lookup_bpf_map(xdp_program__fd(xdp_prog[index]));
	if (xsks_map < 0) {
		fprintf(stderr, "ERROR: no xsks map found: %s\n",
			strerror(xsks_map));
			exit(EXIT_FAILURE);
	}

	printf("Update bpf map for xdp_prog[%d] %s, \n", index, port_params[index].iface);

	int fd = xsk_socket__fd(ports[index]->xsk);
	int key, ret;
	i = 0;
	key = i;
	ret = bpf_map_update_elem(xsks_map, &key, &fd, 0);
	if (ret) {
		fprintf(stderr, "ERROR: bpf_map_update_elem %d %d\n", i, ret);
		exit(EXIT_FAILURE);
	}
}

struct config {
	int ifindex;
	char *ifname;
	bool reuse_maps;
	char pin_dir[512];
	char filename[512];
	char progsec[32];
	char src_mac[18];
	char dest_mac[18];
	int xsk_if_queue;
	bool xsk_poll_mode;
};

static void load_xdp_program(void)
{
	//Outer veth 
    struct config veth_cfg = {
		.ifindex = 6,
		.ifname = "veth1",
		.xsk_if_queue = 0,
		.xsk_poll_mode = true,
		.filename = "veth_kern.o",
		.progsec = "xdp_sock_0"
	};

	//Physical NIC
    struct config nic_cfg = {
		.ifindex = 4,
		.ifname = "enp65s0f0np0",
		.xsk_if_queue = 0,
		.xsk_poll_mode = true,
		.filename = "nic_kern.o",
		.progsec = "xdp_sock_1"
	};

	struct config cfgs[2] = {veth_cfg, nic_cfg};

	int i;
	for (i = 0; i < 2; i++) {

		char errmsg[STRERR_BUFSIZE];
		int err;

		printf("xdp_prog[%d] is %s \n", i, cfgs[i].filename);

		xdp_prog[i] = xdp_program__open_file(cfgs[i].filename, cfgs[i].progsec, NULL);
		err = libxdp_get_error(xdp_prog[i]);
		if (err) {
			libxdp_strerror(err, errmsg, sizeof(errmsg));
			fprintf(stderr, "ERROR: program loading failed: %s\n", errmsg);
			exit(EXIT_FAILURE);
		}

		err = xdp_program__attach(xdp_prog[i], cfgs[i].ifindex, XDP_FLAGS_DRV_MODE, 0);
		if (err) {
			libxdp_strerror(err, errmsg, sizeof(errmsg));
			fprintf(stderr, "ERROR: attaching program failed: %s\n", errmsg);
			exit(EXIT_FAILURE);
		}
	}
}

static int quit;

static void signal_handler(int sig)
{
	quit = 1;
}

static inline u32
port_rx_burst(struct port *p, struct burst_rx *b, int index)
{
	u32 n_pkts, pos, i;

	/* Free buffers for FQ replenish. */
	n_pkts = ARRAY_SIZE(b->addr);
	
	n_pkts = bcache_cons_check(p->bc, n_pkts);

	if (!n_pkts)
		return 0;

	// printf("bp->n_slabs_available %ld \n", p->bc->bp->n_slabs_available);

	/* RXQ. */
	n_pkts = xsk_ring_cons__peek(&p->rxq, n_pkts, &pos);
	if (!n_pkts) {
		if (xsk_ring_prod__needs_wakeup(&p->umem_fq)) {
			struct pollfd pollfd = {
				.fd = xsk_socket__fd(p->xsk),
				.events = POLLIN,
			};

			poll(&pollfd, 1, 0);
		}
		return 0;
	}

	for (i = 0; i < n_pkts; i++) {
		b->addr[i] = xsk_ring_cons__rx_desc(&p->rxq, pos + i)->addr;
		b->len[i] = xsk_ring_cons__rx_desc(&p->rxq, pos + i)->len;
	}

	xsk_ring_cons__release(&p->rxq, n_pkts);
	p->n_pkts_rx += n_pkts;

	/* UMEM FQ. */
	for ( ; ; ) {
		int status;

		status = xsk_ring_prod__reserve(&p->umem_fq, n_pkts, &pos);
		if (status == n_pkts)
			break;

		if (xsk_ring_prod__needs_wakeup(&p->umem_fq)) {
			struct pollfd pollfd = {
				.fd = xsk_socket__fd(p->xsk),
				.events = POLLIN,
			};

			poll(&pollfd, 1, 0);
		}
	}

	for (i = 0; i < n_pkts; i++)
		*xsk_ring_prod__fill_addr(&p->umem_fq, pos + i) =
			bcache_cons(p->bc);

	xsk_ring_prod__submit(&p->umem_fq, n_pkts);

	return n_pkts;
}

static inline void
port_tx_burst(struct port *p, struct burst_tx *b)
{
	u32 n_pkts, pos, i;
	int status;

	/* UMEM CQ. */
	n_pkts = p->params.bp->umem_cfg.comp_size;

	n_pkts = xsk_ring_cons__peek(&p->umem_cq, n_pkts, &pos);

	// printf("n_pkts in port_tx_burst %ld \n", n_pkts);
	// printf("bp->n_slabs_available %ld \n", p->bc->bp->n_slabs_available);

	for (i = 0; i < n_pkts; i++) {
		u64 addr = *xsk_ring_cons__comp_addr(&p->umem_cq, pos + i);

		bcache_prod(p->bc, addr);
	}

	xsk_ring_cons__release(&p->umem_cq, n_pkts);

	/* TXQ. */
	n_pkts = b->n_pkts;

	for ( ; ; ) {
		status = xsk_ring_prod__reserve(&p->txq, n_pkts, &pos);
		if (status == n_pkts)
			break;

		if (xsk_ring_prod__needs_wakeup(&p->txq))
			sendto(xsk_socket__fd(p->xsk), NULL, 0, MSG_DONTWAIT,
			       NULL, 0);
	}

	// printf("Fill tx desc for n_pkts %ld \n", n_pkts);
	// printf("Port tx burst \n");

	for (i = 0; i < n_pkts; i++) {
		xsk_ring_prod__tx_desc(&p->txq, pos + i)->addr = b->addr[i];
		xsk_ring_prod__tx_desc(&p->txq, pos + i)->len = b->len[i];
	}

	xsk_ring_prod__submit(&p->txq, n_pkts);
	if (xsk_ring_prod__needs_wakeup(&p->txq))
		sendto(xsk_socket__fd(p->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	p->n_pkts_tx += n_pkts;
}


/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
static inline unsigned short from32to16(unsigned int x)
{
	/* add up 16-bit and 16-bit for 16+c bit */
	x = (x & 0xffff) + (x >> 16);
	/* add up carry.. */
	x = (x & 0xffff) + (x >> 16);
	return x;
}

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
static unsigned int do_csum(const unsigned char *buff, int len)
{
	unsigned int result = 0;
	int odd;

	if (len <= 0)
		goto out;
	odd = 1 & (unsigned long)buff;
	if (odd) {
#ifdef __LITTLE_ENDIAN
		result += (*buff << 8);
#else
		result = *buff;
#endif
		len--;
		buff++;
	}
	if (len >= 2) {
		if (2 & (unsigned long)buff) {
			result += *(unsigned short *)buff;
			len -= 2;
			buff += 2;
		}
		if (len >= 4) {
			const unsigned char *end = buff +
						   ((unsigned int)len & ~3);
			unsigned int carry = 0;

			do {
				unsigned int w = *(unsigned int *)buff;

				buff += 4;
				result += carry;
				result += w;
				carry = (w > result);
			} while (buff < end);
			result += carry;
			result = (result & 0xffff) + (result >> 16);
		}
		if (len & 2) {
			result += *(unsigned short *)buff;
			buff += 2;
		}
	}
	if (len & 1)
#ifdef __LITTLE_ENDIAN
		result += *buff;
#else
		result += (*buff << 8);
#endif
	result = from32to16(result);
	if (odd)
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
out:
	return result;
}

/*
 *	This is a version of ip_compute_csum() optimized for IP headers,
 *	which always checksum on 4 octet boundaries.
 *	This function code has been taken from
 *	Linux kernel lib/checksum.c
 */
static inline __sum16 ip_fast_csum(const void *iph, unsigned int ihl)
{
	return (__sum16)~do_csum(iph, ihl * 4);
}

struct gre_hdr {
	__be16 flags;
	__be16 proto;
} __attribute__((packed));

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

/* As debug tool print some info about packet */
// static void print_pkt_info(uint8_t *pkt, uint32_t len)
// {
// 	struct ethhdr *eth = (struct ethhdr *) pkt;
// 	__u16 proto = ntohs(eth->h_proto);

// 	char *fmt = "DEBUG-pkt len=%04d Eth-proto:0x%X %s "
// 		"src:%s -> dst:%s\n";
// 	char src_str[128] = { 0 };
// 	char dst_str[128] = { 0 };

// 	if (proto == ETH_P_IP) {
// 		struct iphdr *ipv4 = (struct iphdr *) (eth + 1);
// 		inet_ntop(AF_INET, &ipv4->saddr, src_str, sizeof(src_str));
// 		inet_ntop(AF_INET, &ipv4->daddr, dst_str, sizeof(dst_str));
// 		printf(fmt, len, proto, "IPv4", src_str, dst_str);
// 	} else if (proto == ETH_P_ARP) {
// 		printf(fmt, len, proto, "ARP", "", "");
// 	} else {
// 		printf(fmt, len, proto, "Unknown", "", "");
// 	}
// }

// static unsigned long get_nsecs_realtime(void)
// {
// 	struct timespec ts;

// 	clock_gettime(CLOCK_REALTIME, &ts);
// 	return ts.tv_sec * 1000000000UL + ts.tv_nsec;
// }

// static clockid_t get_clockid(int fd)
// {
// #define CLOCKFD 3
// 	return (((unsigned int) ~fd) << 3) | CLOCKFD;
// }

clockid_t clkid;
static clockid_t get_nic_clock_id(void)
{
	int fd;
    char *device = DEVICE;
    clockid_t clkid;

    fd = open(device, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "opening %s: %s\n", device, strerror(errno));
		return -1;
	}

	clkid = FD_TO_CLOCKID(fd);

	if (CLOCK_INVALID == clkid) {
		fprintf(stderr, "failed to read clock id\n");
		return -1;
	}
	return clkid;
}

// static unsigned long get_nsec_nicclock(void)
// {
// 	struct timespec ts;
// 	clock_gettime(clkid, &ts);
// 	return ts.tv_sec * 1000000000UL + ts.tv_nsec;
// }

static unsigned long get_nsec(struct timespec *ts)
{
    return ts->tv_sec * 1000000000UL + ts->tv_nsec;
}

static struct timespec get_realtime(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return ts;
}

static struct timespec get_nicclock(void)
{
	struct timespec ts;
	clock_gettime(clkid, &ts);
	return ts;
}

// unsigned long timestamp_arr[10050];
struct timespec timestamp_arr[10050];
unsigned int slot_arr[10050];
long time_index = 0;
struct timespec now;

//Header structure of GRE tap packet:
    // Ethernet type of GRE encapsulated packet is ETH_P_TEB (gretap)
	// outer eth
	// outer ip
	// gre
    // inner eth
	// inner ip
	// payload
static int process_rx_packet(void *data, struct port_params *params, uint32_t len, u64 addr)
{
	int is_veth = strcmp(params->iface, "veth1"); 
	int is_nic = strcmp(params->iface, "enp65s0f0np0"); 

	if (is_veth == 0)
	{
		struct iphdr *outer_iphdr; 
		struct iphdr encap_outer_iphdr; 
		struct ethhdr *outer_eth_hdr; 

		// unsigned long now = get_nsec_nicclock();
		// struct timespec now = get_nicclock();
		// struct timespec now = get_realtime();
		// timestamp_arr[time_index] = now;
		// slot_arr[time_index] = 1;
		// time_index++;

		unsigned char out_eth_src[ETH_ALEN+1] = { 0x0c, 0x42, 0xa1, 0xdd, 0x5a, 0x8c}; //0c:42:a1:dd:5a:8c
		unsigned char out_eth_dst[ETH_ALEN+1] = { 0x0c, 0x42, 0xa1, 0xdd, 0x5f, 0xcc}; //0c:42:a1:dd:5f:cc

		struct iphdr *inner_ip_hdr_tmp = (struct iphdr *)(data +
						sizeof(struct ethhdr));
		__builtin_memcpy(&encap_outer_iphdr, inner_ip_hdr_tmp, sizeof(encap_outer_iphdr));
		encap_outer_iphdr.protocol = IPPROTO_GRE;

		int olen = 0;
		olen += ETH_HLEN; 
		olen += sizeof(struct gre_hdr); 

		encap_outer_iphdr.tot_len = bpf_htons(olen + bpf_ntohs(inner_ip_hdr_tmp->tot_len));

		int encap_size = 0; //outer_eth + outer_ip + gre
		int encap_outer_eth_len = ETH_HLEN;
		int encap_outer_ip_len = sizeof(struct iphdr);
		int encap_gre_len = sizeof(struct gre_hdr);
		
		encap_size += encap_outer_eth_len; 
		encap_size += encap_outer_ip_len; 
		encap_size += encap_gre_len; 

		int offset = 0 + encap_size;
		u64 new_addr = addr + offset;
		int new_len = len + encap_size;

		u64 new_new_addr = xsk_umem__add_offset_to_addr(new_addr);
		memcpy(xsk_umem__get_data(params->bp->addr, new_new_addr), data, len);
		u8 *new_data = xsk_umem__get_data(params->bp->addr, new_new_addr);

		struct ethhdr *eth = (struct ethhdr *) new_data;
		struct iphdr *inner_ip_hdr = (struct iphdr *)(new_data +
						sizeof(struct ethhdr));

		if (ntohs(eth->h_proto) != ETH_P_IP ||
		    len < (sizeof(*eth) + sizeof(*inner_ip_hdr)))
			{
				printf("not ETH_P_IP or size is not within the len \n");
				return false;
			}
 
		outer_eth_hdr = (struct ethhdr *) data;
		__builtin_memcpy(outer_eth_hdr->h_source, out_eth_src, sizeof(outer_eth_hdr->h_source));
    	__builtin_memcpy(outer_eth_hdr->h_dest, out_eth_dst, sizeof(outer_eth_hdr->h_dest));
		outer_eth_hdr->h_proto = htons(ETH_P_IP);

		outer_iphdr = (struct iphdr *)(data +
						sizeof(struct ethhdr));
		__builtin_memcpy(outer_iphdr, &encap_outer_iphdr, sizeof(*outer_iphdr));

		struct gre_hdr *gre_hdr;
		gre_hdr = (struct gre_hdr *)(data +
						sizeof(struct ethhdr) + sizeof(struct iphdr));

		gre_hdr->proto = bpf_htons(ETH_P_TEB);
		gre_hdr->flags = 1;

        // printf("Encap GRE packet recevied from veth0 \n");

		return new_len;
		
	} else if (is_nic == 0)
	{
		struct ethhdr *eth = (struct ethhdr *) data;
		struct iphdr *outer_ip_hdr = (struct iphdr *)(data +
						sizeof(struct ethhdr));
		struct gre_hdr *greh = (struct gre_hdr *) (outer_ip_hdr + 1);
		
		if (ntohs(eth->h_proto) != ETH_P_IP || outer_ip_hdr->protocol != IPPROTO_GRE || 
					ntohs(greh->proto) != ETH_P_TEB)
		{
			printf("not a GRE packet \n");
			return false;
		}
		struct ethhdr *inner_eth = (struct ethhdr *) (greh +  1);
		if (ntohs(inner_eth->h_proto) != ETH_P_IP) {
			printf("inner eth proto is not ETH_P_IP %x \n", inner_eth->h_proto);
            return false;
		}

		// timestamp_arr[time_index] = now;
		// slot_arr[time_index] = 2;
		// time_index++;

		void *cutoff_pos = greh + 1;
		int cutoff_len = (int)(cutoff_pos - data);
		int new_len = len - cutoff_len;

		int offset = 0 + cutoff_len;
		u64 inner_eth_start_addr = addr + offset;

		u8 *new_data = xsk_umem__get_data(params->bp->addr, inner_eth_start_addr);
		memcpy(xsk_umem__get_data(params->bp->addr, addr), new_data, new_len);

		//only for clock testing purpose
		// u8 *pkt_data = xsk_umem__get_data(params->bp->addr, addr);

		// struct ethhdr *test_eth = (struct ethhdr *) pkt_data;
		// unsigned char veth_dst_mac[ETH_ALEN+1] = { 0x6e, 0x4e, 0x90, 0x1d, 0xcb, 0x93};  //6e:4e:90:1d:cb:93
		// __builtin_memcpy(test_eth->h_dest, veth_dst_mac, sizeof(test_eth->h_dest));

		// struct iphdr *test_ip_hdr = (struct iphdr *)(pkt_data +
		// 				sizeof(struct ethhdr));
		// test_ip_hdr->daddr = htonl(0xc0a80102); //192.168.1.2

		// printf("node3 received \n");
		
		return new_len;
	}

    return false;
}

static void *
thread_func(void *arg)
{
	
	struct thread_data *t = arg;
	cpu_set_t cpu_cores;
	u32 i;

	CPU_ZERO(&cpu_cores);
	CPU_SET(t->cpu_core_id, &cpu_cores);
	pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu_cores);
	clkid = get_nic_clock_id();
	
	for (i = 0; !t->quit; i = (i + 1) & (t->n_ports_rx - 1)) {
		// printf("port rx %d \n", i);
		// printf("n_buffers_cons %d, \n", t->ports_rx[i]->bc->n_buffers_cons);
		struct port *port_rx = t->ports_rx[i];
		struct port *port_tx = t->ports_tx[i];
		struct burst_rx *brx = &t->burst_rx;
		struct burst_tx *btx = &t->burst_tx[i];
		u32 n_pkts, j;

		// printf("RX \n");
		/* RX. */
		n_pkts = port_rx_burst(port_rx, brx, i);
		// printf("bp->n_slabs_available %ld \n", port_rx->bc->bp->n_slabs_available);
		// break;

		// printf("n_pkts %d \n", n_pkts);
		if (!n_pkts)
			continue;

		/* Process & TX. */
		for (j = 0; j < n_pkts; j++) {

			// printf("bp->n_slabs_available %ld \n", port_rx->bc->bp->n_slabs_available);

			u64 addr = xsk_umem__add_offset_to_addr(brx->addr[j]);
			u8 *pkt = xsk_umem__get_data(port_rx->params.bp->addr,
						     addr);

			int new_len = process_rx_packet(pkt, &port_rx->params, brx->len[j], brx->addr[j]);

			btx->addr[btx->n_pkts] = brx->addr[j];
			// btx->len[btx->n_pkts] = brx->len[j];
			btx->len[btx->n_pkts] = new_len;
			btx->n_pkts++;

			// if (btx->n_pkts == MAX_BURST_TX) {
			if (btx->n_pkts == 1) {
				port_tx_burst(port_tx, btx);
				btx->n_pkts = 0;
			}
		}
	}

	return NULL;
}

static void read_time()
{
	//now = get_realtime();
	now = get_nicclock();
}

int main(int argc, char **argv)
{
    // printf(" hello %ld", sizeof(u64 *));
    int i;

    /* Parse args. */
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

    n_threads = 1; //only 1 thread
    thread_data[0].cpu_core_id = 10; //cat /proc/cpuinfo | grep 'core id'

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
		// printf("af port_init %d, \n", ports[i]->bc->n_buffers_cons);
	}
	printf("All ports created successfully.\n");
	// clkid = get_nic_clock_id();

	/* Threads. */
	for (i = 0; i < n_threads; i++) {
		struct thread_data *t = &thread_data[i];
		u32 n_ports_per_thread = n_ports / n_threads, j;

		for (j = 0; j < n_ports_per_thread; j++) {
			t->ports_rx[j] = ports[i * n_ports_per_thread + j];
			t->ports_tx[j] = ports[i * n_ports_per_thread +
				(j + 1) % n_ports_per_thread];
			printf("t->ports_rx n_buffers_cons %lld, \n", t->ports_rx[j]->bc->n_buffers_cons);
		}

		t->n_ports_rx = n_ports_per_thread;

		print_thread(i);
	}

	for (i = 0; i < n_threads; i++) {
		int status;

		status = pthread_create(&threads[i],
					NULL,
					thread_func,
					&thread_data[i]);
		if (status) {
			printf("Thread %d creation failed.\n", i);
			return -1;
		}
	}
	printf("All threads created successfully.\n");
	

	/* Print statistics. */
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGABRT, signal_handler);

	// for ( ; !quit; ) {
	// 	read_time();
	// }

	// time_t secs = 120; // 2 minutes (can be retrieved from user's input)

	// time_t startTime = time(NULL);
	// while (time(NULL) - startTime < secs)
	// {
	// 	read_time();
	// }

	// int m;
	// for (m = 0; m < 100000; m++) {
	// 	read_time();
	// }

	for ( ; !quit; ) {
		sleep(1);
	}

	// sleep(10);

	/* Threads completion. */
	// printf("Quit.\n");

	// int z;
	// for (z = 0; z < time_index; z++ ) {
	// 	// printf("node1-%d	 %ld\n", slot_arr[z], timestamp_arr[z].tv_nsec);

	// 	unsigned long now_ns = get_nsec(&timestamp_arr[z]);
	// 	char buff[100];
	// 	strftime(buff, sizeof buff, "%D %T", gmtime(&timestamp_arr[z].tv_sec));
	// 	printf("node2-receive,%ld,%ld,%ld,%s\n", timestamp_arr[z].tv_sec, timestamp_arr[z].tv_nsec, now_ns, buff);
	// }

	for (i = 0; i < n_threads; i++)
		thread_data[i].quit = 1;

	for (i = 0; i < n_threads; i++)
		pthread_join(threads[i], NULL);

	for (i = 0; i < n_ports; i++)
		port_free(ports[i]);

    bpool_free(bp);

	remove_xdp_program();

    return 0;
}