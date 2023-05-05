// #include "memory.h"
// #include "spsc_queue.h"
// #include "ringbuffer.h"
#include "mpmc_queue.h"
#include "memory.h"


typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8  u8;

#ifndef MAX_PORTS
#define MAX_PORTS 2
#endif

#ifndef MAX_THREADS
#define MAX_THREADS 8
#endif

#define STRERR_BUFSIZE          1024

#ifndef MAX_BURST_RX
#define MAX_BURST_RX 64
#endif

#ifndef MAX_BURST_TX
#define MAX_BURST_TX 1
#endif

struct gre_hdr {
	__be16 flags;
	__be16 proto;
} __attribute__((packed));

struct burst_rx {
	__u64 addr[MAX_BURST_RX];
	__u32 len[MAX_BURST_RX];
}__attribute__((packed));

struct burst_tx {
	__u64 addr[MAX_BURST_TX];
	__u32 len[MAX_BURST_TX];
}__attribute__((packed));

struct thread_cleanup {
	struct port *port_veth;
	struct port *port_nic;
	u32 cpu_core_id;
	int quit;
};

struct thread_data {
	struct worker_port *worker_rx;
	struct worker_port *worker_tx;
	u32 n_ports_rx;
	struct burst_rx burst_rx;
	struct burst_tx burst_tx;
	u32 cpu_core_id;
	// struct spsc_queue *rb;
	// ringbuf_t *rb;
	struct mpmc_queue *rb;
	int quit;
};

struct bpool_params {
	u32 n_buffers;
	u32 buffer_size;
	int mmap_flags;
	u32 n_buffers_per_slab;
};

struct port_params {
	struct xsk_socket_config xsk_cfg;
	struct bpool *bp;
	const char *iface;
	u32 iface_queue;
};

static const struct bpool_params bpool_params_default = {
	.n_buffers = XSK_RING_PROD__DEFAULT_NUM_DESCS * 4,
	.buffer_size = XSK_UMEM__DEFAULT_FRAME_SIZE,
	.mmap_flags = 0,
	.n_buffers_per_slab = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2 
};

static const struct xsk_umem_config umem_cfg_default = {
	.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
	.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS * 2,
	.frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE,
	.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
	.flags = 0,
};

static const struct port_params port_params_default = {
	.xsk_cfg = {
		.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS * 2,
		.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
		.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
		.xdp_flags = XDP_FLAGS_DRV_MODE,
		.bind_flags = XDP_USE_NEED_WAKEUP,
	},

	.bp = NULL,
	.iface = NULL,
	.iface_queue = 0,
};

struct bpool {
	struct bpool_params params;
	void *addr;

	u64 **slabs;
	u64 *buffers;
	
	u64 n_slabs;
	u64 n_buffers;

	u64 n_slabs_available;

	struct xsk_umem_config umem_cfg;
	struct xsk_ring_prod umem_fq;
	struct xsk_ring_cons umem_cq;
	struct xsk_umem *umem;
};

struct worker_port {
	struct port *parent_port;
	struct xsk_ring_cons rxq;
	struct xsk_ring_prod txq;
	struct xsk_socket *xsk;
};

struct port {
	struct port_params params;

	// struct bcache *bc;
	u64 *slab_cons;
	u64 n_buffers_cons;

	// struct worker_port *workers[2];
	
	struct xsk_ring_prod umem_fq;
	struct xsk_ring_cons umem_cq;
	int umem_fq_initialized;

	u64 n_pkts_rx;
	u64 n_pkts_tx;
};

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

static struct bpool_params bpool_params;
static struct xsk_umem_config umem_cfg;
static struct port_params port_params[MAX_PORTS];
static struct port *ports[MAX_PORTS];
static struct worker_port *workers[4];
static struct xdp_program *xdp_prog[2];
static int n_ports;
static struct bpool *bp;

clockid_t clkid;
unsigned char out_eth_src[ETH_ALEN+1];
static int quit;

static struct thread_data thread_data[MAX_THREADS];
static pthread_t threads[MAX_THREADS];
static int n_threads;

static struct thread_cleanup thread_cleanup[2];
static pthread_t cleanup_threads[2];
static int n_cleanup_threads;

struct timespec now;
uint64_t time_into_cycle_ns;
uint8_t topo;
uint64_t slot_time_ns = 1000000;	// 1 ms
uint64_t cycle_time_ns = 2000000;	// 2 ms

struct mpmc_queue *rb_forward;
struct mpmc_queue *rb_backward;

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


