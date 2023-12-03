#include "ringbuffer.h"

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8  u8;

// #define DEBUG 0

#define DEBUG_PAUSE_Q 0

#ifndef CLOCK_INVALID
#define CLOCK_INVALID -1
#endif

#define CLOCKFD 3
#define FD_TO_CLOCKID(fd)	((clockid_t) ((((unsigned int) ~fd) << 3) | CLOCKFD))
#define CLOCKID_TO_FD(clk)	((unsigned int) ~((clk) >> 3))

#define STRERR_BUFSIZE          1024
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

struct ifaddrs *ifaddr, *ifa;
char *nic_iface;
struct HashNode** ip_set;
mg_Map mac_table; //mac table
mg_Map ip_table; //ip table
mg_Map dest_queue_table; //destination queue table
mg_Map ns_table;
struct ip_set {
	int index;
};
// struct ns_set {
// 	int index;
// };
char *ptp_clock_name;

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
#define MAX_BURST_RX 20
#endif

#ifndef MAX_BURST_TX
#define MAX_BURST_TX 20
#endif

#ifndef MAX_BURST_TX_OBJS
#define MAX_BURST_TX_OBJS 2048
#endif

#ifndef NUM_OF_PER_DEST_QUEUES
#define NUM_OF_PER_DEST_QUEUES 3
#endif

//Total number of NIC rx and tx threads
// #ifndef NIC_THREAD_COUNT
// #define NIC_THREAD_COUNT 4
// #endif

struct burst_rx {
	u64 addr[MAX_BURST_RX];
	u32 len[MAX_BURST_RX];
};

struct burst_tx {
	u64 addr[1];
	u32 len[1];
	// u32 ns_index;
	u32 n_pkts;
};

struct burst_tx_collector {
	u64 addr[MAX_BURST_TX];
	u32 len[MAX_BURST_TX];
	u32 n_pkts;
};

struct port_params {
	struct xsk_socket_config xsk_cfg;
	struct bpool *bp;
	const char *iface;
	u32 iface_queue;
	u32 ns_index;
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
	u64 n_cleanup_tx;
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
	// .n_buffers = 64 * 1024,
	.n_buffers = 128 * 1024 * 4,
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
	// .ns_index = 0,
};


#ifndef MAX_PORTS
#define MAX_PORTS 16
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
static int n_nic_ports;
// static int n_veth_ports;
static int veth_port_count;
static int veth_count_per_nic_q;

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
	// struct burst_tx burst_tx[MAX_PORTS_PER_THREAD]; 
	struct burst_tx_collector burst_tx_collector[MAX_PORTS_PER_THREAD];
	u32 cpu_core_id;
	int quit;
	ringbuf_t *ring_bf_array[13][3]; 
	// ringbuf_t *veth_side_queue_array[13];
	struct mpmc_queue *veth_side_queue_array[13];
	ringbuf_t *burst_tx_queue_array[13];
	int assinged_veth_count;
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

ringbuf_t *ring_array[13][3];
// ringbuf_t *non_local_ring_array[3];
// ringbuf_t *burst_tx_queue_veth[13];
// ringbuf_t *burst_tx_queue_nic[13];
// ringbuf_t *veth_side_queue[13];
struct mpmc_queue *veth_side_queue[13];

__u32 t1ms;

struct return_process_rx { 
	int new_len;
	int ring_buf_index;
	int which_veth;
};

unsigned long total_veth_rx = 0;
unsigned long total_veth_tx = 0;
unsigned long total_nic_rx = 0;
unsigned long total_nic_tx = 0;

unsigned long veth_rx_no_packet_counter = 0;
unsigned long veth_rx_has_packet_counter = 0;
u64 nic_rx_no_packet_counter = 0;
u64 nic_rx_has_packet_counter = 0;

unsigned long veth_tx_no_packet_counter = 0;
unsigned long veth_tx_has_packet_counter = 0;
unsigned long nic_tx_no_packet_counter = 0;
unsigned long nic_tx_has_packet_counter = 0;

static u64 n_pkts_rx[MAX_PORTS];
static u64 n_pkts_tx[MAX_PORTS];
static u64 n_cleanup_tx[MAX_PORTS];

char out_veth_arr[13][10] = {"veth1", "veth3", "vethout23", "vethout24", "vethout26", "vethout27", "vethout28", "vethout29", "vethout30", "vethout31", "vethout32", "vethout33", "vethout34"};

static const struct sched_map {
	const char *name;
	int policy;
} schmap[] = {
	{ "OTHER", SCHED_OTHER },
	{ "FIFO", SCHED_FIFO },
	{ NULL }
};

#define SCHED_PRI__DEFAULT	0