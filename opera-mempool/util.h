typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8  u8;

#ifndef MAX_PORTS
#define MAX_PORTS 2
#endif

#ifndef MAX_THREADS
#define MAX_THREADS 4
#endif

#define STRERR_BUFSIZE          1024

struct thread_data {
	struct port *ports_rx;
	struct port *ports_tx;
	u32 n_ports_rx;
	u32 cpu_core_id;
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
	.n_buffers = 64 * 1024,
	.buffer_size = XSK_UMEM__DEFAULT_FRAME_SIZE,
	.mmap_flags = 0,
	.n_buffers_per_slab = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2 * 8
};

static const struct xsk_umem_config umem_cfg_default = {
	.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2 * 8,
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

struct port {
	struct port_params params;

	// struct bcache *bc;
	u64 *slab_cons;
	u64 n_buffers_cons;

	struct xsk_ring_cons rxq;
	struct xsk_ring_prod txq;
	struct xsk_ring_prod umem_fq;
	struct xsk_ring_cons umem_cq;
	struct xsk_socket *xsk;
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
static struct xdp_program *xdp_prog[2];
static int n_ports;
static int n_threads;
static struct bpool *bp;
static struct thread_data thread_data[MAX_THREADS];
static int n_threads;
clockid_t clkid;
unsigned char out_eth_src[ETH_ALEN+1];

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


