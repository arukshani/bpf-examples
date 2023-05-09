static void
print_port(u32 port_id)
{
	struct port *port = ports[port_id];

	printf("Port %u: interface = %s, queue = %u\n",
	       port_id, port->params.iface, port->params.iface_queue);
}

static inline u64
bcache_cons(struct port *p)
{
	u64 n_buffers_cons = p->n_buffers_cons - 1;
	u64 buffer;

	buffer = p->slab_cons[n_buffers_cons];
	p->n_buffers_cons = n_buffers_cons;
	return buffer;
}

static void
worker_port_free(struct worker_port *p)
{
	if (!p)
		return;

	/* To keep this example simple, the code to free the buffers from the
	 * socket's receive and transmit queues, as well as from the UMEM fill
	 * and completion queues, is not included.
	 */

	if (p->xsk)
		xsk_socket__delete(p->xsk);

	free(p);
}

// static void
// port_free(struct port *p)
// {
// 	if (!p)
// 		return;

// 	/* To keep this example simple, the code to free the buffers from the
// 	 * socket's receive and transmit queues, as well as from the UMEM fill
// 	 * and completion queues, is not included.
// 	 */

// 	if (p->xsk)
// 		xsk_socket__delete(p->xsk);

// 	free(p);
// }

static void init_fq(u32 umem_fq_size, struct port *p) {
	u32 pos = 0;
	/* umem fq. */
	xsk_ring_prod__reserve(&p->umem_fq, umem_fq_size, &pos);
	// printf("INIT FQ POS: %d \n", pos);

	for (int i = 0; i < umem_fq_size; i++) {
		// printf("INIT FQ POS: %d \n", pos + i);
		*xsk_ring_prod__fill_addr(&p->umem_fq, pos + i) = bcache_cons(p);
	}

	xsk_ring_prod__submit(&p->umem_fq, umem_fq_size);
	p->umem_fq_initialized = 1;
	// return NULL;
}

static struct worker_port *
worker_init(struct port_params *params, struct port *p)
{
	struct worker_port *w;
	w = calloc(sizeof(struct worker_port), 1);
	if (!w)
		return NULL;

	w->parent_port = p;

	/* xsk socket. */
	int status = xsk_socket__create_shared(&w->xsk,
					params->iface,
					params->iface_queue,
					params->bp->umem,
					&w->rxq,
					&w->txq,
					&p->umem_fq,
					&p->umem_cq,
					&params->xsk_cfg);

	apply_setsockopt(w->xsk);
	if (status) {
		printf("ERROR in xsk_socket__create_shared \n");
		worker_port_free(w);
		return NULL;
	}
	return w;
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

    u64 n_slabs_available;
    n_slabs_available = params->bp->n_slabs_available;
    n_slabs_available--;
    p->slab_cons = params->bp->slabs[n_slabs_available];
	params->bp->n_slabs_available = n_slabs_available;
	printf("n_slabs_available %lld \n", n_slabs_available);
    u64 n_buffers_per_slab = params->bp->params.n_buffers_per_slab;
    p->n_buffers_cons = n_buffers_per_slab;

	// for (int j=0; j<2; j++) {
	// 	/* xsk socket. */
	// 	status = xsk_socket__create_shared(&p->workers[j]->xsk,
	// 					params->iface,
	// 					params->iface_queue,
	// 					params->bp->umem,
	// 					&p->workers[j]->rxq,
	// 					&p->workers[j]->txq,
	// 					&p->umem_fq,
	// 					&p->umem_cq,
	// 					&params->xsk_cfg);

	// 	apply_setsockopt(p->worker_port[j]->xsk);
	// 	if (status) {
	// 		printf("ERROR in xsk_socket__create_shared \n");
	// 		port_free(p);
	// 		return NULL;
	// 	}
	// }
	
	/* umem fq. */
	// xsk_ring_prod__reserve(&p->umem_fq, umem_fq_size, &pos);
	// // printf("INIT FQ POS: %d \n", pos);

	// for (i = 0; i < umem_fq_size; i++) {
	// 	// printf("INIT FQ POS: %d \n", pos + i);
	// 	*xsk_ring_prod__fill_addr(&p->umem_fq, pos + i) = bcache_cons(p);
	// }

	// xsk_ring_prod__submit(&p->umem_fq, umem_fq_size);
	// p->umem_fq_initialized = 1;

	return p;
}

static void
bpool_free(struct bpool *bp)
{
	if (!bp)
		return;

	xsk_umem__delete(bp->umem);
	munmap(bp->addr, bp->params.n_buffers * bp->params.buffer_size);
	free(bp);
}

static struct bpool *
bpool_init(struct bpool_params *params,
	   struct xsk_umem_config *umem_cfg)
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    u64 n_slabs, n_buffers;
    u64 slabs_size;
    u64 buffers_size;
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
    n_buffers = n_slabs * params->n_buffers_per_slab;
    slabs_size = n_slabs * sizeof(u64 *);
    buffers_size = n_buffers * sizeof(u64);
    total_size = sizeof(struct bpool) + slabs_size  + buffers_size;

    printf("n_slabs %lld \n", n_slabs);
    printf("n_buffers %lld \n", n_buffers);
    printf("slabs_size %lld \n", slabs_size);
    printf("buffers_size %lld \n", buffers_size);
    printf("total_size %lld \n", total_size);

    /* bpool memory allocation. */
	p = calloc(total_size, sizeof(u8)); //store the address of the bool memory block
	if (!p)
		return NULL;

    /* bpool memory initialization. */
	bp = (struct bpool *)p; //address of bpool
	memcpy(&bp->params, params, sizeof(*params));

    bp->params.n_buffers = n_buffers;
    bp->slabs = (u64 **)&p[sizeof(struct bpool)];
    bp->buffers = (u64 *)&p[sizeof(struct bpool) + slabs_size];
    bp->n_slabs = n_slabs;
    bp->n_buffers = n_buffers;

    for (i = 0; i < n_slabs; i++)
		bp->slabs[i] = &bp->buffers[i * params->n_buffers_per_slab];
	bp->n_slabs_available = n_slabs;

    for (i = 0; i < n_buffers; i++)
		bp->buffers[i] = i * params->buffer_size;

    /* mmap. */
	bp->addr = mmap(NULL,
			n_buffers * params->buffer_size,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | params->mmap_flags,
			-1,
			0);
	if (bp->addr == MAP_FAILED) {
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

    return bp;
}