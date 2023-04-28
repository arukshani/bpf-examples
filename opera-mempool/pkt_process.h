
//++++++++++++++CQ++++++++++++++++++++++++++++++++++++++++++
static void *
thread_func_fq_veth(void *arg)
{
	
	struct thread_cleanup *t = arg;
	cpu_set_t cpu_cores;
	// u32 i;

	CPU_ZERO(&cpu_cores);
	CPU_SET(t->cpu_core_id, &cpu_cores);
	pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu_cores);
	

    while (!t->quit) {
		struct port *port_veth = t->port_veth;
		struct port *port_nic = t->port_nic;

		u32 idx_cq = 0, idx_fq = 0;
		
		unsigned int rcvd = 1;

		if (port_nic == NULL) {
			break;
		}
		u32 n_pkts = port_nic->params.bp->umem_cfg.comp_size;
		// printf("n_pkts %d \n", n_pkts);
		// n_pkts = p->params.bp->umem_cfg.comp_size;
		n_pkts = xsk_ring_cons__peek(&port_nic->umem_cq, n_pkts, &idx_cq);
		// printf("VEEEEEETHHHHH.\n");

		// printf("n_pkts %d \n", n_pkts);

		if (n_pkts > 0) {
			unsigned int i;
			// int ret;

			rcvd = xsk_ring_prod__reserve(&port_veth->umem_fq, rcvd, &idx_fq);
			// if (ret != rcvd)
			// 	break;

			if (rcvd > 0) {
				for (i = 0; i < rcvd; i++)
					*xsk_ring_prod__fill_addr(&port_veth->umem_fq, idx_fq + i) =
						*xsk_ring_cons__comp_addr(&port_nic->umem_cq, idx_cq + i);

				xsk_ring_cons__release(&port_nic->umem_cq, rcvd);
				xsk_ring_prod__submit(&port_veth->umem_fq, rcvd);
			}
		}
	}
	return NULL;
}

static void *
thread_func_fq_nic(void *arg)
{
	struct thread_cleanup *t = arg;
	cpu_set_t cpu_cores;
	// u32 i;

	CPU_ZERO(&cpu_cores);
	CPU_SET(t->cpu_core_id, &cpu_cores);
	pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu_cores);
	

    while (!t->quit) {
		struct port *port_veth = t->port_veth;
		struct port *port_nic = t->port_nic;

		u32 idx_cq = 0, idx_fq = 0;
		
		unsigned int rcvd = 1;

		if (port_nic == NULL) {
			break;
		}
		u32 n_pkts = port_veth->params.bp->umem_cfg.comp_size;
		// printf("n_pkts %d \n", n_pkts);
		// n_pkts = p->params.bp->umem_cfg.comp_size;
		n_pkts = xsk_ring_cons__peek(&port_veth->umem_cq, n_pkts, &idx_cq);
		// printf("VEEEEEETHHHHH.\n");

		// printf("n_pkts %d \n", n_pkts);

		if (n_pkts > 0) {
			unsigned int i;
			// int ret;

			rcvd = xsk_ring_prod__reserve(&port_nic->umem_fq, rcvd, &idx_fq);
			// if (ret != rcvd)
			// 	break;

			if (rcvd > 0) {
				for (i = 0; i < rcvd; i++)
					*xsk_ring_prod__fill_addr(&port_nic->umem_fq, idx_fq + i) =
						*xsk_ring_cons__comp_addr(&port_veth->umem_cq, idx_cq + i);

				xsk_ring_cons__release(&port_veth->umem_cq, rcvd);
				xsk_ring_prod__submit(&port_nic->umem_fq, rcvd);
			}
		}
	}
	return NULL;
}

//++++++++++++++TX++++++++++++++++++++++++++++++++++++++++++

static inline void
port_tx_burst(struct port *p, struct burst_tx *b)
{
	u32 n_pkts, pos, i;
	int status;

	/* UMEM CQ. */
	// n_pkts = p->params.bp->umem_cfg.comp_size;

	// n_pkts = xsk_ring_cons__peek(&p->umem_cq, n_pkts, &pos);

	// for (i = 0; i < n_pkts; i++) {
	// 	u64 addr = *xsk_ring_cons__comp_addr(&p->umem_cq, pos + i);

	// 	bcache_prod(p->bc, addr);
	// }

	// xsk_ring_cons__release(&p->umem_cq, n_pkts);

	/* TXQ. */
	// n_pkts = b->n_pkts;
	n_pkts = 1;
	// printf("Fill tx desc for n_pkts %d \n", n_pkts);

	for ( ; ; ) {
		status = xsk_ring_prod__reserve(&p->txq, n_pkts, &pos);
		if (status == n_pkts)
			break;

		if (xsk_ring_prod__needs_wakeup(&p->txq))
			sendto(xsk_socket__fd(p->xsk), NULL, 0, MSG_DONTWAIT,
			       NULL, 0);
	}

	for (i = 0; i < n_pkts; i++) {
		// printf("b->addr[i] %lld \n", b->addr[i]);
		// printf("b->len[i] %d \n", b->len[i]);
		xsk_ring_prod__tx_desc(&p->txq, pos + i)->addr = b->addr[i];
		xsk_ring_prod__tx_desc(&p->txq, pos + i)->len = b->len[i];
	}

	xsk_ring_prod__submit(&p->txq, n_pkts);
	if (xsk_ring_prod__needs_wakeup(&p->txq))
		sendto(xsk_socket__fd(p->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	// p->n_pkts_tx += n_pkts;
}

static void *
thread_func_tx(void *arg)
{
	struct thread_data *t = arg;
	cpu_set_t cpu_cores;

	CPU_ZERO(&cpu_cores);
	CPU_SET(t->cpu_core_id, &cpu_cores);
	pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu_cores);
	while (!t->quit) {
		struct port *port_tx = t->ports_tx;
		struct spsc_queue *q = t->rb;
		void *pulled;
		// struct burst_tx *btx = &t->burst_tx[0];

		if(spsc_queue_pull(q, &pulled)) {
			// printf("Queue Not Empty: \n");
            struct burst_tx *btx = (struct burst_tx *)pulled;
            // printf("btx_test addr %lld \n", btx->addr[0]);
			// printf("btx_test len %d \n", btx->len[0]);
            port_tx_burst(port_tx, btx);
		}
	}
	return NULL;
}

//++++++++++++++RX++++++++++++++++++++++++++++++++++++++++++

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
	int is_veth_1 = strcmp(params->iface, "veth1"); 
	int is_nic = strcmp(params->iface, "enp65s0f0np0"); 

	if (is_veth_1 == 0)
	{
		// printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~from veth \n");
		struct iphdr *outer_iphdr; 
		struct iphdr encap_outer_iphdr; 
		struct ethhdr *outer_eth_hdr; 
		// unsigned char out_eth_src[ETH_ALEN+1] = { 0x0c, 0x42, 0xa1, 0xdd, 0x5f, 0xcc}; //0c:42:a1:dd:5f:cc

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

		u32 dest_ip_index = find(inner_ip_hdr_tmp->daddr);
		// printf("dest_ip_index dest2 = %d\n", dest_ip_index);
		int port_val;
    	getRouteElement(A, dest_ip_index, topo, &port_val);
		struct mac_addr dest_mac_val;
		getMacElement(B, port_val, topo, &dest_mac_val);
		
		__builtin_memcpy(outer_eth_hdr->h_dest, dest_mac_val.bytes, sizeof(outer_eth_hdr->h_dest));


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
		// printf("from NIC \n");
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

		void *cutoff_pos = greh + 1;
		int cutoff_len = (int)(cutoff_pos - data);
		int new_len = len - cutoff_len;

		int offset = 0 + cutoff_len;
		u64 inner_eth_start_addr = addr + offset;

		u8 *new_data = xsk_umem__get_data(params->bp->addr, inner_eth_start_addr);
		memcpy(xsk_umem__get_data(params->bp->addr, addr), new_data, new_len);
		
		return new_len;
	}

    return false;
}

static inline u32
port_rx_burst(struct port *p, struct burst_rx *b)
{
	u32 n_pkts, pos, i;

	/* Free buffers for FQ replenish. */
	// n_pkts = ARRAY_SIZE(b->addr);
	
	// n_pkts = bcache_cons_check(p->bc, n_pkts);

	// if (!n_pkts)
	// 	return 0;

	// printf("bp->n_slabs_available %ld \n", p->bc->bp->n_slabs_available);
    n_pkts = 1;

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
	// p->n_pkts_rx += n_pkts;

	/* UMEM FQ. */
	// for ( ; ; ) {
	// 	int status;

	// 	status = xsk_ring_prod__reserve(&p->umem_fq, n_pkts, &pos);
	// 	if (status == n_pkts)
	// 		break;

	// 	if (xsk_ring_prod__needs_wakeup(&p->umem_fq)) {
	// 		struct pollfd pollfd = {
	// 			.fd = xsk_socket__fd(p->xsk),
	// 			.events = POLLIN,
	// 		};

	// 		poll(&pollfd, 1, 0);
	// 	}
	// }

	// for (i = 0; i < n_pkts; i++)
	// 	*xsk_ring_prod__fill_addr(&p->umem_fq, pos + i) =
	// 		bcache_cons(p->bc);

	// xsk_ring_prod__submit(&p->umem_fq, n_pkts);

	return n_pkts;
}

static void *
thread_func_rx(void *arg)
{
	
	struct thread_data *t = arg;
	cpu_set_t cpu_cores;
	// u32 i;

	CPU_ZERO(&cpu_cores);
	CPU_SET(t->cpu_core_id, &cpu_cores);
	pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu_cores);
	
    while (!t->quit) {
		
		struct port *port_rx = t->ports_rx;
		struct burst_rx *brx = &t->burst_rx;
		struct spsc_queue *q = t->rb;

		u32 n_pkts, j;

		/* RX. */
		n_pkts = port_rx_burst(port_rx, brx);
		
		if (!n_pkts)
			continue;

		// printf("n_pkts %d \n", n_pkts);
		/* Process & TX. */
		for (j = 0; j < n_pkts; j++) {

			u64 addr = xsk_umem__add_offset_to_addr(brx->addr[j]);
			u8 *pkt = xsk_umem__get_data(port_rx->params.bp->addr,
						     addr);
			int new_len = process_rx_packet(pkt, &port_rx->params, brx->len[j], brx->addr[j]);

			struct burst_tx btx;
			btx.addr[j] = brx->addr[j];
			btx.len[j] = new_len;

			if (!spsc_queue_push(q, (void *) &btx)) {
			    // printf("Queue push failed at count %lu, %d, free slots %d\n", count, 1<<20, spsc_queue_available(q));
			    printf("Queue push failed \n");
		    }
		}
	}

	return NULL;
}