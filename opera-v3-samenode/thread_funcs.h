//from_VETH -> to_NIC
static void *
thread_func_veth(void *arg)
{
    struct thread_data *t = arg;
	cpu_set_t cpu_cores;
	u32 i;

	CPU_ZERO(&cpu_cores);
	CPU_SET(t->cpu_core_id, &cpu_cores);
	pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu_cores);

    while (!t->quit) {
        struct port *port_rx = t->ports_rx[0];
		struct port *port_tx = t->ports_tx[0];
		struct burst_rx *brx = &t->burst_rx;
		struct burst_tx *btx = &t->burst_tx[0];

        u32 n_pkts, j;

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

//from_NIC -> to_VETH or from_NIC -> to_NIC
static void *
thread_func_nic(void *arg)
{
    struct thread_data *t = arg;
	cpu_set_t cpu_cores;
	u32 i;

	CPU_ZERO(&cpu_cores);
	CPU_SET(t->cpu_core_id, &cpu_cores);
	pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu_cores);

    while (!t->quit) {
        struct port *port_rx = t->ports_rx[0];
		struct port *port_tx = t->ports_tx[0];
        // struct port *port_tx_nic = t->ports_tx[1];
		struct burst_rx *brx = &t->burst_rx;
		struct burst_tx *btx = &t->burst_tx[0];

        u32 n_pkts, j;

        if (!n_pkts)
			continue;

        /* Process & TX. */
		for (j = 0; j < n_pkts; j++) {

			// printf("bp->n_slabs_available %ld \n", port_rx->bc->bp->n_slabs_available);

			u64 addr = xsk_umem__add_offset_to_addr(brx->addr[j]);
			u8 *pkt = xsk_umem__get_data(port_rx->params.bp->addr,
						     addr);

			int new_len = process_rx_packet(pkt, &port_rx->params, brx->len[j], brx->addr[j]);

			//Needs to send packet back out NIC
			if (new_len == 1) {
				new_len = brx->len[j];
				port_tx = t->ports_tx[1];
				btx = &t->burst_tx[1];
			}

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