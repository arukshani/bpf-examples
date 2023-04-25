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

static void load_xdp_program(void)
{
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