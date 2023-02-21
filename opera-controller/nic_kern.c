/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdpsock.h"
#include "parsing_helpers.h"

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, MAX_SOCKS);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

static __always_inline int parse_eth_hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
    int hdrsize = sizeof(*eth);
    __u16 h_proto;

    /* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

    nh->pos += hdrsize;
    *ethhdr = eth;
    h_proto = eth->h_proto;
    return h_proto;
}

static __always_inline int parse_ip_hdr(struct hdr_cursor *nh,
				       void *data_end,
				       struct iphdr **iphdr)
{
	struct iphdr *iph = nh->pos;
	int hdrsize;

	if (iph + 1 > data_end)
		return -1;

	hdrsize = iph->ihl * 4;
	/* Sanity check packet field is valid */
	if(hdrsize < sizeof(*iph))
		return -1;

	/* Variable-length IPv4 header, need to use byte-based arithmetic */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	// nh->pos +=sizeof(struct iphdr);
	*iphdr = iph;

	return iph->protocol;
}

SEC("xdp_sock_1")
int xdp_sock_prog(struct xdp_md *ctx)
{
    int index = ctx->rx_queue_index;

    void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;
	int ip_type;
	// int icmp_type;
	struct iphdr *iphdr;
    // struct icmphdr_common *icmphdr;

    /* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_eth_hdr(&nh, data_end, &eth);
	// bpf_printk("packet received eth_type is %x %x \n", bpf_htons(ETH_P_IP), eth_type);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		// bpf_printk("packet is ETH_P_IP \n");
		ip_type = parse_ip_hdr(&nh, data_end, &iphdr);
		// if (ip_type != IPPROTO_ICMP) {
		if (ip_type != IPPROTO_GRE) {
			// bpf_printk("ip type is not IPPROTO_GRE %d \n", ip_type);
            goto out;
        }
        else {
            /* A set entry here means that the correspnding queue_id
            * has an active AF_XDP socket bound to it. */
            if (bpf_map_lookup_elem(&xsks_map, &index))
                return bpf_redirect_map(&xsks_map, index, 0);
        }
    }
    return XDP_PASS;
out:
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
