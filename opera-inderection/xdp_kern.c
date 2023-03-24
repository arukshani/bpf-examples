/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdpsock.h"
#include "parsing_helpers.h"
#define DEBUG

// struct {
// 	__uint(type, BPF_MAP_TYPE_XSKMAP);
// 	__uint(max_entries, MAX_SOCKS);
// 	__uint(key_size, sizeof(int));
// 	__uint(value_size, sizeof(int));
// } xsks_map SEC(".maps");

struct gre_hdr {
	__be16 flags;
	__be16 proto;
} __attribute__((packed));

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

static __always_inline int parse_gre_hdr(struct hdr_cursor *nh,
				       void *data_end,
				       struct gre_hdr **grehdr)
{
    struct gre_hdr *greh = nh->pos;
	int hdrsize = sizeof(*greh);
	// int hdrsize = sizeof(struct gre_hdr);
    __u16 h_proto;

    if (nh->pos + hdrsize > data_end)
		return -1;

    nh->pos += hdrsize;
    *grehdr = greh;
    h_proto = greh->proto;
	// #ifdef DEBUG
	// 	bpf_printk("GRE flags=0x%x proto=%x", greh->flags, greh->proto);
	// #endif
    return h_proto;
}

SEC("xdp_sock_1")
int xdp_sock_prog(struct xdp_md *ctx)
{
    // int index = ctx->rx_queue_index;

    void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;
	int ip_type;
	// int icmp_type;
	struct iphdr *iphdr;
    // struct icmphdr_common *icmphdr;
    struct gre_hdr *gre_hdr; //decap gre header
    int gre_protocol;

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
            // if (bpf_map_lookup_elem(&xsks_map, &index))
            //     return bpf_redirect_map(&xsks_map, index, 0);
            // gre_protocol = parse_gre_hdr(&nh, data_end, &gre_hdr);
            u32 dst_node4 = 67217600;
            u32 dst_node1 = 16885952; 
            // #ifdef DEBUG
            //     bpf_printk("dst_node4=%d", dst_node4);
            //     bpf_printk("dst_node1=%d", dst_node1);
            //     bpf_printk("iphdr->daddr=%d", iphdr->daddr);
            // #endif
            if (dst_node4 == (iphdr->daddr)) {
                unsigned char node4_mac[ETH_ALEN+1] = { 0x0c, 0x42, 0xa1, 0xdd, 0x5b, 0x28}; //0c:42:a1:dd:5b:28 node4
                __builtin_memcpy(eth->h_dest, node4_mac, sizeof(eth->h_dest));
            } else if (dst_node1 == (iphdr->daddr)) {
                unsigned char node1_mac[ETH_ALEN+1] = { 0x0c, 0x42, 0xa1, 0xdd, 0x5f, 0xcc}; //0c:42:a1:dd:5f:cc node1 
                __builtin_memcpy(eth->h_dest, node1_mac, sizeof(eth->h_dest));
            }
            unsigned char out_eth_src[ETH_ALEN+1] = { 0x0c, 0x42, 0xa1, 0xdd, 0x5a, 0x8c}; //0c:42:a1:dd:5a:8c node2
            __builtin_memcpy(eth->h_source, out_eth_src, sizeof(eth->h_source));
            return XDP_TX;

        }
    }
    return XDP_PASS;
out:
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
