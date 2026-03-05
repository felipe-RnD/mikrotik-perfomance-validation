/*
 * XDP L3 UDP Reflector with VLAN support
 *
 * - Supports untagged IPv4 and single-tag 802.1Q / 802.1AD VLAN (e.g. VLAN 200).
 * - Reflects UDP packets with destination ports 12–16 back to the sender
 *   by swapping L2 (MAC), L3 (IP) and L4 (UDP ports).
 * - All other traffic is passed to the kernel (XDP_PASS).
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Minimal VLAN header */
struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

/* Fold a 32-bit checksum to 16 bits (standard one's complement folding) */
static __always_inline __u16 csum_fold_helper(__u32 csum)
{
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__u16)(~csum);
}

/* Swap two MAC addresses */
static __always_inline void swap_mac(void *a, void *b)
{
    __u8 tmp[ETH_ALEN];

    __builtin_memcpy(tmp, a, ETH_ALEN);
    __builtin_memcpy(a, b, ETH_ALEN);
    __builtin_memcpy(b, tmp, ETH_ALEN);
}

SEC("xdp_reflector")
int xdp_reflector_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    /* L2: Ethernet */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __be16 h_proto = eth->h_proto;
    void *nh = (void *)(eth + 1);  /* next header pointer */

    /* Optional single VLAN tag (802.1Q or 802.1AD) */
    if (h_proto == bpf_htons(ETH_P_8021Q) ||
        h_proto == bpf_htons(ETH_P_8021AD)) {

        struct vlan_hdr *vh = nh;
        if ((void *)(vh + 1) > data_end)
            return XDP_PASS;

        h_proto = vh->h_vlan_encapsulated_proto;
        nh = (void *)(vh + 1);
    }

    /* Only IPv4 after optional VLAN */
    if (h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* L3: IPv4 */
    struct iphdr *ip = nh;
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->version != 4)
        return XDP_PASS;

    /* Only handle standard 20-byte IPv4 header (IHL = 5) */
    if (ip->ihl != 5)
        return XDP_PASS;

    /* Only UDP */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* L4: UDP header immediately after 20-byte IPv4 header */
    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    __u16 dport = bpf_ntohs(udp->dest);
    if (dport < 12 || dport > 16)
        return XDP_PASS;

    /* === Reflection logic === */

    /* A) Swap MACs (VLAN tag, if present, is left untouched) */
    swap_mac(eth->h_source, eth->h_dest);

    /* B) Swap IP addresses */
    __be32 old_saddr = ip->saddr;
    __be32 old_daddr = ip->daddr;
    ip->saddr = old_daddr;
    ip->daddr = old_saddr;

    /* C) Swap UDP ports */
    __be16 old_sport = udp->source;
    __be16 old_dport = udp->dest;
    udp->source = old_dport;
    udp->dest   = old_sport;

    /* === Checksums === */

    /* 1. Recompute IPv4 header checksum (20 bytes) */
    ip->check = 0;
    __u32 csum = 0;
    csum = bpf_csum_diff(0, 0, (void *)ip, sizeof(*ip), 0);
    ip->check = csum_fold_helper(csum);

    /* 2. Disable UDP checksum for IPv4 (0 = "no checksum") */
    udp->check = 0;

    /* Reflect out the same interface */
    return XDP_TX;
}

/* Mandatory GPL license for eBPF helpers */
char __license[] SEC("license") = "GPL";
