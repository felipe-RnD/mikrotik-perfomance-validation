/* SPDX-License-Identifier: BSD-3-Clause
 * DPDK packet reflector with VLAN support
 */

#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>

#define RX_RING_SIZE 2048
#define TX_RING_SIZE 2048
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 64

#define VLAN_ETHERTYPE 0x8100

struct vlan_hdr {
    uint16_t vlan_tci;      /* Priority, CFI and VLAN ID */
    uint16_t eth_proto;     /* Ethernet type of encapsulated frame */
} __attribute__((__packed__));

static struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode = RTE_ETH_MQ_RX_NONE,
        .offloads = RTE_ETH_RX_OFFLOAD_VLAN_STRIP, /* Strip VLAN on RX */
    },
    .txmode = {
        .mq_mode = RTE_ETH_MQ_TX_NONE,
        .offloads = RTE_ETH_TX_OFFLOAD_VLAN_INSERT, /* Insert VLAN on TX */
    },
};

/* Swap Ethernet addresses */
static inline void swap_eth_addr(struct rte_ether_hdr *eth_hdr)
{
    struct rte_ether_addr tmp;
    rte_ether_addr_copy(&eth_hdr->dst_addr, &tmp);
    rte_ether_addr_copy(&eth_hdr->src_addr, &eth_hdr->dst_addr);
    rte_ether_addr_copy(&tmp, &eth_hdr->src_addr);
}

/* Swap IP addresses */
static inline void swap_ip_addr(struct rte_ipv4_hdr *ip_hdr)
{
    uint32_t tmp = ip_hdr->src_addr;
    ip_hdr->src_addr = ip_hdr->dst_addr;
    ip_hdr->dst_addr = tmp;
}

/* Swap UDP ports */
static inline void swap_udp_ports(struct rte_udp_hdr *udp_hdr)
{
    uint16_t tmp = udp_hdr->src_port;
    udp_hdr->src_port = udp_hdr->dst_port;
    udp_hdr->dst_port = tmp;
}

/* Process and reflect packets - WITH VLAN SUPPORT */
static void reflect_packets(struct rte_mbuf **bufs, uint16_t nb_rx)
{
    uint16_t i;
    struct rte_ether_hdr *eth_hdr;
    struct vlan_hdr *vlan_hdr;
    struct rte_ipv4_hdr *ip_hdr;
    struct rte_udp_hdr *udp_hdr;
    uint16_t ether_type;
    void *l3_hdr;

    for (i = 0; i < nb_rx; i++) {
        eth_hdr = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);
        
        /* Swap Ethernet addresses */
        swap_eth_addr(eth_hdr);
        
        /* Check for VLAN tag */
        ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
        
        if (ether_type == VLAN_ETHERTYPE) {
            /* VLAN-tagged packet */
            vlan_hdr = (struct vlan_hdr *)(eth_hdr + 1);
            ether_type = rte_be_to_cpu_16(vlan_hdr->eth_proto);
            l3_hdr = (void *)(vlan_hdr + 1);
            
            /* Preserve VLAN tag in mbuf metadata */
            bufs[i]->vlan_tci = rte_be_to_cpu_16(vlan_hdr->vlan_tci);
            bufs[i]->ol_flags |= RTE_MBUF_F_TX_VLAN;
        } else {
            /* Non-VLAN packet */
            l3_hdr = (void *)(eth_hdr + 1);
        }
        
        /* If IP packet, swap IP and UDP */
        if (ether_type == RTE_ETHER_TYPE_IPV4) {
            ip_hdr = (struct rte_ipv4_hdr *)l3_hdr;
            swap_ip_addr(ip_hdr);
            
            if (ip_hdr->next_proto_id == IPPROTO_UDP) {
                udp_hdr = (struct rte_udp_hdr *)((unsigned char *)ip_hdr + 
                          ((ip_hdr->version_ihl & 0x0f) * 4));
                swap_udp_ports(udp_hdr);
            }
        }
    }
}

/* Main processing loop */
static int lcore_main(__rte_unused void *arg)
{
    uint16_t port = 0;
    struct rte_mbuf *bufs[BURST_SIZE];
    uint16_t nb_rx, nb_tx;
    uint64_t total_reflected = 0;
    uint64_t last_print = 0;

    printf("Core %u reflecting packets on port %u (VLAN-aware)\n", 
           rte_lcore_id(), port);

    while (1) {
        /* Receive burst of packets */
        nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);
        
        if (nb_rx == 0)
            continue;

        /* Reflect packets (swap addresses, preserve VLAN) */
        reflect_packets(bufs, nb_rx);

        /* Send packets back out */
        nb_tx = rte_eth_tx_burst(port, 0, bufs, nb_rx);
        
        /* Free any unsent packets */
        if (unlikely(nb_tx < nb_rx)) {
            uint16_t i;
            for (i = nb_tx; i < nb_rx; i++)
                rte_pktmbuf_free(bufs[i]);
        }

        total_reflected += nb_tx;

        /* Print stats every 10M packets */
        if (total_reflected - last_print > 10000000) {
            printf("Reflected %"PRIu64" packets\n", total_reflected);
            last_print = total_reflected;
        }
    }
    return 0;
}

/* Initialize port - WITH VLAN OFFLOAD */
static int port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf port_conf_local = port_conf;
    const uint16_t rx_rings = 1, tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_rxconf rxconf;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error getting device info: %s\n", strerror(-retval));
        return retval;
    }

    /* Check VLAN offload support */
    if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_VLAN_STRIP)
        printf("RX VLAN stripping supported\n");
    
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_VLAN_INSERT)
        printf("TX VLAN insertion supported\n");

    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf_local);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    /* Setup RX queue with VLAN offload */
    rxconf = dev_info.default_rxconf;
    rxconf.offloads = port_conf_local.rxmode.offloads;
    
    retval = rte_eth_rx_queue_setup(port, 0, nb_rxd,
            rte_eth_dev_socket_id(port), &rxconf, mbuf_pool);
    if (retval < 0)
        return retval;

    /* Setup TX queue with VLAN offload */
    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf_local.txmode.offloads;
    
    retval = rte_eth_tx_queue_setup(port, 0, nb_txd,
            rte_eth_dev_socket_id(port), &txconf);
    if (retval < 0)
        return retval;

    /* Start device */
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    /* Enable promiscuous mode */
    retval = rte_eth_promiscuous_enable(port);
    if (retval != 0)
        return retval;

    printf("Port %u initialized with VLAN support\n", port);
    
    return 0;
}

int main(int argc, char *argv[])
{
    struct rte_mempool *mbuf_pool;
    uint16_t portid = 0;
    int ret;

    /* Initialize EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret;
    argv += ret;

    /* Check port availability */
    if (rte_eth_dev_count_avail() < 1)
        rte_exit(EXIT_FAILURE, "No Ethernet ports available\n");

    /* Create mbuf pool */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
        rte_socket_id());

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* Initialize port */
    if (port_init(portid, mbuf_pool) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", portid);

    printf("DPDK Packet Reflector (VLAN-aware) initialized\n");
    printf("Press Ctrl+C to stop\n");

    /* Launch main loop on lcore */
    lcore_main(NULL);

    /* Clean up */
    printf("Closing port %d\n", portid);
    rte_eth_dev_stop(portid);
    rte_eth_dev_close(portid);
    rte_eal_cleanup();

    return 0;
}
