#ifndef LWIP_DEMO_H
#define LWIP_DEMO_H

#include "lwip/ip_addr.h"

/*
 * Interface Options
 */
    #define ETH_INTERRUPT 4
    #define ESS_BASE 0xD0000000
    #define FIFO_BASE 0xC0000000
    unsigned int volatile * const ISR   = (unsigned int *) (FIFO_BASE + 0x00000000);
    unsigned int volatile * const IER   = (unsigned int *) (FIFO_BASE + 0x00000004);
    unsigned int volatile * const TDFR   = (unsigned int *) (FIFO_BASE + 0x00000008);
    unsigned int volatile * const TDFV  = (unsigned int *) (FIFO_BASE + 0x0000000C);
    unsigned int * const TDFD  = (unsigned int *) (FIFO_BASE + 0x00000010);
    unsigned int volatile * const TLR   = (unsigned int *) (FIFO_BASE + 0x00000014);
    unsigned int volatile * const RDFR  = (unsigned int *) (FIFO_BASE + 0x00000018);
    unsigned int volatile * const RDFO  = (unsigned int *) (FIFO_BASE + 0x0000001C);
    unsigned int volatile * const RDFD  = (unsigned int *) (FIFO_BASE + 0x00000020);
    unsigned int volatile * const RLR   = (unsigned int *) (FIFO_BASE + 0x00000024);
    unsigned int volatile * const SRR   = (unsigned int *) (FIFO_BASE + 0x00000028);
    unsigned int volatile * const TDR   = (unsigned int *) (FIFO_BASE + 0x0000002C);
    unsigned int volatile * const RDR   = (unsigned int *) (FIFO_BASE + 0x00000030);


/*
 * Ethernet Definitions
 */
int mymac[6] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc};
const void* MYMACADDRESS = &mymac;

unsigned char debug_flags;
/* Incoming packet queue*/
struct optimsoc_list_t *eth_rx_pbuf_queue = NULL;
/* (manual) host IP configuration */
static ip4_addr_t ipaddr, netmask, gw;
static ip6_addr_t ip6addr;
void eth_mac_irq(void* arg);





#endif
