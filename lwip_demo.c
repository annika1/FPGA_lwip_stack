// NO_SYS_MAIN - Versuch 2

// NO_SYS_main.c
// Set up for receiving and transmitting ethernet packet with following specification (done)
// Link layer: Address Resolution Protocol (ARP) etharp (implicitly done)
// Internet layer: Internet Protocol (IP) (implicitly done)
// zuerst UDP (loopback: empfangen dann senden) (implicitly done) dann TCP(loopback analog zu UDP, braucht vermutlich mehr timer)
// Transport layer: Transmission Control Protocol (TCP)
// --- Actually we use LWIP_RAW --- Application layer: Dynamic Host Configuration Protocol (DHCP)/HTTP
// demowebserver von LWIP


// 20.09.2017


//

#include <stdio.h>
#include <string.h>
#include <optimsoc-baremetal.h>
#include <optimsoc-runtime.h>

//#include "lwip/opt.h"
#include "lwip_demo.h"
#include "lwip/init.h"

#include "lwip/debug.h"

#include "lwip/sys.h"
#include "lwip/timeouts.h"

#include "lwip/stats.h"

#include "lwip/udp.h"
#include "lwip/tcp.h"
#include "lwip/etharp.h"

#include "lwip/pbuf.h"
#include "lwip/raw.h"
#include "netif/ethernet.h"
#include "lwip/pbuf.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/dhcp.h"
#include "lwip/snmp.h"
#include "lwip/ethip6.h"

// #include "ping.h"
#include "lwip/inet_chksum.h"

#include "my_udp.h"
#include "my_tcp.h"

/*
 * Initialisation of the FPGA
 * - Interrupt handler
 * - Timer
 * - Clear ISR Register and Enable Interrupts in IER
 */
static void app_init()
{
    printf("Test.\n");
    or1k_interrupt_handler_add(ETH_INTERRUPT, &eth_mac_irq, 0);
    or1k_interrupt_enable(ETH_INTERRUPT);

    *ISR = 0xFFFFFFFF;
    *IER = 0x0C000000;

    printf("app_init: IER Register: %x\n", *IER);
    or1k_timer_init(1000); // Hz == 1ms Timer tickets
    or1k_timer_enable();
    or1k_interrupts_enable();
}

uint32_t swap_uint32( uint32_t val )
{
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF );
    return (val << 16) | (val >> 16);
}

/**
 * Interrupt Service Routine:
 * - New packet has been received
 * - Check the bits if receiving was successful (RDFO, RLR, RDR)
 * - Reading the Stream FIFO Register RDFD into the generated pbuf buffer
 * - List Element in the queue eth_rx_pbuf_queue
 */
void eth_mac_irq(void* arg)
{
    long ISR_V = *ISR;
    uint32_t *eth_data = NULL;
    u16_t eth_data_count = 0;

    if (!(ISR_V & 0x4000000)) {
        printf("eth_mac_irq: got no interrupt_v %x\n", ISR_V);
        *ISR = 0xFFFFFFFF;
        return;
    }


    printf("eth_mac_irq: Receive Complete Bit active.\n");
    printf("eth_mac_irq: ISR is %p\n", *ISR);

    *ISR = 0xFFFFFFFF;
    uint32_t RDFO_V = *RDFO;
    if (RDFO_V > 0) {
        do {
            eth_data_count = *RLR; // don't write u16_t in front!
            printf("eth_mac_irq: Number of Bytes to read: eth_data_count =  %x\n",
                   eth_data_count);
            int des_adr = *RDR;
            int i = 0;
            eth_data = calloc(eth_data_count / 4, sizeof(uint32_t));
            if (eth_data == NULL) {
                printf("eth_mac_irq: Buffer Overflow by generating eth_data.\n");
                return;
            }
            for (i = 0; i < eth_data_count / 4; i++) {
                eth_data[i] = swap_uint32(*RDFD);
                printf("eth_mac_irq: got %x\n", eth_data[i]);
            }
            RDFO_V = *RDFO;

            if (eth_rx_pbuf_queue == NULL) {
                eth_rx_pbuf_queue = optimsoc_list_init(NULL);
            }

            struct pbuf* p = pbuf_alloc(PBUF_RAW, eth_data_count, PBUF_POOL);
            printf("eth_mac_irq: allocation of p at %p of size %d\n", p,
                   eth_data_count);

            if (p != NULL) {
                err_t rv;
                rv = pbuf_take(p, (const void*) eth_data, eth_data_count);
                if (rv != ERR_OK) {
                    printf("eth_mac_irq: pbuf_take() FAILED returned %d\n", rv);
                }
                free(eth_data);
                optimsoc_list_add_tail(eth_rx_pbuf_queue, p);
                optimsoc_list_iterator_t it;
                struct pbuf* test = optimsoc_list_first_element(
                        eth_rx_pbuf_queue, &it);
            } else {
                printf("eth_mac_irq: Buffer Overflow by generating p.\n");
            }
        } while (RDFO_V > 0);
    }
    else{
        printf("eth_mac_irq: RDFO was empty.\n");
        return;
    }
}


/**
 * netif_output: output handler/driver for FPGA (communicate with AXI Stream
 * FIFO
 * - update statistic counters
 * - Read the buffer usage with TDFV
 * - enter critical section
 * - write 2 Bytes-wise into the AXI Stream FIFO Buffer
 * - write the length of the written Bytes into TLR
 * - Reset the ISR
 * - exit critical section
 */
static err_t
netif_output(struct netif *netif, struct pbuf *p)
{
  LINK_STATS_INC(link.xmit);
  MIB2_STATS_NETIF_ADD(netif, ifinoctets, p->tot_len);
  int unicast = ((((uint16_t *) p->payload)[0] & 0x01) == 0);
  if (unicast) {
   MIB2_STATS_NETIF_INC(netif, ifinucastpkts);
  } else {
    MIB2_STATS_NETIF_INC(netif, ifinnucastpkts);
  }

  printf("netif_output: Writing to Stream FIFO and start transmission.\n");
  uint32_t TDFV_before = *TDFV;
  printf("netif_output: TDFV_before: %x\n", TDFV_before);
  uint32_t restore_2 = or1k_critical_begin();
  *TDR = (uint32_t) 0x00000002;
  uint32_t left, tmp_len;
  uint32_t buf_p = 0x0;
  for (left = 0; left < ((p->tot_len)/2); left = left + 2){
      buf_p = ((uint16_t *)p->payload)[left];
      buf_p = buf_p << 16;
      buf_p = buf_p | ((uint16_t *)p->payload)[left+1];
      *TDFD = swap_uint32(buf_p);
      if (left < 31){
          printf("netif_output: p->payload now: %x\n", swap_uint32(buf_p));
      }
      if (left > 30 && left < 34){
          printf("Output more than 120Bytes - stop printing it.\n");
      }
  }
  uint32_t TDFV_after = *TDFV;
  printf("netif_output: TDFV_after: %x\n", TDFV_after);
  *TLR = p->tot_len;
  printf("netif_output: Length %x written to TLR\n", p->tot_len);
  printf("netif_output: ISR_value = %x\n", *ISR);
  *ISR = (unsigned int) 0xFFFFFFFF;
  or1k_critical_end(restore_2);
  return ERR_OK;
}

/*
 * netif_status_callback: callback function if netif status changes
 */

static void
netif_status_callback(struct netif *netif)
{
  printf("netif status changed %s\n", ip4addr_ntoa(netif_ip4_addr(netif)));
}


/*
 * my_init: Initialization function for netif
 */
static err_t
my_init(struct netif *netif)
{
    netif->linkoutput = netif_output;
    netif->output = etharp_output;
    netif->output_ip6 = ethip6_output;
  netif->mtu        = ETHERNET_MTU;
  netif->flags      = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET | NETIF_FLAG_IGMP | NETIF_FLAG_MLD6;
  MIB2_INIT_NETIF(netif, snmp_ifType_ethernet_csmacd, 100000000);

  SMEMCPY(netif->hwaddr, MYMACADDRESS, sizeof(netif->hwaddr));
  netif->hwaddr_len = sizeof(netif->hwaddr);
  return ERR_OK;
}

/*
 * gen_pbuf: Generate a example pbuf for transmitting a packet
 */
struct pbuf* gen_pbuf(u16_t len){
	uint32_t *eth_send = NULL;
	eth_send = calloc(len/4, sizeof(uint32_t)); // TODO: missing check for the buffer overflow
	eth_send[0] = (uint32_t) 0x9abc90e2;
	eth_send[1] = (uint32_t) 0x12345678;
	eth_send[2] = (uint32_t) 0xba465a14;
	eth_send[3] = (uint32_t) 0x08004500;
	eth_send[4] = (uint32_t) 0x0024c24a;
	eth_send[5] = (uint32_t) 0x40004011;
	eth_send[6] = (uint32_t) 0x3e1f81bb;
	eth_send[7] = (uint32_t) 0x9b3781bb;
	eth_send[8] = (uint32_t) 0x9bb1b041;
	eth_send[9] = (uint32_t) 0xd5df0010;
	eth_send[10] = (uint32_t) 0x3a815443;
	eth_send[11] = (uint32_t) 0x46320400;
        struct pbuf* tx_p = pbuf_alloc(PBUF_RAW, (u16_t) len, PBUF_RAM);
	pbuf_take(tx_p, (const void*) eth_send, len);
	printf("gen_pbuf: generate a packet of length: 0x%x\n", tx_p->tot_len);
	return tx_p;
}

/*
 * not used init
 */

void init()
{

}

#if LWIP_DHCP
/*
* DHCP Init
*/
void dhcp_init(struct netif *netif){
    printf("netif-link-is-up-flag: %i\n", netif->flags & NETIF_FLAG_LINK_UP);
    printf("dhcp_init: DHCP init - start.\n");

    err_t error_dhcp;
    /* Start DHCP and HTTPD */
    error_dhcp = dhcp_start(netif);
    if (error_dhcp != ERR_OK){
        printf("DHCP Error occurred - out of memory.\n");
    }
    else
    {
        printf("DHCP started.\n");
        u8_t myip_dhcp;
        myip_dhcp = dhcp_supplied_address(netif);
        printf("main: ip address now: %x\n", myip_dhcp);
    }
}
#endif // LWIP_DHCP



void main(void)
{
    app_init();
    lwip_init();
    struct netif netif;
    struct netif *netif_control;
    err_t err_ipv6_netif;

    // UDP Test Packet
    IP4_ADDR(&gw, 192,168,100,1);
    IP4_ADDR(&ipaddr, 192,168,100,114);

    IP6_ADDR(&ip6addr, 1234, 5666, 1914, 5111);

    // TCP Test Packet
    //IP4_ADDR(&gw, 10,162,229,1);
    //IP4_ADDR(&ipaddr, 10,162,229,2);

     IP4_ADDR(&netmask, 255,255,255,0);
    netif_control = netif_add(&netif, &ipaddr, &netmask, &gw, NULL, my_init,
                              netif_input);
    if (netif_control == NULL) {
        printf("netif_add_ip6_address failed.\n");
    }

    err_ipv6_netif = netif_add_ip6_address(&netif, &ip6addr, NULL);
    if (err_ipv6_netif != ERR_OK) {
        printf("netif_add_ip6_address failed.\n");
    }

    netif.name[0] = 'e';
    netif.name[1] = '0';

    netif_create_ip6_linklocal_address(&netif, 1);
    netif.ip6_autoconfig_enabled = 1;

    netif_set_status_callback(&netif, netif_status_callback);
    netif_set_default(&netif);
    netif_set_up(&netif);

    printf("ip6_addr: %x\n", netif.ip6_addr[0]);
    printf("ip6_addr - state - 0: %x\n", netif.ip6_addr_state[0]);
    printf("ip6_addr - state - 1: %x\n", netif.ip6_addr_state[1]);
    printf("ip6_addr - state - 2: %x\n", netif.ip6_addr_state[2]);
    printf("ip6_addr - state - 3: %x\n", netif.ip6_addr_state[3]);


#if LWIP_DHCP
    dhcp_init(&netif);
    // httpd_init();
#endif // LWIP_DHCP


    // All initialization done, we're ready to receive data
    printf("main: Reset done, Init done, Interrupts enabled\n");
    printf("main: IER Register: %x\n", *IER);


    int T_en = 0;

    optimsoc_list_iterator_t iter = 0;
    eth_rx_pbuf_queue = optimsoc_list_init(NULL);
    eth_rx_pbuf_queue = NULL;

#if LWIP_UDP
    udp_my_init();
    udp_bind_netif(udpecho_raw_pcb, &netif);
#endif // LWIP_UDP


#if LWIP_DEBUG
    debug_flags |= (LWIP_DBG_ON|LWIP_DBG_TRACE|LWIP_DBG_STATE|LWIP_DBG_FRESH|LWIP_DBG_HALT|LWIP_DBG_TRACE);
#endif //LWIP_DEBUG

#if LWIP_TCP
    tcpecho_raw_init();
    tcp_bind_netif(tcpecho_raw_pcb, &netif);
#endif // LWIP_TCP

     while (1) {
        // TODO: Check link status

        if (eth_rx_pbuf_queue != NULL && optimsoc_list_length(eth_rx_pbuf_queue) != 0) //
        {
            if (NULL == optimsoc_list_first_element(eth_rx_pbuf_queue, &iter)) {
                printf("main: Element was NULL, return!\n");
                eth_rx_pbuf_queue = NULL;
            }
            else{
            uint32_t restore = or1k_critical_begin();
            struct pbuf* p = (struct pbuf*) optimsoc_list_remove_head(eth_rx_pbuf_queue);
            or1k_critical_end(restore);

            LINK_STATS_INC(link.recv);
            MIB2_STATS_NETIF_ADD(&netif, ifoutoctets, p->tot_len);
            int unicast = ((((uint16_t *)p->payload)[0] & 0x01) == 0);
            if (unicast) {
            MIB2_STATS_NETIF_INC(&netif, ifoutucastpkts);
            } else {
            MIB2_STATS_NETIF_INC(&netif, ifoutnucastpkts);
            }

            // TODO: activate the checksum test

            if (netif.input(p, &netif) != ERR_OK) {
                pbuf_free(p);
                printf("main: pbuf is freed, error occurred.\n");
            }
            else{
                printf("main: sent payload to netif input\n");
                printf("main: length of list: %i\n", optimsoc_list_length(eth_rx_pbuf_queue));
                eth_rx_pbuf_queue = NULL;
                printf("main: ISR is: %x\n", *ISR);
            }
            }

        }


        /* Transmit a packet */
        if (T_en == 1) {
            // build a packet
            u16_t tx_len = 0x30; // packet length
            struct pbuf* p2 = gen_pbuf(tx_len);
            netif_output(&netif, p2);// write the packet into the stream FIFO and activate the transmit
            T_en = 0;
            printf("main: Back in main after transmission.\n");
        }


      for (int i = 0; i <= 1000; i++)
            ; // For loop for busy waiting

        /* Cyclic lwIP timers check */
       sys_check_timeouts();
    }
}



/*
if (netif_control == NULL){
    printf("main: netif_add failed.\n");
}
else{
    printf("main: netif added.\n");
}

printf("main: ip_addr: %i\n", (&ipaddr)->addr);
printf("main: netif_addr: %i\n", (&(&netif)->ip_addr)->addr);
printf("main: pointer to address: %i\n", netif.ip_addr);


// HTTP Server
netif_control = netif_add(&netif, IP4_ADDR_ANY, IP4_ADDR_ANY, IP4_ADDR_ANY, NULL,
                          my_init, netif_input);
if(netif_control == NULL){
    printf("main: netif_add (2) failed.\n");
}
else{
    printf("main: netif (2) added.\n");
}
*/
