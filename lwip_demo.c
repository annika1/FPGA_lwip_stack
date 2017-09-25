// NO_SYS_MAIN - Versuch 2

// NO_SYS_main.c
// Set up for receiving and transmitting ethernet packet with following specification
// Link layer: Address Resolution Protocol (ARP) etharp
// Internet layer: Internet Protocol (IP)
// zuerst UDP (loopback: empfangen dann senden) dann TCP(loopback analog zu UDP, braucht vermutlich mehr timer)
// Transport layer: Transmission Control Protocol (TCP)
// --- Actually we use LWIP_RAW --- Application layer:Dynamic Host Configuration Protocol (DHCP)/HTTP
// demowebserver von LWIP


// 20.09.2017


//

#include <stdio.h>
#include <string.h>
#include <optimsoc-baremetal.h>
#include <optimsoc-runtime.h>

//#include "lwip/opt.h"
#include "lwip/init.h"
#include "lwip/stats.h"
#include "lwip/pbuf.h"
#include "lwip/raw.h"
#include "netif/ethernet.h"
#include "lwip/pbuf.h"
#include "lwip/ip_addr.h"
// #include "lwip/netif.h" included in ethernet.h

#include "lwip/timeouts.h"
#include "lwip/sys.h"
//#include "queue.h"


#define ETH_INTERRUPT 4
#define ESS_BASE 0xD0000000
#define FIFO_BASE 0xC0000000
// Definition MAC Address
int mymac[6] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc};
const void* MYMACADDRESS = &mymac;



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

//Queue queue; // initalisieren von queue;

// Incoming packet queue
struct optimsoc_list_t *eth_rx_pbuf_queue = NULL;


void eth_mac_irq(void* arg);


// Interrupt Service Routine initialisieren
static void app_init()
{
    or1k_interrupt_handler_add(ETH_INTERRUPT, &eth_mac_irq, 0);
    or1k_interrupt_enable(ETH_INTERRUPT);

    *ISR = 0xFFFFFFFF; // Reset Interrupts
    *IER = 0x0C000000; // Enable ISR for: Receive Complete (with Transmit Compl. is 0xC000000
    printf("IER Register: %x\n", *IER);

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
 * Interrupt Service Routine: New packet has been received
 */
void eth_mac_irq(void* arg)
{
    (void) arg; // unused argument
    long ISR_V = *ISR;
    // Read the input into eth_data and the length into eth_data_count
    // Receive access
    uint32_t *eth_data = NULL;
    u16_t eth_data_count = 0;

    if (!(ISR_V & 0x4000000)) {
        printf("got interrupt_v %x\n", ISR_V);
        *ISR = 0xFFFFFFFF;
        return;
    }


    printf("Receive Complete Bit active.\n");
    printf("ISR is %p\n", *ISR);
    *ISR = 0xFFFFFFFF;
    uint32_t RDFO_V = *RDFO;

    if (RDFO_V > 0) {
        printf("Received Bytes are in the buffer.\n");
        eth_data_count = *RLR; // don't write u16_t in front!
        printf("eth_data_count %x\n", eth_data_count);
        int des_adr = *RDR;
        int i = 0;
        eth_data = calloc(eth_data_count/4, sizeof(uint32_t)); // TODO: missing check for the buffer overflow
        for (i = 0; i < eth_data_count/4; i++) {
            eth_data[i] = swap_uint32(*RDFD);
            //eth_data[i] = *RDFD;
            //printf("got not swaped %x\n", eth_data[i]);
            //eth_data[i] = swap_uint32(eth_data[i]);
            printf("got %x\n", eth_data[i]);
            //printf("got back swaped %x\n", swap_uint32(eth_data[i]));
        }
    } else {
        printf("RDFO was empty+.\n");
    }



    eth_rx_pbuf_queue = optimsoc_list_init(NULL);

    /* Allocate pbuf from pool (avoid using heap in interrupts) */
    printf("eth_data_count %d\n", eth_data_count);
    struct pbuf* p = pbuf_alloc(PBUF_RAW, eth_data_count, PBUF_POOL);
    printf("allocation of p at %p\n", p);

    if (p != NULL) {
        /* Copy ethernet frame into pbuf */
        err_t rv;
        rv = pbuf_take(p, (const void*) eth_data, eth_data_count);
        if (rv != ERR_OK) {
            printf("pbuf_take() FAILED returned %d\n", rv);
        }
        free(eth_data);

        printf("putting data into optimsoc buffer\n");

        /* Put in a queue which is processed in main loop */
        optimsoc_list_add_tail(eth_rx_pbuf_queue, p);

        optimsoc_list_iterator_t it;
        struct pbuf* test = optimsoc_list_first_element(eth_rx_pbuf_queue, &it);
    }
    printf("end of ISR.\n");
}

static err_t 
netif_output(struct netif *netif, struct pbuf *p)
{
  LINK_STATS_INC(link.xmit);

  // TODO: Is this useful for us?
  /* Update SNMP stats (only if you use SNMP) */
  //MIB2_STATS_NETIF_ADD(netif, ifinoctets, p->tot_len);
  //int unicast = ((p->payload[0] & 0x01) == 0);
  //if (unicast) {
  //  MIB2_STATS_NETIF_INC(netif, ifinucastpkts);
  //} else {
  //  MIB2_STATS_NETIF_INC(netif, ifinnucastpkts);
  //}

  printf("Writing to Stream FIFO and start transmission.\n");
  uint32_t TDFV_before = *TDFV;
  printf("TDFV_before: %x\n", TDFV_before);
  uint32_t restore_2 = or1k_critical_begin();
  *TDR = (uint32_t) 0x00000002; // Destination Device Address

  struct pbuf *q;
  uint32_t left, tmp_len;
  for (left = 0; left < ((p->tot_len)/4); left = left + 1){
      *TDFD = swap_uint32(((uint32_t *)p->payload)[left]);
      printf("p->payload now: %x\n", swap_uint32(((uint32_t *)p->payload)[left]));
  }
  /* Start MAC transmit here */
  // Compare Transmit length and occupied storage in Stream FIFO
  uint32_t TDFV_after = *TDFV;
  printf("TDFV_after: %x\n", TDFV_after);
  uint32_t buf_used = TDFV_before - TDFV_after; // used buffer in FIFO
  *TLR = p->tot_len;
  printf("Length %x written to TLR\n", p->tot_len);
  printf("ISR_value = %x\n", *ISR);
  *ISR = (unsigned int) 0xFFFFFFFF;
  printf("ISR_V after reset: %x\n", *ISR);
  or1k_critical_end(restore_2);
  return ERR_OK;
}

static void 
netif_status_callback(struct netif *netif)
{
  // printf("netif status changed %s\n", ip4addr_ntoa(netif_ip4_addr(netif)));
	printf("netif status changed.\n");
}

err_t my_output()
{
	printf("trying to send packet\n");
	return 0;
}

static err_t 
my_init(struct netif *netif)
{
  netif->linkoutput = netif_output;
  netif->output     = my_output;
  // netif->output_ip6 = ethip6_output;
  // netif->mtu        = ETHERNET_MTU;
  netif->flags      = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET | NETIF_FLAG_IGMP | NETIF_FLAG_MLD6;
  // MIB2_INIT_NETIF(netif, snmp_ifType_ethernet_csmacd, 100000000);

  SMEMCPY(netif->hwaddr, MYMACADDRESS, sizeof(netif->hwaddr));
  netif->hwaddr_len = sizeof(netif->hwaddr);

  return ERR_OK;
}

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
	printf("generate a packet of length: 0x%x\n", tx_p->tot_len);
	return tx_p;
}

void init()
{

}

void main(void)
{
    lwip_init();
    app_init();

    // sys_timeouts_init();
    struct netif netif;
    netif_add(&netif, IP4_ADDR_ANY, IP4_ADDR_ANY, IP4_ADDR_ANY, NULL, my_init,
              netif_input);
    netif.name[0] = 'e';
    netif.name[1] = '0';
    //netif_create_ip6_linklocal_address(&netif, 1);
    //netif.ip6_autoconfig_enabled = 1;
    netif_set_status_callback(&netif, netif_status_callback);
    netif_set_default(&netif);
    netif_set_up(&netif);

    // All initialization done, we're ready to receive data
    printf("Reset done, Init done, interrupts enabled\n");
    printf("IER Register: %x\n", *IER);


    /* Start DHCP and HTTPD */
    // dhcp_start(&netif );
    // httpd_init();

    int T_en = 0;
    u32_t now = 0;
    u32_t last = 0;
    optimsoc_list_iterator_t iter = 0;
    eth_rx_pbuf_queue = optimsoc_list_init(NULL);
    printf("ISR is at the beginning: %x\n", *ISR);
    eth_rx_pbuf_queue = NULL;

    while (1) {
        // TODO: Check link status

        /* Check for received frames, feed them to lwIP */
        if (eth_rx_pbuf_queue != NULL && optimsoc_list_length(eth_rx_pbuf_queue) != 0) //
        {
            if (NULL == optimsoc_list_first_element(eth_rx_pbuf_queue, &iter)) {
                printf("Element was NULL, return!\n");
                eth_rx_pbuf_queue = NULL;
            }
            else{
            uint32_t restore = or1k_critical_begin();
            struct pbuf* p = (struct pbuf*) optimsoc_list_remove_head(eth_rx_pbuf_queue);
            or1k_critical_end(restore);

            printf("got packet on main thread from pbuf\n");
            printf("something: %x\n", *((unsigned long *)(p->payload)));
            LINK_STATS_INC(link.recv);
            /* Update SNMP stats (only if you use SNMP) */
            // TODO: see if that's useful for us
            /*MIB2_STATS_NETIF_ADD(netif, ifoutoctets, p->tot_len);
             int unicast = ((p->payload[0] & 0x01) == 0);
             if (unicast) {
             MIB2_STATS_NETIF_INC(netif, ifoutucastpkts);
             } else {
             MIB2_STATS_NETIF_INC(netif, ifoutnucastpkts);
             }*/
            if (netif.input(p, &netif) != ERR_OK) {
                pbuf_free(p);
                printf("pbuf is freed.\n");
            }
            else{
                printf("sent payload to netif input\n");
                printf("length of list: %i\n", optimsoc_list_length(eth_rx_pbuf_queue));
                eth_rx_pbuf_queue = NULL;
            }
            }
            // sys_restart_timeouts();

        }


        /* Transmit a packet */
        if (T_en == 1) {
            // build a packet
            u16_t tx_len = 0x30; // packet length
            struct pbuf* p2 = gen_pbuf(tx_len);
            netif_output(&netif, p2);// write the packet into the stream FIFO and activate the transmit
            T_en = 0;
            printf("Back in main after transmission.\n");
        }

        for(int i=0; i<=100; i++); // For loop for busy waiting
        /* Cyclic lwIP timers check */
       sys_check_timeouts();
       /* your application goes here */
    }
}
