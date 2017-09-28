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
#include "lwip/ip4_addr.h"
#include "lwip/netif.h"

// #include "lwip/netif.h" included in ethernet.h

//#include "queue.h"


#define ETH_INTERRUPT 4
#define ESS_BASE 0xD0000000
#define FIFO_BASE 0xC0000000
// Definition MAC Address
int mymac[6] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc};
const void* MYMACADDRESS = &mymac;

unsigned char debug_flags;


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

/* (manual) host IP configuration */
static ip4_addr_t ipaddr, netmask, gw;


void eth_mac_irq(void* arg);


// Interrupt Service Routine initialisieren
static void app_init()
{
    or1k_interrupt_handler_add(ETH_INTERRUPT, &eth_mac_irq, 0);
    or1k_interrupt_enable(ETH_INTERRUPT);

    *ISR = 0xFFFFFFFF; // Reset Interrupts
    *IER = 0x0C000000; // Enable ISR for: Receive Complete (with Transmit Compl. is 0xC000000
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
        printf("eth_mac_irq: got interrupt_v %x\n", ISR_V);
        *ISR = 0xFFFFFFFF;
        return;
    }


    printf("eth_mac_irq: Receive Complete Bit active.\n");
    printf("eth_mac_irq: ISR is %p\n", *ISR);
    *ISR = 0xFFFFFFFF;
    uint32_t RDFO_V = *RDFO;

    if (RDFO_V > 0) {
        printf("eth_mac_irq: Received Bytes are in the buffer.\n");
        eth_data_count = *RLR; // don't write u16_t in front!
        printf("eth_mac_irq: eth_data_count %x\n", eth_data_count);
        int des_adr = *RDR;
        int i = 0;
        eth_data = calloc(eth_data_count/4, sizeof(uint32_t)); // TODO: missing check for the buffer overflow
        for (i = 0; i < eth_data_count/4; i++) {
            eth_data[i] = swap_uint32(*RDFD);
            //eth_data[i] = *RDFD;
            //printf("got not swaped %x\n", eth_data[i]);
            //eth_data[i] = swap_uint32(eth_data[i]);
            printf("eth_mac_irq: got %x\n", eth_data[i]);
            //printf("got back swaped %x\n", swap_uint32(eth_data[i]));
        }
    } else {
        printf("eth_mac_irq: RDFO was empty+.\n");
    }



    eth_rx_pbuf_queue = optimsoc_list_init(NULL);

    /* Allocate pbuf from pool (avoid using heap in interrupts) */
    printf("eth_mac_irq: eth_data_count %d\n", eth_data_count);
    struct pbuf* p = pbuf_alloc(PBUF_RAW, eth_data_count, PBUF_POOL);
    printf("eth_mac_irq: allocation of p at %p\n", p);

    if (p != NULL) {
        /* Copy ethernet frame into pbuf */
        err_t rv;
        rv = pbuf_take(p, (const void*) eth_data, eth_data_count);
        if (rv != ERR_OK) {
            printf("eth_mac_irq: pbuf_take() FAILED returned %d\n", rv);
        }
        free(eth_data);

        printf("eth_mac_irq: putting data into optimsoc buffer\n");

        /* Put in a queue which is processed in main loop */
        optimsoc_list_add_tail(eth_rx_pbuf_queue, p);

        optimsoc_list_iterator_t it;
        struct pbuf* test = optimsoc_list_first_element(eth_rx_pbuf_queue, &it);
    }
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

  printf("netif_output: Writing to Stream FIFO and start transmission.\n");
  uint32_t TDFV_before = *TDFV;
  printf("netif_output: TDFV_before: %x\n", TDFV_before);
  uint32_t restore_2 = or1k_critical_begin();
  *TDR = (uint32_t) 0x00000002; // Destination Device Address
  uint32_t left, tmp_len;
  uint32_t buf_p = 0x0;
  for (left = 0; left < ((p->tot_len)/2); left = left + 2){
      buf_p = ((uint16_t *)p->payload)[left];
      buf_p = buf_p << 16;
      buf_p = buf_p | ((uint16_t *)p->payload)[left+1];
      *TDFD = swap_uint32(buf_p);
      printf("netif_output: p->payload now: %x\n", swap_uint32(buf_p));
  }
  /* Start MAC transmit here */
  // Compare Transmit length and occupied storage in Stream FIFO
  uint32_t TDFV_after = *TDFV;
  printf("netif_output: TDFV_after: %x\n", TDFV_after);
  uint32_t buf_used = TDFV_before - TDFV_after; // used buffer in FIFO
  *TLR = p->tot_len;
  printf("netif_output: Length %x written to TLR\n", p->tot_len);
  printf("netif_output: ISR_value = %x\n", *ISR);
  *ISR = (unsigned int) 0xFFFFFFFF;
  printf("netif_output: ISR_V after reset: %x\n", *ISR);
  or1k_critical_end(restore_2);
  return ERR_OK;
}

static void 
netif_status_callback(struct netif *netif)
{
  // printf("netif status changed %s\n", ip4addr_ntoa(netif_ip4_addr(netif)));
	printf("netif_status_callback: netif status changed.\n");
}

static err_t 
my_init(struct netif *netif)
{
  netif->linkoutput = netif_output;
  netif->output     = etharp_output;
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
	printf("gen_pbuf: generate a packet of length: 0x%x\n", tx_p->tot_len);
	return tx_p;
}

void init()
{

}



/*
 * LWIP UDP Interface
 */
#if LWIP_UDP
static struct udp_pcb *udpecho_raw_pcb;
static void
udpecho_raw_recv(void *arg, struct udp_pcb *upcb, struct pbuf *p,
                 const ip_addr_t *addr, u16_t port)
{
  LWIP_UNUSED_ARG(arg);
  if (p != NULL) {
    /* send received packet back to sender */
    udp_sendto(upcb, p, addr, port);
    /* free the pbuf */
    printf("udpecho_raw_recv: free p\n");
    pbuf_free(p);
  }
}
void
udp_my_init(void){
    udpecho_raw_pcb = udp_new_ip_type(IPADDR_TYPE_ANY);
    if (udpecho_raw_pcb != NULL) {
        err_t err;

        err = udp_bind(udpecho_raw_pcb, IP_ANY_TYPE, 54751);
        if (err == ERR_OK) {
          udp_recv(udpecho_raw_pcb, udpecho_raw_recv, NULL);
        } else {
          /* abort? output diagnostic? */
        }
      } else {
        /* abort? output diagnostic? */
      }
}
#endif // LWIP_UDP



/*
 * LWIP TCP Interface
 */
#if LWIP_TCP
static struct tcp_pcb *tcpecho_raw_pcb;
enum tcpecho_raw_states
{
  ES_NONE = 0,
  ES_ACCEPTED,
  ES_RECEIVED,
  ES_CLOSING
};
struct tcpecho_raw_state
{
  u8_t state;
  u8_t retries;
  struct tcp_pcb *pcb;
  /* pbuf (chain) to recycle */
  struct pbuf *p;
};
static void
tcpecho_raw_free(struct tcpecho_raw_state *es)
{
  if (es != NULL) {
    if (es->p) {
      /* free the buffer chain if present */
      pbuf_free(es->p);
    }

    mem_free(es);
  }
}
static void
tcpecho_raw_close(struct tcp_pcb *tpcb, struct tcpecho_raw_state *es)
{
  tcp_arg(tpcb, NULL);
  tcp_sent(tpcb, NULL);
  tcp_recv(tpcb, NULL);
  tcp_err(tpcb, NULL);
  tcp_poll(tpcb, NULL, 0);

  tcpecho_raw_free(es);

  tcp_close(tpcb);
}
static void
tcpecho_raw_send(struct tcp_pcb *tpcb, struct tcpecho_raw_state *es)
{
  struct pbuf *ptr;
  err_t wr_err = ERR_OK;

  while ((wr_err == ERR_OK) &&
         (es->p != NULL) &&
         (es->p->len <= tcp_sndbuf(tpcb))) {
    ptr = es->p;

    /* enqueue data for transmission */
    wr_err = tcp_write(tpcb, ptr->payload, ptr->len, 1);
    if (wr_err == ERR_OK) {
      u16_t plen;

      plen = ptr->len;
      /* continue with next pbuf in chain (if any) */
      es->p = ptr->next;
      if(es->p != NULL) {
        /* new reference! */
        pbuf_ref(es->p);
      }
      /* chop first pbuf from chain */
      pbuf_free(ptr);
      /* we can read more data now */
      tcp_recved(tpcb, plen);
    } else if(wr_err == ERR_MEM) {
      /* we are low on memory, try later / harder, defer to poll */
      es->p = ptr;
    } else {
      /* other problem ?? */
    }
  }
}
static void
tcpecho_raw_error(void *arg, err_t err)
{
  struct tcpecho_raw_state *es;

  LWIP_UNUSED_ARG(err);

  es = (struct tcpecho_raw_state *)arg;

  tcpecho_raw_free(es);
}
static err_t
tcpecho_raw_poll(void *arg, struct tcp_pcb *tpcb)
{
  err_t ret_err;
  struct tcpecho_raw_state *es;

  es = (struct tcpecho_raw_state *)arg;
  if (es != NULL) {
    if (es->p != NULL) {
      /* there is a remaining pbuf (chain)  */
      tcpecho_raw_send(tpcb, es);
    } else {
      /* no remaining pbuf (chain)  */
      if(es->state == ES_CLOSING) {
        tcpecho_raw_close(tpcb, es);
      }
    }
    ret_err = ERR_OK;
  } else {
    /* nothing to be done */
    tcp_abort(tpcb);
    ret_err = ERR_ABRT;
  }
  return ret_err;
}
static err_t
tcpecho_raw_sent(void *arg, struct tcp_pcb *tpcb, u16_t len)
{
  struct tcpecho_raw_state *es;

  LWIP_UNUSED_ARG(len);

  es = (struct tcpecho_raw_state *)arg;
  es->retries = 0;

  if(es->p != NULL) {
    /* still got pbufs to send */
    tcp_sent(tpcb, tcpecho_raw_sent);
    tcpecho_raw_send(tpcb, es);
  } else {
    /* no more pbufs to send */
    if(es->state == ES_CLOSING) {
      tcpecho_raw_close(tpcb, es);
    }
  }
  return ERR_OK;
}
static err_t
tcpecho_raw_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
  struct tcpecho_raw_state *es;
  err_t ret_err;

  LWIP_ASSERT("arg != NULL",arg != NULL);
  es = (struct tcpecho_raw_state *)arg;
  if (p == NULL) {
    /* remote host closed connection */
    es->state = ES_CLOSING;
    if(es->p == NULL) {
      /* we're done sending, close it */
      tcpecho_raw_close(tpcb, es);
    } else {
      /* we're not done yet */
      tcpecho_raw_send(tpcb, es);
    }
    ret_err = ERR_OK;
  } else if(err != ERR_OK) {
    /* cleanup, for unknown reason */
    if (p != NULL) {
      pbuf_free(p);
    }
    ret_err = err;
  }
  else if(es->state == ES_ACCEPTED) {
    /* first data chunk in p->payload */
    es->state = ES_RECEIVED;
    /* store reference to incoming pbuf (chain) */
    es->p = p;
    tcpecho_raw_send(tpcb, es);
    ret_err = ERR_OK;
  } else if (es->state == ES_RECEIVED) {
    /* read some more data */
    if(es->p == NULL) {
      es->p = p;
      tcpecho_raw_send(tpcb, es);
    } else {
      struct pbuf *ptr;

      /* chain pbufs to the end of what we recv'ed previously  */
      ptr = es->p;
      pbuf_cat(ptr,p);
    }
    ret_err = ERR_OK;
  } else {
    /* unkown es->state, trash data  */
    tcp_recved(tpcb, p->tot_len);
    pbuf_free(p);
    ret_err = ERR_OK;
  }
  return ret_err;
}
static err_t
tcpecho_raw_accept(void *arg, struct tcp_pcb *newpcb, err_t err)
{
  err_t ret_err;
  struct tcpecho_raw_state *es;

  LWIP_UNUSED_ARG(arg);
  if ((err != ERR_OK) || (newpcb == NULL)) {
    return ERR_VAL;
  }

  /* Unless this pcb should have NORMAL priority, set its priority now.
     When running out of pcbs, low priority pcbs can be aborted to create
     new pcbs of higher priority. */
  tcp_setprio(newpcb, TCP_PRIO_MIN);

  es = (struct tcpecho_raw_state *)mem_malloc(sizeof(struct tcpecho_raw_state));
  if (es != NULL) {
    es->state = ES_ACCEPTED;
    es->pcb = newpcb;
    es->retries = 0;
    es->p = NULL;
    /* pass newly allocated es to our callbacks */
    tcp_arg(newpcb, es);
    tcp_recv(newpcb, tcpecho_raw_recv);
    tcp_err(newpcb, tcpecho_raw_error);
    tcp_poll(newpcb, tcpecho_raw_poll, 0);
    tcp_sent(newpcb, tcpecho_raw_sent);
    ret_err = ERR_OK;
  } else {
    ret_err = ERR_MEM;
  }
  return ret_err;
}
void
tcpecho_raw_init(void)
{
  tcpecho_raw_pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
  if (tcpecho_raw_pcb != NULL) {
    err_t err;

    err = tcp_bind(tcpecho_raw_pcb, IP_ANY_TYPE, 2049);
    if (err == ERR_OK) {
      tcpecho_raw_pcb = tcp_listen(tcpecho_raw_pcb);
      tcp_accept(tcpecho_raw_pcb, tcpecho_raw_accept); // tcpecho_raw_accept (another function)
    } else {
      /* abort? output diagnostic? */
    }
  } else {
    /* abort? output diagnostic? */
  }
}
#endif // LWIP_TCP


void main(void)
{
    app_init();
    struct netif netif;

    // startup defaults (may be overridden by one or more opts)
    // UDP Test Packet
    //IP4_ADDR(&gw, 129,187,155,1);
    // IP4_ADDR(&ipaddr, 129,187,155,177);
    // TCP Test Packet
    IP4_ADDR(&gw, 10,162,229,1);
    IP4_ADDR(&ipaddr, 10,162,229,2);

    IP4_ADDR(&netmask, 255,255,255,0);

    lwip_init();

    netif_add(&netif, &ipaddr, &netmask, &gw, NULL, my_init,
              netif_input);
    //printf("main: ip_addr: %i\n", (&ipaddr)->addr);
    //printf("main: netif_addr: %i\n", (&(&netif)->ip_addr)->addr);
    //printf("main: pointer to address: %i\n", netif.ip_addr);

    netif.name[0] = 'e';
    netif.name[1] = '0';

    //netif_create_ip6_linklocal_address(&netif, 1);
    //netif.ip6_autoconfig_enabled = 1;
    netif_set_status_callback(&netif, netif_status_callback);
    netif_set_default(&netif);
    netif_set_up(&netif);

    // All initialization done, we're ready to receive data
    printf("main: Reset done, Init done, interrupts enabled\n");
    printf("main: IER Register: %x\n", *IER);

    /* Start DHCP and HTTPD */
    // dhcp_start(&netif );
    // httpd_init();

    int T_en = 0;
    u32_t now = 0;
    u32_t last = 0;
    optimsoc_list_iterator_t iter = 0;
    eth_rx_pbuf_queue = optimsoc_list_init(NULL);
    printf("main: ISR is at the beginning: %x\n", *ISR);
    eth_rx_pbuf_queue = NULL;

#if LWIP_UDP
    udp_my_init();
    udp_bind_netif(udpecho_raw_pcb, &netif);
#endif // LWIP_UDP
#if LWIP_DEBUG
    debug_flags |= (LWIP_DBG_ON|LWIP_DBG_TRACE|LWIP_DBG_STATE|LWIP_DBG_FRESH|LWIP_DBG_HALT);
#endif //LWIP_DEBUG

#if LWIP_TCP
    tcpecho_raw_init();
    tcp_bind_netif(tcpecho_raw_pcb, &netif);
#endif // LWIP_TCP

#if LWIP_RAW
    ping_init(&ipaddr);
#endif // LWIP_RAW

    while (1) {
        // TODO: Check link status

        /* Check for received frames, feed them to lwIP */
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

            /* Update SNMP stats (only if you use SNMP) */
            // TODO: see if that's useful for us
            /*MIB2_STATS_NETIF_ADD(netif, ifoutoctets, p->tot_len);
             int unicast = ((p->payload[0] & 0x01) == 0);
             if (unicast) {
             MIB2_STATS_NETIF_INC(netif, ifoutucastpkts);
             } else {
             MIB2_STATS_NETIF_INC(netif, ifoutnucastpkts);
             }*/

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


        for(int i=0; i<=100; i++); // For loop for busy waiting

        /* Cyclic lwIP timers check */
       sys_check_timeouts();
       /* your application goes here */
    }
}



/*
 * REST
 *
 *
     char ip_str[16] = {0}, nm_str[16] = {0}, gw_str[16] = {0};
    /* startup defaults (may be overridden by one or more opts)
    IP4_ADDR(&gw, 192,187,155,1);
    IP4_ADDR(&ipaddr, 192,187,155,199);
    IP4_ADDR(&netmask, 255,255,255,0);

    strncpy(ip_str, ip4addr_ntoa(&ipaddr), sizeof(ip_str));
    strncpy(nm_str, ip4addr_ntoa(&netmask), sizeof(nm_str));
    strncpy(gw_str, ip4addr_ntoa(&gw), sizeof(gw_str));
    printf("Host at %s mask %s gateway %s\n", ip_str, nm_str, gw_str);
 *
  /* old for loop */
  //for (left = 0; left < ((p->tot_len)/4); left = left + 1){
      //*TDFD = swap_uint32(((uint32_t *)p->payload)[left]);

  //printf("p->payload now: %x\n", swap_uint32(((uint32_t *)p->payload)[left]));
  /* end old for loop




 */


