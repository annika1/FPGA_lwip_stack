#ifndef MY_UDP_H
#define MY_UDP_H
/*
 * raw LWIP UDP Interface
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
        printf("is ipv6?: %i\n", IP_IS_V6(addr));
        err_t err_udp = udp_sendto(upcb, p, addr, port);
    /* free the pbuf */
        if (err_udp != ERR_OK) {
            printf("udpecho_raw_recv: There was an error\n");
            printf("err_udp = %i\n", err_udp);
        }
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
          printf("udp_bind done.\n");
          udp_recv(udpecho_raw_pcb, udpecho_raw_recv, NULL);
        } else {
            printf("udp_bind failed.\n");
          /* abort? output diagnostic? */
        }
      } else {
        /* abort? output diagnostic? */
      }
}

#endif // LWIP_UDP
#endif // MY_UDP_H
