#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "dds.h"

static struct head1 {
  short unsigned int version, count;
  unsigned int uptime, curtime, curnanosec;
} *head1;

static struct data1 {
  unsigned int srcaddr, dstaddr, nexthop;
  unsigned short int input, output;
  unsigned int pkts, bytes, first, last;
  unsigned short int srcport, dstport, pad;
  unsigned char prot, tos, flags, pad1, pad2, pad3;
  unsigned int reserved;
} *data1;

static struct head5 {
  short unsigned int version, count;
  unsigned int uptime, curtime, curnanosec;
  unsigned int seq, pad;
} *head5;

static struct data5 {
  unsigned int srcaddr, dstaddr, nexthop;
  unsigned short int input, output;
  unsigned int pkts, bytes, first, last;
  unsigned short int srcport, dstport;
  unsigned char pad1, flags, prot, tos;
  unsigned short src_as, dst_as;
  unsigned char src_mask, dst_mask;
  unsigned short pad2;
} *data5;

static struct
{
  struct sockaddr_in remote_addr;
  int  n;
  char databuf[MTU];
} queue[QSIZE];

static int head, tail;
static int sockfd = -1;
u_long flowip;
static unsigned short flowport;

int bindport(char *netflow)
{
  char *p;
  struct sockaddr_in myaddr;
  int opt;

  p = strchr(netflow, ':');
  if (p) {
    *p = '\0';
    flowip = inet_addr(netflow);
    *p++ = ':';
  } else {
    flowip = INADDR_ANY;
    p = netflow;
  }
  flowport = atoi(p);
  if (flowport == 0 || flowip == 0)
  {
    error("Incorrect netflow port: %s!", netflow);
    return -1;
  }
#if 0
  if (flowport < 1024 && geteuid() != 0 && sockfd != -1)
  { /* do not close socket if we're already drop privileges */
    error("Can't bind: permission denied");
    return -1;
  }
#endif
  if (sockfd != -1)
  {
    close(sockfd);
    sockfd = -1;
  }
  if ((sockfd=socket(PF_INET, SOCK_DGRAM, 0)) == -1)
  { error("socket: %s", strerror(errno));
    return -1;
  }
  if (setsockopt (sockfd, SOL_SOCKET, SO_REUSEADDR, (char *) &opt, sizeof opt))
    warning("Warning: cannot setsockopt SO_REUSEADDR: %s", strerror(errno));

  memset(&myaddr, 0, sizeof(myaddr));
  myaddr.sin_family = AF_INET;
  myaddr.sin_addr.s_addr = flowip;
  myaddr.sin_port = htons(flowport);
  if (bind(sockfd, (struct sockaddr *)&myaddr, sizeof(myaddr)) != 0)
  {
    error("bind: %s (addr %s)", strerror(errno), inet_ntoa(myaddr.sin_addr));
    close(sockfd);
    sockfd = -1;
    return -1;
  }
  return 0;
}

void make_iphdr(void *iphdr, u_long saddr, u_long daddr,
          unsigned char prot, unsigned short dport, unsigned char flags)
{
  struct ip *ip_hdr = (struct ip *)iphdr;
  ip_hdr->ip_p = prot;
  ip_hdr->ip_src = *(struct in_addr *)(void *)&saddr;
  ip_hdr->ip_dst = *(struct in_addr *)(void *)&daddr;
  if (prot == IPPROTO_TCP)
  {
    struct tcphdr *th = (struct tcphdr *)(ip_hdr+1);
    th->th_dport = dport;
#ifdef TH_SYN
    th->th_flags = flags;
#else
    th->syn = flags & 0x02;
    th->ack = 0;
#endif
  }
  else if (prot == IPPROTO_UDP)
  {
    struct udphdr *uh = (struct udphdr *)(ip_hdr+1);
    uh->uh_dport = dport;
  }
}

int check_sockets(void)
{
  int n;
  socklen_t a_len, sl;
  fd_set r;
  struct timeval tv;
  int new_sockfd, maxsock;
  pid_t pid;
  struct sockaddr_in client;

  FD_ZERO(&r);
  if ((tail+1)%QSIZE != head)
    FD_SET(sockfd, &r);
  else
    warning("Queue buffer full (too slow CPU for this flow?)");
  if (servsock != -1) FD_SET(servsock, &r);
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  if (head != tail) tv.tv_sec = 0;
  maxsock = max(servsock, sockfd) + 1;
  switchsignals(SIG_UNBLOCK);
  n = select(maxsock, &r, NULL, NULL, &tv);
  switchsignals(SIG_BLOCK);
  if (n == -1)
  {
    if (errno == EAGAIN || errno == EINTR) return 0;
    error("select() error: %s", strerror(errno));
    return -1;
  }
  if (n == 0)
    return 0;
  if ((servsock != -1) && FD_ISSET(servsock, &r))
  {
    a_len = sizeof(client);
    new_sockfd = accept(servsock, (struct sockaddr *)&client, &a_len);
    if (new_sockfd == -1)
    {
      warning("accept error: %s", strerror(errno));
    }
    else
    {
      /* fork because write alarm list can cause waiting for network */
      pid = fork();
      if (pid == 0)
      {
        print_alarms(new_sockfd);
        exit(0);
      }
      if (pid == -1)
        error("fork() error: %s", strerror(errno));
      else
        debug(1, "print_alarms: start process %u", pid);
      close(new_sockfd);
    }
  }
  if (!FD_ISSET(sockfd, &r))
    return 0;
  sl = sizeof(queue[tail].remote_addr);
  memset(&queue[tail].remote_addr, 0, sizeof(queue[tail].remote_addr));
  n = recvfrom(sockfd, queue[tail].databuf, sizeof(queue[tail].databuf), 0, (struct sockaddr *)&queue[tail].remote_addr, &sl);
  if (n == -1)
  {
    if (errno != EAGAIN && errno != EINTR)
      error("recvfrom error: %s", strerror(errno));
  }
  else if (n > 0)
  {
    queue[tail].n = n;
    tail++;
    if (tail==QSIZE) tail=0;
  }
  return n;
}

#ifdef DO_SNMP
static char *getoidval(struct router_t *pr, enum ifoid_t oid, int ifindex)
{
  int i;

  if (!pr || !pr->data[oid]) return NULL;
  /* TODO: optimize (make index?) */
  for (i=0; i<pr->nifaces[oid]; i++)
    if (pr->data[oid][i].ifindex == ifindex)
      return pr->data[oid][i].val;
  return NULL;
}
#endif

static void add_flow(struct router_t *pr, int input, int output,
	      	     struct ip *iphdr, unsigned long bytes, int pkts)
{
  int n, in = 0;
  char ip_src[20], ip_dst[20];
  char sinput[80], soutput[80];

  for (n = 0; n < pr->nuplinks; n++) {
    if (input == pr->uplinks[n]) in |= 1;
    else if (output == pr->uplinks[n]) in |= 2;
  }
  if ((in & 2) == 0 && output != 0) /* to downlink */
    add_pkt(NULL, NULL, iphdr, bytes*sampled, 1, 0, pkts*sampled, 1, NULL, 0, 0);
  if ((in & 1) == 0) /* from downlink */
    add_pkt(NULL, NULL, iphdr, bytes*sampled, 0, 0, pkts*sampled, 1, NULL, 0, 0);
  if (in != 3 && (input != output || input == 0)) return;
  /* from uplink to uplink or ping-pong */
  strncpy(ip_src, inet_ntoa(iphdr->ip_src), sizeof(ip_src));
  strncpy(ip_dst, inet_ntoa(iphdr->ip_dst), sizeof(ip_dst));
  ip_src[sizeof(ip_src)-1] = ip_dst[sizeof(ip_dst)-1] = '\0';
  sinput[0] = soutput[0] = '\0';
#ifdef DO_SNMP
  {
    int oid = -1;
    char *p;

    if (pr->data[IFNAME]) oid=IFNAME;
    else if (pr->data[IFDESCR]) oid=IFDESCR;
    else if (pr->data[IFALIAS]) oid=IFALIAS;
    if (oid >= 0) {
      if (input > 0 && (p = getoidval(pr, oid, input)) != NULL)
        snprintf(sinput, sizeof(sinput)-1, " (%s %s)", oid2str(oid), p);
      if (output > 0 && (p = getoidval(pr, oid, output)) != NULL)
        snprintf(soutput, sizeof(soutput)-1, " (%s %s)", oid2str(oid), p);
      sinput[sizeof(sinput)-1] = soutput[sizeof(soutput)-1] = '\0';
    }
  }
#endif
  warning("%s: router %s, input %u%s output %u%s pkt %s->%s",
           (input == output) ? "Ping-pong" : "Packet from upstream to upstream",
           printoctets((unsigned char *)&pr->addr, 4), input, sinput, output, soutput, ip_src, ip_dst);
}

void recv_flow(void)
{
  int ver, i, count, n;
  struct sockaddr_in *remote_addr;
  char *databuf;
  char pktbuf[sizeof(struct ip)+max(sizeof(struct tcphdr),sizeof(struct udphdr))];
  struct ip *iphdr = (struct ip *)pktbuf;
  struct router_t *pr;

  /* sockfd and servsock can be changed by signal */
  switchsignals(SIG_BLOCK);
  for (;;)
  {
    if (need_reconfig) reconfig();
    if (time(NULL) - last_check >= check_interval)
      check();
    if (check_sockets() < 0) break;
    if (head == tail) continue;
    remote_addr = &queue[head].remote_addr;
    for (pr=routers->next; pr; pr=pr->next)
    {
      if (pr->addr == (u_long)-1 || pr->addr == remote_addr->sin_addr.s_addr)
        break;
    }
    databuf = queue[head].databuf;
    n = queue[head].n;
    if (!pr)
    { 
      pr = routers;
      if (pr->nuplinks == 0)
      { warning("Packet from unknown router %s ignored", inet_ntoa(remote_addr->sin_addr));
        goto nextpkt;
      }
    }
    ver = ntohs(*(short int *)databuf);
    if (ver == 1)
    {
      if (n < sizeof(struct head1))
      {
        warning("Too small pkt ignored");
        goto nextpkt;
      }
      head1 = (struct head1 *)databuf;
      if (n != sizeof(*head1)+ntohs(head1->count)*sizeof(*data1))
      {
        warning("Pkt with wrong size ignored");
        goto nextpkt;
      }
      data1 = (struct data1 *)(head1+1);
      count = ntohs(head1->count);
      for (i=0; i<count; i++)
      {
        unsigned long bytes;
        unsigned short input, output;

        bytes=ntohl(data1[i].bytes);
        input=ntohs(data1[i].input);
        output=ntohs(data1[i].output);
        make_iphdr(iphdr, data1[i].srcaddr, data1[i].dstaddr, data1[i].prot,
                   data1[i].dstport, data1[i].flags);
	add_flow(pr, input, output, iphdr, bytes, ntohl(data1[i].pkts));
      }
    }
    else if (ver == 5)
    {
      if (n < sizeof(struct head5))
      {
        warning("Too small pkt ignored");
        goto nextpkt;
      }
      head5 = (struct head5 *)databuf;
      if (n != sizeof(*head5)+ntohs(head5->count)*sizeof(*data5))
      {
        warning("Pkt with wrong size ignored");
        continue;
      }
      data5 = (struct data5 *)(head5+1);
      count = ntohs(head5->count);
      for (i=0; i<count; i++)
      {
        unsigned long bytes;
        unsigned short input, output;

        bytes=ntohl(data5[i].bytes);
        input=ntohs(data5[i].input);
        output=ntohs(data5[i].output);
        make_iphdr(iphdr, data5[i].srcaddr, data5[i].dstaddr, data5[i].prot,
                   data5[i].dstport, data5[i].flags);
	add_flow(pr, input, output, iphdr, bytes, ntohl(data5[i].pkts));
      }
    }
    else
    { warning("Unknown netflow version %u ignored", ver);
    }
nextpkt:
    head++;
    if (head == QSIZE) head=0;
  }
  switchsignals(SIG_UNBLOCK);
}
