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
static int ft3_byteorder;
static int ft3_seq;

static struct ft3_header
{
  char magic1; /* 0xcf */
  char magic2; /* 0x10 */
  char byte_order; /* 1 - big endian or 2 - little endian */
  char version; /* should be 3 */
  unsigned int head_off_d; /* header offset */
  /* ignore all tlv's */
} ft3_hdr;

static struct ft3_record /* struct fts3rec_v5_gen */
{
  unsigned int sec;
  unsigned int msec;
  unsigned int uptime;
  unsigned int saddr;
  unsigned int srcaddr, dstaddr;
  unsigned int nexthop;
  unsigned short int input, output;
  unsigned int pkts, bytes;
  unsigned int first, last;
  unsigned short int srcport, dstport;
  char prot, tos, flags, pad;
  char engine_type, engine_id;
  char src_mask, dst_mask;
  unsigned short int src_as, dst_as;
} ft3_rec;

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

static unsigned int swapl(unsigned int n)
{
  return ((n & 0xff) << 24) | ((n & 0xff00) << 8) | ((n & 0xff0000) >> 8) | ((n & 0xff000000u) >> 24);
}

static unsigned short int swaps(unsigned short int n)
{
  return ((n & 0xff) << 8) | ((n & 0xff00) >> 8);
}

static unsigned int ft2nl(unsigned int n)
{
  return (ft3_byteorder == 1) ? swapl(n) : n;
}

static unsigned short int ft2ns(unsigned short int n)
{
  return (ft3_byteorder == 1) ? swaps(n) : n;
}

static int readn(int sockfd, void *buf, int n)
{
  int i, r;
  char tmpbuf[4096];
  char *p;

  i = 0;
  while (buf == NULL && n-i > sizeof(tmpbuf))
  {
    r = readn(sockfd, NULL, sizeof(tmpbuf));
    if (r < 0) return r;
    i += r;
    if (r != sizeof(tmpbuf)) return i;
  }
  p = buf ? (char *)buf : tmpbuf;
  while (n > i)
  {
    r = read(sockfd, p, n-i);
    if (r < 0) return r;
    if (r == 0) break;
    p += r;
    i += r;
  }
  return i;
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
  else if (!stdinsrc)
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
  if (stdinsrc)
  { struct head5 *head5buf;
    struct data5 *data5buf;
    unsigned int saddr;

    n = readn(sockfd, &ft3_rec, sizeof(ft3_rec));
    if (n < 0)
    {
      error("read stdin error");
      return -1;
    }
    if (n != sizeof(ft3_rec))
      return -1;
    /* convert flow-tool record to netflow v5 */
    n = sizeof(struct head5) + sizeof(struct data5);
    saddr = (ft3_byteorder == 1) ? swapl(ft3_rec.saddr) : ft3_rec.saddr;
    memcpy(&queue[tail].remote_addr.sin_addr.s_addr, &saddr, sizeof(saddr));
    curtime = ft3_rec.sec;
    head5buf = (struct head5 *)queue[tail].databuf;
    data5buf = (struct data5 *)(queue[tail].databuf + sizeof(struct head5));
    memset(queue[tail].databuf, 0, n);
    head5buf->version   = htons(5);
    head5buf->count     = htons(1);
    head5buf->uptime    = ft2nl(ft3_rec.uptime);
    head5buf->curtime   = ft2nl(ft3_rec.sec);
    head5buf->curnanosec= htonl(ntohl(ft2nl(ft3_rec.msec)) * 1000);
    head5buf->seq       = htonl(++ft3_seq); /* htonl(ft3_seq+=ntohs(ft2nl(ft3_rec.drops)+1)); */
    data5buf->srcaddr   = ft2nl(ft3_rec.srcaddr);
    data5buf->dstaddr   = ft2nl(ft3_rec.dstaddr);
    data5buf->nexthop   = ft2nl(ft3_rec.nexthop);
    data5buf->input     = ft2ns(ft3_rec.input);
    data5buf->output    = ft2ns(ft3_rec.output);
    data5buf->pkts      = ft2nl(ft3_rec.pkts);
    data5buf->bytes     = ft2nl(ft3_rec.bytes);
    data5buf->first     = ft2nl(ft3_rec.first);
    data5buf->last      = ft2nl(ft3_rec.last);
    data5buf->srcport   = ft2ns(ft3_rec.srcport);
    data5buf->dstport   = ft2ns(ft3_rec.dstport);
    data5buf->prot      = ft3_rec.prot;
    data5buf->tos       = ft3_rec.tos;
    data5buf->flags     = ft3_rec.flags;
    data5buf->src_mask  = ft3_rec.src_mask;
    data5buf->dst_mask  = ft3_rec.dst_mask;
    data5buf->src_as    = ft2ns(ft3_rec.src_as);
    data5buf->dst_as    = ft2ns(ft3_rec.dst_as);
  } else
  {
    sl = sizeof(queue[tail].remote_addr);
    memset(&queue[tail].remote_addr, 0, sizeof(queue[tail].remote_addr));
    n = recvfrom(sockfd, queue[tail].databuf, sizeof(queue[tail].databuf), 0, (struct sockaddr *)&queue[tail].remote_addr, &sl);
  }
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
  for (n = 0; n < pr->nmyas; n++) {
    if (input == pr->myas[n]) in |= 4;
    else if (output == pr->myas[n]) in |= 8;
  }
  if (output == 0) return; /* already filtered? */
  if (((in & 1) && ((in & 2) == 0)) || (((in & 5) == 0) && ((in & 10) == 0))) /* from uplink to not uplink or from downlink to downlink */
    add_pkt(NULL, NULL, iphdr, bytes * pr->sampled, 1, 0, pkts * pr->sampled, 1, NULL, 0, 0);
  if ((((in & 5) == 0) && ((in & 10) == 0)) || (((in & 1) == 0) && (in & 2))) /* from downlink to downlink or from not uplink to uplink */
    add_pkt(NULL, NULL, iphdr, bytes * pr->sampled, 0, 0, pkts * pr->sampled, 1, NULL, 0, 0);
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
  int ver, i, count, n, flip;
  struct sockaddr_in *remote_addr;
  char *databuf;
  char pktbuf[sizeof(struct ip)+max(sizeof(struct tcphdr),sizeof(struct udphdr))];
  struct ip *iphdr = (struct ip *)pktbuf;
  struct router_t *pr;

  /* sockfd and servsock can be changed by signal */
  if (stdinsrc)
  {
    sockfd = fileno(stdin);
    if (readn(sockfd, &ft3_hdr, sizeof(ft3_hdr)) != sizeof(ft3_hdr))
    { error("Cannot read stdin");
      return;
    }
    if (ft3_hdr.version != 3)
    { error("Unknown flow-tools version: %u (expected 3)", ft3_hdr.version);
      return;
    }
    if (ft3_hdr.magic1 != (char)0xcf)
      warning("Unexpected flow-tools magic1: 0x%02x (expected 0xcf)", ft3_hdr.magic1);
    if (ft3_hdr.magic2 != 0x10)
      warning("Unexpected flow-tools magic2: 0x%02x (expected 0x10)", ft3_hdr.magic2);
    ft3_byteorder = ft3_hdr.byte_order;
    if (htons(1) == 1) /* move to configure script! */
      flip = (ft3_byteorder == 1) ? 1 : 0;
    else
      flip = (ft3_byteorder == 1) ? 0 : 1;
    n = (flip ? swapl(ft3_hdr.head_off_d) : ft3_hdr.head_off_d) - sizeof(ft3_hdr);
    if (readn(sockfd, NULL, n) != n)
    { error("Cannot read stdin");
      return;
    }
  }
  switchsignals(SIG_BLOCK);
  for (;;)
  {
    if (need_reconfig) reconfig();
    if (!stdinsrc || !curtime) curtime = time(NULL);
    if (last_check > curtime) last_check = curtime;
    if (curtime - last_check >= check_interval)
      check(curtime);
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
