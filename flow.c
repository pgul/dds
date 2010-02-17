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
#ifdef WITH_ZLIB
#include <zlib.h>
#endif
#include "dds.h"

static struct head1 {
  uint16_t version, count;
  uint32_t uptime, curtime, curnanosec;
} __attribute__((packed)) *head1;

static struct data1 {
  uint32_t srcaddr, dstaddr, nexthop;
  uint16_t input, output;
  uint32_t pkts, bytes, first, last;
  uint16_t srcport, dstport, pad;
  unsigned char prot, tos, flags, pad1, pad2, pad3;
  uint32_t reserved;
} __attribute__((packed)) *data1;

static struct head5 {
  uint16_t version, count;
  uint32_t uptime, curtime, curnanosec;
  uint32_t seq, pad;
} __attribute__((packed)) *head5;

static struct data5 {
  uint32_t srcaddr, dstaddr, nexthop;
  uint16_t input, output;
  uint32_t pkts, bytes, first, last;
  uint16_t srcport, dstport;
  unsigned char pad1, flags, prot, tos;
  uint16_t src_as, dst_as;
  unsigned char src_mask, dst_mask;
  uint16_t pad2;
} __attribute__((packed)) *data5;

static struct
{
  struct sockaddr_in remote_addr;
  int  n;
  union {
    struct {
      struct head1 head;
      struct data1 data[MTU/sizeof(struct data1)];
    } __attribute__((packed)) ver1;
    struct {
      struct head5 head;
      struct data5 data[MTU/sizeof(struct data5)];
    } __attribute__((packed)) ver5;
  } databuf;
} queue[QSIZE];

static int head, tail;
static int sockfd = -1;
in_addr_t flowip;
static unsigned short flowport;
static int ft3_byteorder;
static int ft3_seq;

#define FT_TLV_HEADER_FLAGS     8
#define FT_HEADER_FLAG_COMPRESS 0x2

static struct ft3_header
{
  char magic1; /* 0xcf */
  char magic2; /* 0x10 */
  char byte_order; /* 1 - big endian or 2 - little endian */
  char version; /* should be 3 */
  uint32_t head_off_d; /* header offset */
} __attribute__((packed)) ft3_hdr;
uint32_t ft3_flags;

static struct ft3_record /* struct fts3rec_v5_gen */
{
  uint32_t sec;
  uint32_t msec;
  uint32_t uptime;
  uint32_t saddr;
  uint32_t srcaddr, dstaddr;
  uint32_t nexthop;
  uint16_t input, output;
  uint32_t pkts, bytes;
  uint32_t first, last;
  uint16_t srcport, dstport;
  char prot, tos, flags, pad;
  char engine_type, engine_id;
  char src_mask, dst_mask;
  uint16_t src_as, dst_as;
} __attribute__((packed)) ft3_rec;

#ifdef WITH_ZLIB
z_stream zdata;
#endif

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

void make_iphdr(void *iphdr, uint32_t saddr, uint32_t daddr,
          uint16_t prot, uint16_t dport, unsigned char flags)
{
  struct ip *ip_hdr = (struct ip *)iphdr;
  ip_hdr->ip_p = prot;
  ip_hdr->ip_src.s_addr = saddr;
  ip_hdr->ip_dst.s_addr = daddr;
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
  if ((tail+1) % QSIZE != head)
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

#ifdef WITH_ZLIB
    if (ft3_flags & FT_HEADER_FLAG_COMPRESS)
    {
      int rc;
      static char zbuf[4096];

      zdata.next_out = (Bytef *)&ft3_rec;
      zdata.avail_out = (uLong)sizeof(ft3_rec);
      while (zdata.avail_out)
      {
        if (zdata.avail_in == 0)
        {
          zdata.avail_in = n = readn(sockfd, zbuf, sizeof(zbuf));
          if (n <= 0) break;
          zdata.next_in = (Bytef *)&zbuf;
        }
        rc = inflate(&zdata, 0);
        n = sizeof(ft3_rec) - zdata.avail_out;
        if (rc == Z_STREAM_END)
          break;
        else if (rc != Z_OK)
        {
          error("decompress stdin error, inflate retcode %u", rc);
          return -1;
        }
      }
    }
    else
#endif
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
    saddr = ft2nl(ft3_rec.saddr);
    memcpy(&queue[tail].remote_addr.sin_addr.s_addr, &saddr, sizeof(saddr));
    curtime = ft3_rec.sec;
    head5buf = &queue[tail].databuf.ver5.head;
    data5buf = queue[tail].databuf.ver5.data;
    memset(&queue[tail].databuf, 0, n);
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
    n = recvfrom(sockfd, &queue[tail].databuf, sizeof(queue[tail].databuf), 0, (struct sockaddr *)&queue[tail].remote_addr, &sl);
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
  if (output == 0 && !processfiltered) return; /* already filtered? */
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
  warning("%s:%s%s%s input %u%s output %u%s pkt %s->%s",
           (input == output) ? "Ping-pong" : "Packet from upstream to upstream",
		   pr->addr == (u_long)-1 ? "" : " router ",
		   pr->addr == (u_long)-1 ? "" : printoctets((unsigned char *)&pr->addr, 4),
		   pr->addr == (u_long)-1 ? "" : ",",
           input, sinput, output, soutput, ip_src, ip_dst);
}

void recv_flow(void)
{
  int ver, i, count, n, flip;
  struct sockaddr_in *remote_addr;
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
    if (n)
    { char *tlv_buf, *tlv_p;
      uint16_t tlv_type, tlv_len;

      tlv_buf = malloc(n);
      if (tlv_buf == NULL)
      { error("Cannot allocate memory, needed %u bytes", n);
        return;
      }
      if (readn(sockfd, tlv_buf, n) != n)
      { error("Cannot read stdin");
        return;
      }
      tlv_p = tlv_buf;
      while (n >= 4)
      {
        memcpy(&tlv_type, tlv_p, 2);
        tlv_p += 2;
        tlv_type = flip ? swaps(tlv_type) : tlv_type;
        memcpy(&tlv_len, tlv_p, 2);
        tlv_p += 2;
        tlv_len = flip ? swaps(tlv_len) : tlv_len;
        n -= 4;
        if (n < tlv_len) break;
        switch (tlv_type)
        {
          case FT_TLV_HEADER_FLAGS:
            if (tlv_len >= 4)
            { memcpy(&ft3_flags, tlv_p, 4);
              if (flip) ft3_flags = swapl(ft3_flags);
            }
            break;
        }
        tlv_p += tlv_len;
      }
      free(tlv_buf);
      if (ft3_flags & FT_HEADER_FLAG_COMPRESS)
      {
#ifdef WITH_ZLIB
        if (inflateInit(&zdata) != Z_OK)
        { error("ZLib decompress init error, try to use flow-cat");
          return;
        }
        debug(2, "Process compressed flow data");
#else
        error("Data compressed and no zlib support, use flow-cat");
        return;
#endif
      }
    }
  }
  switchsignals(SIG_BLOCK);
  for (;;)
  {
    if (need_reconfig) {
      logwrite("Reload config");
      reconfig();
    }
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
    n = queue[head].n;
    if (!pr)
    { 
      pr = routers;
      if (pr->nuplinks == 0)
      { warning("Packet from unknown router %s ignored", inet_ntoa(remote_addr->sin_addr));
        goto nextpkt;
      }
    }
    ver = ntohs(queue[head].databuf.ver5.head.version);
    if (ver == 1)
    {
      if (n < sizeof(struct head1))
      {
        warning("Too small pkt ignored");
        goto nextpkt;
      }
      head1 = &queue[head].databuf.ver1.head;
      if (n != sizeof(*head1)+ntohs(head1->count)*sizeof(*data1))
      {
        warning("Pkt with wrong size ignored");
        goto nextpkt;
      }
      data1 = queue[head].databuf.ver1.data;
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
      head5 = &queue[head].databuf.ver5.head;
      if (n != sizeof(*head5)+ntohs(head5->count)*sizeof(*data5))
      {
        warning("Pkt with wrong size ignored");
        continue;
      }
      data5 = queue[head].databuf.ver5.data;
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
#ifdef WITH_ZLIB
  if (stdinsrc)
    if (ft3_flags & FT_HEADER_FLAG_COMPRESS)
      inflateEnd(&zdata);
#endif
}
