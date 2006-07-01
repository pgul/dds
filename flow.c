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

static int sockfd = -1;
u_long flowip;
static unsigned short flowport;

int bindport(char *netflow)
{
  char *p;
  struct sockaddr_in myaddr;

  p = strchr(netflow, ':');
  if (p) {
    *p = '\0';
    flowip = inet_addr(netflow);
    *p++ = ':';
  } else {
    flowip = (u_long)-1;
    p = netflow;
  }
  flowport = atoi(p);
  if (flowport == 0 || flowip == 0)
  {
    fprintf(stderr, "Incorrect netflow port: %s!\n", netflow);
    return -1;
  }
#if 0
  if (flowport < 1024 && geteuid() != 0 && sockfd != -1)
  { /* do not close socket if we're already drop privileges */
    fprintf(stderr, "Can't bind: permission denied\n");
    return -1;
  }
#endif
  if (sockfd != -1)
  {
    close(sockfd);
    sockfd = -1;
  }
  if ((sockfd=socket(PF_INET, SOCK_DGRAM, 0)) == -1)
  { printf("socket: %s\n", strerror(errno));
    return -1;
  }
  memset(&myaddr, 0, sizeof(myaddr));
  myaddr.sin_family = AF_INET;
  myaddr.sin_addr.s_addr = flowip;
  myaddr.sin_port = htons(flowport);
  if (bind(sockfd, (struct sockaddr *)&myaddr, sizeof(myaddr)) != 0)
  {
    printf("bind: %s (addr %s)\n", strerror(errno), inet_ntoa(myaddr.sin_addr));
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

void recv_flow(void)
{
  int ver, n, i, count, new_sockfd, maxsock;
  int oldsockfd, oldservsock;
  socklen_t sl;
  struct sockaddr_in remote_addr, client;
  char databuf[MTU];
  char pktbuf[sizeof(struct ip)+max(sizeof(struct tcphdr),sizeof(struct udphdr))];
  struct ip *iphdr = (struct ip *)pktbuf;
  struct router_t *pr;
  fd_set r;
  socklen_t a_len;
  pid_t pid;
  struct timeval tv;

  /* sockfd and servsock can be changed by signal */
  switchsignals(SIG_BLOCK);
  for (;;)
  {
    FD_ZERO(&r);
    FD_SET(sockfd, &r);
    if (servsock != -1) FD_SET(servsock, &r);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    maxsock = max(servsock, sockfd) + 1;
    switchsignals(SIG_UNBLOCK);
    n = select(maxsock, &r, NULL, NULL, &tv);
    oldsockfd = sockfd;
    oldservsock = servsock;
    switchsignals(SIG_BLOCK);
    if (n == -1)
    {
      if (errno == EAGAIN || errno == EINTR) continue;
      if (errno == EBADF && (sockfd != oldsockfd || servsock != oldservsock))
        continue;
      error("select() error: %s", strerror(errno));
      break;
    }
    if (n == 0)
    {
      if (time(NULL) - last_check >= check_interval)
        check();
      continue;
    }
    if (FD_ISSET(servsock, &r))
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
        close(new_sockfd);
      }
    }
    if (!FD_ISSET(sockfd, &r))
      continue;
    sl = sizeof(remote_addr);
    memset(&remote_addr, 0, sizeof(remote_addr));
    n = recvfrom(sockfd, databuf, sizeof(databuf), 0, (struct sockaddr *)&remote_addr, &sl);
    if (n == -1)
    {
      if (errno == EAGAIN || errno == EINTR) continue;
      error("recvfrom error: %s", strerror(errno));
      break;
    }
    if (n == 0) continue;
    for (pr=routers->next; pr; pr=pr->next)
    {
      if (pr->addr == (u_long)-1 || pr->addr == remote_addr.sin_addr.s_addr)
        break;
    }
    if (!pr)
    { 
      pr = routers;
      if (pr->nuplinks == 0)
      { warning("Packet from unknown router %s ignored", inet_ntoa(remote_addr.sin_addr));
        continue;
      }
    }
    ver = ntohs(*(short int *)databuf);
    if (ver == 1)
    {
      if (n < sizeof(struct head1))
        continue;
      head1 = (struct head1 *)databuf;
      if (n != sizeof(*head1)+ntohs(head1->count)*sizeof(*data1))
        continue;
      data1 = (struct data1 *)(head1+1);
      count=ntohs(head1->count);
      for (i=0; i<count; i++)
      {
        unsigned long bytes;
        unsigned short input, output;

        bytes=ntohl(data1[i].bytes);
        input=ntohs(data1[i].input);
        output=ntohs(data1[i].output);
        make_iphdr(iphdr, data1[i].srcaddr, data1[i].dstaddr, data1[i].prot,
                   data1[i].dstport, data1[i].flags);
        for (n = 0; n < pr->nuplinks; n++) {
          if (input == pr->uplinks[n])
            add_pkt(NULL, NULL, iphdr, bytes, 1, 0, ntohl(data1[i].pkts), 1, NULL, 0);
          else if (output == pr->uplinks[n])
            add_pkt(NULL, NULL, iphdr, bytes, 0, 0, ntohl(data1[i].pkts), 1, NULL, 0);
          else
            continue;
          break;
        }
      }
    }
    else if (ver == 5)
    {
      if (n < sizeof(struct head5))
        continue;
      head5 = (struct head5 *)databuf;
      if (n != sizeof(*head5)+ntohs(head5->count)*sizeof(*data5))
        continue;
      data5 = (struct data5 *)(head5+1);
      count=ntohs(head5->count);
      for (i=0; i<count; i++)
      {
        unsigned long bytes;
        unsigned short input, output;

        bytes=ntohl(data5[i].bytes);
        input=ntohs(data5[i].input);
        output=ntohs(data5[i].output);
        make_iphdr(iphdr, data5[i].srcaddr, data5[i].dstaddr, data5[i].prot,
                   data5[i].dstport, data5[i].flags);
        for (n = 0; n < pr->nuplinks; n++) {
          if (input == pr->uplinks[n])
            add_pkt(NULL, NULL, iphdr, bytes, 1, 0, ntohl(data5[i].pkts), 1, NULL, 0);
          else if (output == pr->uplinks[n])
            add_pkt(NULL, NULL, iphdr, bytes, 0, 0, ntohl(data5[i].pkts), 1, NULL, 0);
          else
            continue;
          break;
        }
      }
    }
    else
    { /* unknown netflow version, ignore */
    }
  }
  switchsignals(SIG_UNBLOCK);
}
