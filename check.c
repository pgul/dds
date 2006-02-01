#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/param.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#else
#include <net/if.h>
#include <netinet/if_ether.h>
#endif
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif
#include "dds.h"

u_char my_mac[ETHER_ADDR_LEN]={MYMAC};
static u_char broadcast[ETHER_ADDR_LEN]={0xff,0xff,0xff,0xff,0xff,0xff};
extern long snap_traf;
extern FILE *fsnap;

static void putsnap(int in, u_char *src_mac, u_char *dst_mac, 
                    u_long src_ip, u_long dst_ip, int len)
{
  u_char *remote_mac=in ? src_mac : dst_mac;
  char str_src_ip[20], str_dst_ip[20];

  sprintf(str_src_ip, "%u.%u.%u.%u", ((char *)&src_ip)[0],
     ((char *)&src_ip)[1], ((char *)&src_ip)[2], ((char *)&src_ip)[3]);
  sprintf(str_dst_ip, "%u.%u.%u.%u", ((char *)&dst_ip)[0],
     ((char *)&dst_ip)[1], ((char *)&dst_ip)[2], ((char *)&dst_ip)[3]);
  if (dst_mac)
    fprintf(fsnap, "%s %s->%s %u bytes (mac %02x%02x.%02x%02x.%02x%02x)",
      (in ? "<-" : "->"), str_src_ip, str_dst_ip, len,
      remote_mac[0], remote_mac[1], remote_mac[2],
      remote_mac[3], remote_mac[4], remote_mac[5]);
  else
    fprintf(fsnap, 
#ifdef HAVE_PKTTYPE
                  "%s "
#endif
                  "%s->%s %u bytes",
#ifdef HAVE_PKTTYPE
      (in ? "<-" : "->"),
#endif
      str_src_ip, str_dst_ip, len);
  fflush(fsnap);
  if ((snap_traf-=len) <= 0)
  { fclose(fsnap);
    fsnap = NULL;
    snap_traf=0;
  }
}

char *printip(unsigned char *ip, int preflen, by_type by, int in)
{
  static char str[36];
  struct in_addr ina;
  u_short port;
  int len;

  len = length(by);
  str[0] = '\0';
  if (len>0 && len<4) return str;
  if (by == BYSRCDST && in == 1)
    memcpy(&ina, ip+4, 4);
  else
    memcpy(&ina, ip, 4);
  strcpy(str, inet_ntoa(ina));
  if (by == BYNONE) {
    sprintf(str+strlen(str), "/%u", preflen);
    return str;
  }
  if (len == 4) return str;
  if (by == BYDSTPORT) {
    memcpy(&port, ip, 2);
    sprintf(str+strlen(str), ":%u", ntohs(port));
    return str;
  }
  if (in)
    memcpy(&ina, ip, 4);
  else
    memcpy(&ina, ip+4, 4);
  strcat(str, "->");
  strcat(str, inet_ntoa(ina));
  return str;
}

static char *printoctets(unsigned char *octets, int length)
{
  static char stroctets[64];
  int i;

  stroctets[0] = '\0';
  for (i=0; i<length; i++)
  {
    sprintf(stroctets + strlen(stroctets), "%u", octets[i]);
    if (i+1 < length) strcat(stroctets, ".");
  }
  return stroctets;
}

void add_pkt(u_char *src_mac, u_char *dst_mac, struct ip *ip_hdr,
             u_long len, int in)
{
  u_long local=0, remote=0;
  time_t curtime;
  struct checktype *pc;
  u_long src_ip = *(u_long *)&(ip_hdr->ip_src);
  u_long dst_ip = *(u_long *)&(ip_hdr->ip_dst);
  u_short dst_port;

  if (dst_mac)
  {
    if (memcmp(src_mac, my_mac, ETHER_ADDR_LEN)==0)
    { /* outgoing packet */
      in =     reverse ? 1 : 0;
      remote = reverse ? src_ip : dst_ip;
      local =  reverse ? dst_ip : src_ip;
    }
    else if (memcmp(dst_mac, my_mac, ETHER_ADDR_LEN)==0 ||
             memcmp(dst_mac, broadcast, ETHER_ADDR_LEN)==0)
    { /* incoming packet */
      in =     reverse ? 0 : 1;
      remote = reverse ? dst_ip : src_ip;
      local =  reverse ? src_ip : dst_ip;
    }
    else
      /* left packet */
      return;
  }
  if (fsnap) putsnap(in, src_mac, dst_mac, src_ip, dst_ip, len);
  curtime = time(NULL);
  for (pc=checkhead; pc; pc=pc->next)
  {
    if (pc->in != in && pc->in != -1)
      continue;
    if ((local & pc->mask) != pc->ip)
      continue;
    if (pc->checkpoint == SYN || pc->by == BYDSTPORT)
    {
      if (ip_hdr->ip_p == IPPROTO_TCP)
      {
        struct tcphdr *th = (struct tcphdr *)(ip_hdr+1);
        dst_port = th->th_dport;
        if (pc->checkpoint == SYN) {
#ifdef TH_SYN
          int flags = th->th_flags;
          if ((flags & TH_SYN) == 0 || (flags & TH_ACK) != 0)
#else
          if (th->syn && !th->ack)
#endif
            continue;
        }
      } else
        continue;
    }
    if (pc->by == BYNONE)
    {
      if (pc->checkpoint == BPS)
        pc->count += len;
      else
        pc->count++;
    } else {
      struct octet **po;
      unsigned char octetsarr[8], *octets;
      int i, len;

      octets = octetsarr;
      len = length(pc->by);
      if (pc->by == BYSRC)
        octets = (unsigned char *)&src_ip;
      else if (pc->by == BYDST)
        octets = (unsigned char *)&dst_ip;
      else if (pc->by == BYSRCDST) {
        memcpy(octetsarr, &local, 4);
        memcpy(octetsarr+4, &remote, 4);
      } else if (pc->by == BYDSTPORT) {
        memcpy(octetsarr, (unsigned char *)&dst_ip, 4);
        memcpy(octetsarr+4, (unsigned char *)&dst_port, 2);
      }
      po = &pc->octet;
      for (i=0; i<len; i++)
      {
        if (*po == NULL)
        {
          *po = calloc(256, sizeof(struct octet));
          debug(3, "New entry %s\n", printoctets(octets, i+1));
        }
        if (i == len-1) break;
        if (po[0][octets[i]].octet == NULL && i == 3) break; /* turn on detailed stats later */
        po[0][octets[i]].used_time = curtime;
        po = &po[0][octets[i]].octet;
      }
      if (pc->checkpoint == BPS)
        po[0][octets[i]].count += len;
      else
        po[0][octets[i]].count++;
    }
    if (pc->last) break;
  }
  if (curtime - last_check >= check_interval)
    check();
}

int length(by_type by)
{
  switch (by) {
    case BYNONE:
    case BYSRC:
    case BYDST:     return 4;
    case BYSRCDST:  return 8;
    case BYDSTPORT: return 6;
  }
  return -1;
}

void check_octet(struct checktype *pc, struct octet *octet, int level,
                 unsigned char *ip, time_t curtime)
{
  int i, len;

  len = length(pc->by);
  for (i=0; i<256; i++)
  {
    ip[level] = (unsigned char)i;
    if (level==len-1) {
      if (octet[i].count >= (unsigned long long)pc->limit * (curtime - last_check)) {
        if (!octet[i].alarmed)
          exec_alarm(ip, octet[i].count * (pc->checkpoint == BPS ? 8 : 1) / (curtime - last_check), pc, 1);
        debug(1, "%s for %s is %lu - DoS\n", cp2str(pc->checkpoint),
              printip(ip, 32, pc->by, pc->in),
              octet[i].count * (pc->checkpoint == BPS ? 8 : 1) / (curtime - last_check));
        octet[i].alarmed = 1;
      } else if (octet[i].count >= (unsigned long long)pc->safelimit * (curtime - last_check)) {
        debug(1, "%s for %s is %lu - safe DoS\n", cp2str(pc->checkpoint),
              printip(ip, 32, pc->by, pc->in),
              octet[i].count * (pc->checkpoint == BPS ? 8 : 1) / (curtime - last_check));
      } else {
        if (octet[i].alarmed) {
          exec_alarm(ip, octet[i].count * (pc->checkpoint == BPS ? 8 : 1) / (curtime - last_check), pc, 0);
          octet[i].alarmed = 0;
        }
        if (octet[i].count)
          debug(2, "%s for %s is %lu - ok\n", cp2str(pc->checkpoint),
                printip(ip, 32, pc->by, pc->in),
                octet[i].count * (pc->checkpoint == BPS ? 8 : 1) / (curtime - last_check));
      }
      octet[i].count = 0;
    } else if (octet[i].octet) {
      check_octet(pc, octet[i].octet, level+1, ip, curtime);
      if (curtime-octet[i].used_time >= expire_interval) {
        debug(3, "Expire %s, unused time %u\n", printoctets(ip, level),
              curtime-octet[i].used_time);
        free(octet[i].octet);
        octet[i].octet = NULL;
      }
    } else if (level==3) {
      if (octet[i].count >= (unsigned long long)pc->limit * (curtime - last_check)) {
        debug(1, "%s for %s is %lu - DoS, turning detailed stats on\n",
              cp2str(pc->checkpoint), printip(ip, 32, BYSRC, pc->in),
              octet[i].count * (pc->checkpoint == BPS ? 8 : 1) / (curtime - last_check));
        octet[i].used_time = curtime - expire_interval; /* remove on next check if no traffic */
        octet[i].octet = calloc(256, sizeof(struct octet));
      } else if (octet[i].count) {
        debug(2, "%s for %s is %lu - ok (no detailed stats)\n",
              cp2str(pc->checkpoint), printip(ip, 32, BYSRC, pc->in),
              octet[i].count * (pc->checkpoint == BPS ? 8 : 1) / (curtime - last_check));
        octet[i].count = 0;
      }
    }
  }
}

void check(void)
{
  time_t curtime;
  struct checktype *pc;

  curtime = time(NULL);
  if (curtime == last_check) return;
  for (pc=checkhead; pc; pc=pc->next) {
    if (pc->by == BYNONE) {
      if (pc->count >= (unsigned long long)pc->limit * (curtime - last_check)) {
        if (!pc->alarmed)
          exec_alarm((unsigned char *)&pc->ip, pc->count * (pc->checkpoint == BPS ? 8 : 1) / (curtime - last_check), pc, 1);
        debug(1, "%s for %s/%u is %lu - DoS\n", cp2str(pc->checkpoint),
              inet_ntoa(*(struct in_addr *)&pc->ip), pc->preflen,
              pc->count * (pc->checkpoint == BPS ? 8 : 1) / (curtime - last_check));
        pc->alarmed = 1;
      } else if (pc->count >= (unsigned long long)pc->safelimit * (curtime - last_check)) {
        debug(1, "%s for %s/%u is %lu - safe DoS\n", cp2str(pc->checkpoint),
              inet_ntoa(*(struct in_addr *)&pc->ip), pc->preflen,
              pc->count * (pc->checkpoint == BPS ? 8 : 1) / (curtime - last_check));
      } else {
        if (pc->count)
          debug(2, "%s for %s/%u is %lu - ok\n", cp2str(pc->checkpoint),
                inet_ntoa(*(struct in_addr *)&pc->ip), pc->preflen,
                pc->count * (pc->checkpoint == BPS ? 8 : 1) / (curtime - last_check));
	if (pc->alarmed) {
          exec_alarm((unsigned char *)&pc->ip, pc->count * (pc->checkpoint == BPS ? 8 : 1) / (curtime - last_check), pc, 0);
          pc->alarmed = 0;
        }
      }
      pc->count = 0;
    } else if (pc->octet) {
      unsigned char c[8];
      check_octet(pc, pc->octet, 0, c, curtime);
    }
  }
  last_check = curtime;
}

