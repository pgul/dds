#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/param.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
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

#define cps(count) (count_t)((unsigned long long)(count) * (pc->checkpoint == BPS ? 8 : 1) / ((curtime > last_check) ? (curtime - last_check) : 1))
#define addcount(count, p)	(((count) + (p) >= (count)) ? ((count) += (p)) : (count_t)-1)

#ifdef WITH_PCAP
u_char *my_mac[MAXMYMACS];
static u_char broadcast[ETHER_ADDR_LEN]={0xff,0xff,0xff,0xff,0xff,0xff};
#endif
extern long snap_start;
extern FILE *fsnap;
struct recheck_t *recheck_arr;
int recheck_cur, recheck_size;
static unsigned long leafs, nodes, emptyleafs, emptynodes, semileafs;

static void putsnap(int flow, int in, u_char *src_mac, u_char *dst_mac, 
                    uint32_t src_ip, uint32_t dst_ip, int len, int vlan, int pkts)
{
  char str_src_ip[20], str_dst_ip[20], pvlan[20];

  sprintf(str_src_ip, "%u.%u.%u.%u", ((char *)&src_ip)[0],
     ((char *)&src_ip)[1], ((char *)&src_ip)[2], ((char *)&src_ip)[3]);
  sprintf(str_dst_ip, "%u.%u.%u.%u", ((char *)&dst_ip)[0],
     ((char *)&dst_ip)[1], ((char *)&dst_ip)[2], ((char *)&dst_ip)[3]);
  if (vlan)
    sprintf(pvlan, " vlan %d", vlan);
  else
    pvlan[0] = '\0';
  if (dst_mac)
    fprintf(fsnap, "%s %s->%s %u bytes (%02x%02x.%02x%02x.%02x%02x->%02x%02x.%02x%02x.%02x%02x%s)\n",
      (in ? "<-" : "->"), str_src_ip, str_dst_ip, len,
      src_mac[0], src_mac[1], src_mac[2],
      src_mac[3], src_mac[4], src_mac[5],
      dst_mac[0], dst_mac[1], dst_mac[2],
      dst_mac[3], dst_mac[4], dst_mac[5], pvlan);
  else
  { if (flow)
      fprintf(fsnap, "%s %s->%s %u bytes %u pkts\n",
        (in ? "<-" : "->"), str_src_ip, str_dst_ip, len, pkts);
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
  }
  fflush(fsnap);
  if (!stdinsrc || !curtime) curtime = time(NULL);
  if (snap_start + SNAP_TIME < curtime)
  { fclose(fsnap);
    fsnap = NULL;
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
    memcpy(&port, ip+4, 2);
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

char *printoctets(unsigned char *octets, int length)
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

static void reprocess(struct checktype *pc, unsigned char *local_ip, int iplen)
{
  int i;
  char pktbuf[sizeof(struct ip)+max(sizeof(struct tcphdr),sizeof(struct udphdr))];
  struct ip *iphdr = (struct ip *)pktbuf;

  if (!recheck_arr) return;
  debug(2, "Reprocess saved queue (%u entries)", recheck_cur);
  for (i=0; i<recheck_cur; i++)
  {
    make_iphdr(iphdr, recheck_arr[i].s_addr, recheck_arr[i].d_addr,
             recheck_arr[i].proto, recheck_arr[i].d_port, recheck_arr[i].flags);
    add_pkt(NULL, NULL, iphdr, recheck_arr[i].len,
            recheck_arr[i].in, 0, recheck_arr[i].pkts, 1, pc, local_ip, iplen);
    if (i % 1000 == 0 && (pflow || netflow[0])) check_sockets();
  }
  debug(3, "Reprocess finished");
}

void add_pkt(u_char *src_mac, u_char *dst_mac, struct ip *ip_hdr,
       count_t len, int in, int vlan, count_t pkts, int flow,
       struct checktype *recheck, unsigned char *recheck_local, int recheck_len)
{
  uint32_t local=0, remote=0;
  struct checktype *pc;
  uint32_t src_ip, dst_ip;
  uint16_t dst_port = 0; /* not needed, but inhibit warning */
  count_t val;

#if 0
  uint32_t src_ip = *(uint32_t *)&(ip_hdr->ip_src);
  uint32_t dst_ip = *(uint32_t *)&(ip_hdr->ip_dst);
#else
  memcpy(&src_ip, &(ip_hdr->ip_src), sizeof(src_ip));
  memcpy(&dst_ip, &(ip_hdr->ip_dst), sizeof(dst_ip));
#endif
#ifdef WITH_PCAP
  if (allmacs)
    in = (allmacs == 1) ? 1 : 0;
#endif
  if (in != -1)
  {
    if (reverse) in ^= 1;
    remote = in ? src_ip : dst_ip;
    local  = in ? dst_ip : src_ip;
  }
#ifdef WITH_PCAP
  if (dst_mac && !allmacs)
  {
    int i;

    for (i=0; i<MAXMYMACS; i++)
    {
      if (my_mac[i] == NULL)
        /* left packet */
        return;
      if (memcmp(src_mac, my_mac[i], ETHER_ADDR_LEN)==0)
      { /* outgoing packet */
        in =     reverse ? 1 : 0;
        remote = reverse ? src_ip : dst_ip;
        local =  reverse ? dst_ip : src_ip;
        break;
      }
      else if (memcmp(dst_mac, my_mac[i], ETHER_ADDR_LEN)==0 ||
               (i==0 && memcmp(dst_mac, broadcast, ETHER_ADDR_LEN)==0))
      { /* incoming packet */
        in =     reverse ? 0 : 1;
        remote = reverse ? dst_ip : src_ip;
        local =  reverse ? src_ip : dst_ip;
        break;
      }
    }
    if (i == MAXMYMACS)
      return;
  }
#endif
  if (fsnap && !recheck)
    putsnap(flow, in, src_mac, dst_mac, src_ip, dst_ip, len, vlan, pkts);
  if (!stdinsrc || !curtime) curtime = time(NULL);
  if (verb >= 9)
    debug(9, "%s %u.%u.%u.%u->%u.%u.%u.%u: %llu bytes, %llu pkts",
          in ? "Inbound" : "Outbound",
          ((char *)&src_ip)[0], ((char *)&src_ip)[1],
          ((char *)&src_ip)[2], ((char *)&src_ip)[3],
          ((char *)&dst_ip)[0], ((char *)&dst_ip)[1],
          ((char *)&dst_ip)[2], ((char *)&dst_ip)[3],
          (unsigned long long)len, (unsigned long long)pkts);
  for (pc=checkhead; pc; pc=pc->next)
  {
    if (pc->in != in && pc->in != -1)
      goto endofloop;
    if ((local & pc->mask) != pc->ip)
      goto endofloop;
    if (pc->checkpoint == SYN || pc->checkpoint == ICMP ||
        pc->checkpoint == UDP || pc->by == BYDSTPORT)
    {
      if (ip_hdr->ip_p == IPPROTO_TCP)
      {
        struct tcphdr *th = (struct tcphdr *)(ip_hdr+1);
        if (pc->checkpoint == UDP || pc->checkpoint == ICMP)
          goto endofloop;
        dst_port = th->th_dport;
        if (pc->checkpoint == SYN) {
#ifdef TH_SYN
          int flags = th->th_flags;
          if ((flags & TH_SYN) == 0 || (flags & TH_ACK) != 0)
#else
          if (th->syn==0 || th->ack)
#endif
            goto endofloop;
        }
      } else if (pc->checkpoint == UDP && ip_hdr->ip_p == IPPROTO_UDP)
      {
        struct udphdr *uh = (struct udphdr *)(ip_hdr+1);
        dst_port = uh->uh_dport;
      } else if (pc->checkpoint != ICMP || ip_hdr->ip_p != IPPROTO_ICMP)
        goto endofloop;
    }
    if (recheck && pc != recheck)
    {
      if (verb >= 6)
        debug(6, "Matched but no action - rechecking another rule: %s %s %s %s (%u.%u.%u.%u->%u.%u.%u.%u)", cp2str(pc->checkpoint),
              pc->in ? "to" : "from", pc->ipmask, by2str(pc->by),
              ((char *)&src_ip)[0], ((char *)&src_ip)[1],
              ((char *)&src_ip)[2], ((char *)&src_ip)[3],
              ((char *)&dst_ip)[0], ((char *)&dst_ip)[1],
              ((char *)&dst_ip)[2], ((char *)&dst_ip)[3]);
    } else
    {
      if (pc->checkpoint == BPS)
        val = len;
      else if (pc->checkpoint == SYN)
        val = 1;
      else
        val = pkts;
      if (pc->by == BYNONE)
        pc->count += val;
      else {
        struct octet **po;
        unsigned char octetsarr[8], *octets;
        int i, pclen;

        octets = octetsarr;
        pclen = length(pc->by);
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
        if (recheck && memcmp(octets, recheck_local, recheck_len)) {
          if (verb >= 6)
            debug(6, "Matched but no action - recheckng another octets: %s %s %s %s (%u.%u.%u.%u->%u.%u.%u.%u)", cp2str(pc->checkpoint),
                  pc->in ? "to" : "from", pc->ipmask, by2str(pc->by),
                  ((char *)&src_ip)[0], ((char *)&src_ip)[1],
                  ((char *)&src_ip)[2], ((char *)&src_ip)[3],
                  ((char *)&dst_ip)[0], ((char *)&dst_ip)[1],
                  ((char *)&dst_ip)[2], ((char *)&dst_ip)[3]);
          break;
        }
        po = &pc->octet;
        if (verb >= 6)
          debug(6, "Matched: %s %s %s %s (%u.%u.%u.%u->%u.%u.%u.%u)", cp2str(pc->checkpoint),
                pc->in ? "to" : "from", pc->ipmask, by2str(pc->by),
                ((char *)&src_ip)[0], ((char *)&src_ip)[1],
                ((char *)&src_ip)[2], ((char *)&src_ip)[3],
                ((char *)&dst_ip)[0], ((char *)&dst_ip)[1],
                ((char *)&dst_ip)[2], ((char *)&dst_ip)[3]);
        for (i=0; ; i++)
        {
          if (*po == NULL)
          {
            if (verb >= 3)
              debug(3, "New entry %s %s %s (%s): %s", cp2str(pc->checkpoint),
                    pc->in ? "to" : "from", pc->ipmask, by2str(pc->by),
                    printoctets(octets, i+1));
            *po = calloc(256, sizeof(struct octet));
            if (*po == NULL) {
              error("Cannot allocate memory: %s", strerror(errno));
              exit(4);
            }
          }
          if (i == pclen-1) {
            addcount(po[0][octets[i]].u1.count, val);
            break;
          }
          po[0][octets[i]].u1.s1.used_time = curtime;
          if (po[0][octets[i]].u2.octet == NULL) {
            /* no detailed stats */
            count_t newcnt;
            newcnt = (count_t)(po[0][octets[i]].u1.s1.precount) + val;
            if (newcnt > 0xffffffffuL || newcnt > (count_t)pc->safelimit * check_interval) {
              /* turn on detailed stats */
              if (verb >= 2)
                debug(2, "%s %s (%s): %s (%u.%u.%u.%u->%u.%u.%u.%u), %llu %s - detailize",
                      pc->in ? "to" : "from", pc->ipmask, by2str(pc->by),
                      printoctets(octets, i+1),
                      ((char *)&src_ip)[0], ((char *)&src_ip)[1],
                      ((char *)&src_ip)[2], ((char *)&src_ip)[3],
                      ((char *)&dst_ip)[0], ((char *)&dst_ip)[1],
                      ((char *)&dst_ip)[2], ((char *)&dst_ip)[3],
                      (unsigned long long)cps(newcnt),
                      cp2str(pc->checkpoint));
              po[0][octets[i]].u2.octet = calloc(256, sizeof(struct octet));
              po[0][octets[i]].u1.s1.precount = 0xffffffffu;
              if (recheck_arr)
                reprocess(pc, octets, i+1);
            } else {
              if (verb >= 5)
                debug(5, "%s %s (%s): %s, %llu %s - ok",
                      pc->in ? "to" : "from", pc->ipmask, by2str(pc->by),
                      printoctets(octets, i+1), (unsigned long long)cps(newcnt),
                      cp2str(pc->checkpoint));
              po[0][octets[i]].u1.s1.precount = (uint32_t)newcnt;
              break;
            }
          }
          po = &po[0][octets[i]].u2.octet;
        }
      }
    }
    if (pc->last) break;
endofloop:
    if (pc == recheck) break;
  }
  if (last_check > curtime) last_check = curtime;
  if (!recheck && (recheck_arr || recheck_size == 0) && redo)
  { /* save for future recheck */
    while (len > 0 || pkts > 0)
    {
      if (recheck_size == recheck_cur)
      {
        if (curtime - last_check <= 2)
        {
          if (check_interval <= 2)
            recheck_size = recheck_size * 3 / 2;
          else
            recheck_size = recheck_size * check_interval / 2;
        } else
        {
          recheck_size = recheck_size * check_interval / (curtime - last_check);
          recheck_size = recheck_size * 5 / 4;
        }
        if (recheck_size <= recheck_cur || recheck_cur == 0)
          recheck_size = recheck_size * 5 / 4 + 64*1024;
        recheck_arr = realloc(recheck_arr, recheck_size * sizeof(*recheck_arr));
        if (recheck_arr == NULL)
        {
          warning("Cannot allocate memory for recheck: %s (%u bytes needed)",
                  strerror(errno), recheck_size * sizeof(*recheck_arr));
          break;
        }
        else
          debug(1, "recheck array reallocated to %u bytes (%u entries)",
                recheck_size * sizeof(*recheck_arr), recheck_size);
      }
      if (recheck_arr)
      {
        recheck_arr[recheck_cur].len  = (len > 0xfffffffful ? 0xfffffffful : (uint32_t)len);
        len -= recheck_arr[recheck_cur].len;
        recheck_arr[recheck_cur].pkts = (pkts > 0xfffffful ? 0xfffffful : (uint32_t)pkts);
        pkts -= recheck_arr[recheck_cur].pkts;
        recheck_arr[recheck_cur].in   = in;
        recheck_arr[recheck_cur].proto = ip_hdr->ip_p;
#if 0
        recheck_arr[recheck_cur].s_addr = *(uint32_t *)&ip_hdr->ip_src;
        recheck_arr[recheck_cur].d_addr = *(uint32_t *)&ip_hdr->ip_dst;
#else
        memcpy(&(recheck_arr[recheck_cur].s_addr), &ip_hdr->ip_src, 4);
        memcpy(&(recheck_arr[recheck_cur].d_addr), &ip_hdr->ip_dst, 4);
#endif
        if (ip_hdr->ip_p == IPPROTO_TCP)
        {
          struct tcphdr *th = (struct tcphdr *)(ip_hdr+1);
          recheck_arr[recheck_cur].d_port = th->th_dport;
#ifdef TH_SYN
          recheck_arr[recheck_cur].flags = th->th_flags;
#else
          recheck_arr[recheck_cur].flags = th->syn ? 0x02 : 0;
#endif
        } else if (ip_hdr->ip_p == IPPROTO_UDP)
          recheck_arr[recheck_cur].d_port=((struct udphdr *)(ip_hdr+1))->uh_dport;
        recheck_cur++;
      }
    }
  }
  if (curtime - last_check >= check_interval && !recheck)
    check(curtime);
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
    if (level == 0 && (pflow || netflow[0])) check_sockets();
    ip[level] = (unsigned char)i;
    if (level==len-1) {
      if (octet[i].u1.count == 0)
        emptyleafs++;
      else
        leafs++;
#ifdef DO_PERL
      perl_check(ip, cps(octet[i].u1.count), pc);
#endif
      if (octet[i].u1.count >= (unsigned long long)pc->limit * (curtime - last_check)) {
        exec_alarm(ip, cps(octet[i].u1.count), pc);
        octet[i].u2.alarmed = alarm_flaps;
      } else if (octet[i].u1.count >= (unsigned long long)pc->safelimit * (curtime - last_check)) {
        if (octet[i].u2.alarmed) {
          exec_alarm(ip, cps(octet[i].u1.count), pc);
          octet[i].u2.alarmed = alarm_flaps;
        }
        else
          debug(1, "%s %s %s is %llu - safe DoS", cp2str(pc->checkpoint),
                pc->in ? "to" : "from",
                printip(ip, 32, pc->by, pc->in), (unsigned long long)cps(octet[i].u1.count));
      } else {
        if (octet[i].u2.alarmed) {
          exec_alarm(ip, cps(octet[i].u1.count), pc);
          octet[i].u2.alarmed--;
        }
        if (octet[i].u1.count && verb >= 2)
          debug(2, "%s %s %s is %llu - ok", cp2str(pc->checkpoint),
                pc->in ? "to" : "from",
                printip(ip, 32, pc->by, pc->in), (unsigned long long)cps(octet[i].u1.count));
      }
      octet[i].u1.count = 0;
    } else if (octet[i].u2.octet) {
      nodes++;
      check_octet(pc, octet[i].u2.octet, level+1, ip, curtime);
      octet[i].u1.s1.precount = 0;
      if (curtime-octet[i].u1.s1.used_time >= expire_interval) {
        if (verb >= 3)
          debug(3, "Expire %s %s %s (%s): %s, unused time %u",
                cp2str(pc->checkpoint), pc->in ? "to" : "from", pc->ipmask,
                by2str(pc->by), printoctets(ip, level+1),
                curtime-octet[i].u1.s1.used_time);
        /* dangerous for memory leaks */
        /* but all suboctets should not has more fresh used_time */
        /* and thats because should be already expired and freed */
        /* curtime should not be increased during recursive check() function */
        free(octet[i].u2.octet);
        octet[i].u2.octet = NULL;
      }
    } else {
      /* no detailed stats */
      if (octet[i].u1.s1.precount)
        semileafs++;
      else
        emptynodes++;
      octet[i].u1.s1.precount = 0;
    }
  }
}

void check(time_t curtime)
{
  struct checktype *pc;

  if (curtime == last_check) return;
  leafs = nodes = emptyleafs = emptynodes = semileafs = 0;
  for (pc=checkhead; pc; pc=pc->next) {
    if (pc->by == BYNONE) {
#ifdef DO_PERL
      perl_check((unsigned char *)&pc->ip, cps(pc->count), pc);
#endif
      if (pc->count >= (unsigned long long)pc->limit * (curtime - last_check)) {
        exec_alarm((unsigned char *)&pc->ip, cps(pc->count), pc);
        pc->alarmed = alarm_flaps;
      } else if (pc->count >= (unsigned long long)pc->safelimit * (curtime - last_check)) {
        if (pc->alarmed) {
          exec_alarm((unsigned char *)&pc->ip, cps(pc->count), pc);
          pc->alarmed = alarm_flaps;
        }
        else
          debug(1, "%s %s %s/%u is %lu - safe DoS", cp2str(pc->checkpoint),
                pc->in ? "to" : "from",
                printoctets((unsigned char *)&pc->ip, 4), pc->preflen,
                cps(pc->count));
      } else {
        if (pc->count && verb >= 2)
          debug(2, "%s %s %s/%u is %lu - ok", cp2str(pc->checkpoint),
                pc->in ? "to" : "from",
                printoctets((unsigned char *)&pc->ip, 4), pc->preflen,
                cps(pc->count));
        if (pc->alarmed) {
          exec_alarm((unsigned char *)&pc->ip, cps(pc->count), pc);
          pc->alarmed--;
        }
      }
      pc->count = 0;
    } else if (pc->octet) {
      unsigned char c[8];
      check_octet(pc, pc->octet, 0, c, curtime);
    }
    if (pflow || netflow[0]) check_sockets();
  }
  debug(1, "Leafs: %u, nodes: %u, empty leafs: %u, empty nodes: %u, not detailed leafs: %u", leafs, nodes, emptyleafs, emptynodes, semileafs);
  debug(1, "Memory usage: %uM", ((leafs+emptyleafs+semileafs)*sizeof(struct octet)+(nodes+emptynodes)*sizeof(struct octet))/(1024*1024ul));
  do_alarms();
  last_check = curtime;
  if (recheck_arr)
    debug(3, "check done, %u entries saved for recheck", recheck_cur);
  recheck_cur = 0;
}

