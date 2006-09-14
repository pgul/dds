#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/param.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
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

#define cps(count) (unsigned long)((unsigned long long)(count) * (pc->checkpoint == BPS ? 8 : 1) / ((curtime > last_check) ? (curtime - last_check) : 1))
#define addcount(count, p)	(((count) + (p) >= (count)) ? ((count) += (p)) : (count_t)-1)

u_char *my_mac[MAXMYMACS];
static u_char broadcast[ETHER_ADDR_LEN]={0xff,0xff,0xff,0xff,0xff,0xff};
extern long snap_traf;
extern FILE *fsnap;
struct recheck_t *recheck_arr;
int recheck_cur, recheck_size;

static void putsnap(int flow, int in, u_char *src_mac, u_char *dst_mac, 
                    u_long src_ip, u_long dst_ip, int len, int vlan, int pkts)
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

static void reprocess(struct checktype *pc, u_long local_ip)
{
  int i;
  char pktbuf[sizeof(struct ip)+max(sizeof(struct tcphdr),sizeof(struct udphdr))];
  struct ip *iphdr = (struct ip *)pktbuf;

  if (!recheck_arr) return;
  debug(2, "Reprocess saved queue (%u entries)", recheck_cur);
  debug(1, "Detailize %s %s %s", cp2str(pc->checkpoint),
        pc->in ? "to" : "from", inet_ntoa(*(struct in_addr *)(void *)&local_ip));
  for (i=0; i<recheck_cur; i++)
  {
    make_iphdr(iphdr, recheck_arr[i].s_addr, recheck_arr[i].d_addr,
             recheck_arr[i].proto, recheck_arr[i].d_port, recheck_arr[i].flags);
    add_pkt(NULL, NULL, iphdr, recheck_arr[i].len,
            recheck_arr[i].in, 0, recheck_arr[i].pkts, 1, pc, local_ip);
  }
  debug(3, "Reprocess finished");
}

void add_pkt(u_char *src_mac, u_char *dst_mac, struct ip *ip_hdr,
             u_long len, int in, int vlan, int pkts, int flow,
             struct checktype *recheck, u_long recheck_local)
{
  u_long local=0, remote=0;
  time_t curtime;
  struct checktype *pc;
  u_long src_ip = *(u_long *)&(ip_hdr->ip_src);
  u_long dst_ip = *(u_long *)&(ip_hdr->ip_dst);
  u_short dst_port;

  if (allmacs)
    in = (allmacs == 1) ? 1 : 0;
  if (in != -1)
  {
    if (reverse) in ^= 1;
    remote = in ? src_ip : dst_ip;
    local  = in ? dst_ip : src_ip;
  }
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
  if (recheck && local != recheck_local) return;
  if (fsnap && !recheck)
    putsnap(flow, in, src_mac, dst_mac, src_ip, dst_ip, len, vlan, pkts);
  curtime = time(NULL);
  if (!recheck && (recheck_arr || recheck_size == 0) && redo)
  { /* save for future recheck */
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
        warning("Cannot allocate memory for recheck: %s (%u bytes needed)",
                strerror(errno), recheck_size * sizeof(*recheck_arr));
      else
        debug(1, "recheck array reallocated to %u bytes (%u entries)",
              recheck_size * sizeof(*recheck_arr), recheck_size);
    }
    if (recheck_arr)
    {
      recheck_arr[recheck_cur].len  = len;
      recheck_arr[recheck_cur].pkts = pkts;
      recheck_arr[recheck_cur].in   = in;
      recheck_arr[recheck_cur].proto = ip_hdr->ip_p;
      recheck_arr[recheck_cur].s_addr = *(u_long *)&ip_hdr->ip_src;
      recheck_arr[recheck_cur].d_addr = *(u_long *)&ip_hdr->ip_dst;
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
  for (pc=checkhead; pc; pc=pc->next)
  {
    if (pc->in != in && pc->in != -1)
      continue;
    if (recheck && pc != recheck)
      continue;
    if ((local & pc->mask) != pc->ip)
      continue;
    if (pc->checkpoint == SYN || pc->checkpoint == ICMP ||
        pc->checkpoint == UDP || pc->by == BYDSTPORT)
    {
      if (ip_hdr->ip_p == IPPROTO_TCP)
      {
        struct tcphdr *th = (struct tcphdr *)(ip_hdr+1);
        if (pc->checkpoint == UDP || pc->checkpoint == ICMP) continue;
        dst_port = th->th_dport;
        if (pc->checkpoint == SYN) {
#ifdef TH_SYN
          int flags = th->th_flags;
          if ((flags & TH_SYN) == 0 || (flags & TH_ACK) != 0)
#else
          if (th->syn==0 || th->ack)
#endif
            continue;
        } else if (pc->checkpoint == UDP || pc->checkpoint == ICMP)
          continue;
      } else if (pc->checkpoint == UDP && ip_hdr->ip_p == IPPROTO_UDP)
      {
        struct udphdr *uh = (struct udphdr *)(ip_hdr+1);
        dst_port = uh->uh_dport;
      } else if (pc->checkpoint != ICMP || ip_hdr->ip_p != IPPROTO_ICMP)
        continue;
    }

    if (pc->by == BYNONE)
    {
      if (pc->checkpoint == BPS)
        pc->count += len;
      else if (pc->checkpoint == SYN)
        pc->count += 1;
      else
        pc->count += pkts;
    } else {
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
      po = &pc->octet;
      for (i=0; i<pclen; i++)
      {
        if (*po == NULL)
        {
          if (verb >= 3)
          {
            debug(9, "%s packet %u.%u.%u.%u->%u.%u.%u.%u",
                  in ? "Inbound" : "Outbound",
                  ((char *)&src_ip)[0], ((char *)&src_ip)[1],
                  ((char *)&src_ip)[2], ((char *)&src_ip)[3],
                  ((char *)&dst_ip)[0], ((char *)&dst_ip)[1],
                  ((char *)&dst_ip)[2], ((char *)&dst_ip)[3]);
            debug(3, "New entry %s %s %s", pc->in ? "from" : "to",
                  printoctets(octets, i+1), cp2str(pc->checkpoint));
          }
          *po = calloc(256, sizeof(struct octet));
          if (*po == NULL) {
            logwrite("Cannot allocate memory: %s", strerror(errno));
            fprintf(stderr, "Cannot allocate memory\n");
            exit(4);
          }
        }
        if (i == pclen-1) break;
        if (po[0][octets[i]].octet == NULL && i == 3) break; /* turn on detailed stats later */
        po[0][octets[i]].used_time = curtime;
        po = &po[0][octets[i]].octet;
      }
      if (pc->checkpoint == BPS)
        addcount(po[0][octets[i]].count, len);
      else if (pc->checkpoint == SYN)
        addcount(po[0][octets[i]].count, 1);
      else
        addcount(po[0][octets[i]].count, pkts);
    }
    if (pc->last) break;
  }
  if (curtime - last_check >= check_interval && !recheck)
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
#ifdef DO_PERL
      perl_check(ip, cps(octet[i].count), pc);
#endif
      if (octet[i].count == (count_t)-1) {
         warning("Counter for %s limited (rebuild with --with-huge-counters?)",
                 printip(ip, 32, pc->by, pc->in));
      }
      if (octet[i].count >= (unsigned long long)pc->limit * (curtime - last_check)) {
        exec_alarm(ip, cps(octet[i].count), pc);
        octet[i].alarmed = alarm_flaps;
      } else if (octet[i].count >= (unsigned long long)pc->safelimit * (curtime - last_check)) {
        if (octet[i].alarmed) {
          exec_alarm(ip, cps(octet[i].count), pc);
          octet[i].alarmed = alarm_flaps;
        }
        else
          debug(1, "%s for %s is %lu - safe DoS", cp2str(pc->checkpoint),
                printip(ip, 32, pc->by, pc->in), cps(octet[i].count));
      } else {
        if (octet[i].alarmed) {
          exec_alarm(ip, cps(octet[i].count), pc);
          octet[i].alarmed--;
        }
        if (octet[i].count)
          debug(2, "%s for %s is %lu - ok", cp2str(pc->checkpoint),
                printip(ip, 32, pc->by, pc->in), cps(octet[i].count));
      }
      octet[i].count = 0;
    } else if (octet[i].octet) {
have_detailed:
      check_octet(pc, octet[i].octet, level+1, ip, curtime);
      if (curtime-octet[i].used_time >= expire_interval) {
        if (verb >= 3)
          debug(3, "Expire %s %s %s, unused time %u",
                printoctets(ip, level+1),
                pc->in ? "from" : "to", cp2str(pc->checkpoint),
                curtime-octet[i].used_time);
        /* dangerous for memory leaks */
        /* but all suboctets should not has more fresh used_time */
        /* and thats because should be already expired and freed */
        /* curtime should not be increased during recursive check() function */
        free(octet[i].octet);
        octet[i].octet = NULL;
      }
    } else if (level==3) {
      if (octet[i].count >= (unsigned long long)pc->limit * (curtime - last_check) || octet[i].count == (count_t)-1) {
        debug(1, "%s for %s is %lu - DoS, turning detailed stats on",
              cp2str(pc->checkpoint), printip(ip, 32, BYSRC, pc->in),
              cps(octet[i].count));
        octet[i].used_time = curtime - expire_interval; /* remove on next check if no traffic */
        if ((octet[i].octet = calloc(256, sizeof(struct octet))) == NULL) {
          logwrite("Cannot allocate memory: %s", strerror(errno));
          fprintf(stderr, "Cannot allocate memory\n");
          exit(4);
        }
        if (recheck_arr) {
          reprocess(pc, *(u_long *)ip);
          goto have_detailed;
        }
      } else if (octet[i].count) {
        debug(2, "%s for %s is %lu - ok (no detailed stats)",
              cp2str(pc->checkpoint), printip(ip, 32, BYSRC, pc->in),
              cps(octet[i].count));
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
          debug(1, "%s for %s/%u is %lu - safe DoS", cp2str(pc->checkpoint),
                inet_ntoa(*(struct in_addr *)&pc->ip), pc->preflen,
                cps(pc->count));
      } else {
        if (pc->count)
          debug(2, "%s for %s/%u is %lu - ok", cp2str(pc->checkpoint),
                inet_ntoa(*(struct in_addr *)&pc->ip), pc->preflen,
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
  }
  run_alarms();
  last_check = curtime;
  if (recheck_arr)
    debug(3, "check done, %u entries saved for recheck", recheck_cur);
  recheck_cur = 0;
}

