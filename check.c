#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/param.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
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

void add_pkt(u_char *src_mac, u_char *dst_mac, u_long src_ip, u_long dst_ip,
             u_long len, int in)
{
  u_long local=0, remote=0;
  time_t curtime;
  struct checktype *pc;

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
    if (pc->octet == NULL)
    {
      if (pc->pps)
        pc->count++;
      else
        pc->count += len;
    } else {
      struct octet *po;
      unsigned char *octets = (unsigned char *)&local;
      po = &pc->octet[octets[0]];
      po->data.used_time = curtime;
      if (po->octet == NULL) {
        po->octet = calloc(256, sizeof(struct octet));
        debug("New entry %u\n", octets[0]);
      }
      po = &po->octet[octets[1]];
      po->data.used_time = curtime;
      if (po->octet == NULL) {
        po->octet = calloc(256, sizeof(struct octet));
        debug("New entry %u.%u\n", octets[0], octets[1]);
      }
      po = &po->octet[octets[2]];
      po->data.used_time = curtime;
      if (po->octet == NULL) {
        po->octet = calloc(256, sizeof(struct octet));
        debug("New entry %u.%u.%u\n", octets[0], octets[1], octets[2]);
      }
      po = &po->octet[octets[3]];
      if (pc->pps)
        po->data.count++;
      else
        po->data.count += len;
    }
    if (pc->last) break;
  }
  if (curtime - last_check >= check_interval)
    check();
}

void check_octet(struct checktype *pc, struct octet *octet, int level,
                 unsigned char *ip, time_t curtime)
{
  int i;

  for (i=0; i<256; i++)
  {
    ip[level] = (unsigned char)i;
    if (level==3) {
      if (octet[i].data.count >= (unsigned long long)pc->limit * (curtime - last_check)) {
        exec_alarm(*(u_long *)ip, 32, octet[i].data.count * (pc->pps ? 1 : 8) / (curtime - last_check), pc->pps, 1);
        debug("%s for %s/%u is %lu - DoS\n", pc->pps ? "pps" : "bps",
              inet_ntoa(*(struct in_addr *)ip), 32,
              octet[i].data.count * (pc->pps ? 1 : 8) / (curtime - last_check));
      } else if (octet[i].data.count >= (unsigned long long)pc->safelimit * (curtime - last_check)) {
        exec_alarm(*(u_long *)ip, 32, octet[i].data.count * (pc->pps ? 1 : 8) / (curtime - last_check), pc->pps, 0);
        debug("%s for %s/%u is %lu - safe DoS\n", pc->pps ? "pps" : "bps",
              inet_ntoa(*(struct in_addr *)ip), 32,
              octet[i].data.count * (pc->pps ? 1 : 8) / (curtime - last_check));
      } else if (octet[i].data.count)
        debug("%s for %s/%u is %lu - ok\n", pc->pps ? "pps" : "bps",
              inet_ntoa(*(struct in_addr *)ip), 32,
              octet[i].data.count * (pc->pps ? 1 : 8) / (curtime - last_check));
      octet[i].data.count = 0;
    } else {
      if (octet[i].octet) {
        check_octet(pc, octet[i].octet, level+1, ip, curtime);
        if (curtime-octet[i].data.used_time >= expire_interval) {
          if (level==0)
            debug("Expire entry %u, unused for %u seconds\n",
                  i, curtime-octet[i].data.used_time);
          else if (level==1) 
            debug("Expire entry %u.%u, unused for %u seconds\n",
                  ip[0], i, curtime-octet[i].data.used_time);
          else if (level==2) 
            debug("Expire entry %u.%u.%u, unused for %u seconds\n",
                  ip[0], ip[1], i, curtime-octet[i].data.used_time);
          free(octet[i].octet);
          octet[i].octet = NULL;
        }
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
    if (pc->octet == NULL) {
      if (pc->count >= (unsigned long long)pc->limit * (curtime - last_check)) {
        exec_alarm(pc->ip, pc->preflen, pc->count * (pc->pps ? 1 : 8) / (curtime - last_check), pc->pps, 1);
        debug("%s for %s/%u is %lu - DoS\n", pc->pps ? "pps" : "bps",
              inet_ntoa(*(struct in_addr *)&pc->ip), pc->preflen,
              pc->count * (pc->pps ? 1 : 8) / (curtime - last_check));
      } else if (pc->count >= (unsigned long long)pc->safelimit * (curtime - last_check)) {
        exec_alarm(pc->ip, pc->preflen, pc->count * (pc->pps ? 1 : 8) / (curtime - last_check), pc->pps, 0);
        debug("%s for %s/%u is %lu - safe DoS\n", pc->pps ? "pps" : "bps",
              inet_ntoa(*(struct in_addr *)&pc->ip), pc->preflen,
              pc->count * (pc->pps ? 1 : 8) / (curtime - last_check));
      } else if (pc->count)
        debug("%s for %s/%u is %lu - ok\n", pc->pps ? "pps" : "bps",
              inet_ntoa(*(struct in_addr *)&pc->ip), pc->preflen,
              pc->count * (pc->pps ? 1 : 8) / (curtime - last_check));
      pc->count = 0;
    } else {
      u_long l=0;
      check_octet(pc, pc->octet, 0, (unsigned char *)&l, curtime);
    }
  }
  clear_alarm();
  last_check = curtime;
}

