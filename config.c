#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <signal.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <pwd.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
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

struct checktype *checkhead=NULL;
char iface[32]=IFACE;
char logname[256], snapfile[256]=SNAPFILE, pidfile[256]=PIDFILE;
int  check_interval, expire_interval, redo, inhibit, alarm_flaps;
char alarmcmd[CMDLEN], noalarmcmd[CMDLEN], contalarmcmd[CMDLEN];
char netflow[256], *pflow;
char *uids;
uid_t uid;
gid_t gid;
struct router_t *routers;
static struct router_t *cur_router, *old_routers;
static struct checktype *checktail;
#ifdef DO_PERL
static char perlfile[256];
static time_t perl_mtime;
#endif
int servsock = -1;
unsigned short servport;
#ifdef WITH_PCAP
int servpid, my_pid, servpipe[2], allmacs;
#endif

#ifdef DO_SNMP
static unsigned short get_ifindex(struct router_t*, enum ifoid_t, char **s);
static int snmp_time_out;
#endif

static void freerouter(struct router_t *router)
{
#ifdef DO_SNMP
  int i;
  for (i=0; i<NUM_OIDS; i++)
    if (router->data[i])
    { free(router->data[i]);
      router->data[i] = NULL;
      router->nifaces[i] = 0;
    }
#endif
}

static void read_ip(char *p, uint32_t *ip, uint32_t *mask, int *pref_len)
{ char c, *p1;

  for (p1=p; *p1 && (isdigit(*p1) || *p1=='.'); p1++);
  c=*p1;
  *p1='\0';
  *ip = inet_addr(p);
  *pref_len = 32;
  *mask = 0xfffffffful;
  if (c=='/')
  { *pref_len = atoi(p1+1);
    if (*pref_len == 0)
      *mask = 0;
    else {
      (*mask)<<=(32-*pref_len);
      (*mask)=htonl(*mask);
    }
  }
  *p1=c; p=p1;
  if ((*ip & *mask) != *ip)
  { uint32_t masked = (*ip & *mask);
    warning("%u.%u.%u.%u inconsistent with /%d (mask %u.%u.%u.%u)!",
           ((char *)ip)[0], ((char *)ip)[1],
           ((char *)ip)[2], ((char *)ip)[3],
           atoi(p+1),
           ((char *)mask)[0], ((char *)mask)[1],
           ((char *)mask)[2], ((char *)mask)[3]);
    warning("ip & mask is %u.%u.%u.%u",
           ((char *)&masked)[0], ((char *)&masked)[1],
           ((char *)&masked)[2], ((char *)&masked)[3]);
  }
}

static u_long readlimit(char *p, int bps2cps)
{
   unsigned long long limit;
   char *endp;

#ifdef HAVE_STRTOULL
   limit = strtoull(p, &endp, 10);
#else
   limit = strtoul(p, &endp, 10);
#endif
   if (tolower(*endp) == 'k')
   {
     limit *= (bps2cps ? 1000/8 : 1000);
     endp++;
   } else if (tolower(*endp) == 'm')
   {
     limit *= (bps2cps ? 1000000/8 : 1000000);
     endp++;
   } else if (tolower(*endp) == 'g')
   {
     limit *= (bps2cps ? 1000000000/8 : 1000000000);
     endp++;
   } else if (bps2cps)
     limit /= 8;
   if (*endp && !isspace(*endp))
     limit = 0;
#ifndef ULONG_MAX
  #define ULONG_MAX 0xfffffffful
#endif
   if (limit > ULONG_MAX)
   { warning("limit more then max unsigned long, set to ulong_max");
     limit = ULONG_MAX;
   }
   return (u_long) limit;
}

static int parse_line(char *str, char *fname, int nline)
{
  char *p;
  struct checktype *pc;

  p=strchr(str, '\n');
  if (p) *p='\0';
  p=strchr(str, '#');
  if (p) *p='\0';
  for (p=str; isspace(*p); p++);
  if (*p=='\0') return 0;
  if (p!=str) strcpy(str, p);
  if (str[0]=='\0') return 0;
  for (p=str+strlen(str)-1; isspace(*p); *p--='\0');
  p=str;
#ifdef WITH_PCAP
  if (strncmp(p, "mymac=", 6)==0)
  {
    if (strncmp(p+6, "all-in", 6) == 0)
      allmacs=2;
    else if (strncmp(p+6, "all-out", 7) == 0)
      allmacs=1;
    else
    { 
      short int m[3];
      int i;

      sscanf(p+6, "%04hx.%04hx.%04hx", m, m+1, m+2);
      m[0] = htons(m[0]);
      m[1] = htons(m[1]);
      m[2] = htons(m[2]);
      for (i=0; i<MAXMYMACS; i++)
        if (my_mac[i] == NULL) break;
      if (i == MAXMYMACS)
        warning("Too many mymacs (%d max), extra ignored", MAXMYMACS);
      else
      {
        my_mac[i] = malloc(ETHER_ADDR_LEN);
        memcpy(my_mac[i], m, ETHER_ADDR_LEN);
        if (i < MAXMYMACS-1) my_mac[i+1] = NULL;
      }
    }
    return 0;
  }
  if (strncmp(p, "iface=", 6)==0)
  { strncpy(iface, p+6, sizeof(iface)-1);
    return 0;
  }
#endif
  if (strncmp(p, "netflow=", 8)==0)
  { strncpy(netflow, p+8, sizeof(netflow)-1);
    return 0;
  }
  if (strncmp(p, "router=", 7)==0)
  { struct hostent *he;

    cur_router->next = calloc(1, sizeof(struct router_t));
    cur_router = cur_router->next;
    p+=7;
#ifdef DO_SNMP
    { char *p1;
      if ((p1=strchr(p, '@'))!=NULL)
      { *p1++='\0';
        strncpy(cur_router->community, p, sizeof(cur_router->community)-1);
        p=p1;
      } else
        strcpy(cur_router->community, "public");
    }
#endif
    /* get router address */
    if ((he=gethostbyname(p))==0 || he->h_addr_list[0]==NULL)
    { if (strcmp(p, "any")==0)
        cur_router->addr=(u_long)-1;
      else
        warning("Router %s not found (%s:%d)", p, fname, nline);
      return 0;
    }
    /* use only first address */
    memcpy(&cur_router->addr, he->h_addr_list[0], he->h_length);
    cur_router->sampled=1;
    return 0;
  }
  if (strncmp(p, "uplink-ifindex=", 15)==0)
  { if (cur_router->nuplinks == MAXUPLINKS)
      warning("Too many uplink interfaces (%d max), extra ignored", MAXUPLINKS);
    else
      cur_router->uplinks[cur_router->nuplinks++] = atoi(p+15);
    return 0;
  }
  if (strncmp(p, "myas-ifindex=", 13)==0)
  { if (cur_router->nmyas == MAXMYAS)
      warning("Too many myas interfaces (%d max), extra ignored", MAXMYAS);
    else
      cur_router->myas[cur_router->nmyas++] = atoi(p+13);
    return 0;
  }

#ifdef DO_SNMP
  if (strncmp(p, "snmp-timeout=", 13)==0)
  { snmp_time_out = atoi(p+13);
    return 0;
  }
  { int oid = -1;
    if (strncmp(p, "uplink-ifname=", 14)==0)
      oid = IFNAME;
    else if (strncmp(p, "uplink-ifdescr=", 15)==0)
      oid = IFDESCR;
    else if (strncmp(p, "uplink-ifalias=", 15)==0)
      oid = IFALIAS;
    else if (strncmp(p, "uplink-ifip=", 12)==0)
      oid = IFIP;
    if (oid != -1)
    { if (cur_router->nuplinks == MAXUPLINKS)
        warning("Too many uplink interfaces (%d max), extra ignored", MAXUPLINKS);
      else
        cur_router->uplinks[cur_router->nuplinks++] = get_ifindex(cur_router, oid, &p);
      return 0;
    }
  }
  { int oid = -1;
    if (strncmp(p, "myas-ifname=", 12)==0)
      oid = IFNAME;
    else if (strncmp(p, "myas-ifdescr=", 13)==0)
      oid = IFDESCR;
    else if (strncmp(p, "myas-ifalias=", 13)==0)
      oid = IFALIAS;
    else if (strncmp(p, "myas-ifip=", 10)==0)
      oid = IFIP;
    if (oid != -1)
    { if (cur_router->nmyas == MAXMYAS)
        warning("Too many myas interfaces (%d max), extra ignored", MAXMYAS);
      else
        cur_router->myas[cur_router->nmyas++] = get_ifindex(cur_router, oid, &p);
      return 0;
    }
  }

#endif
  if (strncmp(p, "log=", 4)==0)
  { /* reopen log immediately, report below config error to the log */
    if (strcmp(logname, p+4))
    { if (strcmp(logname, "syslog") == 0)
        closelog();
      strncpy(logname, p+4, sizeof(logname)-1);
      if (strcmp(logname, "syslog") == 0)
        openlog("dds", LOG_PID, LOG_DAEMON);
    }
    return 0;
  }
  if (strncmp(p, "snap=", 5)==0)
  { strncpy(snapfile, p+5, sizeof(snapfile)-1);
    return 0;
  }
  if (strncmp(p, "pid=", 4)==0)
  { strncpy(pidfile, p+4, sizeof(pidfile)-1);
    return 0;
  }
  if (strncmp(p, "interval=", 9)==0)
  { check_interval = atoi(p+9);
    if (check_interval == 0) check_interval=CHECK_INTERVAL;
    return 0;
  }
  if (strncmp(p, "noalarm-intervals=", 18)==0)
  { alarm_flaps = atoi(p+18);
    if (alarm_flaps == 0) alarm_flaps = 1;
    return 0;
  }
  if (strncmp(p, "expire=", 7)==0)
  { expire_interval = atoi(p+7);
    if (expire_interval == 0) expire_interval=EXPIRE_INTERVAL;
    return 0;
  }
  if (strncmp(p, "serv-port=", 10)==0)
  { servport = atoi(p+10);
    return 0;
  }
  if (strncmp(p, "sampled=", 8)==0)
  { cur_router->sampled = atoi(p+8);
    if (cur_router->sampled == 0) cur_router->sampled=1;
    return 0;
  }
  if (strncmp(p, "user=", 5)==0)
  { struct passwd *pw = getpwnam(p+5);
    if (pw)
    { uid = pw->pw_uid;
      gid = pw->pw_gid;
      if (uids) free(uids);
      uids = strdup(p+5);
    }
    else
      warning("User %s unknown", p+5);
    return 0;
  }
  if (strncmp(p, "alarm=", 6)==0)
  {
    p+=6;
    if (*p == '\"' && p[1]) {
      strncpy(alarmcmd, p+1, sizeof(alarmcmd)-1);
      p=alarmcmd+strlen(alarmcmd)-1;
      if (*p == '\"') *p='\0';
    } else
      strncpy(alarmcmd, p, sizeof(alarmcmd)-1);
    return 0;
  }
  if (strncmp(p, "noalarm=", 8)==0)
  {
    p+=8;
    if (*p == '\"' && p[1]) {
      strncpy(noalarmcmd, p+1, sizeof(noalarmcmd)-1);
      p=noalarmcmd+strlen(noalarmcmd)-1;
      if (*p == '\"') *p='\0';
    } else
      strncpy(noalarmcmd, p, sizeof(noalarmcmd)-1);
    return 0;
  }
  if (strncmp(p, "contalarm=", 10)==0)
  {
    p+=10;
    if (*p == '\"' && p[1]) {
      strncpy(contalarmcmd, p+1, sizeof(contalarmcmd)-1);
      p=contalarmcmd+strlen(contalarmcmd)-1;
      if (*p == '\"') *p='\0';
    } else
      strncpy(contalarmcmd, p, sizeof(contalarmcmd)-1);
    return 0;
  }
  if (strncmp(p, "recheck=", 8)==0)
  {
    p+=8;
    if (*p == 'y' || *p == 'Y')
      redo=1;
    else if (*p == 'n' || *p == 'N')
      redo=0;
    else
      warning("Unknown recheck value ignored (%s:%d): %s", fname, nline, p);
    return 0;
  }
  if (strncmp(p, "inhibit=", 8)==0)
  {
    p+=8;
    if (*p == 'y' || *p == 'Y')
      inhibit=1;
    else if (*p == 'n' || *p == 'N')
      inhibit=0;
    else
      warning("Unknown inhibit value ignored (%s:%d): %s", fname, nline, p);
    return 0;
  }
#ifdef DO_PERL
  if (strncmp(p, "perlfile=", 9)==0)
  {
    strncpy(perlfile, p+9, sizeof(perlfile)-1);
    return 0;
  }
#endif

  for (p=str; *p && !isspace(*p); p++);
  if (*p) *p++='\0';
  if (strchr(str, '=')) return 0; /* keyword */
  /* it's alarm rule */
  if (strcmp(str, "check") != 0)
  {
    warning("Unknown keyword %s in config ignored (%s:%d)", str, fname, nline);
    return 0;
  }
  /* create structure */
  pc = calloc(1, sizeof(*pc));
  while (*p && isspace(*p)) p++;
  if (!*p)
  {
incorr:
    warning("Incorrect check line %d in config file %s ignored", nline, fname);
    free(pc);
    return 0;
  }
  if (strncmp(p, "pps", 3)==0)
    pc->checkpoint = PPS;
  else if (strncmp(p, "bps", 3)==0)
    pc->checkpoint = BPS;
  else if (strncmp(p, "syn", 3)==0)
    pc->checkpoint = SYN;
  else if (strncmp(p, "udp", 3)==0)
    pc->checkpoint = UDP;
  else if (strncmp(p, "icmp", 4)==0)
    pc->checkpoint = ICMP;
  else
    goto incorr;
  while (*p && !isspace(*p)) p++;
  while (*p && isspace(*p)) p++;
  if (strncmp(p, "in", 2) == 0)
    pc->in = 1;
  else if (strncmp(p, "out", 3) == 0)
    pc->in = 0;
  else goto incorr;
  while (*p && !isspace(*p)) p++;
  while (*p && isspace(*p)) p++;
  read_ip(p, &pc->ip, &pc->mask, &pc->preflen);
  sprintf(pc->ipmask, "%s/%u", printoctets((unsigned char *)&pc->ip, 4), pc->preflen);
  while (*p && !isspace(*p)) p++;
  while (*p && isspace(*p)) p++;
  pc->limit = readlimit(p, pc->checkpoint == BPS);
  if (pc->limit == 0) goto incorr;
  while (*p && !isspace(*p)) p++;
  while (*p && isspace(*p)) p++;
  pc->safelimit = readlimit(p, pc->checkpoint == BPS);
  if (pc->safelimit == 0) goto incorr;
  if (pc->safelimit > pc->limit)
  {
    warning("safelimit %lu is more then hardlimit %lu (%s:%d)", pc->safelimit, pc->limit, fname, nline);
    pc->safelimit = pc->limit;
  }
  for (;;)
  {
    while (*p && !isspace(*p)) p++;
    while (*p && isspace(*p)) p++;
    if (*p == '\0') break;
    if (strncmp(p, "bysrcdst", 8) == 0)
      pc->by = BYSRCDST;
    else if (strncmp(p, "bydstport", 8) == 0)
    {
      pc->by = BYDSTPORT;
      if (pc->checkpoint == ICMP) {
        warning("bydstport selector is senseless for icmp traffic");
        pc->by = BYNONE;
      }
    }
    else if (strncmp(p, "bysrc", 5) == 0)
      pc->by = BYSRC;
    else if (strncmp(p, "bydst", 5) == 0)
      pc->by = BYDST;
    else if (strncmp(p, "break", 5) == 0)
      pc->last = 1;
  }
  strcpy(pc->alarmcmd, alarmcmd);
  strcpy(pc->noalarmcmd, noalarmcmd);
  strcpy(pc->contalarmcmd, contalarmcmd);
  if (checkhead == NULL)
    checkhead = checktail = pc;
  else
  {
    checktail->next = pc;
    checktail = pc;
  }
  return 0;
}

static int parse_file(FILE *f, char *fname)
{
  FILE *finc;
  char str[256];
  char *p, *p1;
  int nline;

  alarmcmd[0] = noalarmcmd[0] = contalarmcmd[0] = '\0';
  nline = 0;
  p = uids;
  uids = NULL;
  if (p) free(p);
  while (fgets(str, sizeof(str), f))
  {
    nline++;
    if (strncasecmp(str, "@include", 8) == 0 && isspace(str[8]))
    {
      for (p=str+9; *p && isspace(*p); p++);
      if (*p=='\"')
      {
        p++;
        p1=strchr(p, '\"');
        if (p1==NULL)
        {
          warning("Unmatched quotes in include, ignored: %s", str);
          continue;
        }
        *p1='\0';
      } else
      { for (p1=p; *p1 && !isspace(*p1); p1++);
        *p1='\0';
      }
      if ((finc=fopen(p, "r")) == NULL)
      {
        warning("Can't open %s: %s, include ignored", p, strerror(errno));
        continue;
      }
      parse_file(finc, p);
      fclose(finc);
      continue;
    }
    parse_line(str, fname, nline);
  } 
  return 0;
}

static void freeoctet(struct octet *po, int level, int levels)
{
  int i;

  if (level < levels)
    for (i=0; i<256; i++)
      if (po[i].u2.octet)
        freeoctet(po[i].u2.octet, level+1, levels);
  free(po);
}

static void freecheck(struct checktype *pc)
{
  if (pc->octet)
    freeoctet(pc->octet, 1, length(pc->by));
  free(pc);
}

int bindserv(void)
{
  /* bind servsock to servport */
  struct sockaddr_in serv_addr;
  int opt;

  servsock = socket(PF_INET, SOCK_STREAM, 0);
  if (servsock == -1)
  {
    error("Can't create socket: %s", strerror(errno));
    return -1;
  }
  opt = 1;
  if (setsockopt (servsock, SOL_SOCKET, SO_REUSEADDR, (char *) &opt, sizeof opt))
    warning("Can't servsock SO_REUSEADDR: %s", strerror(errno));
  if (fcntl (servsock, F_SETFD, FD_CLOEXEC))
    warning("Can't fcntl D_SETFD FD_CLOEXEC: %s", strerror(errno));
  memset(&serv_addr, 0, sizeof serv_addr);
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = htonl (INADDR_ANY);
  serv_addr.sin_port = htons(servport);
  if (bind(servsock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0)
  {
    error("Can't bind server socket: %s", strerror(errno));
    close(servsock);
    servsock = -1;
    return -1;
  }
  listen(servsock, 5);
  debug(1, "Listen service port %d", servport);
  return 0;
}

int config(char *name)
{
  FILE *f;
  char *old_netflow = NULL;
#ifdef DO_PERL
  char *old_perlfile = NULL;
  time_t old_mtime = 0;
#endif

  f = fopen(name, "r");
  if (f==NULL)
  { error("Can't open %s: %s!", name, strerror(errno));
    return -1;
  }
  /* free check list */
  for (checktail=checkhead; checktail;)
  {
    checktail = checktail->next;
    freecheck(checkhead);
    checkhead = checktail;
  }
#ifdef WITH_PCAP
  { int i;
    for (i=0; i<MAXMYMACS; i++)
    {
      if (my_mac[i] == NULL) break;
      free(my_mac[i]);
      my_mac[i] = NULL;
    }
    allmacs = 0;
  }
#endif
  old_routers = routers;
  cur_router = routers = calloc(1, sizeof(struct router_t));
  cur_router->addr = (u_long)-1;
  cur_router->sampled = 1;
  if (!pflow) old_netflow = strdup(netflow);
  netflow[0] = '\0';
#ifdef DO_PERL
  if (perlfile[0]) old_perlfile = strdup(perlfile);
  perlfile[0] = '\0';
#endif
  redo = 1;
  inhibit = 1;
  alarm_flaps = 1;
  check_interval=CHECK_INTERVAL;
  expire_interval=EXPIRE_INTERVAL;
  if (recheck_arr)
    free(recheck_arr);
  recheck_arr = NULL;
  recheck_size = recheck_cur = 0;
  if (servsock != -1)
  {
    debug(2, "server socket closed");
    close(servsock);
    servsock = -1;
  }
#ifdef WITH_PCAP
  if (servpid)
  {
    close(servpipe[1]);
    servpipe[1] = -1;
    kill(servpid, SIGTERM);
    waitpid(servpid, NULL, 0);
    servpid = 0;
  }
#endif
  servport = 0;

  parse_file(f, name);

  fclose(f);
  for (cur_router=old_routers; cur_router;)
  { freerouter(cur_router);
    old_routers = cur_router;
    cur_router = cur_router->next;
    free(old_routers);
  }
  if (logname[0] == '\0')
    strncpy(logname, LOGNAME, sizeof(logname)-1);
  if (!pflow && !stdinsrc)
  {
    if (strcmp(netflow, old_netflow))
    {
      /* restart netflow listen process */
      /* ... */
      if (bindport(netflow) == -1)
        return -1;
    }
    free(old_netflow);
  }
  if (servport && (pflow || netflow[0]))
    if (bindserv())
      return -1;
#ifdef DO_PERL
  if (perlfile[0])
  {
    struct stat st;
    old_mtime = perl_mtime;
    if (stat(perlfile, &st) == 0)
      perl_mtime = st.st_mtime;
    else
    {
      error("Cannot stat perlfile %s: %s", perlfile, strerror(errno));
      perlfile[0] = '\0';
    }
  }
  if (old_perlfile && (strcmp(perlfile, old_perlfile) || perl_mtime != old_mtime))
  {
    perl_done();
    free(old_perlfile);
    old_perlfile = NULL;
  }
  if (perlfile[0] && old_perlfile == NULL)
    perl_init(perlfile);
  if (old_perlfile) free(old_perlfile);
#endif
  return 0;
}

void reconfig(void)
{
  need_reconfig = 0;
  if (config(confname))
  { error("Config error!");
    perl_done();
    unlink(pidfile);
    exit(1);
  }
#ifdef WITH_PCAP
  if (my_mac[0] == NULL && pflow==NULL && netflow[0]=='\0' && !allmacs)
  {
    my_mac[0] = malloc(ETHER_ADDR_LEN);
    get_mac(piface, my_mac[0]);
    my_mac[1] = NULL;
    debug(1, "mac-addr for %s is %02x:%02x:%02x:%02x:%02x:%02x",
          piface, my_mac[0][0], my_mac[0][1], my_mac[0][2], my_mac[0][3],
          my_mac[0][4], my_mac[0][5]);
  }
  if (servport && !pflow && !netflow[0])
  {
    pipe(servpipe);
    servpid = fork();
    if (servpid == 0)
    {
      close(servpipe[1]);
      if (bindserv())
        _exit(1);
      serv();
      _exit(0);
    } else if (servpid == -1)
      error("Cannot fork: %s", strerror(errno));
    else
      debug(1, "process %u started", servpid);
    close(servpipe[0]);
  }
#endif
}

#ifdef DO_SNMP
/* find ifindex by snmp param */
#ifdef NET_SNMP
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#define ds_get_int(a, b)   netsnmp_ds_get_int(a, b)
#define DS_LIBRARY_ID      NETSNMP_DS_LIBRARY_ID
#define DS_LIB_SNMPVERSION NETSNMP_DS_LIB_SNMPVERSION
#else
#include <ucd-snmp/ucd-snmp-config.h>
#include <ucd-snmp/asn1.h>
#include <ucd-snmp/snmp.h>
#include <ucd-snmp/snmp_api.h>
#include <ucd-snmp/snmp_client.h>
#include <ucd-snmp/snmp_impl.h>
#include <ucd-snmp/snmp_parse_args.h>
#include <ucd-snmp/mib.h>
#include <ucd-snmp/system.h>
#include <ucd-snmp/default_store.h>
#endif

char *oid2str(enum ifoid_t oid)
{
  switch (oid)
  { case IFNAME:  return "ifName";
    case IFDESCR: return "ifDescr";
    case IFALIAS: return "ifAlias";
    case IFIP:    return "ifIP";
  }
  return "";
}

static char *oid2oid(enum ifoid_t oid)
{
  switch (oid)
  { case IFNAME:  return "ifName";
    case IFDESCR: return "ifDescr";
    case IFALIAS: return "ifAlias";
    case IFIP:    return "ipAdEntIfIndex";
  }
  return "";
}

static int comp(const void *a, const void *b)
{
  return strcasecmp(((struct routerdata *)a)->val, ((struct routerdata *)b)->val);
}

static int snmpwalk(struct router_t *router, enum ifoid_t noid)
{
  struct snmp_session  session, *ss;
  struct snmp_pdu *pdu, *response;
  struct variable_list *vars;
  oid    root[MAX_OID_LEN], name[MAX_OID_LEN];
  size_t rootlen, namelen;
  int    running, status, exitval=0, nifaces, varslen, ifindex;
  char   *oid, *curvar, ipbuf[16], soid[256];
  struct {
           unsigned short ifindex;
           char val[256];
  } *data;

  /* get the initial object and subtree */
  memset(&session, 0, sizeof(session));
  snmp_sess_init(&session);
  init_snmp("dds");
  /* open an SNMP session */
  strcpy(ipbuf, printoctets((unsigned char *)&router->addr, 4));
  session.peername = ipbuf;
  session.community = (unsigned char *)router->community;
  session.community_len = strlen(router->community);
  session.version = ds_get_int(DS_LIBRARY_ID, DS_LIB_SNMPVERSION);
  if (snmp_time_out) {
    session.timeout = snmp_time_out * 1000l;
  }
  oid=oid2oid(noid);
  debug(1, "Do snmpwalk %s %s %s", ipbuf, router->community, oid);
  if ((ss = snmp_open(&session)) == NULL)
  { snmp_sess_perror("dds", &session);
    return 1;
  }
  debug(6, "snmp session opened");
  while (router->ifnumber == 0 && noid!=IFIP) {
    rootlen=MAX_OID_LEN;
    if (snmp_parse_oid("ifNumber.0", root, &rootlen)==NULL)
    { warning("Can't parse oid ifNumber.0");
      snmp_perror("ifNumber.0");
      break;
    }
    pdu = snmp_pdu_create(SNMP_MSG_GET);
    snmp_add_null_var(pdu, root, rootlen);
    status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS){
      if (response->errstat == SNMP_ERR_NOERROR){
        vars = response->variables;
        if (vars) {
          router->ifnumber = vars->val.integer[0];
          debug(2, "ifNumber = %d", router->ifnumber);
        }
      } else
        warning("snmpget response error");
    } else {
      warning("snmpget status error");
      snmp_sess_perror("dds", ss);
    }
    if (response) snmp_free_pdu(response);
    break;
  }

  /* get first object to start walk */
  rootlen=MAX_OID_LEN;
  if (snmp_parse_oid(oid, root, &rootlen)==NULL)
  { warning("Can't parse oid %s", oid);
    snmp_perror(oid);
    return 1;
  }
  memmove(name, root, rootlen*sizeof(oid));
  namelen = rootlen;
  running = 1;
  nifaces = varslen = ifindex = 0;
  data = NULL;

  while (running) {
    /* create PDU for GETNEXT request and add object name to request */
    if (router->ifnumber > 0 && noid != IFIP && running == 2) {
      snprintf(soid, sizeof(soid), "%s.%d", oid, ifindex+1);
      namelen=MAX_OID_LEN;
      if (snmp_parse_oid(soid, name, &namelen)==NULL)
      { warning("Can't parse oid %s", soid);
        snmp_perror(soid);
        break;
      }
      pdu = snmp_pdu_create(SNMP_MSG_GET);
    } else
      pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
    snmp_add_null_var(pdu, name, namelen);
    /* do the request */
    status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS) {
      ifindex++;
      if (response->errstat == SNMP_ERR_NOERROR) {
        /* check resulting variables */
        for (vars = response->variables; vars; vars = vars->next_variable) {
          if ((vars->name_length < rootlen) ||
              (memcmp(root, vars->name, rootlen * sizeof(oid))!=0)) {
            /* not part of this subtree */
            running = 0;
            if (router->ifnumber > 0 && noid != IFIP) {
              if (ifindex < router->ifnumber) running = 2;
              debug(6, "%s.%d - not part of this subtree", oid, ifindex);
            } else
              debug(6, "Not part of this subtree");
            continue;
          }
          if (nifaces%16==0)
            data=realloc(data, (nifaces+16)*sizeof(data[0]));
          if (noid==IFIP)
          { sprintf(data[nifaces].val, "%lu.%lu.%lu.%lu",
                    vars->name_loc[vars->name_length-4],
                    vars->name_loc[vars->name_length-3],
                    vars->name_loc[vars->name_length-2],
                    vars->name_loc[vars->name_length-1]);
            data[nifaces++].ifindex=vars->val.integer[0];
          } else
          {
            strncpy(data[nifaces].val, (char *)vars->val.string, sizeof(data->val)-1);
            if (vars->val_len<sizeof(data->val))
              data[nifaces].val[vars->val_len]='\0';
            else
              data[nifaces].val[sizeof(data->val)-1]='\0';
            data[nifaces++].ifindex=(unsigned short)vars->name_loc[vars->name_length-1];
          }
          debug(6, "ifindex %u val '%s'", data[nifaces-1].ifindex, data[nifaces-1].val);
          varslen += strlen(data[nifaces-1].val)+1;
          if ((vars->type != SNMP_ENDOFMIBVIEW) &&
              (vars->type != SNMP_NOSUCHOBJECT) &&
              (vars->type != SNMP_NOSUCHINSTANCE)) {
            /* not an exception value */
            memmove((char *)name, (char *)vars->name,
                    vars->name_length * sizeof(oid));
            namelen = vars->name_length;
          } else
            /* an exception value, so stop */
            running = 0;
        }
      } else {
        /* error in response */
        if (response->errstat != SNMP_ERR_NOSUCHNAME) {
          warning("Error in snmp packet.");
          exitval = 2;
          running = 0;
        } else if (ifindex < router->ifnumber && noid != IFIP)
          debug(2, "%s.%d - no such name", oid, ifindex);
        else {
          debug(2, "snmpwalk successfully done");
          running = 0;
        }
      }
    } else if (status == STAT_TIMEOUT) {
      warning("snmp timeout");
      running = 0;
      exitval = 2;
    } else {    /* status == STAT_ERROR */
      warning("SNMP Error");
      snmp_sess_perror("dds", ss);
      running = 0;
      exitval = 2;
    }
    if (response) snmp_free_pdu(response);
  }
  snmp_close(ss);
  if (exitval)
  { if (data) free(data);
    return exitval;
  }
  /* ok, copy data to router structure */
  if (router->data[noid]) free(router->data[noid]);
  router->data[noid] = malloc(sizeof(router->data[0][0])*nifaces+varslen);
  curvar=((char *)router->data[noid])+sizeof(router->data[0][0])*nifaces;
  router->nifaces[noid]=nifaces;
  for (nifaces=0; nifaces<router->nifaces[noid]; nifaces++)
  { router->data[noid][nifaces].ifindex=data[nifaces].ifindex;
    router->data[noid][nifaces].val=curvar;
    strcpy(curvar, data[nifaces].val);
    curvar+=strlen(curvar)+1;
  }
  if (data) free(data);
  /* data copied, sort it */
  qsort(router->data[noid], nifaces, sizeof(router->data[0][0]), comp);
  return 0;
}

static unsigned short get_ifindex(struct router_t *router, enum ifoid_t oid, char **s)
{
  int left, right, mid, i;
  char val[256], *p;
  struct router_t *crouter;

  if (router->addr==(u_long)-1)
  { warning("Router not specified for %s", oid2str(oid));
    return (unsigned short)-2; /* not matched for any interface */
  }
  if ((p=strchr(*s, '=')) == NULL)
  { error("Internal error");
    exit(2);
  }
  *s = p+1;
  if (router->data[oid] == NULL)
    /* do snmpwalk for the oid */
    if (snmpwalk(router, oid) && old_routers)
    { /* use old values if exists */
      for (crouter = old_routers; crouter; crouter = crouter->next)
        if (crouter->addr == router->addr &&
            strcmp(crouter->community, router->community) == 0)
          break;
      if (crouter && crouter->data[oid]) {
        warning("snmpwalk on %s error, use old values", printoctets((unsigned char *)&crouter->addr, 4));
        router->data[oid] = crouter->data[oid];
        router->nifaces[oid] = crouter->nifaces[oid];
        if (!router->ifnumber) router->ifnumber = crouter->ifnumber;
        crouter->nifaces[oid] = 0;
        free(crouter->data[oid]);
        crouter->data[oid] = NULL;
      } else
        warning("snmpwalk on %s error and no old values", printoctets((unsigned char *)&crouter->addr, 4));
    }
  /* copy value to val string */
  if (**s == '\"')
  { strncpy(val, *s+1, sizeof(val));
    val[sizeof(val)-1] = '\0';
    if ((p=strchr(val, '\"')) != NULL)
      *p='\0';
    if ((p=strchr(*s, '\"')) != NULL)
      *s=p+1;
  } else
  { strncpy(val, *s, sizeof(val));
    val[sizeof(val)-1] = '\0';
    for (p=val; *p && !isspace(*p); p++);
    *p='\0';
  }
  /* find ifindex for given val */
  left=0; right=router->nifaces[oid];
  while (left<right)
  { mid=(left+right)/2;
    if ((i=strcasecmp(router->data[oid][mid].val, val))==0)
    {
      debug(4, "ifindex for %s=%s at %s is %d", oid2str(oid), val, 
        printoctets((unsigned char *)&router->addr, 4),
        router->data[oid][mid].ifindex);
      return router->data[oid][mid].ifindex;
    }
    if (i>0) right=mid;
    else left=mid+1;
  }
  warning("%s %s not found at %s", oid2str(oid), val,
          printoctets((unsigned char *)&(router->addr), 4));
  return (unsigned short)-2;
}
#endif

