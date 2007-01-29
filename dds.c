#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <stdarg.h>
#include <ctype.h>
#include <syslog.h>
#include <sys/wait.h>
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#ifdef WITH_PCAP
#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#else
#include <netinet/if_ether.h>
#endif
#ifdef HAVE_NET_IF_VLAN_VAR_H
#include <net/if_vlan_var.h>
#endif
#if defined(HAVE_PCAP_PCAP_H)
#include <pcap/pcap.h>
#elif defined(HAVE_PCAP_H)
#include <pcap.h>
#else
#define DLT_NULL	0	/* no link-layer encapsulation */
#define DLT_EN10MB	1	/* Ethernet (10Mb) */
#define DLT_EN3MB	2	/* Experimental Ethernet (3Mb) */
#define DLT_AX25	3	/* Amateur Radio AX.25 */
#define DLT_PRONET	4	/* Proteon ProNET Token Ring */
#define DLT_CHAOS	5	/* Chaos */
#define DLT_IEEE802	6	/* IEEE 802 Networks */
#define DLT_ARCNET	7	/* ARCNET */
#define DLT_SLIP	8	/* Serial Line IP */
#define DLT_PPP		9	/* Point-to-point Protocol */
#define DLT_FDDI	10	/* FDDI */
#define DLT_ATM_RFC1483	11	/* LLC/SNAP encapsulated atm */
#define DLT_RAW		12	/* raw IP */
#define DLT_SLIP_BSDOS	13	/* BSD/OS Serial Line IP */
#define DLT_PPP_BSDOS	14	/* BSD/OS Point-to-point Protocol */
#define DLT_LANE8023    15      /* LANE 802.3(Ethernet) */
#define DLT_CIP         16      /* ATM Classical IP */
#define DLT_LINUX_SLL	113	/* Linux cooked sockets */

typedef struct pcap pcap_t;
struct pcap_pkthdr {
	struct timeval ts;      /* time stamp */
	unsigned caplen;     /* length of portion present */
	unsigned len;        /* length this packet (off wire) */
};                                                                 
struct bpf_program {
#ifdef __linux__
	/* Thanks, Alan  8) */
	unsigned short bf_len;
#else
	unsigned int bf_len;
#endif
	struct bpf_insn *bf_insns;
};
typedef int bpf_int32;
typedef unsigned int bpf_u_int32;
typedef void (*pcap_handler)(u_char *, const struct pcap_pkthdr *, const u_char *);

pcap_t	*pcap_open_live(char *, int, int, int, char *);
void	pcap_close(pcap_t *);
int	pcap_loop(pcap_t *, int, pcap_handler, u_char *);
int	pcap_datalink(pcap_t *);
int	pcap_lookupnet(char *, bpf_u_int32 *, bpf_u_int32 *, char *);
int	pcap_compile(pcap_t *, struct bpf_program *, char *, int, bpf_u_int32);
int	pcap_setfilter(pcap_t *, struct bpf_program *);

#endif
#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE 256
#endif
#ifdef NEED_PCAP_OPEN_LIVE_NEW_PROTO
pcap_t	*pcap_open_live_new(char *, int, int, int, char *, int, int, char *);
#endif
#endif
#include "dds.h"

#ifdef WITH_PCAP
#ifndef NO_TRUNK
#ifndef HAVE_NET_IF_VLAN_VAR_H
struct ether_vlan_header {
        unsigned char  evl_dhost[ETHER_ADDR_LEN];
        unsigned char  evl_shost[ETHER_ADDR_LEN];
        unsigned short evl_encap_proto;
        unsigned short evl_tag;
        unsigned short evl_proto;
};
#endif
#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100	/* IEEE 802.1Q VLAN tagging */
#endif
#endif

#ifdef	DLT_LINUX_SLL
#ifndef	SLL_HDR_LEN
#define SLL_HDR_LEN     16
#endif
#ifndef	SLL_ADDRLEN
#define SLL_ADDRLEN     8
#endif
struct sll_header {
	u_int16_t	sll_pkttype;	/* packet type */
	u_int16_t	sll_hatype;	/* link-layer address type */
	u_int16_t	sll_halen;	/* link-layer address length */
	u_int8_t	sll_addr[SLL_ADDRLEN];	/* link-layer address */
	u_int16_t	sll_protocol;	/* protocol */
};
#endif

static int get_mac(const char *iface, unsigned char *mac);

static pcap_t *pk;
static int linktype;
#ifdef HAVE_PCAP_OPEN_LIVE_NEW
static int  real_linktype;
#endif
static char *dlt[] = {
 "null", "ethernet", "eth3m", "ax25", "pronet", "chaos",
 "ieee802", "arcnet", "slip", "ppp", "fddi", "llc/snap atm", "raw ip",
 "bsd/os slip", "bsd/os ppp", "lane 802.3", "atm" };
static char *piface=NULL;
#endif
long snap_traf;
FILE *fsnap;
int  reverse, verb;
time_t last_check;
static char *saved_argv[20];
static char *confname;

void hup(int signo)
{
#ifdef HAVE_STRSIGNAL
  debug(1, "Received signal %s (%d)", strsignal(signo), signo);
#else
  debug(1, "Received signal %d", signo);
#endif
  if (signo==SIGCHLD)
  { pid_t pid;
    while ((pid = waitpid(-1, NULL, WNOHANG)) > 0)
    {
      debug(1, "Process %u ended", pid);
#ifdef WITH_PCAP
      if (pid == servpid)
      {
        servpid = 0;
        close(servpipe[1]);
      }
#endif
    }
  }
  if (signo==SIGTERM || signo==SIGINT)
  { perl_done();
    unlink(pidfile);
#ifdef WITH_PCAP
    if (servpid) kill(servpid, SIGTERM);
#endif
    _exit(0);
  }
  if (signo==SIGHUP)
  {
    if (config(confname))
    { fprintf(stderr, "Config error!\n");
      perl_done();
      unlink(pidfile);
      _exit(1);
    }
#ifdef WITH_PCAP
    if (my_mac[0] == NULL && (!pflow || netflow[0]) && !allmacs)
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
        bindserv();
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
  if (signo==SIGUSR1)
  { /* snap 100M of traffic */
    int wassnap=1;
    if (fsnap) fclose(fsnap);
    else wassnap=0;
    snap_traf=100*1024*1024; 
    fsnap=fopen(snapfile, "a");
    if (fsnap==NULL)
    { snap_traf=0;
      warning("Can't open %s: %s!", snapfile, strerror(errno));
    }
    else if (!wassnap)
    { time_t curtime=time(NULL);
      fprintf(fsnap, "\n\n----- %s\n", ctime(&curtime));
    }
  }
  if (signo==SIGUSR2)
  { /* restart myself */
    setuid(0);
#ifdef WITH_PCAP
    pcap_close(pk);
#endif
    perl_done();
    unlink(pidfile);
    execvp(saved_argv[0], saved_argv);
    _exit(5);
  }
  signal(signo, hup);
}

void switchsignals(int how)
{
  sigset_t sigset;

  /* block signals */
  sigemptyset(&sigset);
  sigaddset(&sigset, SIGHUP);
  sigaddset(&sigset, SIGTERM);
  sigaddset(&sigset, SIGINT);
  sigaddset(&sigset, SIGUSR1);
  sigaddset(&sigset, SIGUSR2);
  sigprocmask(how, &sigset, NULL);
}

#ifdef WITH_PCAP
void dopkt(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
  struct ether_header *eth_hdr;
  struct ip *ip_hdr;
  u_char *src_mac, *dst_mac;
#ifndef NO_TRUNK
  struct ether_vlan_header *vlan_hdr;
#endif
  int vlan = 0;
#ifdef DLT_LINUX_SLL
  struct sll_header *sll_hdr;
#endif
  int in=-1;

  switchsignals(SIG_BLOCK);
#ifdef HAVE_PKT_TYPE
  if (hdr->pkt_type == 4) // PACKET_OUTGOING
    in = 0;
  else if (hdr->pkt_type == 0) // PACKET_HOST
    in = 1;
  // PACKET_BROADCAST, PACKET_MULTICAST, PACKET_OTHERHOST - use unknown
#endif
  if (linktype == DLT_EN10MB)
  {
    if (hdr->len < sizeof(*eth_hdr)+sizeof(*ip_hdr))
      goto dopkt_end;
    eth_hdr = (struct ether_header *)data;
#ifndef NO_TRUNK
    if (ntohs(eth_hdr->ether_type)==ETHERTYPE_VLAN)
    {
      vlan_hdr=(struct ether_vlan_header *)data;
      vlan=ntohs(vlan_hdr->evl_tag);
      if (ntohs(vlan_hdr->evl_proto)!=ETHERTYPE_IP)
        goto dopkt_end;
      ip_hdr = (struct ip *)(vlan_hdr+1);
    }
    else
#endif
    if (ntohs(eth_hdr->ether_type)==ETHERTYPE_IP)
      ip_hdr = (struct ip *)(eth_hdr+1);
    else
      goto dopkt_end;
  } else if (linktype == DLT_RAW)
  { 
    if (hdr->len < sizeof(*ip_hdr))
      goto dopkt_end;
    eth_hdr = NULL;
    ip_hdr = (struct ip *)data;
#ifdef DLT_LINUX_SLL
  } else if (linktype == DLT_LINUX_SLL)
  { 
    if (hdr->len < sizeof(*sll_hdr)+sizeof(*ip_hdr))
      goto dopkt_end;
    sll_hdr = (struct sll_header *)data;
    eth_hdr = NULL;
    if (ntohs(sll_hdr->sll_protocol)==ETHERTYPE_IP)
      ip_hdr = (struct ip *)(sll_hdr+1);
    else
      goto dopkt_end;
    if (sll_hdr->sll_pkttype == 0)	// LINUX_SLL_HOST
      in = 1;
    else if (ntohs(sll_hdr->sll_pkttype) == 4)	// LINUX_SLL_OUTGOING
      in = 0;
#endif
  } else
    goto dopkt_end;
#ifdef HAVE_PCAP_OPEN_LIVE_NEW
  if (real_linktype != DLT_EN10MB)
    src_mac = dst_mac = NULL;
  else
#endif
  if (eth_hdr)
  { src_mac = (u_char *)&eth_hdr->ether_shost;
    dst_mac = (u_char *)&eth_hdr->ether_dhost;
  } else
    src_mac = dst_mac = NULL;
  add_pkt(src_mac, dst_mac, ip_hdr,
         hdr->len-(eth_hdr ? ((char *)ip_hdr - (char *)eth_hdr) : 0),
         in, vlan, 1, 0, NULL, 0);
dopkt_end:
  switchsignals(SIG_UNBLOCK);
}
#endif

#ifndef HAVE_DAEMON
int daemon(int nochdir, int noclose)
{
  int i;
  if (!nochdir) chdir("/");
  if (!noclose)
  {
    i=open("/dev/null", O_RDONLY);
    if (i!=-1)
    { if (i>0) dup2(i, 0);
      close(i);
    }
    i=open("/dev/null", O_WRONLY);
    if (i!=-1)
    { if (i>1) dup2(i, 1);
      if (i>2) dup2(i, 2);
      close(i);
    }
  }
  if ((i=fork()) == -1) return -1;
  if (i>0) exit(0);
  setsid();
  return 0;
}
#endif

int usage(void)
{
  printf("DoS/DDoS Detector      " __DATE__ "\n");
  printf("    Usage:\n");
  printf("dds [-d] [-r] [-v] "
#ifdef WITH_PCAP
         "[-p] [-i <iface>] "
#endif
         "[-b [<ip>:]<port>] [config]\n");
  printf("  -d               - daemonize\n");
#ifdef WITH_PCAP
  printf("  -i <iface>       - listen interface <iface>.\n");
  printf("  -p               - do not put the interface into promiscuous mode\n");
#endif
  printf("  -r               - reverse in/out check (for work on downlink's channel)\n");
  printf("  -b [<ip>:]<port> - receive netflow to <ip>:<port>\n");
  printf("  -v               - increase verbouse level\n");
  return 0;
}

#ifdef WITH_PCAP
#if defined(HAVE_GETIFADDRS) && defined(HAVE_NET_IF_DL_H)
#include <net/if_dl.h>
#include <ifaddrs.h>
#include <net/if_types.h>
static int get_mac(const char *iface, unsigned char *mac)
{
  struct ifaddrs *ifap, *ifa;
  struct sockaddr_dl *sa;
  int rc=-1;

  if (getifaddrs(&ifap))
    return -1;
  for (ifa=ifap; ifa; ifa=ifa->ifa_next) {
    if (ifa->ifa_addr->sa_family != AF_LINK) continue;
    if (strcmp(ifa->ifa_name, iface)) continue;
    sa = (struct sockaddr_dl *)ifa->ifa_addr;
    if (sa->sdl_type == IFT_ETHER) {
      memcpy(mac, sa->sdl_data+sa->sdl_nlen, 6);
      rc=0;
    }
    break;
  }
  freeifaddrs(ifap);
  return rc;
}
#elif defined(SIOCGIFHWADDR)
static int get_mac(const char *iface, unsigned char *mac)
{
  struct ifreq ifr;
  int rc=-1, fd = socket(PF_INET, SOCK_DGRAM, 0);
  if (fd >= 0)
  {
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, iface);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0 &&
        ifr.ifr_hwaddr.sa_family == 1 /* ARPHRD_ETHER */)
    { memcpy(mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
      rc=0;
    }
    close(fd);
  }
  return rc;
}
#else
static int get_mac(const char *iface, unsigned char *mac)
{
  char cmd[80], str[256], *p;
  FILE *fout;
  unsigned short m[6];
  int rc=-1;

  snprintf(cmd, sizeof(cmd), "/sbin/ifconfig %s", iface);
  cmd[sizeof(cmd)-1]='\0';
  if ((fout=popen(cmd, "r")) == NULL)
    return -1;
  while (fgets(str, sizeof(str), fout))
  {
    for (p=str; *p; p++) *p=tolower(*p);
    if ((p=strstr(str, "hwaddr ")) || (p=strstr(str, "ether ")))
    {
      while (*p && !isspace(*p)) p++;
      while (*p && isspace(*p)) p++;
      if (rc == 0) continue;
      if (sscanf(p, "%hx:%hx:%hx:%hx:%hx:%hx", m, m+1, m+2, m+3, m+4, m+5) == 6)
        if (((m[0]|m[1]|m[2]|m[3]|m[4]|m[5]) & 0xff00) == 0)
	{
          mac[0] = (unsigned char)m[0];
          mac[1] = (unsigned char)m[1];
          mac[2] = (unsigned char)m[2];
          mac[3] = (unsigned char)m[3];
          mac[4] = (unsigned char)m[4];
          mac[5] = (unsigned char)m[5];
          rc=0;
        }
    }
  }
  pclose(fout);
  return rc;
}
#endif
#endif

int main(int argc, char *argv[])
{
#ifdef WITH_PCAP
  char ebuf[PCAP_ERRBUF_SIZE]="";
#endif
  int i, daemonize, promisc;
  FILE *f;

  for (i=0; i<=argc && i<sizeof(saved_argv)/sizeof(saved_argv[0]); i++)
    saved_argv[i]=argv[i];
  confname=CONFNAME;
  daemonize=promisc=0;
  while ((i=getopt(argc, argv, "db:hrv?"
#ifdef WITH_PCAP
                                         "pi:"
#endif
				  )) != -1)
  {
    switch (i)
    {
      case 'd': daemonize=1;   break;
#ifdef WITH_PCAP
      case 'p': promisc=1;     break;
      case 'i': piface=optarg; break;
#endif
      case 'r': reverse=1;     break;
      case 'b': pflow=optarg;  break;
      case 'v': verb++;        break;
      case 'h':
      case '?': usage(); return 1;
      default:  fprintf(stderr, "Unknown option -%c\n", (char)i);
                usage(); return 2;
    }
  }
  if (argc>optind)
    confname=argv[optind];

  if (config(confname))
  { fprintf(stderr, "Config error\n");
    return 1;
  }
  if (pflow)
    if (bindport(pflow) == -1)
      return 1;
  if (daemonize)
    daemon(0, 0);
  if (strcmp(logname, "syslog") == 0)
    openlog("dds", LOG_PID, LOG_DAEMON);
  last_check=time(NULL);
  switchsignals(SIG_BLOCK);
  signal(SIGHUP, hup);
  signal(SIGUSR1, hup);
  signal(SIGUSR2, hup);
  signal(SIGTERM, hup);
  signal(SIGINT, hup);
  signal(SIGCHLD, hup);
  f=fopen(pidfile, "w");
  if (f)
  { fprintf(f, "%u\n", (unsigned)getpid());
    fclose(f);
  }
  if (pflow || netflow[0])
  {
    if (uid) {
      if (setuid(uid))
        warning("setuid failed: %s", strerror(errno));
      else
        debug(1, "Setuid to uid %d done", uid);
    }
    last_check = time(NULL);
    switchsignals(SIG_UNBLOCK);
    recv_flow();
    perl_done();
    unlink(pidfile);
    if (strcmp(logname, "syslog") == 0)
      closelog();
    return 0;
  }
#ifdef WITH_PCAP
  my_pid = getpid();
  if (servport)
  {
    pipe(servpipe);
    servpid = fork();
    if (servpid == 0)
    {
      close(servpipe[1]);
      bindserv();
      if (uid) {
        if (setuid(uid))
          warning("setuid failed: %s", strerror(errno));
        else
          debug(1, "Setuid to uid %d done", uid);
      }
      switchsignals(SIG_UNBLOCK);
      serv();
      exit(0);
    } else if (servpid == -1)
      error("Cannot fork: %s", strerror(errno));
    else
      debug("process %u started", servpid);
    close(servpipe[0]);
    print_alarms(servpipe[1]);
    write(servpipe[1], "", 1);
  }
  if (!piface) piface=iface;
  if (strcmp(piface, "all") == 0)
    piface = NULL;
  pk = pcap_open_live(piface, MTU, promisc ? 0 : 1, 0, ebuf);
#ifdef HAVE_PCAP_OPEN_LIVE_NEW
  if (pk)
  { real_linktype = pcap_datalink(pk);
    if (real_linktype != DLT_EN10MB)
    { pcap_close(pk);
      pk = NULL;
    }
  }
  if (pk==NULL)
    pk = pcap_open_live_new(piface, MTU, promisc ? -1 : 0, 0, ebuf, 0, 0, NULL);
#endif
  if (pk)
  {
    linktype = pcap_datalink(pk);
    if (linktype != DLT_EN10MB && linktype != DLT_RAW
#ifdef DLT_LINUX_SLL
        && linktype != DLT_LINUX_SLL
#endif
       )
    { char *sdlt, unspec[32];
      if (linktype>0 && linktype<sizeof(dlt)/sizeof(dlt[0]))
        sdlt = dlt[linktype];
      else
      { sprintf(unspec, "unspec (%d)", linktype);
        sdlt = unspec;
      }
      warning("Unsupported link type %s!", sdlt);
    }
    else
    {
      struct bpf_program fcode;
      bpf_u_int32 localnet, netmask;
#ifdef HAVE_PCAP_OPEN_LIVE_NEW
      if (real_linktype == DLT_EN10MB
#else
      if (linktype == DLT_EN10MB
#endif
          && my_mac[0] == NULL && !allmacs)
      {
        my_mac[0] = malloc(ETHER_ADDR_LEN);
        get_mac(piface, my_mac[0]);
        my_mac[1] = NULL;
        debug(1, "mac-addr for %s is %02x:%02x:%02x:%02x:%02x:%02x",
                piface, my_mac[0][0], my_mac[0][1], my_mac[0][2], my_mac[0][3],
                my_mac[0][4], my_mac[0][5]);
      }
      if (pcap_lookupnet(piface, &localnet, &netmask, ebuf))
      { warning("pcap_lookupnet error: %s", ebuf);
        netmask = localnet = 0;
      }
      if (pcap_compile(pk, &fcode, NULL, 1, netmask) == 0)
        pcap_setfilter(pk, &fcode);
// fprintf(stderr, "localnet %s, ", inet_ntoa(*(struct in_addr *)&localnet));
// fprintf(stderr, "netmask %s\n", inet_ntoa(*(struct in_addr *)&netmask));
      switchsignals(SIG_UNBLOCK);
      if (uid) {
        if (setuid(uid))
          warning("setuid failed: %s", strerror(errno));
        else
          debug(1, "Setuid to uid %d done", uid);
      }
      last_check = time(NULL);
      pcap_loop(pk, -1, dopkt, NULL);
      warning("pcap_loop error: %s", ebuf);
    } 
    perl_done();
    unlink(pidfile);
    pcap_close(pk);
    if (strcmp(logname, "syslog") == 0)
      closelog();
  }
  else
  { warning("pcap_open_live fails: %s", ebuf);
    perl_done();
  }
  if (servpid) kill(servpid, SIGTERM);
  return 0;
#else
  error("Netflow IP and port not defined");
  perl_done();
  return 1;
#endif
}

void debug(int level, char *format, ...)
{
  va_list ap;

  if (level > verb) return;
  if (strcmp(logname, "syslog") == 0) {
    va_start(ap, format);
    vsyslog(LOG_DEBUG, format, ap);
    va_end(ap);
  }
  va_start(ap, format);
  vfprintf(stderr, format, ap);
  fprintf(stderr, "\n");
  fflush(stderr);
  va_end(ap);
}

void warning(char *format, ...)
{
  va_list ap;

  if (strcmp(logname, "syslog") == 0) {
    va_start(ap, format);
    vsyslog(LOG_WARNING, format, ap);
    va_end(ap);
  }
  va_start(ap, format);
  vfprintf(stderr, format, ap);
  fprintf(stderr, "\n");
  fflush(stderr);
  va_end(ap);
}

void error(char *format, ...)
{
  va_list ap;

  if (strcmp(logname, "syslog") == 0) {
    va_start(ap, format);
    vsyslog(LOG_ERR, format, ap);
    va_end(ap);
  }
  va_start(ap, format);
  vfprintf(stderr, format, ap);
  fprintf(stderr, "\n");
  fflush(stderr);
  va_end(ap);
}

