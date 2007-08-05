#define CONFNAME	CONFDIR "/dds.conf"
#define IFACE		"all"
#define MTU		2048
#define LOGNAME		LOGDIR "/dds.log"
#define SNAPFILE	LOGDIR "/snap"
#define SNAP_TIME	60
#define PIDFILE		"/var/run/dds.pid"
#define CHECK_INTERVAL	60
#define EXPIRE_INTERVAL	300
#define CMDLEN		1024
#define MAXMYMACS	128
#define MAXUPLINKS	128
#define MAXVRF		128
#define QSIZE		4096	/* ~6M queue */

#define ALARM_NEW       1
#define ALARM_FOUND     2
#define ALARM_FINISHED  4

#define ALARM_START     1
#define ALARM_FINISH    2
#define ALARM_CONT      3

#ifndef max
#define max(a, b)	((a) > (b) ? (a) : (b))
#endif

#ifdef WITH_LONGLONG_COUNTERS
typedef unsigned long long count_t;
#else
typedef unsigned long count_t;
#endif

struct octet {
	union {
		count_t count;            /* for leaf */
		time_t used_time;         /* for non-leaf */
	} u1;
	union {
		int alarmed;              /* for leaf */
		struct octet *octet;      /* for non-leaf */
	} u2;
};

typedef enum { PPS, BPS, SYN, UDP, ICMP } cp_type;
typedef enum { BYNONE, BYSRC, BYDST, BYSRCDST, BYDSTPORT } by_type;

#ifdef DO_SNMP
enum ifoid_t { IFNAME, IFDESCR, IFALIAS, IFIP };
#define NUM_OIDS (IFIP+1)
#endif

struct router_t {
	u_long addr;
#ifdef DO_SNMP
	char community[256];
	int  ifnumber;
	int  nifaces[NUM_OIDS];
	struct routerdata {
		unsigned short ifindex;
		char *val;
	} *data[NUM_OIDS];
#endif
	unsigned seq[MAXVRF]; /* for future use */
	int nuplinks, uplinks[MAXUPLINKS];
	struct router_t *next;
};

struct checktype {
	u_long ip, mask;
	int preflen, in, last, alarmed;
	cp_type checkpoint;
	by_type by;
	u_long limit, safelimit;
	unsigned long long count;
	struct octet *octet;
	struct checktype *next;
	char alarmcmd[CMDLEN], noalarmcmd[CMDLEN], contalarmcmd[CMDLEN];
};

struct recheck_t {
	u_long s_addr, d_addr;
	int len;
	int in:8;
	unsigned int pkts:24;
	unsigned short d_port;
	unsigned char proto, flags;
};

struct alarm_t
{
	int reported, finished, in, preflen;
	cp_type cp;
	by_type by;
	unsigned char ip[8];
	u_long limit, safelimit, count;
	char alarmcmd[CMDLEN], noalarmcmd[CMDLEN], contalarmcmd[CMDLEN];
	char id[64];
	struct alarm_t *next, *inhibited;
};

extern struct recheck_t *recheck_arr;
extern int recheck_cur, recheck_size;
extern int need_reconfig;
extern time_t last_check;
extern struct checktype *checkhead;
extern char iface[];
extern char logname[], snapfile[], pidfile[];
extern char alarmcmd[], noalarmcmd[], contalarmcmd[], netflow[], *pflow;
extern int  check_interval, expire_interval, reverse, verb, redo, inhibit;
extern int  alarm_flaps;
extern uid_t uid;
extern u_char *my_mac[];
extern struct router_t *routers;
extern u_long flowip;
extern unsigned short servport;
extern int servsock;
extern char *confname;
#ifdef WITH_PCAP
extern int servpid, my_pid, allmacs;
extern int servpipe[2];
extern char *piface;
#endif

void add_pkt(u_char *src_mac, u_char *dst_mac, struct ip *ip_hdr, u_long len,
             int in, int vlan, int pkts, int flow,
             struct checktype *recheck, u_long local_ip);
void check(void);
int  config(char *name);
void reconfig(void);
int  check_sockets(void);
void exec_alarm(unsigned char *ip, u_long count, struct checktype *p);
void run_alarms(void);
char *cp2str(cp_type cp);
char *printip(unsigned char *ip, int preflen, by_type by, int in);
int  length(by_type by);
void logwrite(char *format, ...);
void debug(int level, char *format, ...);
void warning(char *format, ...);
void error(char *format, ...);
int  bindport(char *netflow);
void recv_flow(void);
void make_iphdr(void *iphdr, u_long saddr, u_long daddr,
          unsigned char prot, unsigned short dport, unsigned char flags);
int  bindserv(void);
void serv(void);
void print_alarms(int fd);
void switchsignals(int how);
#ifdef WITH_PCAP
int get_mac(const char *iface, unsigned char *mac);
#endif
#ifdef DO_SNMP
char *oid2str(enum ifoid_t oid);
#endif

#ifdef DO_PERL
int  perl_init(char *perlfile);
void perl_done(void);
int  perl_alarm_event(struct alarm_t *pa, int event);
int  perl_check(unsigned char *ip, u_long count, struct checktype *pc);
#else
#define perl_done()
#endif
