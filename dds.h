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
#define MAXMYAS		128
#define MAXVRF		128
#define QSIZE		8192	/* ~12M queue */

#define ALARM_NEW       1
#define ALARM_FOUND     2
#define ALARM_FINISHED  4

#define ALARM_START     1
#define ALARM_FINISH    2
#define ALARM_CONT      3

#ifndef max
#define max(a, b)	((a) > (b) ? (a) : (b))
#endif

typedef uint64_t count_t;

struct octet {
	union {
		count_t count;			/* 64-bit */
		struct {
			time_t used_time;	/* 32-bit */
			uint32_t precount;	/* 32-bit */
		} s1;
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
	uint32_t addr;
#ifdef DO_SNMP
	char community[256];
	int  ifnumber;
	int  nifaces[NUM_OIDS];
	struct routerdata {
		unsigned short ifindex;
		char *val;
	} *data[NUM_OIDS];
#endif
	int sampled;
	unsigned seq[MAXVRF]; /* for future use */
	int nuplinks, uplinks[MAXUPLINKS];
	int nmyas, myas[MAXMYAS];
	struct router_t *next;
};

struct checktype {
	uint32_t ip, mask;
	int preflen, in, last, alarmed;
	cp_type checkpoint;
	by_type by;
	count_t limit, safelimit;
	count_t count;
	struct octet *octet;
	struct checktype *next;
	char alarmcmd[CMDLEN], noalarmcmd[CMDLEN], contalarmcmd[CMDLEN];
	char ipmask[32];
};

struct recheck_t {
	uint32_t s_addr, d_addr;
	uint32_t len;
	int in:8;
	unsigned int pkts:24;
	uint16_t d_port;
	unsigned char proto, flags;
} __attribute__((packed));

struct alarm_t
{
	int reported, finished, in, preflen;
	cp_type cp;
	by_type by;
	unsigned char ip[8];
	count_t limit, safelimit, count;
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
extern char *uids;
extern uid_t uid;
extern gid_t gid;
extern u_char *my_mac[];
extern struct router_t *routers;
extern in_addr_t flowip;
extern uint16_t servport;
extern int servsock;
extern char *confname;
extern int stdinsrc;
extern time_t curtime;
extern int processfiltered;
#ifdef WITH_PCAP
extern int servpid, my_pid, allmacs;
extern int servpipe[2];
extern char *piface;
#endif

void add_pkt(u_char *src_mac, u_char *dst_mac, struct ip *ip_hdr, count_t len,
             int in, int vlan, count_t pkts, int flow,
             struct checktype *recheck, unsigned char *local_ip, int re_len);
void check(time_t curtime);
int  config(char *name);
void reconfig(void);
int  check_sockets(void);
void exec_alarm(unsigned char *ip, count_t count, struct checktype *p);
void do_alarms(void);
char *cp2str(cp_type cp);
char *by2str(by_type by);
char *printip(unsigned char *ip, int preflen, by_type by, int in);
int  length(by_type by);
void logwrite(char *format, ...);
void debug(int level, char *format, ...);
void warning(char *format, ...);
void error(char *format, ...);
int  bindport(char *netflow);
void recv_flow(void);
void make_iphdr(void *iphdr, uint32_t saddr, uint32_t daddr,
          uint16_t prot, uint16_t dport, unsigned char flags);
int  bindserv(void);
void serv(void);
void print_alarms(int fd);
char *printoctets(unsigned char *octets, int length);
void switchsignals(int how);
#ifdef WITH_PCAP
int  get_mac(const char *iface, unsigned char *mac);
#endif
#ifdef DO_SNMP
char *oid2str(enum ifoid_t oid);
#endif

#ifdef DO_PERL
int  perl_init(char *perlfile);
void perl_done(void);
int  perl_alarm_event(struct alarm_t *pa, int event);
int  perl_check(unsigned char *ip, count_t count, struct checktype *pc);
#else
#define perl_done()
#endif
