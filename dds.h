#define CONFNAME	CONFDIR "/dds.conf"
#define IFACE		"all"
#define MTU		2048
#define LOGNAME		LOGDIR "/dds.log"
#define SNAPFILE	LOGDIR "/snap"
#define PIDFILE		"/var/run/dds.pid"
#define CHECK_INTERVAL	60
#define EXPIRE_INTERVAL	300
#define CMDLEN		1024
#define MAXMYMACS	128

struct octet {
	union {
		unsigned long long count; /* for leaf */
		time_t used_time;         /* for non-leaf */
	};
	union {
		int alarmed;              /* for leaf */
		struct octet *octet;      /* for non-leaf */
	};
};

typedef enum { PPS, BPS, SYN, UDP, ICMP } cp_type;
typedef enum { BYNONE, BYSRC, BYDST, BYSRCDST, BYDSTPORT } by_type;

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

extern time_t last_check;
extern struct checktype *checkhead;
extern char iface[];
extern char logname[], snapfile[], pidfile[];
extern char alarmcmd[], noalarmcmd[], contalarmcmd[];
extern int  check_interval, expire_interval, reverse, verb;
extern uid_t uid;
extern u_char *my_mac[MAXMYMACS];

void add_pkt(u_char *src_mac, u_char *dst_mac, struct ip *ip_hdr, u_long len, int in, int vlan);
void check(void);
int  config(char *name);
void exec_alarm(unsigned char *ip, u_long count, struct checktype *p, int set);
char *cp2str(cp_type cp);
char *printip(unsigned char *ip, int preflen, by_type by, int in);
int  length(by_type by);
void logwrite(char *format, ...);
void debug(int level, char *format, ...);

