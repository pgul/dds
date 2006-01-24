#define CONFNAME	CONFDIR "/dds.conf"
#define IFACE		"all"
#define MTU		2048
#define MYMAC		0x00,0x00,0x00,0x00,0x00,0x00
#define LOGNAME		LOGDIR "/dds.log"
#define SNAPFILE	LOGDIR "/snap"
#define PIDFILE		"/var/run/dds.pid"
#define CHECK_INTERVAL	60
#define EXPIRE_INTERVAL	300

struct octet {
	union {
	  unsigned long long count;
	  time_t used_time;
	} data;
	struct octet *octet;
};

struct checktype {
	u_long ip, mask;
	int preflen, pps, in, last;
	u_long limit, safelimit;
	unsigned long long count;
	struct octet *octet;
	struct checktype *next;
};

extern time_t last_check;
extern struct checktype *checkhead;
extern char iface[];
extern char logname[], snapfile[], pidfile[], alarmcmd[], noalarmcmd[];
extern int  check_interval, expire_interval, reverse, verb;
extern u_char my_mac[];

void add_pkt(u_char *src_mac, u_char *dst_mac, u_long src_ip, u_long dst_ip,
              u_long len, int in);
void check(void);
int  config(char *name);
void clear_alarm(void);
void exec_alarm(u_long ip, int preflen, u_long count, int pps, int hard);
void debug(char *format, ...);

