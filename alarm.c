#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "dds.h"

struct alarm
{
	unsigned char ip[8];
	int preflen, in, set;
	cp_type checkpoint;
	by_type by;
	struct alarm *next;
} *alarms;

void unset_alarm(void)
{
	struct alarm *pa;

	for (pa=alarms; pa; pa=pa->next)
		pa->set = 0;
}

static void logwrite(char *format, ...)
{
	FILE *f;
	va_list ap;
	time_t curtime;
	struct tm *tm;
#ifdef HAVE_LOCALTIME_R
	struct tm tm1;
#endif
	char *month[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	                 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
	
	if (strcmp(logname, "syslog") == 0) {
		va_start(ap, format);
		vsyslog(LOG_NOTICE, format, ap);
		va_end(ap);
		return;
	}
	curtime = time(NULL);
#ifdef HAVE_LOCALTIME_R
	tm = localtime_r(&curtime, &tm1);
#else
	tm = localtime(&curtime);
#endif
	if ((f=fopen(logname, "a")) != NULL) {
		fprintf(f, "%s %2u %02u:%02u:%02u ",
		        month[tm->tm_mon], tm->tm_mday,
			tm->tm_hour, tm->tm_min, tm->tm_sec);
		va_start(ap, format);
		vfprintf(f, format, ap);
		va_end(ap);
		fprintf(f, "\n");
		fclose(f);
	}
}

/* replace all occurences of substring s1 in str to s2 */
static void chstring(char **str, char *s1, char *s2)
{
	char *p, *newstr;
	int l1 = strlen(s1);
	int l2 = strlen(s2);
	int l  = strlen(*str);

	p=*str;
	while ((p=strstr(p, s1)) != NULL) {
		if (l1<l2) {
			l += l2-l1;
			newstr=realloc(*str, l+1);
			p += (newstr-*str);
			*str = newstr;
		}
		memmove(p+l2, p+l1, strlen(p+l1)+1);
		memcpy(p, s2, l2);
		p += l2;
	}
}

static void run(char *cmd)
{
	/* do we need fork() and any security checks? */
	debug(1, "executing command '%s'\n", cmd);
	system(cmd);
}

char *cp2str(cp_type cp)
{
	switch (cp) {
		case PPS: return "pps";
		case BPS: return "bps";
		case SYN: return "syn pps";
	}
	return "";
}

static void noalarm(struct alarm *pa)
{
	char str[64];

	logwrite("DoS %s %s finished", pa->in ? "to" : "from",
	         printip(pa->ip, pa->preflen, pa->by, pa->in));
	if (noalarmcmd[0]) {
		char *cmd = strdup(noalarmcmd);
		chstring(&cmd, "%b", cp2str(pa->checkpoint));
		strncpy(str, printip(pa->ip, pa->preflen, pa->by, pa->in), sizeof(str)-1);
		chstring(&cmd, "%d", str);
		run(cmd);
		free(cmd);
	}
}

void clear_alarm(void)
{
	struct alarm *pa, *ppa;

	/* remove all alarms with unset flag */
	while (alarms && !alarms->set) {
		noalarm(alarms);
		pa = alarms->next;
		free(alarms);
		alarms = pa;
	}
	pa = alarms;
	while (pa) {
		if (pa->next && pa->next->set == 0) {
			noalarm(pa->next);
			ppa = pa->next->next;
			free(pa->next);
			pa->next = ppa;
		} else
			pa = pa->next;
	}
	/* unset all flags */
	for (pa=alarms; pa; pa=pa->next)
		pa->set = 0;
}

void exec_alarm(unsigned char *ip, u_long count, struct checktype *pc, int hard)
{
	struct alarm *pa;
	char str[64];
	int len;

	len = length(pc->by);
	/* search for this alarm */
	for (pa = alarms; pa; pa=pa->next)
		if (pa->preflen == pc->preflen && pa->checkpoint == pc->checkpoint && pa->by == pc->by && pa->in == pc->in && memcmp(pa->ip, ip, len) == 0)
			break;
	if (pa) {
		/* already reported */
		pa->set = 1;
		debug(1, "DoS %s %s still active, %s %lu\n", pa->in ? "to":"from",
		      printip(pa->ip, pa->preflen, pa->by, pa->in),
		      cp2str(pa->checkpoint), count);
		return;
	}
	if (!hard)
		return;
	pa = malloc(sizeof(*pa));
	pa->in = pc->in;
	memcpy(pa->ip, ip, len);
	pa->preflen = pc->preflen;
	pa->checkpoint = pc->checkpoint;
	pa->by = pc->by;
	pa->set = 1;
	pa->next = alarms;
	alarms = pa;
	logwrite("DoS %s %s: %lu %s", pa->in ? "to" : "from",
	         printip(pa->ip, pa->preflen, pa->by, pa->in),
	         count, cp2str(pc->checkpoint));
	if (alarmcmd[0]) {
		char *cmd = strdup(alarmcmd);
		chstring(&cmd, "%b", cp2str(pa->checkpoint));
		strncpy(str, printip(pa->ip, pa->preflen, pa->by, pa->in), sizeof(str)-1);
		chstring(&cmd, "%d", str);
		snprintf(str, sizeof(str), "%lu", count);
		chstring(&cmd, "%p", str);
		run(cmd);
		free(cmd);
	}
}

