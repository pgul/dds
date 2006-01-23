#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "dds.h"

struct alarm
{
	u_long ip;
	int preflen, pps, set;
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
	char *p;
	int l1 = strlen(s1);
	int l2 = strlen(s2);
	int l  = strlen(*str);

	p=*str;
	while ((p=strstr(p, s1)) != NULL) {
		if (l1<l2) {
			l += l2-l1;
			*str=realloc(*str, l+1);
		}
		memmove(p+l2, p+l1, strlen(p+l1)+1);
		memcpy(p, s2, l2);
		p += l2;
	}
}

static void run(char *cmd)
{
	/* do we need fork() and any security checks? */
	debug("executing command '%s'\n", cmd);
	system(cmd);
}

static void noalarm(struct alarm *pa)
{
	char str[64];

	logwrite("DoS to %s/%u finished",
	         inet_ntoa(*(struct in_addr *)&pa->ip), pa->preflen);
	if (noalarmcmd[0]) {
		char *cmd = strdup(noalarmcmd);
		chstring(&cmd, "%b", pa->pps ? "pps" : "bps");
		snprintf(str, sizeof(str), "%s/%u",
		         inet_ntoa(*(struct in_addr *)&pa->ip), pa->preflen);
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

void exec_alarm(u_long ip, int preflen, u_long count, int pps, int hard)
{
	struct alarm *pa;
	char str[64];

	/* search for this alarm */
	for (pa = alarms; pa; pa=pa->next)
		if (pa->ip == ip && pa->preflen == preflen && pa->pps == pps)
			break;
	if (pa) {
		/* already reported */
		pa->set = 1;
		debug("DoS to %s/%u still active, %s %lu\n",
		      inet_ntoa(*(struct in_addr *)&pa->ip), pa->preflen,
		      pps ? "pps" : "bps", count);
		return;
	}
	if (!hard)
		return;
	pa = malloc(sizeof(*pa));
	pa->ip = ip;
	pa->preflen = preflen;
	pa->pps = pps;
	pa->set = 1;
	pa->next = alarms;
	alarms = pa;
	logwrite("DoS to %s/%u: %lu %s", 
	         inet_ntoa(*(struct in_addr *)&pa->ip), pa->preflen,
		 count, pps ? "pps" : "bps");
	if (alarmcmd[0]) {
		char *cmd = strdup(alarmcmd);
		chstring(&cmd, "%b", pa->pps ? "pps" : "bps");
		snprintf(str, sizeof(str), "%s/%u",
		         inet_ntoa(*(struct in_addr *)&pa->ip), pa->preflen);
		chstring(&cmd, "%d", str);
		snprintf(str, sizeof(str), "%lu", count);
		chstring(&cmd, "%p", str);
		run(cmd);
		free(cmd);
	}
}

