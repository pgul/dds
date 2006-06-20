#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "dds.h"

#define ALARM_NEW	1
#define ALARM_FOUND	2
#define ALARM_FINISHED	4

#define ALARM_START	1
#define ALARM_FINISH	2
#define ALARM_CONT	3

static struct alarm_t
{
	int reported, in, preflen;
	cp_type cp;
	by_type by;
	unsigned char ip[8];
	u_long limit, safelimit, count;
	char alarmcmd[CMDLEN], noalarmcmd[CMDLEN], contalarmcmd[CMDLEN];
	char id[64];
	struct alarm_t *next, *inhibited;
} *alarm_head;

static unsigned seq;

void logwrite(char *format, ...)
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
	debug(1, "executing command '%s'", cmd);
	system(cmd);
}

char *cp2str(cp_type cp)
{
	switch (cp) {
		case PPS:  return "pps";
		case BPS:  return "bps";
		case SYN:  return "syn pps";
		case UDP:  return "udp pps";
		case ICMP: return "icmp pps";
	}
	return "";
}

void exec_alarm(unsigned char *ip, u_long count, struct checktype *pc)
{
	struct alarm_t *pa;
	int iplen;

	iplen = length(pc->by);
	/* find this alarm in the queue */
	for (pa = alarm_head; pa; pa=pa->next) {
		if (pa->cp != pc->checkpoint) continue;
		if (pa->by != pc->by) continue;
		if (pa->in != pc->in) continue;
		if (pa->limit != pc->limit) continue;
		if (pa->safelimit != pc->safelimit) continue;
		if (pa->by == BYNONE && pa->preflen != pc->preflen) continue;
		if (memcmp(ip, pa->ip, iplen)) continue;
		if (strncmp(pa->alarmcmd, pc->alarmcmd, CMDLEN)) continue;
		if (strncmp(pa->noalarmcmd, pc->noalarmcmd, CMDLEN)) continue;
		if (strncmp(pa->contalarmcmd,pc->contalarmcmd,CMDLEN)) continue;
		break;
	}
	if (pa) {
		pa->count = count;
		pa->reported |= ALARM_FOUND;
		return;
	}
	pa = calloc(1, sizeof(struct alarm_t));
	if (pa == NULL) {
		error("Cannot allocate memory: %s", strerror(errno));
		return;
	}
	pa->cp = pc->checkpoint;
	pa->by = pc->by;
	pa->in = pc->in;
	pa->limit = pc->limit;
	pa->safelimit = pc->safelimit;
	pa->preflen = (pc->by == BYNONE ? pc->preflen : 32);
	memcpy(pa->ip, ip, iplen);
	strncpy(pa->alarmcmd, pc->alarmcmd, CMDLEN);
	strncpy(pa->noalarmcmd, pc->noalarmcmd, CMDLEN);
	strncpy(pa->contalarmcmd, pc->contalarmcmd, CMDLEN);
	pa->count = count;
	pa->reported = ALARM_NEW | ALARM_FOUND;
	seq++;
	if (seq < time(NULL)) seq = time(NULL);
	snprintf(pa->id, sizeof(pa->id), "dds-%08x-%08x-%08lx",
	         (unsigned int)getpid(), seq, 
#ifdef WITH_PCAP
	         my_mac[0] ? *(u_long *)(my_mac+2) :
#endif
	         flowip);
	pa->next = alarm_head;
	alarm_head = pa;
}

static void alarm_event(struct alarm_t *pa, int event)
{
	char str[64], *cmd;

	logwrite("DoS %s %s %s: %lu %s%s", pa->in ? "to" : "from",
	         printip(pa->ip, pa->preflen, pa->by, pa->in),
	         event == ALARM_START ? "detected" : (event == ALARM_FINISH ? "finished" : "continue"),
	         pa->count, cp2str(pa->cp),
		 pa->inhibited ? " (inhibited by more specific)" : "");
	if (pa->inhibited && inhibit) return;
	cmd = (event == ALARM_START) ? pa->alarmcmd : (event == ALARM_FINISH ? pa->noalarmcmd : pa->contalarmcmd);
	if (cmd[0]) {
		cmd = strdup(cmd);
		chstring(&cmd, "%b", cp2str(pa->cp));
		strncpy(str, printip(pa->ip, pa->preflen, pa->by, pa->in), sizeof(str)-1);
		chstring(&cmd, "%d", str);
		snprintf(str, sizeof(str), "%lu", pa->count);
		chstring(&cmd, "%p", str);
		chstring(&cmd, "%t", pa->in ? "to" : "from");
		chstring(&cmd, "%i", pa->id);
		run(cmd);
		free(cmd);
	}
}

static int cmp_cp(cp_type cp1, cp_type cp2)
{
	/* return 0 if cp1 may be inhibited by cp2 */
	if (cp1 == cp2) return 0;
	if (cp1 == PPS && cp2 != BPS) return 0;
	return 1;
}

void run_alarms(void)
{
	struct alarm_t *pa, *ppa;
	int iplen;

	/* 1. Inhibit alarms */
	for (pa = alarm_head; pa; pa = pa->next) {
		iplen = length(pa->by);
		for (ppa = alarm_head; ppa; ppa = ppa->next) {
			if (pa == ppa) continue;
			if (ppa->inhibited) continue;
			if (pa->in != ppa->in) continue;
			if (iplen > length(ppa->by)) continue;
			if (cmp_cp(pa->cp, ppa->cp)) continue;
			if (pa->by != BYNONE && ppa->by == BYNONE) continue;
			if (strcmp(pa->alarmcmd, ppa->alarmcmd)) continue;
			if (pa->by == BYNONE) {
				if (pa->preflen > ppa->preflen) continue;
				if (pa->preflen) {
					u_long mask;
					mask = 0xfffffffful << (32-pa->preflen);
					mask = htonl(mask);
					if ((*(u_long *)ppa->ip & mask) != *(u_long *)pa->ip)
						continue;
				}
			} else {
				if (memcmp(pa->ip, ppa->ip, iplen)) continue;
			}
			/* inhibit */
			pa->inhibited = ppa;
		}
	}
	/* 2. Run alarm events */
	for (pa = alarm_head; pa; pa = pa->next) {
		if (pa->count<pa->safelimit || !(pa->reported & ALARM_FOUND)) {
			if ((pa->reported & ALARM_NEW) == 0)
				alarm_event(pa, ALARM_FINISH);
			pa->reported |= ALARM_FINISHED;
			continue;
		}
		if (pa->reported & ALARM_NEW) {
			if (pa->count >= pa->limit)
				alarm_event(pa, ALARM_START);
			else
				/* what is it?! */
				pa->reported |= ALARM_FINISHED;
			continue;
		}
		/* found, not new, more then safelimit */
		alarm_event(pa, ALARM_CONT);
	}
	/* 3. Free finished alarms */
	for (pa = alarm_head; pa && pa->next;) {
		if (pa->next->reported & ALARM_FINISHED) {
			ppa = pa->next;
			pa->next = ppa->next;
			free(ppa);
		} else
			pa = pa->next;
	}
	if (alarm_head && alarm_head->reported & ALARM_FINISHED) {
		pa = alarm_head;
		alarm_head = alarm_head->next;
		free(pa);
	}
	/* 4. Clear reported flags */
	for (pa = alarm_head; pa; pa = pa->next) {
		pa->reported = 0;
		pa->inhibited = NULL;
	}
}

