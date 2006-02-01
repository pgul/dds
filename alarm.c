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

void exec_alarm(unsigned char *ip, u_long count, struct checktype *pc, int set)
{
	char str[64], *cmd;

	logwrite("DoS %s %s %s: %lu %s", pc->in ? "to" : "from",
	         printip(ip, pc->preflen, pc->by, pc->in),
	         set ? "detected" : "finished",
	         count, cp2str(pc->checkpoint));
	cmd = set ? alarmcmd : noalarmcmd;
	if (cmd[0]) {
		cmd = strdup(cmd);
		chstring(&cmd, "%b", cp2str(pc->checkpoint));
		strncpy(str, printip(ip, pc->preflen, pc->by, pc->in), sizeof(str)-1);
		chstring(&cmd, "%d", str);
		snprintf(str, sizeof(str), "%lu", count);
		chstring(&cmd, "%p", str);
		run(cmd);
		free(cmd);
	}
}

