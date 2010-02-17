#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "dds.h"

static struct alarm_t *alarm_head;
static unsigned seq;

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
	pid_t pid;
	/* do we need any security checks? */
	debug(1, "executing command '%s'", cmd);
	if ((pid=fork()) == 0) {
		system(cmd);
		exit(0);
	} else if (pid<0)
		error("Cannot fork: %s", strerror(errno));
	else
		debug(1, "start process %u", (unsigned int)pid);
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

char *by2str(by_type by)
{
	switch (by) {
		case BYNONE:    return "bynone";
		case BYSRC:     return "bysrc";
		case BYDST:     return "bydst";
		case BYSRCDST:  return "bysrcdst";
		case BYDSTPORT: return "bydstport";
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
	         (u_long)flowip);
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
#ifdef DO_PERL
	perl_alarm_event(pa, event);
#endif
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

void do_alarms(void)
{
	struct alarm_t *pa, *ppa;
	int iplen;

	/* 1. Inhibit alarms */
	for (pa = alarm_head; pa; pa = pa->next)
		pa->inhibited = NULL;
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
					u_long ip, mask;
					mask = 0xfffffffful << (32-pa->preflen);
					/* if (*(u_long *)ppa->ip & htonl(mask) != *(u_long *)pa->ip) -- warning */
					/* assert(iplen >= sizeof(ip)) */
					memcpy(&ip, ppa->ip, iplen);
					ip &= htonl(mask);
					if (memcmp(&ip, pa->ip, iplen))
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
			if (!(pa->reported & ALARM_FOUND))
				pa->finished = alarm_flaps;
			else
				pa->finished++;
			if (pa->finished >= alarm_flaps) {
				if (!(pa->reported & ALARM_NEW))
					alarm_event(pa, ALARM_FINISH);
				pa->reported |= ALARM_FINISHED;
			} else
				alarm_event(pa, ALARM_CONT);
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
		pa->finished = 0;
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
	if (alarm_head && (alarm_head->reported & ALARM_FINISHED)) {
		pa = alarm_head;
		alarm_head = alarm_head->next;
		free(pa);
	}
	/* 4. Clear reported flags */
	for (pa = alarm_head; pa; pa = pa->next)
		pa->reported = 0;
#ifdef WITH_PCAP
	if (servpid) {
		print_alarms(servpipe[1]);
		write(servpipe[1], "", 1);
	}
#endif
}

void print_alarms(int fd)
{
	struct alarm_t *pa;
	char str[256];

	if (alarm_head == NULL) {
		strncpy(str, "200-No alarms\n200\n", sizeof(str));
		write(fd, str, strlen(str));
		return;
	}
	str[sizeof(str)-1] = '\0';
	/* 1. Print non-inhibited alarms */
	for (pa = alarm_head; pa; pa = pa->next) {
		if (pa->inhibited) continue;
		snprintf(str, sizeof(str)-1, "500-DoS %s %s: %lu %s\n",
		         pa->in ? "to" : "from",
		         printip(pa->ip, pa->preflen, pa->by, pa->in),
			 pa->count, cp2str(pa->cp));
		write(fd, str, strlen(str));
	}
	/* 2. Print inhibited alarms */
	for (pa = alarm_head; pa; pa = pa->next) {
		if (!pa->inhibited) continue;
		snprintf(str, sizeof(str)-1, "500-DoS %s %s: %lu %s (inhibited)\n",
		         pa->in ? "to" : "from",
		         printip(pa->ip, pa->preflen, pa->by, pa->in),
			 pa->count, cp2str(pa->cp));
		write(fd, str, strlen(str));
	}
	write(fd, "500\n", 4);
}

#ifdef WITH_PCAP
void serv(void)
{
  fd_set r;
  char *buf;
  int new_sock, bufsize, listsize, sentsize, n;
  struct sockaddr_in client;
  socklen_t a_len;
  pid_t pid;

  bufsize = 16384;
  listsize = 0;
  buf = malloc(bufsize);
  if (buf == NULL)
  { error("Malloc failed: %s", strerror(errno));
    return;
  }
  for (;;)
  {
    FD_ZERO(&r);
    FD_SET(servsock, &r);
    FD_SET(servpipe[0], &r);
    n = select(max(servsock, servpipe[0]) + 1, &r, NULL, NULL, NULL);
    if (n == -1)
    { if (errno == EAGAIN || errno == EINTR) continue;
      error("select error: %s", strerror(errno));
      return;
    }
    if (n == 0) continue;
    if (FD_ISSET(servpipe[0], &r))
    { /* read info from pipe to buffer */
      listsize = 0;
      for (;;)
      {
        if (listsize == bufsize)
        {
          buf = realloc(buf, bufsize *= 2);
          if (buf == NULL)
          {
            error("realloc failed: %s", strerror(errno));
            return;
          }
        }
        n = read(servpipe[0], buf+listsize, bufsize-listsize);
        if (n == -1)
        {
          error("read pipe failed: %s", strerror(errno));
          return;
        }
        if (n == 0) continue;
        if (memchr(buf+listsize, 0, n) == NULL)
        {
          listsize += n;
          continue;
        }
        listsize += n-1; /* do not send zero byte */
        break;
      }
    }
    if (FD_ISSET(servsock, &r) == 0) continue;
    a_len = sizeof(client);
    new_sock = accept(servsock, (struct sockaddr *)&client, &a_len);
    if (new_sock == -1)
    { if (errno == EAGAIN || errno == EINTR) continue;
      error("accept error: %s", strerror(errno));
      return;
    }
    /* write buffer to socket */
    pid = fork();
    if (pid == 0) {
      sentsize = 0;
      while (sentsize < listsize)
      {
        n = write(new_sock, buf + sentsize, listsize - sentsize);
        if (n == -1)
        { warning("write failed: %s", strerror(errno));
          break;
        }
        sentsize += n;
      }
      exit(0);
    } else if (pid==-1)
      error("cannot fork: %s", strerror(errno));
    else
      debug(1, "serv: process %u started", pid);
    close(new_sock);
  }
}
#endif

