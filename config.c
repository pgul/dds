#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <pwd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#else
#include <net/if.h>
#include <netinet/if_ether.h>
#endif
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif
#include "dds.h"

struct checktype *checkhead=NULL;
char iface[32]=IFACE;
char logname[256]=LOGNAME, snapfile[256]=SNAPFILE, pidfile[256]=PIDFILE;
int  check_interval=CHECK_INTERVAL, expire_interval=EXPIRE_INTERVAL;
char alarmcmd[1024], noalarmcmd[1024];
uid_t uid;
static struct checktype *checktail;

static void read_ip(char *p, u_long *ip, u_long *mask, int *pref_len)
{ char c, *p1;

  for (p1=p; *p1 && (isdigit(*p1) || *p1=='.'); p1++);
  c=*p1;
  *p1='\0';
  *ip = inet_addr(p);
  *pref_len = 32;
  *mask = 0xfffffffful;
  if (c=='/')
  { *pref_len = atoi(p1+1);
    if (*pref_len == 0)
      *mask = 0;
    else {
      (*mask)<<=(32-*pref_len);
      (*mask)=htonl(*mask);
    }
  }
  *p1=c; p=p1;
  if ((*ip & *mask) != *ip)
  { unsigned long masked = (*ip & *mask);
    printf("Warning: %u.%u.%u.%u inconsistent with /%d (mask %u.%u.%u.%u)!\n",
           ((char *)ip)[0], ((char *)ip)[1],
           ((char *)ip)[2], ((char *)ip)[3],
           atoi(p+1),
           ((char *)mask)[0], ((char *)mask)[1],
           ((char *)mask)[2], ((char *)mask)[3]);
    printf("ip & mask is %u.%u.%u.%u\n",
           ((char *)&masked)[0], ((char *)&masked)[1],
           ((char *)&masked)[2], ((char *)&masked)[3]);
  }
}

static int parse_line(char *str)
{
  char *p;
  struct checktype *pc;

  p=strchr(str, '\n');
  if (p) *p='\0';
  p=strchr(str, '#');
  if (p) *p='\0';
  for (p=str; isspace(*p); p++);
  if (*p=='\0') return 0;
  if (p!=str) strcpy(str, p);
  if (str[0]=='\0') return 0;
  for (p=str+strlen(str)-1; isspace(*p); *p--='\0');
  p=str;
  if (strncmp(p, "mymac=", 6)==0)
  { short int m[3];
    sscanf(p+6, "%04hx.%04hx.%04hx", m, m+1, m+2);
    m[0] = htons(m[0]);
    m[1] = htons(m[1]);
    m[2] = htons(m[2]);
    memcpy(my_mac, m, ETHER_ADDR_LEN);
    return 0;
  }
  if (strncmp(p, "iface=", 6)==0)
  { strncpy(iface, p+6, sizeof(iface)-1);
    return 0;
  }
  if (strncmp(p, "log=", 4)==0)
  { strncpy(logname, p+4, sizeof(logname)-1);
    return 0;
  }
  if (strncmp(p, "snap=", 5)==0)
  { strncpy(snapfile, p+5, sizeof(snapfile)-1);
    return 0;
  }
  if (strncmp(p, "pid=", 4)==0)
  { strncpy(pidfile, p+4, sizeof(pidfile)-1);
    return 0;
  }
  if (strncmp(p, "interval=", 9)==0)
  { check_interval = atoi(p+9);
    if (check_interval == 0) check_interval=CHECK_INTERVAL;
    return 0;
  }
  if (strncmp(p, "expire=", 7)==0)
  { expire_interval = atoi(p+7);
    if (expire_interval == 0) expire_interval=EXPIRE_INTERVAL;
    return 0;
  }
  if (strncmp(p, "user=", 5)==0)
  { struct passwd *pw = getpwnam(p+5);
    if (pw)
      uid = pw->pw_uid;
    else
      fprintf(stderr, "Warning: user %s unknown\n", p+5);
    return 0;
  }
  if (strncmp(p, "alarm=", 6)==0)
  {
    p+=6;
    if (*p == '\"' && p[1]) {
      strncpy(alarmcmd, p+1, sizeof(alarmcmd)-1);
      p=alarmcmd+strlen(alarmcmd)-1;
      if (*p == '\"') *p='\0';
    } else
      strncpy(alarmcmd, p, sizeof(alarmcmd)-1);
    return 0;
  }
  if (strncmp(p, "noalarm=", 8)==0)
  {
    p+=8;
    if (*p == '\"' && p[1]) {
      strncpy(noalarmcmd, p+1, sizeof(noalarmcmd)-1);
      p=noalarmcmd+strlen(noalarmcmd)-1;
      if (*p == '\"') *p='\0';
    } else
      strncpy(noalarmcmd, p, sizeof(noalarmcmd)-1);
    return 0;
  }
  for (p=str; *p && !isspace(*p); p++);
  if (*p) *p++='\0';
  if (strchr(str, '=')) return 0; /* keyword */
  /* it's alarm rule */
  if (strcmp(str, "check") != 0)
  {
    printf("Unknown keyword %s in config ignored\n", str);
    return 0;
  }
  /* create structure */
  pc = calloc(1, sizeof(*pc));
  while (*p && isspace(*p)) p++;
  if (!*p) {
incorr:
    printf("Incorrect check line in config ignored\n");
    free(pc);
    return 0;
  }
  if (strncmp(p, "pps", 3)==0)
    pc->pps = 1;
  else if (strncmp(p, "bps", 3)==0)
    pc->pps = 0;
  else
    goto incorr;
  while (*p && !isspace(*p)) p++;
  while (*p && isspace(*p)) p++;
  if (strncmp(p, "in", 2) == 0)
    pc->in = 1;
  else if (strncmp(p, "out", 3) == 0)
    pc->in = 0;
  else if (strncmp(p, "any", 3) == 0)
    pc->in = -1;
  else goto incorr;
  while (*p && !isspace(*p)) p++;
  while (*p && isspace(*p)) p++;
  read_ip(p, &pc->ip, &pc->mask, &pc->preflen);
  while (*p && !isspace(*p)) p++;
  while (*p && isspace(*p)) p++;
  pc->limit = strtoul(p, NULL, 10);
  if (pc->limit == 0) goto incorr;
  if (pc->pps == 0) pc->limit /= 8; /* bps -> cps */
  while (*p && !isspace(*p)) p++;
  while (*p && isspace(*p)) p++;
  pc->safelimit = strtoul(p, NULL, 10);
  if (pc->safelimit == 0) goto incorr;
  if (pc->pps == 0) pc->safelimit /= 8;
  for (;;) {
    while (*p && !isspace(*p)) p++;
    while (*p && isspace(*p)) p++;
    if (*p == '\0') break;
    if (strncmp(p, "byhost", 6) == 0)
      pc->octet = calloc(256, sizeof(struct octet));
    else if (strncmp(p, "break", 5) == 0)
      pc->last = 1;
  }
  if (checkhead == NULL)
    checkhead = checktail = pc;
  else {
    checktail->next = pc;
    checktail = pc;
  }
  return 0;
}

static int parse_file(FILE *f)
{
  FILE *finc;
  char str[256];
  char *p, *p1;

  while (fgets(str, sizeof(str), f))
  {
    if (strncasecmp(str, "@include", 8) == 0 && isspace(str[8]))
    {
      for (p=str+9; *p && isspace(*p); p++);
      if (*p=='\"')
      {
        p++;
	p1=strchr(p, '\"');
	if (p1==NULL)
	{
          printf("Unmatched quotes in include, ignored: %s\n", str);
	  continue;
	}
	*p1='\0';
      } else
      { for (p1=p; *p1 && !isspace(*p1); p1++);
        *p1='\0';
      }
      if ((finc=fopen(p, "r")) == NULL)
      {
        printf("Can't open %s: %s, include ignored\n", p, strerror(errno));
	continue;
      }
      parse_file(finc);
      fclose(finc);
      continue;
    }
    parse_line(str);
  } 
  return 0;
}

static void freeoctet(struct octet *po)
{
  int i;

  for (i=0; i<256; i++)
    if (po[i].octet)
      freeoctet(po[i].octet);
  free(po);
}

static void freecheck(struct checktype *pc)
{
  if (pc->octet)
    freeoctet(pc->octet);
  free(pc);
}

int config(char *name)
{
  FILE *f;

  if (strcmp(logname, "syslog") == 0)
    closelog();
  f = fopen(name, "r");
  if (f==NULL)
  { fprintf(stderr, "Can't open %s: %s!\n", name, strerror(errno));
    return -1;
  }
  /* free check list */
  for (checktail=checkhead; checktail;)
  {
    checktail = checktail->next;
    freecheck(checkhead);
    checkhead = checktail;
  }
  parse_file(f);
  fclose(f);
  if (strcmp(logname, "syslog") == 0)
    openlog("dds", LOG_PID, LOG_DAEMON);
  return 0;
}

