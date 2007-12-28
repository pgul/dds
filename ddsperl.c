
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

#include "dds.h"

/* perl prior to 5.6 support */
#ifndef get_sv
#  define get_sv perl_get_sv
#endif

#ifndef eval_pv
#  define eval_pv perl_eval_pv
#endif

#ifndef newSVuv
#  define newSVuv newSViv
#endif

#ifndef sv_undef
#  define sv_undef PL_sv_undef
#endif

#ifndef aTHX_
#  define aTHX_
#endif

static PerlInterpreter *perl = NULL;
static int perl_ok_alarm_start, perl_ok_alarm_finish, perl_ok_alarm_cont;
static int perl_ok_onexit, perl_ok_check;

static int perl_on_exit(void);

/* =========================== err handling ========================== */
static void perl_warn_str (char *str)
{
  char c, *cp;
  while (str && *str) {
    cp = strchr(str, '\n');
    c  = 0;
    if (cp) {
      c = *cp;
      *cp = 0;
    }
    warning("Perl error: %s", str);
    if (cp) *cp = c;
    else break;
    str = cp + 1;
  }
}

static void perl_warn_sv (SV* sv)
{
  STRLEN n_a;
  char *str = (char *)SvPV(sv, n_a);
  perl_warn_str(str);
}

static XS(perl_warn)
{
  dXSARGS;
  if (items == 1)
    perl_warn_sv(ST(0));
  XSRETURN_EMPTY;
}

/* handle multi-line perl eval error message */
static void sub_err(char *func)
{
  STRLEN len;
  char *s, *p;

  p = SvPV(ERRSV, len);
  if (len)
  { 
    s = malloc(len+1);
    strncpy(s, p, len);
    s[len] = '\0';
  }
  else
    s = "(empty error message)";
  if (strchr(s, '\n') == NULL)
    warning("Perl %s error: %s", func, s);
  else
  {
    p = s;
    warning("Perl %s error below:", func);
    while (*p && (*p != '\n' || *(p+1)))
    {
      char *r = strchr(p, '\n');
      if (r)
      {
        *r = 0;
        warning("  %s", p);
        p = r+1;
      } else
      {
        warning("  %s", p);
        break;
      }
    }
  }
  free(s);
}

XS(boot_DynaLoader);

#ifdef pTHXo
static void xs_init(pTHXo)
#else
static void xs_init(void)
#endif
{
  static char *file = __FILE__;

  dXSUB_SYS;
  newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);
  newXS("dds_warn", perl_warn, file);
}

static char *perlargs[] = {"", NULL, NULL, NULL};
/* init perl, parse hooks file, return success */
int perl_init(char *perlfile)
{
  int rc, i;
  SV *sv;
  char cmd[1024];

  debug(1, "perl_init(): %s", perlfile);
  perl_ok_alarm_start = perl_ok_alarm_finish = perl_ok_alarm_cont = 0;
  perl_ok_onexit = perl_ok_check = 0;
  /* try to find out the actual path to perl script and set dir to -I */
  i = 1;
  perlargs[i++] = "-e";
  perlargs[i++] = "0";
  /* check perm */
  if (access(perlfile, R_OK))
    return 1;
  /* init perl */
  perl = perl_alloc();
  perl_construct(perl);
  rc = perl_parse(perl, xs_init, i, perlargs, NULL);
  debug(1, "perl_init(): parse rc=%d", rc);
  /* can't parse */
  if (rc)
  {
    perl_destruct(perl);
    perl_free(perl);
    perl = NULL;
    warning("Can't parse %s, perl filtering disabled", perlfile);
    return 1;
  }
  /* Set warn and die hooks */
  if (PL_warnhook) SvREFCNT_dec (PL_warnhook);
  if (PL_diehook ) SvREFCNT_dec (PL_diehook );
  PL_warnhook = newRV_inc ((SV*) perl_get_cv ("dds_warn", TRUE));
  PL_diehook  = newRV_inc ((SV*) perl_get_cv ("dds_warn", TRUE));
  /* run main program body */
  debug(2, "perl_init(): running body");
  cmd[sizeof(cmd)-1] = '\0';
  strcpy(cmd, "do '");
  strncat (cmd, perlfile, sizeof(cmd)-1);
  strncat (cmd, "'; $@ ? $@ : '';", sizeof(cmd)-1);
  sv = perl_eval_pv (cmd, TRUE);
  if (!SvPOK(sv)) {
    warning("Syntax error in internal perl expression: %s", cmd);
    rc = 1;
  } else if (SvTRUE (sv)) {
    perl_warn_sv (sv);
    rc = 1;
  }
  if (rc) {
    perl_destruct(perl);
    perl_free(perl);
    perl = NULL;
    return rc;
  }
  if (perl_get_cv("alarm_start",   FALSE)) perl_ok_alarm_start  = 1;
  if (perl_get_cv("alarm_finish",  FALSE)) perl_ok_alarm_finish = 1;
  if (perl_get_cv("alarm_cont",    FALSE)) perl_ok_alarm_cont   = 1;
  if (perl_get_cv("on_exit",       FALSE)) perl_ok_onexit       = 1;
  if (perl_get_cv("check",         FALSE)) perl_ok_check        = 1;
  debug(2, "perl_init(): end");
  return 0;
}

/* deallocate perl, call on_exit() */
void perl_done(void)
{
  debug(1, "perl_done()");
  if (perl) {
    perl_on_exit();
    debug(3, "perl_done(): destructing perl");
    perl_destruct(perl);
    perl_free(perl);
    perl = NULL;
    debug(3, "perl_done(): end");
  }
}

/* hooks */
int perl_alarm_event(struct alarm_t *pa, int event)
{
  char *func;
  int rc, *perl_ok;
  SV *svret, *svcount, *svin, *svcp, *svby, *svip, *svid, *svinhibited;
  SV *svlimit, *svsafelimit, *svinterval;

  if (event == ALARM_START)
  { func = "alarm_start";
    perl_ok = &perl_ok_alarm_start;
  } else if (event == ALARM_FINISH)
  { func = "alarm_finish";
    perl_ok = &perl_ok_alarm_finish;
  } else
  { func = "alarm_cont";
    perl_ok = &perl_ok_alarm_cont;
  }
  if (*perl_ok)
  {
    dSP;
    if ((svcount = perl_get_sv("count", TRUE))) sv_setiv(svcount, pa->count);
    if ((svin    = perl_get_sv("in",    TRUE))) sv_setiv(svin,    pa->in);
    if ((svid    = perl_get_sv("id",    TRUE))) sv_setpv(svid,    pa->id);
    if ((svlimit = perl_get_sv("limit", TRUE))) sv_setiv(svlimit, pa->limit);
    if ((svsafelimit = perl_get_sv("safelimit", TRUE))) sv_setiv(svsafelimit, pa->safelimit);
    if ((svinhibited = perl_get_sv("inhibited", TRUE))) sv_setiv(svinhibited, pa->inhibited ? 1 : 0);
    if ((svcp    = perl_get_sv("cp",    TRUE))) sv_setpv(svcp, cp2str(pa->cp));
    if ((svby    = perl_get_sv("by",    TRUE))) sv_setpv(svcp, by2str(pa->by));
    if ((svip    = perl_get_sv("ip",    TRUE))) sv_setpv(svip, printip(pa->ip, pa->preflen, pa->by, pa->in));
    if ((svinterval = perl_get_sv("interval", TRUE))) sv_setiv(svinterval, check_interval);
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    PUTBACK;
    perl_call_pv(func, G_EVAL|G_SCALAR);
    SPAGAIN;
    svret=POPs;
    if (!SvOK(svret)) rc = 1;
    else rc = SvIV(svret);
    PUTBACK;
    FREETMPS;
    LEAVE;
    if (SvTRUE(ERRSV)) sub_err(func);
    return rc;
  }
  return 1;
}

int perl_check(unsigned char *ip, u_long count, struct checktype *pc)
{
  char *func;
  int rc;
  SV *svret, *svcount, *svin, *svcp, *svby, *svip;
  SV *svlimit, *svsafelimit, *svinterval;

  func = "check";
  if (perl_ok_check)
  {
    dSP;
    if ((svcount = perl_get_sv("count", TRUE))) sv_setiv(svcount, count);
    if ((svin    = perl_get_sv("in",    TRUE))) sv_setiv(svin,    pc->in);
    if ((svlimit = perl_get_sv("limit", TRUE))) sv_setiv(svlimit, pc->limit);
    if ((svsafelimit = perl_get_sv("safelimit", TRUE))) sv_setiv(svsafelimit, pc->safelimit);
    if ((svcp    = perl_get_sv("cp",    TRUE))) sv_setpv(svcp, cp2str(pc->checkpoint));
    if ((svby    = perl_get_sv("by",    TRUE))) sv_setpv(svcp, by2str(pc->by));
    if ((svip    = perl_get_sv("ip",    TRUE))) sv_setpv(svip, printip(ip, pc->preflen, pc->by, pc->in));
    if ((svinterval = perl_get_sv("interval", TRUE))) sv_setiv(svinterval, check_interval);
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    PUTBACK;
    perl_call_pv("check", G_EVAL|G_SCALAR);
    SPAGAIN;
    svret=POPs;
    if (!SvOK(svret)) rc = 1;
    else rc = SvIV(svret);
    PUTBACK;
    FREETMPS;
    LEAVE;
    if (SvTRUE(ERRSV)) sub_err(func);
    return rc;
  }
  return 1;
}


static int perl_on_exit(void)
{
  char *func = "on_exit";
  int rc;
  SV *svret;

  if (perl_ok_onexit)
  {
    dSP;
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    PUTBACK;
    perl_call_pv(func, G_EVAL|G_SCALAR);
    SPAGAIN;
    svret=POPs;
    if (!SvOK(svret)) rc = 1;
    else rc = SvIV(svret);
    PUTBACK;
    FREETMPS;
    LEAVE;
    if (SvTRUE(ERRSV)) sub_err(func);
    return rc;
  }
  return 1;
}

