/*
 * Copyright (c) 2003, Trent Nelson, <trent@arpa.com>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTIFSTAT_ERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <net/if.h>
#include <net/if_mib.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <fnmatch.h>

#include <altq/altq.h>
#include <altq/altq_cbq.h>
#include <altq/altq_priq.h>
#include <altq/altq_hfsc.h>

#include <net/pfvar.h>

#include "systat.h"
#include "extern.h"
#include "convtbl.h"

				/* Column numbers */

#define C1	0		/*  0-19 */
#define C2	20		/* 20-39 */
#define C3	40		/* 40-59 */
#define C4	60		/* 60-80 */
#define C5	80		/* Used for label positioning. */

static const int col0 = 0;
static const int col1 = C1;
static const int col2 = C2;
static const int col3 = C3;
static const int col4 = C4;
static const int col5 = C5;

static SLIST_HEAD(, qcol)		qcols;
static SLIST_HEAD(, if_stat)		curlist;
static int pf_fd = -1;
static int qccols;
static int TopSection1;
static int TopSection2;
static int TopSection3;

struct qcol {
	SLIST_ENTRY(qcol) link;
	char *qname;
	int col;
};

typedef struct qcol qcol_t;

union class_stats {
	class_stats_t		cbq;
	struct priq_classstats	priq;
	struct hfsc_classstats	hfsc;
};

struct queue_stats {
	SLIST_ENTRY(queue_stats) link;
	struct pfioc_altq	pa;
	struct pfioc_qstats	pq;
	qcol_t			*qc;
	union class_stats	ostats;
	union class_stats	nstats;
};

typedef struct queue_stats queue_stats_t;

struct if_stat {
	SLIST_ENTRY(if_stat)	 link;
	SLIST_HEAD(, queue_stats) queues;
	char	if_name[IF_NAMESIZE];
	struct	ifmibdata if_mib;
	struct	timeval tv;
	struct	timeval tv_lastchanged;
	uint64_t if_in_curtraffic;
	uint64_t if_out_curtraffic;
	uint64_t if_in_traffic_peak;
	uint64_t if_out_traffic_peak;
	uint64_t if_in_curpps;
	uint64_t if_out_curpps;
	uint64_t if_in_pps_peak;
	uint64_t if_out_pps_peak;
	u_int	if_row;			/* Index into ifmib sysctl */
	u_int	row;			/* display row (relative) */
	int 	if_ypos;		/* -1 if not being displayed */
	u_int	display;
	u_int	match;
};

typedef struct if_stat if_stat_t;

extern	 int curscale;
extern	 char *matchline;
extern	 int showpps;
extern	 int needsort;

static	 int needclear = 0;

static	 void  load_altqs(void);
static	 void  print_altq(if_stat_t *p, queue_stats_t *q);
static	 void  right_align_string(struct if_stat *);
static	 void  getifmibdata(const int, struct ifmibdata *);
static	 void  sort_interface_list(void);
static	 u_int getifnum(void);

#define IFSTAT_ERR(n, s)	do {					\
	putchar('\014');						\
	closeifstat(wnd);						\
	err((n), (s));							\
} while (0)

#define TOPLINE 3
#define TOPQSTART	20
#define TOPQWIDTH	10
#define TOPLABEL \
"      Interface           Traffic               Peak                Total"

#define STARTING_ROW	(TOPLINE + 1)
#define ROW_SPACING	(3)

#define IN_col2		(showpps ? ifp->if_in_curpps : ifp->if_in_curtraffic)
#define OUT_col2	(showpps ? ifp->if_out_curpps : ifp->if_out_curtraffic)
#define IN_col3		(showpps ? \
		ifp->if_in_pps_peak : ifp->if_in_traffic_peak)
#define OUT_col3	(showpps ? \
		ifp->if_out_pps_peak : ifp->if_out_traffic_peak)
#define IN_col4		(showpps ? \
	ifp->if_mib.ifmd_data.ifi_ipackets : ifp->if_mib.ifmd_data.ifi_ibytes)
#define OUT_col4	(showpps ? \
	ifp->if_mib.ifmd_data.ifi_opackets : ifp->if_mib.ifmd_data.ifi_obytes)

#define EMPTY_COLUMN 	"                    "
#define CLEAR_COLUMN(y, x)	mvprintw((y), (x), "%20s", EMPTY_COLUMN);

#define DOPUTRATE(c, r, d)	do {					\
	CLEAR_COLUMN(r, c);						\
	if (showpps) {							\
		mvprintw(r, (c), "%10.3f %cp%s  ",			\
			 convert(d##_##c, curscale),			\
			 *get_string(d##_##c, curscale),		\
			 "/s");						\
	}								\
	else {								\
		mvprintw(r, (c), "%10.3f %s%s  ",			\
			 convert(d##_##c, curscale),			\
			 get_string(d##_##c, curscale),			\
			 "/s");						\
	}								\
} while (0)

#define DOPUTTOTAL(c, r, d)	do {					\
	CLEAR_COLUMN((r), (c));						\
	if (showpps) {							\
		mvprintw((r), (c), "%12.3f %cp  ",			\
			 convert(d##_##c, SC_AUTO),			\
			 *get_string(d##_##c, SC_AUTO));		\
	}								\
	else {								\
		mvprintw((r), (c), "%12.3f %s  ",			\
			 convert(d##_##c, SC_AUTO),			\
			 get_string(d##_##c, SC_AUTO));			\
	}								\
} while (0)

#define PUTRATE(c, r)	do {						\
	DOPUTRATE(c, (r), IN);						\
	DOPUTRATE(c, (r)+1, OUT);					\
} while (0)

#define PUTTOTAL(c, r)	do {						\
	DOPUTTOTAL(c, (r), IN);						\
	DOPUTTOTAL(c, (r)+1, OUT);					\
} while (0)

#define PUTNAME(p) do {							\
	mvprintw(p->if_ypos, 0, "%s", p->if_name);			\
	mvprintw(p->if_ypos, col2-3, "%s", (const char *)"in");		\
	mvprintw(p->if_ypos+1, col2-3, "%s", (const char *)"out");	\
} while (0)

WINDOW *
openifstat(void)
{
	struct if_stat *p = NULL;
	u_int n = 0, i = 0;

	n = getifnum();		/* NOTE: can return < 0 */

	SLIST_INIT(&curlist);
	for (i = 0; i < n; i++) {
		p = (struct if_stat *)calloc(1, sizeof(struct if_stat));
		if (p == NULL)
			IFSTAT_ERR(1, "out of memory");
		SLIST_INSERT_HEAD(&curlist, p, link);
		p->if_row = i+1;
		getifmibdata(p->if_row, &p->if_mib);
		right_align_string(p);

		/*
		 * Initially, we only display interfaces that have
		 * received some traffic
		 */
		if (p->if_mib.ifmd_data.ifi_ibytes != 0)
			p->display = 1;
	}

	sort_interface_list();

	return (subwin(stdscr, LINES-3-1, 0, MAINWIN_ROW, 0));
}

void
closeifstat(WINDOW *w)
{
	struct if_stat	*node = NULL;

	while (!SLIST_EMPTY(&curlist)) {
		node = SLIST_FIRST(&curlist);
		SLIST_REMOVE_HEAD(&curlist, link);
		free(node);
	}

	if (w != NULL) {
		wclear(w);
		wrefresh(w);
		delwin(w);
	}

	return;
}

void
labelifstat(void)
{

	wmove(wnd, TOPLINE, 0);
	wclrtoeol(wnd);
	mvprintw(TOPLINE, 0, "%s", TOPLABEL);

	return;
}

void
showifstat(void)
{
	struct	if_stat *ifp = NULL;
	
	SLIST_FOREACH(ifp, &curlist, link) {
		if (ifp->if_ypos < LINES - 3 && ifp->if_ypos != -1)
			if (ifp->display == 0 || ifp->match == 0) {
					wmove(wnd, ifp->if_ypos, 0);
					wclrtoeol(wnd);
					wmove(wnd, ifp->if_ypos + 1, 0);
					wclrtoeol(wnd);
			}
			else {
				PUTNAME(ifp);
				PUTRATE(col2, ifp->if_ypos);
				PUTRATE(col3, ifp->if_ypos);
				PUTTOTAL(col4, ifp->if_ypos);
			}
	}

	return;
}

int
initifstat(void)
{
	struct   if_stat *p = NULL;
	u_int	 n = 0, i = 0;

	n = getifnum();
	if (n <= 0)
		return (-1);

	SLIST_INIT(&curlist);

	for (i = 0; i < n; i++) {
		p = (struct if_stat *)calloc(1, sizeof(struct if_stat));
		if (p == NULL)
			IFSTAT_ERR(1, "out of memory");
		SLIST_INSERT_HEAD(&curlist, p, link);
		p->if_row = i+1;
		getifmibdata(p->if_row, &p->if_mib);
		right_align_string(p);
		p->match = 1;

		/*
		 * Initially, we only display interfaces that have
		 * received some traffic.
		 */
		if (p->if_mib.ifmd_data.ifi_ibytes != 0)
			p->display = 1;
	}

	sort_interface_list();

	return (1);
}

void
fetchifstat(void)
{
	struct	if_stat *ifp = NULL;
	struct	timeval tv, new_tv, old_tv;
	double	elapsed = 0.0;
	uint64_t new_inb, new_outb, old_inb, old_outb = 0;
	uint64_t new_inp, new_outp, old_inp, old_outp = 0;

	SLIST_FOREACH(ifp, &curlist, link) {
		/*
		 * Grab a copy of the old input/output values before we
		 * call getifmibdata().
		 */
		old_inb = ifp->if_mib.ifmd_data.ifi_ibytes;
		old_outb = ifp->if_mib.ifmd_data.ifi_obytes;
		old_inp = ifp->if_mib.ifmd_data.ifi_ipackets;
		old_outp = ifp->if_mib.ifmd_data.ifi_opackets;
		ifp->tv_lastchanged = ifp->if_mib.ifmd_data.ifi_lastchange;

		(void)gettimeofday(&new_tv, NULL);
		(void)getifmibdata(ifp->if_row, &ifp->if_mib);

		new_inb = ifp->if_mib.ifmd_data.ifi_ibytes;
		new_outb = ifp->if_mib.ifmd_data.ifi_obytes;
		new_inp = ifp->if_mib.ifmd_data.ifi_ipackets;
		new_outp = ifp->if_mib.ifmd_data.ifi_opackets;

		/* Display interface if it's received some traffic. */
		if (new_inb > 0 && old_inb == 0) {
			ifp->display = 1;
			needsort = 1;
		}

		/*
		 * The rest is pretty trivial.  Calculate the new values
		 * for our current traffic rates, and while we're there,
		 * see if we have new peak rates.
		 */
		old_tv = ifp->tv;
		timersub(&new_tv, &old_tv, &tv);
		elapsed = tv.tv_sec + (tv.tv_usec * 1e-6);

		ifp->if_in_curtraffic = new_inb - old_inb;
		ifp->if_out_curtraffic = new_outb - old_outb;

		ifp->if_in_curpps = new_inp - old_inp;
		ifp->if_out_curpps = new_outp - old_outp;

		/*
		 * Rather than divide by the time specified on the comm-
		 * and line, we divide by ``elapsed'' as this is likely
		 * to be more accurate.
		 */
		ifp->if_in_curtraffic /= elapsed;
		ifp->if_out_curtraffic /= elapsed;
		ifp->if_in_curpps /= elapsed;
		ifp->if_out_curpps /= elapsed;

		if (ifp->if_in_curtraffic > ifp->if_in_traffic_peak)
			ifp->if_in_traffic_peak = ifp->if_in_curtraffic;

		if (ifp->if_out_curtraffic > ifp->if_out_traffic_peak)
			ifp->if_out_traffic_peak = ifp->if_out_curtraffic;

		if (ifp->if_in_curpps > ifp->if_in_pps_peak)
			ifp->if_in_pps_peak = ifp->if_in_curpps;

		if (ifp->if_out_curpps > ifp->if_out_pps_peak)
			ifp->if_out_pps_peak = ifp->if_out_curpps;

		ifp->tv.tv_sec = new_tv.tv_sec;
		ifp->tv.tv_usec = new_tv.tv_usec;

	}

	if (needsort)
		sort_interface_list();

	return;
}

/*
 * We want to right justify our interface names against the first column
 * (first sixteen or so characters), so we need to do some alignment.
 */
static void
right_align_string(struct if_stat *ifp)
{
	int	 str_len = 0, pad_len = 0;
	char	*newstr = NULL, *ptr = NULL;

	if (ifp == NULL || ifp->if_mib.ifmd_name == NULL)
		return;
	else {
		/* string length + '\0' */
		str_len = strlen(ifp->if_mib.ifmd_name)+1;
		pad_len = IF_NAMESIZE-(str_len);

		newstr = ifp->if_name;
		ptr = newstr + pad_len;
		(void)memset((void *)newstr, (int)' ', IF_NAMESIZE);
		(void)strncpy(ptr, (const char *)&ifp->if_mib.ifmd_name,
			      str_len);
	}

	return;
}

static int
check_match(const char *ifname) 
{
	char *p = matchline, *c, t;
	int match = 0, mlen;
	
	if (matchline == NULL)
		return (0);

	/* Strip leading whitespaces */
	while (*p == ' ')
		p ++;

	c = p;
	while ((mlen = strcspn(c, " ;,")) != 0) {
		p = c + mlen;
		t = *p;
		if (p - c > 0) {
			*p = '\0';
			if (fnmatch(c, ifname, FNM_CASEFOLD) == 0) {
				*p = t;
				return (1);
			}
			*p = t;
			c = p + strspn(p, " ;,");
		}
		else {
			c = p + strspn(p, " ;,");
		}
	}

	return (match);
}

/*
 * This function iterates through our list of interfaces, identifying
 * those that are to be displayed (ifp->display = 1).  For each interf-
 * rface that we're displaying, we generate an appropriate position for
 * it on the screen (ifp->if_ypos).
 *
 * This function is called any time a change is made to an interface's
 * ``display'' state.
 */
void
sort_interface_list(void)
{
	struct	if_stat	*ifp = NULL;
	u_int	y = 0;

	y = STARTING_ROW;
	SLIST_FOREACH(ifp, &curlist, link) {
		if (matchline && !check_match(ifp->if_mib.ifmd_name))
			ifp->match = 0;
		else
			ifp->match = 1;
		if (ifp->display && ifp->match) {
			ifp->if_ypos = y;
			y += ROW_SPACING;
		}
		else
			ifp->if_ypos = -1;
	}
	
	needsort = 0;
	needclear = 1;
}

static
unsigned int
getifnum(void)
{
	u_int	data    = 0;
	size_t	datalen = 0;
	static	int name[] = { CTL_NET,
			       PF_LINK,
			       NETLINK_GENERIC,
			       IFMIB_SYSTEM,
			       IFMIB_IFCOUNT };

	datalen = sizeof(data);
	if (sysctl(name, 5, (void *)&data, (size_t *)&datalen, (void *)NULL,
	    (size_t)0) != 0)
		IFSTAT_ERR(1, "sysctl error");
	return (data);
}

static void
getifmibdata(int row, struct ifmibdata *data)
{
	size_t	datalen = 0;
	static	int name[] = { CTL_NET,
			       PF_LINK,
			       NETLINK_GENERIC,
			       IFMIB_IFDATA,
			       0,
			       IFDATA_GENERAL };
	datalen = sizeof(*data);
	name[4] = row;

	if ((sysctl(name, 6, (void *)data, (size_t *)&datalen, (void *)NULL,
	    (size_t)0) != 0) && (errno != ENOENT))
		IFSTAT_ERR(2, "sysctl error getting interface data");
}

int
cmdifstat(const char *cmd, const char *args)
{
	int	retval = 0;

	retval = ifcmd(cmd, args);
	/* ifcmd() returns 1 on success */
	if (retval == 1) {
		if (needclear) {
			showifstat();
			refresh();
			werase(wnd);
			labelifstat();
			needclear = 0;
		}
	}
	return (retval);
}

WINDOW *
openaltqs(void)
{
	if_stat_t *p = NULL;
	u_int	 n = 0, i = 0;

	pf_fd = open("/dev/pf", O_RDONLY);

	n = getifnum();		/* NOTE: can return < 0 */

	SLIST_INIT(&curlist);
	SLIST_INIT(&qcols);
	for (i = 0; i < n; i++) {
		p = (if_stat_t *)calloc(1, sizeof(if_stat_t));
		if (p == NULL)
			IFSTAT_ERR(1, "out of memory");
		SLIST_INSERT_HEAD(&curlist, p, link);
		SLIST_INIT(&p->queues);
		p->if_row = i+1;
		getifmibdata(p->if_row, &p->if_mib);
		right_align_string(p);

		/*
		 * Initially, we only display interfaces that have
		 * received some traffic.
		 */
		if (p->if_mib.ifmd_data.ifi_ibytes != 0)
			p->display = 1;
	}
	load_altqs();

	sort_interface_list();

	return (subwin(stdscr, LINES-1-5, 0, 5, 0));
}

void
closealtqs(WINDOW *w)
{
	if_stat_t	*node = NULL;
	queue_stats_t	*q;

	while (!SLIST_EMPTY(&curlist)) {
		node = SLIST_FIRST(&curlist);
		SLIST_REMOVE_HEAD(&curlist, link);
		while ((q = SLIST_FIRST(&node->queues)) != NULL) {
			SLIST_REMOVE_HEAD(&node->queues, link);
			free(q);
		}
		free(node);
	}
	while (!SLIST_EMPTY(&qcols)) {
		qcol_t *qc = SLIST_FIRST(&qcols);
		SLIST_REMOVE_HEAD(&qcols, link);
		free(qc->qname);
		free(qc);
	}
	qccols = 0;

	if (w != NULL) {
		wclear(w);
		wrefresh(w);
		delwin(w);
	}

	if (pf_fd >= 0) {
		close(pf_fd);
		pf_fd = -1;
	}

	return;
}

void
labelaltqs(void)
{
	wmove(wnd, TOPLINE, 0);
	wclrtoeol(wnd);
}

void
showaltqs(void)
{
	if_stat_t *p = NULL;
	queue_stats_t	*q;
	qcol_t		*qc;

	mvprintw(TopSection1, 0, "        PACKETS");
	mvprintw(TopSection2, 0, "        BYTES");
	mvprintw(TopSection3, 0, "   DROPS/QLEN");
	SLIST_FOREACH(qc, &qcols, link) {
		mvprintw(TopSection1, TOPQSTART + TOPQWIDTH * qc->col,
			 "%9s", qc->qname);
		mvprintw(TopSection2, TOPQSTART + TOPQWIDTH * qc->col,
			 "%9s", qc->qname);
		mvprintw(TopSection3, TOPQSTART + TOPQWIDTH * qc->col,
			 "%9s", qc->qname);
	}

	SLIST_FOREACH(p, &curlist, link) {
		if (p->display == 0)
			continue;
		mvprintw(TopSection1 + p->row, 0, "%s", p->if_name);
		mvprintw(TopSection2 + p->row, 0, "%s", p->if_name);
		mvprintw(TopSection3 + p->row, 0, "%s", p->if_name);
		SLIST_FOREACH(q, &p->queues, link) {
			print_altq(p, q);
		}
	}
}

int
initaltqs(void)
{
	TopSection1 = TOPLINE;

	return 1;
}


void
fetchaltqs(void)
{
	struct	if_stat *ifp = NULL;
	struct	timeval tv, new_tv, old_tv;
	double	elapsed = 0.0;
	u_int	new_inb, new_outb, old_inb, old_outb = 0;
	u_int	we_need_to_sort_interface_list = 0;

	SLIST_FOREACH(ifp, &curlist, link) {
		/*
		 * Grab a copy of the old input/output values before we
		 * call getifmibdata().
		 */
		old_inb = ifp->if_mib.ifmd_data.ifi_ibytes;
		old_outb = ifp->if_mib.ifmd_data.ifi_obytes;
		ifp->tv_lastchanged = ifp->if_mib.ifmd_data.ifi_lastchange;

		if (gettimeofday(&new_tv, NULL) != 0)
			IFSTAT_ERR(2, "error getting time of day");
		(void)getifmibdata(ifp->if_row, &ifp->if_mib);


                new_inb = ifp->if_mib.ifmd_data.ifi_ibytes;
                new_outb = ifp->if_mib.ifmd_data.ifi_obytes;

		/* Display interface if it's received some traffic. */
		if (new_inb > 0 && old_inb == 0) {
			ifp->display = 1;
			we_need_to_sort_interface_list++;
		}

		/*
		 * The rest is pretty trivial.  Calculate the new values
		 * for our current traffic rates, and while we're there,
		 * see if we have new peak rates.
		 */
                old_tv = ifp->tv;
                timersub(&new_tv, &old_tv, &tv);
                elapsed = tv.tv_sec + (tv.tv_usec * 1e-6);

		ifp->if_in_curtraffic = new_inb - old_inb;
		ifp->if_out_curtraffic = new_outb - old_outb;

		/*
		 * Rather than divide by the time specified on the comm-
		 * and line, we divide by ``elapsed'' as this is likely
		 * to be more accurate.
		 */
                ifp->if_in_curtraffic /= elapsed;
                ifp->if_out_curtraffic /= elapsed;

		if (ifp->if_in_curtraffic > ifp->if_in_traffic_peak)
			ifp->if_in_traffic_peak = ifp->if_in_curtraffic;

		if (ifp->if_out_curtraffic > ifp->if_out_traffic_peak)
			ifp->if_out_traffic_peak = ifp->if_out_curtraffic;

		ifp->tv.tv_sec = new_tv.tv_sec;
		ifp->tv.tv_usec = new_tv.tv_usec;

	}

	load_altqs();

	if (we_need_to_sort_interface_list)
		sort_interface_list();

	return;
}
static void
load_altqs(void)
{
	struct pfioc_altq pa;
	struct pfioc_qstats pq;
	if_stat_t *p;
	queue_stats_t *q;
	qcol_t *qc;
	int i;
	int n;

	bzero(&pa, sizeof(pa));
	bzero(&pq, sizeof(pq));

	if (ioctl(pf_fd, DIOCGETALTQS, &pa))
		return;
	n = pa.nr;
	for (i = 0; i < n; ++i) {
		pa.nr = i;
		if (ioctl(pf_fd, DIOCGETALTQ, &pa))
			return;
		if (pa.altq.qid <= 0)
			continue;

		SLIST_FOREACH(p, &curlist, link) {
			if (strcmp(pa.altq.ifname, p->if_mib.ifmd_name) == 0)
				break;
		}
		if (p == NULL)
			continue;
		SLIST_FOREACH(q, &p->queues, link) {
			if (strcmp(pa.altq.qname, q->pa.altq.qname) == 0)
				break;
		}
		if (q == NULL) {
			q = calloc(1, sizeof(*q));
			q->pa = pa;
			SLIST_INSERT_HEAD(&p->queues, q, link);
		} else {
			q->pa.ticket = pa.ticket;
		}
		q->ostats = q->nstats;
		q->pq.nr = i;
		q->pq.ticket = q->pa.ticket;
		q->pq.buf = &q->nstats;
		q->pq.nbytes = sizeof(q->nstats);
		if (ioctl(pf_fd, DIOCGETQSTATS, &q->pq) < 0) {
			SLIST_REMOVE(&p->queues, q, queue_stats, link);
			free(q);
		}
		SLIST_FOREACH(qc, &qcols, link) {
			if (strcmp(q->pa.altq.qname, qc->qname) == 0)
				break;
		}
		if (qc == NULL) {
			qc = calloc(1, sizeof(*qc));
			qc->qname = strdup(q->pa.altq.qname);
			qc->col = qccols++;
			SLIST_INSERT_HEAD(&qcols, qc, link);
		}
		q->qc = qc;
	}
}

static
void
print_altq(if_stat_t *p, queue_stats_t *q)
{
	uint64_t xmit_pkts;
	uint64_t xmit_bytes;
	uint64_t drop_pkts;
	uint64_t drop_bytes __unused;
	uint64_t qlen;

	switch(q->pa.altq.scheduler) {
	case ALTQT_CBQ:
		xmit_pkts = q->nstats.cbq.xmit_cnt.packets;
		xmit_bytes = q->nstats.cbq.xmit_cnt.bytes;
		drop_pkts = q->nstats.cbq.drop_cnt.packets;
		drop_bytes = q->nstats.cbq.drop_cnt.bytes;
		xmit_pkts -= q->ostats.cbq.xmit_cnt.packets;
		xmit_bytes -= q->ostats.cbq.xmit_cnt.bytes;
		drop_pkts -= q->ostats.cbq.drop_cnt.packets;
		drop_bytes -= q->ostats.cbq.drop_cnt.bytes;
		qlen = 0;
		break;
	case ALTQT_PRIQ:
		xmit_pkts = q->nstats.priq.xmitcnt.packets;
		xmit_bytes = q->nstats.priq.xmitcnt.bytes;
		drop_pkts = q->nstats.priq.dropcnt.packets;
		drop_bytes = q->nstats.priq.dropcnt.bytes;
		xmit_pkts -= q->ostats.priq.xmitcnt.packets;
		xmit_bytes -= q->ostats.priq.xmitcnt.bytes;
		drop_pkts -= q->ostats.priq.dropcnt.packets;
		drop_bytes -= q->ostats.priq.dropcnt.bytes;
		qlen = q->nstats.priq.qlength;
		break;
	case ALTQT_HFSC:
		xmit_pkts = q->nstats.hfsc.xmit_cnt.packets;
		xmit_bytes = q->nstats.hfsc.xmit_cnt.bytes;
		drop_pkts = q->nstats.hfsc.drop_cnt.packets;
		drop_bytes = q->nstats.hfsc.drop_cnt.bytes;
		xmit_pkts -= q->ostats.hfsc.xmit_cnt.packets;
		xmit_bytes -= q->ostats.hfsc.xmit_cnt.bytes;
		drop_pkts -= q->ostats.hfsc.drop_cnt.packets;
		drop_bytes -= q->ostats.hfsc.drop_cnt.bytes;
		qlen = q->nstats.hfsc.qlength;
		break;
	default:
		xmit_pkts = 0;
		xmit_bytes = 0;
		drop_pkts = 0;
		drop_bytes = 0;
		qlen = 0;
		break;
	}
	if (xmit_pkts == 0)
		mvprintw(TopSection1 + p->row,
			 TOPQSTART + q->qc->col * TOPQWIDTH - 1,
			 "%10s", "");
	else
		mvprintw(TopSection1 + p->row,
			 TOPQSTART + q->qc->col * TOPQWIDTH - 1,
			 "%10jd",  (intmax_t)xmit_pkts);

	if (xmit_bytes == 0)
		mvprintw(TopSection2 + p->row,
			 TOPQSTART + q->qc->col * TOPQWIDTH - 1,
			 "%10s", "");
	else
		mvprintw(TopSection2 + p->row,
			 TOPQSTART + q->qc->col * TOPQWIDTH - 1,
			 "%10jd",  (intmax_t)xmit_bytes);
	if (drop_pkts)
		mvprintw(TopSection3 + p->row,
			 TOPQSTART + q->qc->col * TOPQWIDTH - 1,
			 "%10jd",  (intmax_t)drop_pkts);
	else if (qlen)
		mvprintw(TopSection3 + p->row,
			 TOPQSTART + q->qc->col * TOPQWIDTH - 1,
			 "%9jdQ",  (intmax_t)qlen);
	else
		mvprintw(TopSection3 + p->row,
			 TOPQSTART + q->qc->col * TOPQWIDTH - 1,
			 "%10s", "");
}

int
cmdaltqs(const char *cmd, const char *args)
{
	int	retval = 0;

	retval = ifcmd(cmd, args);
	/* ifcmd() returns 1 on success */
	if (retval == 1) {
		showaltqs();
		refresh();
	}

	return retval;
}
