/*-
 * Copyright (c) 2014, by David Carlier <devnexen at gmail.com>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_ptrace_hardening.h"

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/imgact.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/malloc.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/sbuf.h>
#include <sys/limits.h>
#include <sys/queue.h>
#include <sys/jail.h>
#include <sys/libkern.h>

#include <sys/syslimits.h>
#include <sys/param.h>

#include <sys/ptrace_hardening.h>

#include <machine/stdarg.h>

#include <security/mac_bsdextended/mac_bsdextended.h>

static MALLOC_DEFINE(HARDENING_PTRACE, "ptrace hardening",
	"Ptrace Hardening allocations");

static char ptrace_request_flags[PT_FIRSTMACH + 1] = { 0 };
static int ptrace_request_flags_all = 0;

#define PTRACE_REQUEST_FLAG(PTFLAG, name)				\
TUNABLE_STR("hardening.ptrace.flag."#name, 				\
    &ptrace_request_flags[PTFLAG], 1);					\
									\
static int sysctl_ptrace_hardening_##name##_flag(SYSCTL_HANDLER_ARGS);	\
									\
SYSCTL_PROC(_hardening_ptrace_flag, OID_AUTO, name,			\
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE,		\
    NULL, 0, sysctl_ptrace_hardening_##name##_flag, "I",		\
    "Request "#name" flag");						\
									\
int									\
sysctl_ptrace_hardening_##name##_flag(SYSCTL_HANDLER_ARGS)		\
{									\
	struct prison *pr = NULL;					\
	int err, val;                   				\
									\
	pr = ptrace_get_prison(req->td->td_proc);			\
									\
	val = (pr != NULL) ? pr->pr_ptrace_request_flags[PTFLAG] :	\
	    ptrace_request_flags[PTFLAG];				\
	err = sysctl_handle_int(oidp, &val, sizeof(int), req);		\
	if (err || (req->newptr == NULL))				\
		return (err);						\
									\
	switch (val) {							\
	case 0:								\
	case 1:								\
		if ((pr == NULL) || (pr == &prison0))			\
			ptrace_request_flags[PTFLAG] = val;		\
									\
		if (pr != NULL) {					\
			prison_lock(pr);				\
			pr->pr_ptrace_request_flags[PTFLAG] = val;	\
			prison_unlock(pr);				\
		}							\
		break;							\
	default:							\
		return (EINVAL);					\
	}								\
									\
	return (0);							\
}

static void ptrace_hardening_sysinit(void);
static struct prison *ptrace_get_prison(struct proc *);

int ptrace_hardening_status = PTRACE_HARDENING_ENABLED;
int ptrace_hardening_flag_status = PTRACE_HARDENING_REQFLAG_ENABLED;

#ifdef PTRACE_HARDENING_GRP
gid_t ptrace_hardening_allowed_gid = 0;
#endif

FEATURE(ptrace_hardening, "Ptrace call restrictions.");

TUNABLE_INT("hardening.ptrace.status", &ptrace_hardening_status);
TUNABLE_INT("hardening.ptrace.flag_status", &ptrace_hardening_flag_status);

#ifdef PTRACE_HARDENING_GRP
TUNABLE_INT("hardening.ptrace.allowed_gid", &ptrace_hardening_allowed_gid);
#endif

static int sysctl_ptrace_hardening_status(SYSCTL_HANDLER_ARGS);
static int sysctl_ptrace_hardening_flag(SYSCTL_HANDLER_ARGS);
static int sysctl_ptrace_hardening_flagall(SYSCTL_HANDLER_ARGS);

#ifdef PTRACE_HARDENING_GRP
static int sysctl_ptrace_hardening_gid(SYSCTL_HANDLER_ARGS);
#endif

SYSCTL_NODE(_hardening, OID_AUTO, ptrace, CTLFLAG_RD, 0,
    "PTrace settings.");

SYSCTL_NODE(_hardening_ptrace, OID_AUTO, flag, CTLFLAG_RD, 0,
    "PTrace request flags settings.");

SYSCTL_PROC(_hardening_ptrace, OID_AUTO, status,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE,
    NULL, 0, sysctl_ptrace_hardening_status, "I",
    "Restrictions status. "
    "0 - disabled, "
    "1 - enabled");

SYSCTL_PROC(_hardening_ptrace, OID_AUTO, flag_status,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE,
    NULL, 0, sysctl_ptrace_hardening_flag, "I",
    "Flag status");

SYSCTL_PROC(_hardening_ptrace, OID_AUTO, flag_all,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE,
    NULL, 0, sysctl_ptrace_hardening_flagall, "I",
    "Flag status");

#ifdef PTRACE_HARDENING_GRP
SYSCTL_PROC(_hardening_ptrace, OID_AUTO, allowed_gid,
    CTLTYPE_ULONG|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE,
    NULL, 0, sysctl_ptrace_hardening_gid, "LU",
    "Allowed gid");
#endif

PTRACE_REQUEST_FLAG(PT_TRACE_ME, trace_me)
PTRACE_REQUEST_FLAG(PT_READ_I, read_i)
PTRACE_REQUEST_FLAG(PT_READ_D, read_d)
PTRACE_REQUEST_FLAG(PT_WRITE_I, write_i)
PTRACE_REQUEST_FLAG(PT_WRITE_D, write_d)
PTRACE_REQUEST_FLAG(PT_CONTINUE, continue)
PTRACE_REQUEST_FLAG(PT_KILL, kill)
PTRACE_REQUEST_FLAG(PT_STEP, step)
PTRACE_REQUEST_FLAG(PT_ATTACH, attach)
PTRACE_REQUEST_FLAG(PT_DETACH, detach)
PTRACE_REQUEST_FLAG(PT_IO, io);
PTRACE_REQUEST_FLAG(PT_LWPINFO, lwpinfo)
PTRACE_REQUEST_FLAG(PT_GETNUMLWPS, getnumlwps)
PTRACE_REQUEST_FLAG(PT_GETLWPLIST, getlwplist)
PTRACE_REQUEST_FLAG(PT_CLEARSTEP, clearstep)
PTRACE_REQUEST_FLAG(PT_SETSTEP, setstep)
PTRACE_REQUEST_FLAG(PT_SUSPEND, suspend)
PTRACE_REQUEST_FLAG(PT_RESUME, resume)
PTRACE_REQUEST_FLAG(PT_TO_SCE, to_sce)
PTRACE_REQUEST_FLAG(PT_TO_SCX, to_scx)
PTRACE_REQUEST_FLAG(PT_SYSCALL, syscall)
PTRACE_REQUEST_FLAG(PT_FOLLOW_FORK, follow_fork)
PTRACE_REQUEST_FLAG(PT_GETREGS, getregs)
PTRACE_REQUEST_FLAG(PT_SETREGS, setregs)
PTRACE_REQUEST_FLAG(PT_GETFPREGS, getfpregs)
PTRACE_REQUEST_FLAG(PT_SETFPREGS, setfpregs)
PTRACE_REQUEST_FLAG(PT_GETDBREGS, getdbregs)
PTRACE_REQUEST_FLAG(PT_SETDBREGS, setdbregs)
PTRACE_REQUEST_FLAG(PT_VM_TIMESTAMP, vm_timestamp)
PTRACE_REQUEST_FLAG(PT_VM_ENTRY, vm_entry)
PTRACE_REQUEST_FLAG(PT_FIRSTMACH, firstmach)

int
sysctl_ptrace_hardening_status(SYSCTL_HANDLER_ARGS)
{
	struct prison *pr = NULL;
	int err, val;

	pr = ptrace_get_prison(req->td->td_proc);

	val = (pr != NULL) ? pr->pr_ptrace_hardening_status :
	    ptrace_hardening_status;
	err = sysctl_handle_int(oidp, &val, sizeof(int), req);
	if (err || (req->newptr == NULL))
		return (err);

	switch (val) {
	case    PTRACE_HARDENING_DISABLED:
	case    PTRACE_HARDENING_ENABLED:
		if ((pr == NULL) || (pr == &prison0))
			ptrace_hardening_status = val;

		if (pr != NULL) {
			prison_lock(pr);
			pr->pr_ptrace_hardening_status = val;
			prison_unlock(pr);
		}
		break;
	default:
		return (EINVAL);
	}

	return (0);
}

int
sysctl_ptrace_hardening_flag(SYSCTL_HANDLER_ARGS)
{
	struct prison *pr = NULL;
	int err, val;

	pr = ptrace_get_prison(req->td->td_proc);

	val = (pr != NULL) ? pr->pr_ptrace_hardening_flag_status :
	    ptrace_hardening_flag_status;
	err = sysctl_handle_int(oidp, &val, sizeof(int), req);
	if (err || (req->newptr == NULL))
		return (err);

	switch (val) {
	case PTRACE_HARDENING_REQFLAG_ENABLED:
	case PTRACE_HARDENING_REQFLAG_DISABLED:
		if ((pr == NULL) || (pr == &prison0))
			ptrace_hardening_flag_status = val;

		if (pr != NULL) {
			prison_lock(pr);
			pr->pr_ptrace_hardening_flag_status = val;
			prison_unlock(pr);
		}
		break;
	default:
		return (EINVAL);
	}

	return (0);
}

int
sysctl_ptrace_hardening_flagall(SYSCTL_HANDLER_ARGS)
{
	struct prison *pr = NULL;
	struct sysctl_oid_list *oidlist;
	struct sysctl_oid *oid;
	size_t buflen, sysctlpreflen;
	int err, val;

	pr = ptrace_get_prison(req->td->td_proc);
	oidlist = &sysctl___hardening_ptrace_flag.oid_children;
	sysctlpreflen = sizeof("hardening.ptrace.flag.");

	val = (pr != NULL) ? pr->pr_ptrace_request_flags_all :
	    ptrace_request_flags_all;
	err = sysctl_handle_int(oidp, &val, sizeof(int), req);
	if (err || (req->newptr == NULL))
		return (err);

	switch (val) {
	case 0:
	case 1:
		if ((pr == NULL) || (pr == &prison0))
			ptrace_request_flags_all = val;

		if (pr != NULL) {
			prison_lock(pr);
			pr->pr_ptrace_request_flags_all = val;
			prison_unlock(pr);
		}

		SLIST_FOREACH(oid, oidlist, oid_link) {
			buflen = sysctlpreflen + strlen(oid->oid_name);
			char *buf = malloc(sizeof(char) * (buflen + 1), 
				HARDENING_PTRACE, M_WAITOK);
			snprintf(buf, buflen, "hardening.ptrace.flag.%s",
				oid->oid_name);	
			buf[buflen] = '\0';

			kernel_sysctlbyname(req->td, buf, NULL, 
				0, &val, sizeof(val), NULL, 0);
			free(buf, HARDENING_PTRACE);
		}
		break;
	default:
		return (EINVAL);
	}

	return (0);
}

#ifdef PTRACE_HARDENING_GRP
int
sysctl_ptrace_hardening_gid(SYSCTL_HANDLER_ARGS)
{
	struct prison *pr = NULL;
	long val;
	int err;

	pr = ptrace_get_prison(req->td->td_proc);

	val = (pr != NULL) ? pr->pr_ptrace_hardening_allowed_gid :
	    ptrace_hardening_allowed_gid;
	err = sysctl_handle_long(oidp, &val, sizeof(long), req);
	if (err || (req->newptr == NULL))
		return (err);

	if (val < 0 || val > GID_MAX)
		return (EINVAL);

	if ((pr == NULL) || (pr == &prison0))
		ptrace_hardening_allowed_gid = val;

	if (pr != NULL) {
		prison_lock(pr);
		pr->pr_ptrace_hardening_allowed_gid = val;
		prison_unlock(pr);
	}

	return (0);
}
#endif

int
ptrace_hardening(struct thread *td, struct proc *p, int ptrace_flag)
{
	struct prison *pr = NULL;
	uid_t uid;
	gid_t gid;
	pid_t pid;

	pr = ptrace_get_prison(td->td_proc);

	if (pr == NULL && !ptrace_hardening_status)
		return (0);
	if (pr != NULL && !pr->pr_ptrace_hardening_status)
		return (0);

	if (p->p_ptrace_hardening & PTRACE_HARDENING_MODE_PUBLIC)
		return (0);

	uid = td->td_ucred->cr_ruid;
	gid = td->td_ucred->cr_rgid;
	pid = p->p_pid;

	if (pr == NULL && ptrace_hardening_flag_status &&
	    !ptrace_request_flags[ptrace_flag])
		goto fail;
	if (pr != NULL && pr->pr_ptrace_hardening_flag_status &&
	    !pr->pr_ptrace_request_flags[ptrace_flag])
		goto fail;

#ifdef PTRACE_HARDENING_GRP
	if (uid && pr == NULL && (ptrace_hardening_allowed_gid &&
	    gid != ptrace_hardening_allowed_gid))
		goto fail;
	if (uid && pr != NULL && (pr->pr_ptrace_hardening_allowed_gid &&
	    gid != pr->pr_ptrace_hardening_allowed_gid))
		goto fail;
#else
	if (uid != 0)
		goto fail;
#endif

	return (0);

fail:
	ptrace_log_hardening(td->td_proc, __func__, "forbidden ptrace call attempt "
	    "from %ld:%ld, pid %ld\n", uid, gid, pid);

	return (EPERM);
}

void
ptrace_hardening_mode(struct image_params *imgp, uint32_t mode)
{
	u_int flags = 0;

	if ((mode & MBI_ALLPTRACE_HARDENING) != MBI_ALLPTRACE_HARDENING) {
		if (mode & MBI_FORCE_PTRACE_HARDENING_ENABLED)
			flags |= PTRACE_HARDENING_MODE_ROOTONLY;
		else if (mode & MBI_FORCE_PTRACE_HARDENING_DISABLED)
			flags |= PTRACE_HARDENING_MODE_PUBLIC;
	}

	if (imgp != NULL && imgp->proc != NULL) {
		PROC_LOCK(imgp->proc);
		imgp->proc->p_ptrace_hardening = flags;
		PROC_UNLOCK(imgp->proc);
	}
}

static void
ptrace_hardening_sysinit(void)
{
	if (ptrace_hardening_status < 0 || ptrace_hardening_status > 1)
		ptrace_hardening_status = PTRACE_HARDENING_ENABLED;

	if (ptrace_hardening_flag_status < 0 || ptrace_hardening_flag_status > 1)
		ptrace_hardening_flag_status = PTRACE_HARDENING_REQFLAG_ENABLED;

	printf("[PTRACE HARDENING] status : %s\n",
	    ptrace_hardening_status ? "enabled" : "disabled");
	printf("[PTRACE HARDENING] flags : %s\n",
	    ptrace_hardening_flag_status ? "enabled" : "disabled");
#ifdef PTRACE_HARDENING_GRP
	printf("[PTRACE HARDENING] allowed gid : %d\n",
	    ptrace_hardening_allowed_gid);
#endif
}
SYSINIT(ptrace, SI_SUB_PTRACE_HARDENING, SI_ORDER_FIRST, ptrace_hardening_sysinit, NULL);

struct prison *
ptrace_get_prison(struct proc *p)
{
	if ((p == NULL) || (p->p_ucred == NULL))
		return (NULL);

	return (p->p_ucred->cr_prison);
}

void
ptrace_hardening_init_prison(struct prison *pr)
{
	if (pr == NULL)
		return;

	if (pr->pr_ptrace_hardening_set)
		return;

	mtx_lock(&(pr->pr_mtx));

	pr->pr_ptrace_hardening_status = ptrace_hardening_status;

#ifdef PTRACE_HARDENING_GRP
	pr->pr_ptrace_hardening_allowed_gid = ptrace_hardening_allowed_gid;
#endif

	pr->pr_ptrace_request_flag_status = ptrace_request_flag_status;
	pr->pr_ptrace_request_flags_all = ptrace_request_flags_all;
	memcpy(pr->pr_ptrace_request_flags, ptrace_request_flags,
		sizeof(pr->pr_ptrace_request_flags));

	mtx_unlock(&(pr->pr_mtx));
}
