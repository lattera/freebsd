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

#ifndef	__SYS_PTRACE_HARDENING_H
#define	__SYS_PTRACE_HARDENING_H

#ifdef _KERNEL

struct image_params;
struct thread;
struct proc;

extern int ptrace_hardening_status;
extern int ptrace_hardening_flag_status;

#ifdef PTRACE_HARDENING_GRP
extern gid_t ptrace_hardening_allowed_gid;
#endif

#define PTRACE_HARDENING_DISABLED			0
#define PTRACE_HARDENING_ENABLED			1
#define PTRACE_HARDENING_REQFLAG_DISABLED	0
#define PTRACE_HARDENING_REQFLAG_ENABLED	1

#define PTRACE_HARDENING_MODE_ROOTONLY	0x00
#define PTRACE_HARDENING_MODE_PUBLIC	0x01

int ptrace_hardening(struct thread *, struct proc *, int);
void ptrace_hardening_mode(struct image_params *, uint32_t);
void ptrace_hardening_init_prison(struct prison *);

extern int hardening_log_log;
extern int hardening_log_ulog;

void ptrace_log_hardening(struct proc *, const char *func,
	const char *fmt, ...);
void ptrace_ulog_hardening(const char *func, const char *fmt, ...);
#endif /* _KERNEL */

#endif /* __SYS_PTRACE_HARDENING_H */
