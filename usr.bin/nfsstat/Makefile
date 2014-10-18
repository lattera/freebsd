#	@(#)Makefile	8.1 (Berkeley) 6/6/93
# $FreeBSD$

.include <src.opts.mk>

PROG=	nfsstat
CFLAGS+=-DNFS

WANTS_PIE=yes

.if ${MK_PIE} != "no"
DPADD=  ${LIBKVM_PIC}
LDADD= -lkvm_pic
.else
DPADD=  ${LIBKVM}
LDADD= -lkvm
.endif

WARNS?=	3

.include <bsd.prog.mk>
