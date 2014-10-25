#	From: @(#)Makefile	8.3 (Berkeley) 1/25/94
# $FreeBSD$

.include <src.opts.mk>

PROG=	mountd
SRCS=	mountd.c getmntopts.c
MAN=	exports.5 netgroup.5 mountd.8

MOUNT=  ${.CURDIR}/../../sbin/mount
CFLAGS+= -I${MOUNT}
WARNS?= 2

.PATH: ${MOUNT}

WANTS_PIE=	yes

.if ${MK_PIE} != "no"
DPADD=	${LIBUTIL_PIC}
LDADD=	-lutil_pic
.else
DPADD=	${LIBUTIL}
LDADD=	-lutil
.endif

.include <bsd.prog.mk>
