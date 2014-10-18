# $FreeBSD$

.include <src.opts.mk>

PROG=	ipfw
SRCS=	ipfw2.c dummynet.c ipv6.c main.c nat.c tables.c
WARNS?=	2

.if ${MK_PF} != "no"
SRCS+=	altq.c
CFLAGS+=-DPF
.endif

WANTS_PIE=yes

.if ${MK_PIE} != "no"
DPADD=	${LIBUTIL_PIC}
LDADD=	-lutil_pic
.else
DPADD=	${LIBUTIL}
LDADD=	-lutil
.endif

MAN=	ipfw.8

.include <bsd.prog.mk>
