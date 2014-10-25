# $FreeBSD$

.include <src.opts.mk>

PROG=		iscsid
SRCS=		chap.c discovery.c iscsid.c keys.c log.c login.c pdu.c
CFLAGS+=	-I${.CURDIR}
CFLAGS+=	-I${.CURDIR}/../../sys/cam
CFLAGS+=	-I${.CURDIR}/../../sys/dev/iscsi
#CFLAGS+=	-DICL_KERNEL_PROXY
MAN=		iscsid.8

WANTS_PIE=	yes

.if ${MK_PIE} != "no"
DPADD=		${LIBCRYPTO_PIC} ${LIBSSL_PIC} ${LIBUTIL_PIC}
LDADD=		-lcrypto_pic -lssl_pic -lutil_pic
.else
DPADD=		${LIBCRYPTO} ${LIBSSL} ${LIBUTIL}
LDADD=		-lcrypto -lssl -lutil
.endif

WARNS=		6

.include <bsd.prog.mk>
