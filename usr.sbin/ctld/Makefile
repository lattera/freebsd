# $FreeBSD$

.include <src.opts.mk>

PROG=		ctld
SRCS=		ctld.c discovery.c kernel.c keys.c log.c login.c parse.y pdu.c token.l y.tab.h
CFLAGS+=	-I${.CURDIR}
CFLAGS+=	-I${.CURDIR}/../../sys
CFLAGS+=	-I${.CURDIR}/../../sys/cam/ctl
CFLAGS+=	-I${.CURDIR}/../../sys/dev/iscsi
#CFLAGS+=	-DICL_KERNEL_PROXY
MAN=		ctld.8 ctl.conf.5

WANTS_PIE=yes

.if ${MK_PIE} != "no"
DPADD=		${LIBBSDXML_PIC} ${LIBCAM_PIC} ${LIBCRYPTO_PIC} ${LIBL_PIC} ${LIBSBUF_PIC} ${LIBSSL_PIC} ${LIBUTIL_PIC}
LDADD=		-lbsdxml_pic -lcam_pic -lcrypto_pic -ll_pic -lsbuf_pic -lssl_pic -lutil_pic
.else
DPADD=		${LIBBSDXML} ${LIBCAM} ${LIBCRYPTO} ${LIBL} ${LIBSBUF} ${LIBSSL} ${LIBUTIL}
LDADD=		-lbsdxml -lcam -lcrypto -ll -lsbuf -lssl -lutil
.endif

YFLAGS+=	-v
CLEANFILES=	y.tab.c y.tab.h y.output

WARNS=		6
NO_WMISSING_VARIABLE_DECLARATIONS=

.include <bsd.prog.mk>
