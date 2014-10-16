# $FreeBSD$

.include <src.opts.mk>

PROG=	casperd

SRCS=	casperd.c zygote.c

.if ${MK_PIE} != "no"
DPADD=	${LIBCASPER_PIC} ${LIBCAPSICUM_PIC} ${LIBNV_PIC} ${LIBPJDLOG_PIC} ${LIBUTIL_PIC}
LDADD=	-lcasper_pic -lcapsicum_pic -lnv_pic -lpjdlog_pic -lutil_pic
.else
DPADD=	${LIBCASPER} ${LIBCAPSICUM} ${LIBNV} ${LIBPJDLOG} ${LIBUTIL}
LDADD=	-lcasper -lcapsicum -lnv -lpjdlog -lutil
.endif

MAN=	casperd.8

CFLAGS+=-I${.CURDIR}
CFLAGS+=-I${.CURDIR}/../../lib/libcapsicum
CFLAGS+=-I${.CURDIR}/../../lib/libcasper
CFLAGS+=-I${.CURDIR}/../../lib/libnv
CFLAGS+=-I${.CURDIR}/../../lib/libpjdlog

.include <bsd.prog.pie.mk>
