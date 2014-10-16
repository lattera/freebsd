#	@(#)Makefile	8.1 (Berkeley) 7/19/93
# $FreeBSD$

.include <src.opts.mk>

PROG=	su

WARNS?=	5

.if ${MK_PIE} != "no"
DPADD=	${LIBUTIL_PIC} ${LIBPAM_PIC}
LDADD=	-lutil_pic ${MINUSLPAM_PIC}
.else
DPADD=	${LIBUTIL} ${LIBPAM}
LDADD=	-lutil ${MINUSLPAM}
.endif

.if ${MK_AUDIT} != "no"
CFLAGS+= -DUSE_BSM_AUDIT
.if ${MK_PIE} != "no"
DPADD+=  ${LIBBSM_PIC}
LDADD+=  -lbsm_pic
.else
DPADD+=  ${LIBBSM}
LDADD+=  -lbsm
.endif
.endif

BINOWN=	root
BINMODE=4555
PRECIOUSPROG=

.include <bsd.prog.pie.mk>
