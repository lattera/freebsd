# $FreeBSD$

.include <src.opts.mk>

.PATH:	${.CURDIR}/../../../contrib/flex

INSTALL_PIC_ARCHIVE=yes
LIB=    ln
SRCS=   libmain.c libyywrap.c


.if ${MK_INSTALLLIB} != "no"
LINKS=  ${LIBDIR}/libln.a ${LIBDIR}/libl.a
LINKS+=	${LIBDIR}/libln.a ${LIBDIR}/libfl.a
.if !defined(NO_PIC)
LINKS+=  ${LIBDIR}/libln_pic.a ${LIBDIR}/libl_pic.a
LINKS+=	${LIBDIR}/libln_pic.a ${LIBDIR}/libfl_pic.a
.endif
.endif

.if ${MK_PROFILE} != "no"
LINKS+= ${LIBDIR}/libln_p.a ${LIBDIR}/libl_p.a
LINKS+=	${LIBDIR}/libln_p.a ${LIBDIR}/libfl_p.a
.endif

.include <bsd.lib.mk>

