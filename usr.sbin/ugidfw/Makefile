# $FreeBSD$

.include <bsd.opts.mk>

PROG=	ugidfw
MAN=	ugidfw.8

WANTS_PIE=	yes

.if ${MK_PIE} != "no"
DPADD=	${LIBUGIDFW_PIC}
LDADD=	-lugidfw_pic
.else
DPADD=	${LIBUGIDFW}
LDADD=	-lugidfw
.endif

.include <bsd.prog.mk>
