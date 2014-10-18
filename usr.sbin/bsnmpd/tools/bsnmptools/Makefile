# $FreeBSD$
# Author: Shteryana Shopova <syrinx@FreeBSD.org>

.include <src.opts.mk>

.PATH: ${.CURDIR}

PROG=	bsnmpget

WANTS_PIE=yes

.if ${MK_PIE} != "no"
DPADD+=	${LIBBSNMP_PIC} ${LIBBSNMPTOOLS_PIC}
LDADD+=	-lbsnmp_pic -lbsnmptools_pic
.else
DPADD+=	${LIBBSNMP} ${LIBBSNMPTOOLS}
LDADD+=	-lbsnmp -lbsnmptools
.endif
CFLAGS+=	-I${.CURDIR}/../libbsnmptools
LDFLAGS+=	-L${LIBBSNMPTOOLSDIR}

.if ${MK_OPENSSL} != "no"
.if ${MK_PIE} != "no"
DPADD+= ${LIBCRYPTO_PIC}
LDADD+= -lcrypto_pic
.else
DPADD+= ${LIBCRYPTO}
LDADD+= -lcrypto
.endif
.endif

LINKS=  ${BINDIR}/bsnmpget ${BINDIR}/bsnmpwalk
LINKS+=  ${BINDIR}/bsnmpget ${BINDIR}/bsnmpset

MAN=	bsnmpget.1

MLINKS=		bsnmpget.1 bsnmpwalk.1
MLINKS+=	bsnmpget.1 bsnmpset.1

.include <bsd.prog.mk>
