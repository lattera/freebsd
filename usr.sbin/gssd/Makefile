# $FreeBSD$

.include <src.opts.mk>

PROG=	gssd
MAN=	gssd.8
SRCS=	gssd.c gssd.h gssd_svc.c gssd_xdr.c gssd_prot.c

CFLAGS+= -I.
WARNS?= 1

WANTS_PIE=	yes

.if ${MK_PIE} != "no"
DPADD=	${LIBGSSAPI_PIC}
LDADD=	-lgssapi_pic
.else
DPADD=	${LIBGSSAPI}
LDADD=	-lgssapi
.endif

.if ${MK_KERBEROS_SUPPORT} != "no"
.if ${MK_PIE} != "no"
DPADD+=	${LIBKRB5_PIC} ${LIBHX509_PIC} ${LIBASN1_PIC} ${LIBROKEN_PIC} ${LIBCOM_ERR_PIC} ${LIBCRYPT_PIC} ${LIBCRYPTO_PIC}
DPADD+= ${LIBWIND_PIC} ${LIBHEIMBASE_PIC} ${LIBHEIMIPCC}
LDADD+=	-lkrb5_pic -lhx509_pic -lasn1_pic -lroken_pic -lcom_err_pic -lcrypt_pic -lcrypto_pic -lwind_pic -lheimbase_pic
LDADD+= ${LDHEIMIPCC}
.else
DPADD+=	${LIBKRB5} ${LIBHX509} ${LIBASN1} ${LIBROKEN} ${LIBCOM_ERR} ${LIBCRYPT} ${LIBCRYPTO}
LDADD+=	-lkrb5 -lhx509 -lasn1 -lroken -lcom_err -lcrypt -lcrypto
.endif
.else
CFLAGS+= -DWITHOUT_KERBEROS
.endif

CLEANFILES= gssd_svc.c gssd.h

RPCSRC=	${.CURDIR}/../../sys/kgssapi/gssd.x
RPCGEN= RPCGEN_CPP=${CPP:Q} rpcgen -L -C -M

gssd_svc.c: ${RPCSRC} gssd.h
	${RPCGEN} -m -o ${.TARGET} ${RPCSRC}

gssd_xdr.c: ${RPCSRC} gssd.h
	${RPCGEN} -c -o ${.TARGET} ${RPCSRC}

gssd.h: ${RPCSRC}
	${RPCGEN} -h -o ${.TARGET} ${RPCSRC}

.PATH:	${.CURDIR}/../../sys/kgssapi

.include <bsd.prog.mk>
