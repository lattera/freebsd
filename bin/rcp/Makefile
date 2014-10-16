#	@(#)Makefile	8.1 (Berkeley) 7/19/93
# $FreeBSD$

.include <src.opts.mk>

PROG=	rcp
SRCS=	rcp.c util.c
CFLAGS+=-DBINDIR=${BINDIR}


BINOWN=	root
BINMODE=4555
PRECIOUSPROG=

.include <bsd.prog.pie.mk>
