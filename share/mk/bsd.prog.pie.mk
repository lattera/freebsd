# $FreeBSD$

.include <bsd.prog.mk>
# to include only if a binary needs those flags, otherwise bsd.prog.mk ...

.if ${MACHINE_CPUARCH} == "sparc64"
PIEFLAG=-fPIE
.else
PIEFLAG=-fpie
.endif

.if ${MK_PIE} != "no"
.if !defined(PROG_CXX)
CFLAGS+=${PIEFLAG}
.else
CXXFLAGS+=${PIEFLAG}
.endif
LDFLAGS+=-pie
.endif
