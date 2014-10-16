# $FreeBSD$

# The include file <bsd.libnames.mk> define library names.
# Other include files (e.g. bsd.prog.mk, bsd.lib.mk) include this
# file where necessary.

.if !target(__<bsd.init.mk>__)
.error bsd.libnames.mk cannot be included directly.
.endif

.sinclude <src.libnames.mk>

LIBCRT0?=	${DESTDIR}${LIBDIR}/crt0.o

LIBALIAS?=	${DESTDIR}${LIBDIR}/libalias.a
LIBARCHIVE?=	${DESTDIR}${LIBDIR}/libarchive.a
LIBASN1?=	${DESTDIR}${LIBDIR}/libasn1.a
LIBASN1_PIC?=	${DESTDIR}${LIBDIR}/libasn1_pic.a
LIBATM?=	${DESTDIR}${LIBDIR}/libatm.a
LIBAUDITD?=	${DESTDIR}${LIBDIR}/libauditd.a
LIBAUDITD_PIC?=	${DESTDIR}${LIBDIR}/libauditd_pic.a
LIBAVL?=	${DESTDIR}${LIBDIR}/libavl.a
LIBBEGEMOT?=	${DESTDIR}${LIBDIR}/libbegemot.a
LIBBLUETOOTH?=	${DESTDIR}${LIBDIR}/libbluetooth.a
LIBBSDXML?=	${DESTDIR}${LIBDIR}/libbsdxml.a
LIBBSM?=	${DESTDIR}${LIBDIR}/libbsm.a
LIBBSM_PIC?=	${DESTDIR}${LIBDIR}/libbsm_pic.a
LIBBSNMP?=	${DESTDIR}${LIBDIR}/libbsnmp.a
LIBBZ2?=	${DESTDIR}${LIBDIR}/libbz2.a
LIBCXXRT?=	${DESTDIR}${LIBDIR}/libcxxrt.a
LIBCPLUSPLUS?=	${DESTDIR}${LIBDIR}/libc++.a
LIBC?=		${DESTDIR}${LIBDIR}/libc.a
LIBC_PIC?=	${DESTDIR}${LIBDIR}/libc_pic.a
LIBCALENDAR?=	${DESTDIR}${LIBDIR}/libcalendar.a
LIBCAM?=	${DESTDIR}${LIBDIR}/libcam.a
LIBCAPSICUM?=	${DESTDIR}${LIBDIR}/libcapsicum.a
LIBCAPSICUM_PIC?=	${DESTDIR}${LIBDIR}/libcapsicum_pic.a
LIBCASPER?=	${DESTDIR}${LIBDIR}/libcasper.a
LIBCASPER_PIC?=	${DESTDIR}${LIBDIR}/libcasper_pic.a
LIBCOM_ERR?=	${DESTDIR}${LIBDIR}/libcom_err.a
LIBCOM_ERR_PIC?=	${DESTDIR}${LIBDIR}/libcom_err_pic.a
LIBCOMPAT?=	${DESTDIR}${LIBDIR}/libcompat.a
LIBCOMPILER_RT?=${DESTDIR}${LIBDIR}/libcompiler_rt.a
LIBCRYPT?=	${DESTDIR}${LIBDIR}/libcrypt.a
LIBCRYPT_PIC?=	${DESTDIR}${LIBDIR}/libcrypt_pic.a
LIBCRYPTO?=	${DESTDIR}${LIBDIR}/libcrypto.a
LIBCRYPTO_PIC?=	${DESTDIR}${LIBDIR}/libcrypto_pic.a
LIBCTF?=	${DESTDIR}${LIBDIR}/libctf.a
LIBCURSES?=	${DESTDIR}${LIBDIR}/libcurses.a
LIBDEVINFO?=	${DESTDIR}${LIBDIR}/libdevinfo.a
LIBDEVSTAT?=	${DESTDIR}${LIBDIR}/libdevstat.a
LIBDIALOG?=	${DESTDIR}${LIBDIR}/libdialog.a
LIBDNS?=	${DESTDIR}${LIBDIR}/libdns.a
LIBDTRACE?=	${DESTDIR}${LIBDIR}/libdtrace.a
LIBDWARF?=	${DESTDIR}${LIBDIR}/libdwarf.a
LIBEDIT?=	${DESTDIR}${LIBDIR}/libedit.a
LIBEDIT_PIC?=	${DESTDIR}${LIBDIR}/libedit_pic.a
LIBELF?=	${DESTDIR}${LIBDIR}/libelf.a
LIBEXECINFO?=	${DESTDIR}${LIBDIR}/libexecinfo.a
LIBFETCH?=	${DESTDIR}${LIBDIR}/libfetch.a
LIBFL?=		"don't use LIBFL, use LIBL"
LIBFORM?=	${DESTDIR}${LIBDIR}/libform.a
LIBFORM_PIC?=	${DESTDIR}${LIBDIR}/libform_pic.a
LIBG2C?=	${DESTDIR}${LIBDIR}/libg2c.a
LIBGEOM?=	${DESTDIR}${LIBDIR}/libgeom.a
LIBGNUREGEX?=	${DESTDIR}${LIBDIR}/libgnuregex.a
LIBGSSAPI?=	${DESTDIR}${LIBDIR}/libgssapi.a
LIBGSSAPI_PIC?=	${DESTDIR}${LIBDIR}/libgssapi_pic.a
LIBGSSAPI_KRB5?= ${DESTDIR}${LIBDIR}/libgssapi_krb5.a
LIBGSSAPI_KRB5_PIC?= ${DESTDIR}${LIBDIR}/libgssapi_krb5_pic.a
LIBHDB?=	${DESTDIR}${LIBDIR}/libhdb.a
LIBHDB_PIC?=	${DESTDIR}${LIBDIR}/libhdb_pic.a
LIBHEIMBASE?=	${DESTDIR}${LIBDIR}/libheimbase.a
LIBHEIMBASE_PIC?=	${DESTDIR}${LIBDIR}/libheimbase_pic.a
LIBHEIMNTLM?=	${DESTDIR}${LIBDIR}/libheimntlm.a
LIBHEIMNTLM_PIC?=	${DESTDIR}${LIBDIR}/libheimntlm_pic.a
LIBHEIMSQLITE?=	${DESTDIR}${LIBDIR}/libheimsqlite.a
LIBHEIMSQLITE_PIC?=	${DESTDIR}${LIBDIR}/libheimsqlite_pic.a
LIBHX509?=	${DESTDIR}${LIBDIR}/libhx509.a
LIBHX509_PIC?=	${DESTDIR}${LIBDIR}/libhx509_pic.a
LIBIPSEC?=	${DESTDIR}${LIBDIR}/libipsec.a
LIBIPSEC_PIC?=	${DESTDIR}${LIBDIR}/libipsec_pic.a
LIBJAIL?=	${DESTDIR}${LIBDIR}/libjail.a
LIBJAIL_PIC?=	${DESTDIR}${LIBDIR}/libjail_pic.a
LIBKADM5CLNT?=	${DESTDIR}${LIBDIR}/libkadm5clnt.a
LIBKADM5CLNT_PIC?=	${DESTDIR}${LIBDIR}/libkadm5clnt_pic.a
LIBKADM5SRV?=	${DESTDIR}${LIBDIR}/libkadm5srv.a
LIBKADM5SRV_PIC?=	${DESTDIR}${LIBDIR}/libkadm5srv_pic.a
LIBKAFS5?=	${DESTDIR}${LIBDIR}/libkafs5.a
LIBKAFS5_PIC?=	${DESTDIR}${LIBDIR}/libkafs5_pic.a
LIBKDC?=	${DESTDIR}${LIBDIR}/libkdc.a
LIBKDC_PIC?=	${DESTDIR}${LIBDIR}/libkdc_pic.a
LIBKEYCAP?=	${DESTDIR}${LIBDIR}/libkeycap.a
LIBKICONV?=	${DESTDIR}${LIBDIR}/libkiconv.a
LIBKRB5?=	${DESTDIR}${LIBDIR}/libkrb5.a
LIBKRB5_PIC?=	${DESTDIR}${LIBDIR}/libkrb5_pic.a
LIBKVM?=	${DESTDIR}${LIBDIR}/libkvm.a
LIBKVM_PIC?=	${DESTDIR}${LIBDIR}/libkvm_pic.a
LIBL?=		${DESTDIR}${LIBDIR}/libl.a
LIBL_PIC?=		${DESTDIR}${LIBDIR}/libl_pic.a
LIBLN?=		"don't use LIBLN, use LIBL"
LIBLZMA?=	${DESTDIR}${LIBDIR}/liblzma.a
LIBM?=		${DESTDIR}${LIBDIR}/libm.a
LIBMAGIC?=	${DESTDIR}${LIBDIR}/libmagic.a
LIBMD?=		${DESTDIR}${LIBDIR}/libmd.a
LIBMD_PIC?=		${DESTDIR}${LIBDIR}/libmd_pic.a
LIBMEMSTAT?=	${DESTDIR}${LIBDIR}/libmemstat.a
LIBMENU?=	${DESTDIR}${LIBDIR}/libmenu.a
LIBMENU_PIC?=	${DESTDIR}${LIBDIR}/libmenu_pic.a
LIBMILTER?=	${DESTDIR}${LIBDIR}/libmilter.a
LIBMP?=		${DESTDIR}${LIBDIR}/libmp.a
LIBNCURSES?=	${DESTDIR}${LIBDIR}/libncurses.a
LIBNCURSES_PIC?=	${DESTDIR}${LIBDIR}/libncurses_pic.a
LIBNCURSESW?=	${DESTDIR}${LIBDIR}/libncursesw.a
LIBNCURSESW_PIC?=	${DESTDIR}${LIBDIR}/libncursesw_pic.a
LIBNETGRAPH?=	${DESTDIR}${LIBDIR}/libnetgraph.a
LIBNGATM?=	${DESTDIR}${LIBDIR}/libngatm.a
LIBNV?=		${DESTDIR}${LIBDIR}/libnv.a
LIBNV_PIC?=		${DESTDIR}${LIBDIR}/libnv_pic.a
LIBNVPAIR?=	${DESTDIR}${LIBDIR}/libnvpair.a
LIBOPIE?=	${DESTDIR}${LIBDIR}/libopie.a
LIBOPIE_PIC?=	${DESTDIR}${LIBDIR}/libopie_pic.a

# The static PAM library doesn't know its secondary dependencies,
# so we have to specify them explicitly. Ths is an unfortunate,
# but necessary departure from testing MK_ flags to define
# values here.
LIBPAM?=	${DESTDIR}${LIBDIR}/libpam.a
LIBPAM_PIC?=	${DESTDIR}${LIBDIR}/libpam_pic.a
MINUSLPAM=	-lpam
MINUSLPAM_PIC=	-lpam_pic
.if defined(LDFLAGS) && !empty(LDFLAGS:M-static)
.if ${MK_KERBEROS} != "no"
LIBPAM+=	${LIBKRB5} ${LIBHX509} ${LIBASN1} ${LIBCRYPTO} ${LIBCRYPT} \
		${LIBROKEN} ${LIBCOM_ERR}
LIBPAM_PIC+=	${LIBKRB5_PIC} ${LIBHX509_PIC} ${LIBASN1_PIC} ${LIBCRYPTO_PIC} ${LIBCRYPT_PIC} \
		${LIBROKEN_PIC} ${LIBCOM_ERR_PIC}
MINUSLPAM+=	-lkrb5 -lhx509 -lasn1 -lcrypto -lcrypt -lroken -lcom_err
MINUSLPAM_PIC+=	-lkrb5_pic -lhx509_pic -lasn1_pic -lcrypto_pic -lcrypt_pic -lroken_pic -lcom_err_pic
.endif
LIBPAM+=	${LIBRADIUS} ${LIBTACPLUS} ${LIBCRYPT} \
		${LIBUTIL} ${LIBOPIE} ${LIBMD}
LIBPAM_PIC+=	${LIBRADIUS_PIC} ${LIBTACPLUS_PIC} ${LIBCRYPT_PIC} \
		${LIBUTIL_PIC} ${LIBOPIE_PIC} ${LIBMD_PIC}
MINUSLPAM+=	-lradius -ltacplus -lcrypt \
		-lutil -lopie -lmd
MINUSLPAM_PIC+=	-lradius_pic -ltacplus_pic -lcrypt_pic \
		-lutil_pic -lopie_pic -lmd_pic
.if ${MK_OPENSSH} != "no"
LIBPAM+=	${LIBSSH} ${LIBCRYPTO} ${LIBCRYPT}
LIBPAM_PIC+=	${LIBSSH_PIC} ${LIBCRYPTO_PIC} ${LIBCRYPT_PIC}
MINUSLPAM+=	-lssh -lcrypto -lcrypt
MINUSLPAM_PIC+=	-lssh_pic -lcrypto_pic -lcrypt_pic
.endif
.if ${MK_NIS} != "no"
LIBPAM+=	${LIBYPCLNT}
LIBPAM_PIC+=	${LIBYPCLNT_PIC}
MINUSLPAM+=	-lypclnt
MINUSLPAM_PIC+=	-lypclnt_pic
.endif
.endif

LIBPANEL?=	${DESTDIR}${LIBDIR}/libpanel.a
LIBPANEL_PIC?=	${DESTDIR}${LIBDIR}/libpanel_pic.a
LIBPCAP?=	${DESTDIR}${LIBDIR}/libpcap.a
LIBPCAP_PIC?=	${DESTDIR}${LIBDIR}/libpcap_pic.a
LIBPJDLOG?=	${DESTDIR}${LIBDIR}/libpjdlog.a
LIBPJDLOG_PIC?=	${DESTDIR}${LIBDIR}/libpjdlog_pic.a
LIBPMC?=	${DESTDIR}${LIBDIR}/libpmc.a
LIBPROC?=	${DESTDIR}${LIBDIR}/libproc.a
LIBPROCSTAT?=	${DESTDIR}${LIBDIR}/libprocstat.a
LIBPTHREAD?=	${DESTDIR}${LIBDIR}/libpthread.a
LIBRADIUS?=	${DESTDIR}${LIBDIR}/libradius.a
LIBROKEN?=	${DESTDIR}${LIBDIR}/libroken.a
LIBROKEN_PIC?=	${DESTDIR}${LIBDIR}/libroken_pic.a
LIBRPCSVC?=	${DESTDIR}${LIBDIR}/librpcsvc.a
LIBRPCSEC_GSS?=	${DESTDIR}${LIBDIR}/librpcsec_gss.a
LIBRT?=		${DESTDIR}${LIBDIR}/librt.a
LIBRTLD_DB?=	${DESTDIR}${LIBDIR}/librtld_db.a
LIBSBUF?=	${DESTDIR}${LIBDIR}/libsbuf.a
LIBSDP?=	${DESTDIR}${LIBDIR}/libsdp.a
LIBSMB?=	${DESTDIR}${LIBDIR}/libsmb.a
LIBSSL?=	${DESTDIR}${LIBDIR}/libssl.a
LIBSSL_PIC?=	${DESTDIR}${LIBDIR}/libssl_pic.a
LIBSSP_NONSHARED?=	${DESTDIR}${LIBDIR}/libssp_nonshared.a
LIBSTAND?=	${DESTDIR}${LIBDIR}/libstand.a
LIBSTDCPLUSPLUS?= ${DESTDIR}${LIBDIR}/libstdc++.a
LIBTACPLUS?=	${DESTDIR}${LIBDIR}/libtacplus.a
LIBTACPLUS_PIC?=	${DESTDIR}${LIBDIR}/libtacplus_pic.a
LIBTERMCAP?=	${DESTDIR}${LIBDIR}/libtermcap.a
LIBTERMCAP_PIC?=	${DESTDIR}${LIBDIR}/libtermcap_pic.a
LIBTERMCAPW?=	${DESTDIR}${LIBDIR}/libtermcapw.a
LIBTERMCAPW_PIC?=	${DESTDIR}${LIBDIR}/libtermcapw_pic.a
LIBTERMLIB?=	"don't use LIBTERMLIB, use LIBTERMCAP"
LIBTINFO?=	"don't use LIBTINFO, use LIBNCURSES"
LIBUFS?=	${DESTDIR}${LIBDIR}/libufs.a
LIBUGIDFW?=	${DESTDIR}${LIBDIR}/libugidfw.a
LIBUMEM?=	${DESTDIR}${LIBDIR}/libumem.a
LIBUSBHID?=	${DESTDIR}${LIBDIR}/libusbhid.a
LIBUSB?=	${DESTDIR}${LIBDIR}/libusb.a
LIBULOG?=	${DESTDIR}${LIBDIR}/libulog.a
LIBUTIL?=	${DESTDIR}${LIBDIR}/libutil.a
LIBUTIL_PIC?=	${DESTDIR}${LIBDIR}/libutil_pic.a
LIBUUTIL?=	${DESTDIR}${LIBDIR}/libuutil.a
LIBVGL?=	${DESTDIR}${LIBDIR}/libvgl.a
LIBVMMAPI?=	${DESTDIR}${LIBDIR}/libvmmapi.a
LIBWIND?=	${DESTDIR}${LIBDIR}/libwind.a
LIBWIND_PIC?=	${DESTDIR}${LIBDIR}/libwind_pic.a
LIBWRAP?=	${DESTDIR}${LIBDIR}/libwrap.a
LIBWRAP_PIC?=	${DESTDIR}${LIBDIR}/libwrap_pic.a
LIBXPG4?=	${DESTDIR}${LIBDIR}/libxpg4.a
LIBY?=		${DESTDIR}${LIBDIR}/liby.a
LIBYPCLNT?=	${DESTDIR}${LIBDIR}/libypclnt.a
LIBZ?=		${DESTDIR}${LIBDIR}/libz.a
LIBZ_PIC?=		${DESTDIR}${LIBDIR}/libz_pic.a
LIBZFS?=	${DESTDIR}${LIBDIR}/libzfs.a
LIBZFS_CORE?=	${DESTDIR}${LIBDIR}/libzfs_core.a
LIBZPOOL?=	${DESTDIR}${LIBDIR}/libzpool.a
