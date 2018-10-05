AC_INIT(py-netif, 1.0)

AC_LANG(C)
AC_PROG_CC

define(SECTION_TITLE,
[
	echo >& AS_MESSAGE_FD
	echo '   $1   ' | sed -e's/./-/g' >&AS_MESSAGE_FD
	echo '   $1' >& AS_MESSAGE_FD
	echo '   $1   ' | sed -e's/./-/g' >&AS_MESSAGE_FD
])

dnl works for checking define statements in c
m4_include([m4/AX_CHECK_DEFINE.m4])

freebsd_src=${FREEBSD_SRC:=/usr/src}

dnl Setting appropriate CFLAGS


CFLAGS="-nostdinc
-I${freebsd_src}/sys/ 
-I${freebsd_src}/sbin/ifconfig/ 
${CFLAGS} -I/usr/include"


SECTION_TITLE([RUNNING TESTS ON if_lagg HEADER])

AC_CHECK_HEADERS([sys/types.h], [], [AC_ERROR([A working sys/types header is required])])
AC_CHECK_HEADERS([sys/sysctl.h], [], [AC_ERROR([A working sys/sysctl header is required])])
AC_CHECK_HEADERS([net/if_lagg.h], [], [AC_ERROR([A working if_lagg header is required])],[
	#include <sys/types.h>
	#include <sys/sysctl.h>
	#include <net/ethernet.h>
	#include <net/if.h>
])


dnl Checking for LAGG_PROTO_ETHERCHANNEL define
AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
		[
#include <sys/types.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_lagg.h>
],
		[
#ifdef LAGG_PROTO_ETHERCHANNEL
int ok;
(void)ok;
#else
choke me
#endif
		]
	)],
	[AC_SUBST(HAVE_LAGG_PROTO_ETHERCHANNEL, 1)],
	[AC_SUBST(HAVE_LAGG_PROTO_ETHERCHANNEL, 0)]
)

dnl Checking for LAGG_PORT_DISABLED define
AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
		[
#include <sys/types.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_lagg.h>
],
		[
#ifdef LAGG_PORT_DISABLED
int ok;
(void)ok;
#else
choke me
#endif
		]
	)],
	[AC_SUBST(HAVE_LAGG_PORT_DISABLED, 1)],
	[AC_SUBST(HAVE_LAGG_PORT_DISABLED, 0)]
)

SECTION_TITLE([RUNNING TESTS ON if HEADER])

AC_CHECK_HEADERS([sys/cdefs.h], [], [AC_ERROR([A working sys/cdef header is required])])
AC_CHECK_HEADERS([net/if.h], [], [AC_ERROR([A working net/if.h is required])],[
	#include <sys/cdefs.h>
])


dnl Checking for IFCAP_POLLING_NOCOUNT define

AX_CHECK_DEFINE(
	[net/if.h], [IFCAP_POLLING_NOCOUNT],
	[AC_SUBST(HAVE_IFCAP_POLLING_NOCOUNT, 1)],
	[AC_SUBST(HAVE_IFCAP_POLLING_NOCOUNT, 0)]
)


SECTION_TITLE([RUNNING TESTS ON ifmedia.c])


AC_CHECK_HEADERS([ifmedia.c], [], [AC_ERROR([A working ifmedia.c is required])])


dnl Checking ifm_subtype_tokenring_descriptions existence
AC_MSG_NOTICE([Checking ifm_subtype_tokenring_descriptions existence])

AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
		[#include <ifmedia.c>],
		[
			size_t n = sizeof(ifm_subtype_tokenring_descriptions) /* ; */
		]
	)],
	[AC_DEFINE(HAVE_IFM_SUBTYPE_TOKENRING_DESCRIPTIONS, 1, [FreeBSD with Token Ring support]) AC_MSG_NOTICE([OK])],
	[AC_MSG_NOTICE([Not found])]
)


dnl Checking ifm_subtype_fddi_descriptions existence
AC_MSG_NOTICE([Checking IFM_SUBTYPE_FDDI_DESCRIPTIONS existence])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
		[
#include <sys/types.h>
#include <net/if_media.h>
],
		[
#ifdef IFM_SUBTYPE_FDDI_DESCRIPTIONS
int ok;
(void)ok;
#else
choke me
#endif
		]
	)],
	[AC_DEFINE(HAVE_IFM_SUBTYPE_FDDI_DESCRIPTIONS, 1, [FreeBSD with FDDI support]) AC_MSG_NOTICE([OK])],
	[AC_MSG_NOTICE([Not found])]
)


SECTION_TITLE([GENERATING CONFIG FILES])
AC_CONFIG_FILES([config.pxi])
AC_CONFIG_HEADERS([config.h])

dnl Process Makefile.in to create Makefile
AC_OUTPUT(Makefile)
