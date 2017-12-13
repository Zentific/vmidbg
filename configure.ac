AC_PREREQ([2.60])
AC_INIT([vmidbg], [0.1], [steve@zentific.com], [], [http://zentific.com/])
AM_INIT_AUTOMAKE([1.10 no-define foreign])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# We need to save old cflags to remove -O2
OLD_CFLAGS=$CFLAGS
OLD_CXXFLAGS=$CXXFLAGS

AC_PROG_CC
AC_PROG_CXX

CFLAGS=$OLD_CFLAGS
CXXFLAGS=$OLD_CXXFLAGS

AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h malloc.h stdio.h stdlib.h string.h sys/time.h sys/mman.h syslog.h unistd.h errno.h pthread.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM
# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_VPRINTF

PKG_CHECK_MODULES([GLIB], [glib-2.0], [], [AC_ERROR([glib-2.0 has to be installed!])])
AC_CHECK_LIB(glib-2.0, [g_malloc0, g_tree_lookup], [], [AC_ERROR([glib-2.0 library is not functional!])])

# Check for LibVMI
AC_CHECK_HEADER([libvmi/libvmi.h], [], [AC_ERROR([LibVMI was not found on the system!])])

AC_CHECK_LIB(vmi, [vmi_init], [], [AC_ERROR([LibVMI library unusable!])])

AC_CHECK_HEADER([xenstore.h])
AC_CHECK_LIB(xenstore, [xc_read, xs_transaction_start], [], [AC_ERROR([Xenstore not found!])])


AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
