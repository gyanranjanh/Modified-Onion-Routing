#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([onionrouting], [1.0], [gyanranjanh@gmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([config.h.in])


# Checks for header files.
AC_CHECK_HEADERS([config.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/socket.h])

# Checks for programs.
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([bzero gethostbyname select socket strerror strstr])

AM_PROG_AR

#LT_INIT
#AC_SUBST([LIBTOOL_DEPS])


# Checks for libraries.

# Checks for header files.


AC_CONFIG_FILES([Makefile
                 src/Makefile
		 src/sha2_third_party/Makefile])
AC_OUTPUT
