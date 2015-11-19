#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([lttng2prv], [0.1], [lau.mercadal@bsc.es])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/getArgValue.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for libraries.
AC_SEARCH_LIBS([cos], [m], [],
							 [AC_MSG_ERROR([Cannot find m.])])
AC_SEARCH_LIBS([poptGetContext], [popt], [],
							 [AC_MSG_ERROR([Cannot find popt.])])
AC_SEARCH_LIBS([bt_context_create], [babeltrace], [],
							 [AC_MSG_ERROR([Cannot find babeltrace.])])
AC_SEARCH_LIBS([bt_ctf_get_field], [babeltrace-ctf], [],
							 [AC_MSG_ERROR([Cannot find babeltrace-ctf.])])

PKG_CHECK_MODULES([glib2], [glib-2.0], [],
									[AC_MSG_ERROR([Cannot find glib-2.0.])])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h inttypes.h stdlib.h string.h])
AC_CHECK_HEADER([babeltrace/babeltrace.h], [],
								[AC_MSG_ERROR([Cannot find babeltrace/babeltrace.h])],
								[AC_INCLUDES_DEFAULT])
AC_CHECK_HEADER([babeltrace/context.h], [],
								[AC_MSG_ERROR([Cannot find babeltrace/context.h])],
								[AC_INCLUDES_DEFAULT])
AC_CHECK_HEADER([babeltrace/format.h], [],
								[AC_MSG_ERROR([Cannot find babeltrace/format.h])],
								[AC_INCLUDES_DEFAULT])
AC_CHECK_HEADER([babeltrace/ctf/callbacks.h], [],
								[AC_MSG_ERROR([Cannot find babeltrace/ctf/callbacks.h])],
								[AC_INCLUDES_DEFAULT])
AC_CHECK_HEADER([babeltrace/ctf/events.h], [],
								[AC_MSG_ERROR([Cannot find babeltrace/ctf/events.h])],
								[AC_INCLUDES_DEFAULT])
AC_CHECK_HEADER([babeltrace/ctf/iterator.h], [],
								[AC_MSG_ERROR([Cannot find babeltrace/ctf/iterator.h])],
								[AC_INCLUDES_DEFAULT])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memmove strndup strstr])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT

