# LIBGSASL_CHECK_CONFIG ([DEFAULT-ACTION])
# ----------------------------------------------------------
#    Seh Hui "Felix" Leong <felixleong@gmail.com>
#
# Checks for libgsasl.  DEFAULT-ACTION is the string yes or no to
# specify whether to default to --with-gsasl or --without-gsasl.
# If not supplied, DEFAULT-ACTION is no.
#
# This macro #defines HAVE_LIBGSASL and HAVE_LIBGSASL if a required header files is
# found, and sets @LIBGSASL_LDFLAGS@ and @LIBGSASL_CPPFLAGS@ to the necessary
# values.
#
# Users may override the detected values by doing something like:
# LIBGSASL_LDFLAGS="-lgsasl" LIBGSASL_CPPFLAGS="-I/usr/myinclude" ./configure
#
# This macro is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
AC_DEFUN([LIBGSASL_CHECK_CONFIG],
[
  AC_ARG_WITH(gsasl,
    [
    If you want to enable client agent authentication:
    AC_HELP_STRING([--with-gsasl@<:@=DIR@:>@], [Include GNU SASL support @<:@default=no@:>@. DIR is the libgsasl library install directory.])] ,[
    if test "$withval" = "no"; then
      want_gsasl="no"
      _libgsasl_with="no"
    elif test "$withval" = "yes"; then
      want_gsasl="yes"
      _libgsasl_with="yes"
    else
      want_gsasl="yes"
      _libgsasl_with=$withval
    fi
    ],[_libgsasl_with=ifelse([$1],,[no],[$1])])

  if test "x$_libgsasl_with" != x"no" ; then
    if test "$_libgsasl_with" = "yes"; then
      PKG_CHECK_MODULES(GSASL, libgsasl >= 1.6.1,
        [
          GSASL_INCDIR=$GSASL_CPPFLAGS
          GSASL_LIBDIR=$GSASL_LIBS
          GSASL_LIBS="-lgsasl"
        ],[found_gsasl="no"])
    else
      AC_MSG_CHECKING(for libgsasl support)
      if test -f $_libgsasl_with/include/gsasl.h; then
        GSASL_INCDIR=-I$_libgsasl_with/include
        GSASL_LIBDIR=-L$_libgsasl_with/lib
        GSASL_LIBS="-lgsasl"
        AC_MSG_RESULT(yes)
      else
        found_gsasl="no"
        AC_MSG_RESULT(no)
      fi
    fi

    if test "x$found_gsasl" != x"no"; then
      GSASL_CPPFLAGS=$GSASL_INCDIR
      GSASL_LDFLAGS=$GSASL_LIBDIR

      found_gsasl="yes"
      AC_DEFINE(HAVE_GSASL,1,[Define to 1 if Gsasl library should be enabled.])
    fi
  fi

  AC_SUBST(GSASL_CPPFLAGS)
  AC_SUBST(GSASL_LDFLAGS)
  AC_SUBST(GSASL_LIBS)
])dnl
