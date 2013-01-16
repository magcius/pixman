include $(top_srcdir)/pixman/Makefile.sources

lib_LTLIBRARIES = libpixman-1.la

libpixman_1_la_LDFLAGS = -version-info $(LT_VERSION_INFO) -no-undefined @PTHREAD_LDFLAGS@ 
libpixman_1_la_LIBADD = @PTHREAD_LIBS@ -lm
libpixman_1_la_SOURCES = $(libpixman_sources) $(libpixman_headers)

libpixmanincludedir = $(includedir)/pixman-1
libpixmaninclude_HEADERS = pixman.h pixman-version.h
noinst_LTLIBRARIES = 

EXTRA_DIST =				\
	Makefile.win32			\
	pixman-region.c			\
	$(NULL)
