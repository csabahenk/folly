lib_LTLIBRARIES=	libfolly.la

libfolly_la_SOURCES= 	\
	folly.c		\
	folly_nodeops.c
	tree_xd.h

if !HAVE_SYS_QUEUE_H
libfolly_la_SOURCES+=	queue.h
endif

if LINUX
libfolly_la_SOURCES+=	sendfd.c
endif

libfolly_la_CFLAGS=	-I$(top_builddir)/include

libfolly_la_LDFLAGS = -version-number $(LIBTOOL_VERSNUM)
