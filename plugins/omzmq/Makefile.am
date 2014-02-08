pkglib_LTLIBRARIES = omzmq.la

omzmq_la_SOURCES = omzmq.c
omzmq_la_CPPFLAGS =  $(RSRT_CFLAGS) $(PTHREADS_CFLAGS) $(CZMQ_CFLAGS)
omzmq_la_LDFLAGS = -module -avoid-version
omzmq_la_LIBADD =  $(CZMQ_LIBS)

EXTRA_DIST = 
