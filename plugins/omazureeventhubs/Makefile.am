pkglib_LTLIBRARIES = omazureeventhubs.la

omazureeventhubs_la_SOURCES = omazureeventhubs.c
omazureeventhubs_la_LDFLAGS = -module -avoid-version
omazureeventhubs_la_CPPFLAGS = $(RSRT_CFLAGS) $(PTHREADS_CFLAGS) $(CURL_CFLAGS) $(PROTON_CFLAGS) -Wno-error=switch
omazureeventhubs_la_LIBADD = $(PROTON_LIBS) $(PTHREADS_LIBS) $(OPENSSL_LIBS)

EXTRA_DIST = 
