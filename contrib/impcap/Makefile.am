pkglib_LTLIBRARIES = impcap.la

impcap_la_SOURCES = impcap.c packets.c
impcap_la_CPPFLAGS = -I$(top_srcdir) $(PTHREADS_CFLAGS) $(RSRT_CFLAGS)
impcap_la_LDFLAGS = -module -avoid-version
impcap_la_LIBADD = -lpcap
