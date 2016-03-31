bin_PROGRAMS = lttng2prv
lttng2prv_CFLAGS = $(CFLAGS) $(glib2_CFLAGS)
lttng2prv_SOURCES = lttng2prv.h lttng2prv.c getArgValue.c getThreadInfo.h \
		    getThreadInfo.c printHeaders.c fillArgTypes.h fillArgTypes.c \
		    listEvents.h listEvents.c types.h
lttng2prv_LDADD = $(LDFLAGS) $(glib2_LIBS)
