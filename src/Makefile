CFLAGS=-march=native -Wall -g
LIBS=-I/home/emercada/Projects/babeltrace/include -L/home/emercada/Projects/babeltrace/lib/.libs -lbabeltrace -L/home/emercada/Projects/babeltrace/formats/ctf/.libs -lbabeltrace-ctf -lpopt -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include -lglib-2.0 -lstdc++ -lm

sources = lttng2prv.c getArgValue.c getThreadInfo.c printHeaders.c

all: lttng2prv

lttng2prv: $(sources)
	gcc ${CFLAGS} -o $@ $+ ${LIBS}

clean:
	-rm lttng2prv
