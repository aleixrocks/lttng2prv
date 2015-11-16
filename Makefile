CFLAGS=-march=native -Wall -g
LIBS=-I/home/emercada/Projects/babeltrace/include -L/home/emercada/Projects/babeltrace/lib/.libs -lbabeltrace -L/home/emercada/Projects/babeltrace/formats/ctf/.libs -lbabeltrace-ctf -lpopt -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include -lglib-2.0 -lstdc++ -lm

all: lttng2prv

lttng2prv:
	mkdir -p bin
	gcc ${CFLAGS} src/getArgValue.c src/printHeaders.c src/getThreadInfo.c src/lttng2prv.c -o bin/lttng2prv ${LIBS}

clean:
	rm -r bin
