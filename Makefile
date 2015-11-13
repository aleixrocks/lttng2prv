CFLAGS=-Wall -g
LIBS=-lbabeltrace -lbabeltrace-ctf -lpopt -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -lglib-2.0 -lstdc++ -lm

all:
	mkdir -p bin
	gcc ${CFLAGS} src/getArgValue.c src/printHeaders.c src/getThreadInfo.c src/ctf2prv.c -o bin/ctf2prv ${LIBS}

clean:
	rm -r bin
