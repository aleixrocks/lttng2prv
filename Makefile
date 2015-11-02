#CFLAGS=-Wall -g
#DIMEMAS_HOME=/home/emercada/soft/src/dimemas
#DIMEMAS_LIBS+=$(DIMEMAS_HOME)/Simulator/prv_utils/paraver.o
#DIMEMAS_LIBS+=$(DIMEMAS_HOME)/Simulator/prv_utils/external_sort.o
LIBS=-lbabeltrace -lbabeltrace-ctf -lpopt -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -lglib-2.0 -lstdc++ -lm #$(DIMEMAS_LIBS)

all:
	mkdir -p bin
	gcc ${CFLAGS} src/ctf2prv.c -o bin/ctf2prv ${LIBS}

clean:
	rm -r bin
