COPT = -O3

all:	pin forkserver.so

pin:
	make -f makefile.pin default
	
forkserver.so:	forkserver.c
	$(CC) $(COPT) -fpic -shared -o forkserver.so forkserver.c

install:
	install -d /usr/local/lib/pintool
	install obj-intel64/afl-pin.so forkserver.so /usr/local/lib/pintool
	install afl-fuzz-pin.sh /usr/local/bin

clean:
	rm -rf obj* *~ *.so *.o
